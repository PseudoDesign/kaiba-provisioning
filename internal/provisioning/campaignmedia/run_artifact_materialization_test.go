package campaignmedia

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

func TestRunArtifactMaterializationCoversEveryFixedRun(t *testing.T) {
	plan := mustStableCampaignPlan(t)
	baseline := mustArtifactSet(t, plan)
	resolved := resolvedArtifactsForSet(plan, baseline)
	runs, err := stablecampaign.ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 33 {
		t.Fatalf("got %d fixed runs, want 33", len(runs))
	}

	mutationCount := 0
	noMutationCount := 0
	kindCounts := make(map[RunArtifactMutationKind]int)
	roleCounts := make(map[PartitionRole]int)
	for _, run := range runs {
		run := run
		t.Run(run.RunID, func(t *testing.T) {
			artifacts := materializedArtifactsForRun(t, plan, baseline, resolved, run)
			materialization, err := NewRunArtifactMaterialization(
				plan, baseline, resolved, run.Index, artifacts,
			)
			if err != nil {
				t.Fatalf("construct run %d: %v", run.Index, err)
			}
			if materialization.RunIndex != run.Index || materialization.RunID != run.RunID ||
				materialization.PlanDigest != plan.PlanDigest ||
				materialization.ArtifactSetContentDigest != baseline.ArtifactSetContentDigest {
				t.Fatal("materialization does not bind the fixed run, plan, and baseline artifact set")
			}
			if err := materialization.ValidateAgainst(plan, baseline, resolved); err != nil {
				t.Fatalf("validate run %d: %v", run.Index, err)
			}

			encoded, err := materialization.CanonicalJSON()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseRunArtifactMaterialization(append(append([]byte(nil), encoded...), '\n'))
			if err != nil {
				t.Fatalf("parse canonical run %d: %v", run.Index, err)
			}
			if !reflect.DeepEqual(parsed, materialization) {
				t.Fatal("canonical round trip changed the materialization")
			}
			if err := parsed.ValidateAgainst(plan, baseline, resolved); err != nil {
				t.Fatalf("validate parsed run %d: %v", run.Index, err)
			}

			changed := changedMaterializedRoles(baseline.Artifacts, materialization.MaterializedArtifacts)
			if run.MutationRecipeID == "" {
				noMutationCount++
				if materialization.Mutation != nil || len(changed) != 0 ||
					!reflect.DeepEqual(materialization.MaterializedArtifacts, baseline.Artifacts) {
					t.Fatal("no-mutation run did not preserve the complete baseline payload set")
				}
				return
			}

			mutationCount++
			if materialization.Mutation == nil {
				t.Fatal("mutated run omitted its selected recipe")
			}
			role := materialization.Mutation.AffectedArtifactRole
			kindCounts[materialization.Mutation.Kind]++
			roleCounts[role]++
			if len(changed) != 1 || changed[0] != role {
				t.Fatalf("changed roles = %v, want exactly [%s]", changed, role)
			}
			if materialization.Mutation.RecipeID != run.MutationRecipeID {
				t.Fatalf("selected recipe = %q, want %q", materialization.Mutation.RecipeID, run.MutationRecipeID)
			}
			result := artifactEntryForRole(t, materialization.MaterializedArtifacts, role)
			selected := materialization.Mutation.SelectedTarget
			if strings.HasPrefix(selected.Target, "release/") {
				// The selected target is inside the release filesystem. Use a
				// deliberately distinct digest to ensure validation never treats
				// the file digest as the enclosing filesystem-payload digest.
				if result.Digest == selected.After.Digest {
					t.Fatal("release filesystem payload incorrectly aliases selected file after digest")
				}
			} else if result.Digest != selected.After.Digest || result.SizeBytes != selected.After.SizeBytes {
				t.Fatal("direct-media materialization does not bind selected_target.after")
			}
		})
	}

	if mutationCount != 30 || noMutationCount != 3 {
		t.Fatalf("got %d mutation and %d no-mutation runs, want 30 and 3", mutationCount, noMutationCount)
	}
	if kindCounts[RunArtifactMutationByteXOR] != 10 ||
		kindCounts[RunArtifactMutationBoundReplacement] != 20 || len(kindCounts) != 2 {
		t.Fatalf("unexpected recipe-kind coverage: %v", kindCounts)
	}
	if roleCounts[PartitionReleaseFilesystem] != 28 || roleCounts[PartitionRootData] != 1 ||
		roleCounts[PartitionRootHash] != 1 || len(roleCounts) != 3 {
		t.Fatalf("unexpected mutation role coverage: %v", roleCounts)
	}
	if baseline.RunID != artifactSetRunID || baseline.RecipeID != nil || baseline.Capabilities.MutationPerformed {
		t.Fatal("run materialization changed the positive-baseline ArtifactSet invariant")
	}
}

func TestRunArtifactMaterializationRejectsInvalidResultsAndDetachedInputs(t *testing.T) {
	plan := mustStableCampaignPlan(t)
	baseline := mustArtifactSet(t, plan)
	resolved := resolvedArtifactsForSet(plan, baseline)
	runs, err := stablecampaign.ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	baselineRun := runByID(t, runs, "positive-baseline")
	releaseRun := firstRunForRole(t, plan, resolved, runs, PartitionReleaseFilesystem)
	rootDataRun := firstRunForRole(t, plan, resolved, runs, PartitionRootData)

	tests := []struct {
		name      string
		run       stablecampaign.RunSpec
		artifacts func() []ArtifactSetEntry
	}{
		{
			name: "no-mutation payload changed", run: baselineRun,
			artifacts: func() []ArtifactSetEntry {
				result := cloneArtifactEntries(baseline.Artifacts)
				result[0].Digest = testDigest("changed boot payload in baseline run")
				return result
			},
		},
		{
			name: "mutation payload unchanged", run: releaseRun,
			artifacts: func() []ArtifactSetEntry { return cloneArtifactEntries(baseline.Artifacts) },
		},
		{
			name: "unrelated payload changed", run: releaseRun,
			artifacts: func() []ArtifactSetEntry {
				result := materializedArtifactsForRun(t, plan, baseline, resolved, releaseRun)
				entry := artifactEntryIndex(t, result, PartitionBootFilesystem)
				result[entry].Digest = testDigest("unrelated changed boot payload")
				return result
			},
		},
		{
			name: "direct-media digest not recipe after", run: rootDataRun,
			artifacts: func() []ArtifactSetEntry {
				result := materializedArtifactsForRun(t, plan, baseline, resolved, rootDataRun)
				entry := artifactEntryIndex(t, result, PartitionRootData)
				result[entry].Digest = testDigest("detached direct-media result")
				return result
			},
		},
		{
			name: "affected payload size changed", run: releaseRun,
			artifacts: func() []ArtifactSetEntry {
				result := materializedArtifactsForRun(t, plan, baseline, resolved, releaseRun)
				entry := artifactEntryIndex(t, result, PartitionReleaseFilesystem)
				result[entry].SizeBytes++
				return result
			},
		},
		{
			name: "missing payload", run: releaseRun,
			artifacts: func() []ArtifactSetEntry {
				return materializedArtifactsForRun(t, plan, baseline, resolved, releaseRun)[:3]
			},
		},
		{
			name: "extra payload", run: releaseRun,
			artifacts: func() []ArtifactSetEntry {
				result := materializedArtifactsForRun(t, plan, baseline, resolved, releaseRun)
				return append(result, result[0])
			},
		},
		{
			name: "reordered payloads", run: releaseRun,
			artifacts: func() []ArtifactSetEntry {
				result := materializedArtifactsForRun(t, plan, baseline, resolved, releaseRun)
				result[0], result[1] = result[1], result[0]
				return result
			},
		},
		{
			name: "invalid payload digest", run: releaseRun,
			artifacts: func() []ArtifactSetEntry {
				result := materializedArtifactsForRun(t, plan, baseline, resolved, releaseRun)
				result[1].Digest = "sha256:not-canonical"
				return result
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewRunArtifactMaterialization(
				plan, baseline, resolved, test.run.Index, test.artifacts(),
			); err == nil {
				t.Fatal("invalid materialized artifact set was accepted")
			}
		})
	}

	for _, index := range []uint16{0, 34} {
		t.Run("run index", func(t *testing.T) {
			if _, err := NewRunArtifactMaterialization(
				plan, baseline, resolved, index, baseline.Artifacts,
			); err == nil {
				t.Fatalf("run index %d was accepted", index)
			}
		})
	}

	detachedResolved := resolvedArtifactsForSet(plan, baseline)
	detachedResolved.ByteXORMutations[0].After.Digest = testDigest("detached resolved recipe")
	if _, err := NewRunArtifactMaterialization(
		plan, baseline, detachedResolved, releaseRun.Index,
		materializedArtifactsForRun(t, plan, baseline, resolved, releaseRun),
	); err == nil {
		t.Fatal("exact-byte resolution detached from plan was accepted")
	}

	detachedBaseline := baseline
	detachedBaseline.ArtifactSetContentDigest = testDigest("detached baseline seal")
	if _, err := NewRunArtifactMaterialization(
		plan, detachedBaseline, resolved, baselineRun.Index, baseline.Artifacts,
	); err == nil {
		t.Fatal("detached positive-baseline ArtifactSet was accepted")
	}
}

func TestRunArtifactMaterializationRejectsCapabilityDigestAndContractTampering(t *testing.T) {
	plan := mustStableCampaignPlan(t)
	baseline := mustArtifactSet(t, plan)
	resolved := resolvedArtifactsForSet(plan, baseline)
	runs, err := stablecampaign.ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	releaseRun := firstRunForRole(t, plan, resolved, runs, PartitionReleaseFilesystem)
	base, err := NewRunArtifactMaterialization(
		plan,
		baseline,
		resolved,
		releaseRun.Index,
		materializedArtifactsForRun(t, plan, baseline, resolved, releaseRun),
	)
	if err != nil {
		t.Fatal(err)
	}

	capabilityTests := map[string]func(*RunArtifactMaterializationCapabilities){
		"creation mode": func(value *RunArtifactMaterializationCapabilities) { value.CreationMode = "in-place" },
		"output scope":  func(value *RunArtifactMaterializationCapabilities) { value.OutputScope = "arbitrary-path" },
		"device access": func(value *RunArtifactMaterializationCapabilities) { value.DeviceAccessPerformed = true },
		"signing":       func(value *RunArtifactMaterializationCapabilities) { value.SigningPerformed = true },
		"private key":   func(value *RunArtifactMaterializationCapabilities) { value.PrivateKeyOperationPerformed = true },
		"hardware":      func(value *RunArtifactMaterializationCapabilities) { value.HardwareObserved = true },
		"execution":     func(value *RunArtifactMaterializationCapabilities) { value.ExecutionPerformed = true },
		"claim closure": func(value *RunArtifactMaterializationCapabilities) { value.ClaimClosurePerformed = true },
		"production":    func(value *RunArtifactMaterializationCapabilities) { value.ProductionReady = true },
	}
	for name, mutate := range capabilityTests {
		t.Run("capability "+name, func(t *testing.T) {
			tampered := cloneRunArtifactMaterialization(base)
			mutate(&tampered.Capabilities)
			tampered.MaterializationDigest = ""
			if _, err := tampered.DerivedDigest(); err == nil {
				t.Fatal("forbidden capability was accepted")
			}
		})
	}

	t.Run("stale digest", func(t *testing.T) {
		tampered := cloneRunArtifactMaterialization(base)
		tampered.MaterializedArtifacts[1].Digest = testDigest("unsealed output change")
		if err := tampered.Validate(); err == nil {
			t.Fatal("materialization with a stale content digest was accepted")
		}
	})
	t.Run("malformed digest", func(t *testing.T) {
		tampered := cloneRunArtifactMaterialization(base)
		tampered.MaterializationDigest = "sha256:not-canonical"
		if err := tampered.Validate(); err == nil {
			t.Fatal("malformed materialization digest was accepted")
		}
	})
	t.Run("selected target", func(t *testing.T) {
		tampered := cloneRunArtifactMaterialization(base)
		tampered.Mutation.SelectedTarget.After.Digest = testDigest("forged selected target after")
		resealRunArtifactMaterialization(t, &tampered)
		if err := tampered.Validate(); err != nil {
			t.Fatalf("self-contained validation should accept a structurally valid resealed target: %v", err)
		}
		if err := tampered.ValidateAgainst(plan, baseline, resolved); err == nil {
			t.Fatal("recipe target detached from independently resolved plan was accepted")
		}
	})
	t.Run("unrelated output", func(t *testing.T) {
		tampered := cloneRunArtifactMaterialization(base)
		tampered.MaterializedArtifacts[0].Digest = testDigest("forged unrelated boot output")
		resealRunArtifactMaterialization(t, &tampered)
		if err := tampered.Validate(); err != nil {
			t.Fatalf("self-contained validation should not infer baseline bytes: %v", err)
		}
		if err := tampered.ValidateAgainst(plan, baseline, resolved); err == nil {
			t.Fatal("resealed unrelated role change was accepted")
		}
	})
	t.Run("baseline binding", func(t *testing.T) {
		tampered := cloneRunArtifactMaterialization(base)
		tampered.ArtifactSetContentDigest = testDigest("forged baseline artifact set")
		resealRunArtifactMaterialization(t, &tampered)
		if err := tampered.ValidateAgainst(plan, baseline, resolved); err == nil {
			t.Fatal("resealed detached baseline binding was accepted")
		}
	})
	t.Run("run spec", func(t *testing.T) {
		tampered := cloneRunArtifactMaterialization(base)
		tampered.RunIndex++
		resealRunArtifactMaterialization(t, &tampered)
		if err := tampered.ValidateAgainst(plan, baseline, resolved); err == nil {
			t.Fatal("resealed materialization detached from fixed RunSpec was accepted")
		}
	})
	t.Run("nil mutation needs external plan", func(t *testing.T) {
		baselineRun := runByID(t, runs, "positive-baseline")
		materialization, err := NewRunArtifactMaterialization(
			plan, baseline, resolved, baselineRun.Index, baseline.Artifacts,
		)
		if err != nil {
			t.Fatal(err)
		}
		materialization.RunIndex = releaseRun.Index
		materialization.RunID = releaseRun.RunID
		resealRunArtifactMaterialization(t, &materialization)
		if err := materialization.Validate(); err != nil {
			t.Fatalf("self-contained validation unexpectedly inferred the plan-owned mutation: %v", err)
		}
		if err := materialization.ValidateAgainst(plan, baseline, resolved); err == nil {
			t.Fatal("cross-bound validation accepted nil mutation for a mutated fixed run")
		}
	})

	encoded, err := base.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parserTests := map[string][]byte{
		"duplicate": bytes.Replace(
			encoded,
			[]byte(`"materialization_digest":`),
			[]byte(`"materialization_digest":"duplicate","materialization_digest":`),
			1,
		),
		"unknown": bytes.Replace(
			encoded,
			[]byte(`"campaign_id":`),
			[]byte(`"unexpected":false,"campaign_id":`),
			1,
		),
		"null": bytes.Replace(
			encoded,
			[]byte(`"mutation":{`),
			[]byte(`"mutation":null,"discarded_mutation":{`),
			1,
		),
		"whitespace": append([]byte(" "), encoded...),
		"trailing":   append(append([]byte(nil), encoded...), []byte(`{}`)...),
	}
	for name, input := range parserTests {
		t.Run("parser "+name, func(t *testing.T) {
			if _, err := ParseRunArtifactMaterialization(input); err == nil {
				t.Fatal("ambiguous or noncanonical materialization JSON was accepted")
			}
		})
	}
}

func materializedArtifactsForRun(
	t *testing.T,
	plan stablecampaign.Plan,
	baseline ArtifactSet,
	resolved stablecampaign.ResolvedPublicArtifacts,
	run stablecampaign.RunSpec,
) []ArtifactSetEntry {
	t.Helper()
	result := cloneArtifactEntries(baseline.Artifacts)
	mutation, role, err := selectedRunMutation(plan, resolved, run)
	if err != nil {
		t.Fatal(err)
	}
	if mutation == nil {
		return result
	}
	index := artifactEntryIndex(t, result, *role)
	if strings.HasPrefix(mutation.SelectedTarget.Target, "media/") {
		result[index].Digest = mutation.SelectedTarget.After.Digest
		result[index].SizeBytes = mutation.SelectedTarget.After.SizeBytes
	} else {
		result[index].Digest = testDigest("materialized release filesystem for " + run.RunID)
	}
	return result
}

func changedMaterializedRoles(before, after []ArtifactSetEntry) []PartitionRole {
	var result []PartitionRole
	for index := range before {
		if before[index].Digest != after[index].Digest || before[index].SizeBytes != after[index].SizeBytes {
			result = append(result, after[index].Role)
		}
	}
	return result
}

func artifactEntryForRole(t *testing.T, artifacts []ArtifactSetEntry, role PartitionRole) ArtifactSetEntry {
	t.Helper()
	return artifacts[artifactEntryIndex(t, artifacts, role)]
}

func artifactEntryIndex(t *testing.T, artifacts []ArtifactSetEntry, role PartitionRole) int {
	t.Helper()
	for index, artifact := range artifacts {
		if artifact.Role == role {
			return index
		}
	}
	t.Fatalf("artifact role %q absent", role)
	return -1
}

func cloneArtifactEntries(entries []ArtifactSetEntry) []ArtifactSetEntry {
	return append([]ArtifactSetEntry(nil), entries...)
}

func runByID(t *testing.T, runs []stablecampaign.RunSpec, runID string) stablecampaign.RunSpec {
	t.Helper()
	for _, run := range runs {
		if run.RunID == runID {
			return run
		}
	}
	t.Fatalf("fixed run %q absent", runID)
	return stablecampaign.RunSpec{}
}

func firstRunForRole(
	t *testing.T,
	plan stablecampaign.Plan,
	resolved stablecampaign.ResolvedPublicArtifacts,
	runs []stablecampaign.RunSpec,
	role PartitionRole,
) stablecampaign.RunSpec {
	t.Helper()
	for _, run := range runs {
		mutation, affected, err := selectedRunMutation(plan, resolved, run)
		if err != nil {
			t.Fatal(err)
		}
		if mutation != nil && *affected == role {
			return run
		}
	}
	t.Fatalf("no fixed mutation run affects %q", role)
	return stablecampaign.RunSpec{}
}

func cloneRunArtifactMaterialization(value RunArtifactMaterialization) RunArtifactMaterialization {
	result := value
	result.MaterializedArtifacts = cloneArtifactEntries(value.MaterializedArtifacts)
	if value.Mutation != nil {
		mutation := *value.Mutation
		if value.Mutation.OffsetBytes != nil {
			offset := *value.Mutation.OffsetBytes
			mutation.OffsetBytes = &offset
		}
		if value.Mutation.XORMask != nil {
			mask := *value.Mutation.XORMask
			mutation.XORMask = &mask
		}
		result.Mutation = &mutation
	}
	return result
}

func resealRunArtifactMaterialization(t *testing.T, materialization *RunArtifactMaterialization) {
	t.Helper()
	materialization.MaterializationDigest = ""
	digest, err := materialization.DerivedDigest()
	if err != nil {
		t.Fatalf("reseal materialization: %v", err)
	}
	materialization.MaterializationDigest = digest
}
