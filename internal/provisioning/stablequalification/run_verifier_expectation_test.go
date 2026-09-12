package stablequalification

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

func TestResolveRunVerifierExpectationDerivesAllRunsFromResolvedBytes(t *testing.T) {
	fixture := runExpectationFixture(t)
	runs, err := stablecampaign.ExpectedRuns(fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 33 {
		t.Fatalf("derived %d runs, want 33", len(runs))
	}

	for _, run := range runs {
		expectation, err := ResolveRunVerifierExpectation(fixture.plan, fixture.set, fixture.resolved, run.Index)
		if err != nil {
			t.Fatalf("resolve run %d: %v", run.Index, err)
		}
		if err := expectation.ValidateAgainst(fixture.plan, fixture.set, fixture.resolved); err != nil {
			t.Fatalf("validate run %d: %v", run.Index, err)
		}
		if expectation.RunID != run.RunID || expectation.RecipeID != run.MutationRecipeID ||
			len(expectation.ExpectedVerifierTrace) != len(run.VerifierTrace) {
			t.Fatalf("run %d expectation is detached from its RunSpec: %#v", run.Index, expectation)
		}
		if (expectation.PlannedMutation != nil) != (run.MutationRecipeID != "") {
			t.Fatalf("run %d planned mutation presence differs from its RunSpec", run.Index)
		}
		if expectation.PlannedMutation != nil {
			switch expectation.PlannedMutation.Kind {
			case PlannedMutationByteXOR:
				if expectation.PlannedMutation.OffsetBytes == nil || *expectation.PlannedMutation.OffsetBytes != 0 ||
					expectation.PlannedMutation.XORMask == nil || *expectation.PlannedMutation.XORMask != 1 {
					t.Fatalf("run %d omitted its exact byte-XOR coordinates", run.Index)
				}
			case PlannedMutationBoundReplacement:
				if expectation.PlannedMutation.OffsetBytes != nil || expectation.PlannedMutation.XORMask != nil {
					t.Fatalf("run %d replacement carries byte-XOR coordinates", run.Index)
				}
			default:
				t.Fatalf("run %d has unsupported mutation kind %q", run.Index, expectation.PlannedMutation.Kind)
			}
		}
		wantDetails := runTraceHasDetails(run.VerifierTrace)
		if (expectation.ReleaseDetails != nil) != wantDetails {
			t.Fatalf("run %d release-detail presence = %t, want %t", run.Index, expectation.ReleaseDetails != nil, wantDetails)
		}
		if expectation.ReleaseDetails != nil {
			wantManifest := fixture.set.SemanticResolution.PositiveReleaseManifest.SemanticDigest
			if run.MutationRecipeID == "delegated-key-replacement-boots:replacement-manifest" {
				wantManifest = fixture.set.SemanticResolution.ReplacementReleaseManifest.SemanticDigest
			}
			if expectation.ReleaseDetails.PolicyDigest != fixture.set.SemanticResolution.StableVerifierPolicy.SemanticDigest ||
				expectation.ReleaseDetails.ManifestDigest != wantManifest ||
				expectation.ReleaseDetails.KernelCommandLine != fixture.set.SemanticResolution.KernelCommandLine.Value {
				t.Fatalf("run %d has detached release details: %#v", run.Index, expectation.ReleaseDetails)
			}
		}

		encoded, err := expectation.CanonicalJSON(fixture.plan, fixture.set, fixture.resolved)
		if err != nil {
			t.Fatalf("encode run %d: %v", run.Index, err)
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &object); err != nil {
			t.Fatal(err)
		}
		for _, prohibited := range []string{"pass", "outcome", "claim", "claims", "closure"} {
			if _, present := object[prohibited]; present {
				t.Fatalf("run %d expectation contains prohibited field %q", run.Index, prohibited)
			}
		}
	}

	first, err := ResolveRunVerifierExpectation(fixture.plan, fixture.set, fixture.resolved, 1)
	if err != nil {
		t.Fatal(err)
	}
	first.ExpectedVerifierTrace[0].Event = "caller-mutated"
	second, err := ResolveRunVerifierExpectation(fixture.plan, fixture.set, fixture.resolved, 1)
	if err != nil {
		t.Fatal(err)
	}
	if second.ExpectedVerifierTrace[0].Event == "caller-mutated" {
		t.Fatal("resolved expectation exposed mutable verifier trace state")
	}
}

func TestResolvedRunVerifierExpectationRejectsDetachedInputsAndTampering(t *testing.T) {
	fixture := runExpectationFixture(t)
	expectation, err := ResolveRunVerifierExpectation(fixture.plan, fixture.set, fixture.resolved, 1)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*ResolvedRunVerifierExpectation){
		"run ID": func(value *ResolvedRunVerifierExpectation) { value.RunID = "other-run" },
		"trace": func(value *ResolvedRunVerifierExpectation) {
			value.ExpectedVerifierTrace = append([]ExpectedVerifierEvent(nil), value.ExpectedVerifierTrace...)
			value.ExpectedVerifierTrace[0].Event = "other-event"
		},
		"release details": func(value *ResolvedRunVerifierExpectation) {
			copy := *value.ReleaseDetails
			copy.ManifestDigest = expectationDigest("other manifest")
			value.ReleaseDetails = &copy
		},
		"digest": func(value *ResolvedRunVerifierExpectation) {
			value.ExpectationDigest = expectationDigest("forged expectation")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			detached := expectation
			mutate(&detached)
			if err := detached.ValidateAgainst(fixture.plan, fixture.set, fixture.resolved); err == nil {
				t.Fatal("tampered expectation accepted")
			}
		})
	}

	if _, err := ResolveRunVerifierExpectation(fixture.plan, fixture.set, fixture.resolved, 0); err == nil {
		t.Fatal("accepted run index zero")
	}
	if _, err := ResolveRunVerifierExpectation(fixture.plan, fixture.set, fixture.resolved, 34); err == nil {
		t.Fatal("accepted run index outside the fixed campaign")
	}

	detachedResolution := fixture.resolved
	detachedResolution.PublicInputs = append([]stablecampaign.ArtifactBinding(nil), fixture.resolved.PublicInputs...)
	detachedResolution.PublicInputs[0].Digest = expectationDigest("detached resolution")
	if _, err := ResolveRunVerifierExpectation(fixture.plan, fixture.set, detachedResolution, 1); err == nil {
		t.Fatal("accepted exact-byte resolution detached from the campaign plan")
	}

	detachedSet := fixture.set
	detachedSet.SemanticResolution.PositiveReleaseManifest.SemanticDigest = expectationDigest("detached artifact semantics")
	detachedSet.ArtifactSetContentDigest = ""
	digest, err := detachedSet.DerivedDigest()
	if err != nil {
		t.Fatal(err)
	}
	detachedSet.ArtifactSetContentDigest = digest
	if _, err := ResolveRunVerifierExpectation(fixture.plan, detachedSet, fixture.resolved, 1); err == nil {
		t.Fatal("accepted a resealed artifact set detached from exact-byte semantics")
	}
}

func TestRunVerifierExpectationDigestIsDomainSeparated(t *testing.T) {
	fixture := runExpectationFixture(t)
	expectation, err := ResolveRunVerifierExpectation(fixture.plan, fixture.set, fixture.resolved, 1)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := expectation.CanonicalJSON(fixture.plan, fixture.set, fixture.resolved)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"expectation_digest":"`+string(expectation.ExpectationDigest)+`"`)) {
		t.Fatal("canonical expectation omitted its derived digest")
	}
	wrongDomain := bundle.Sum(encoded)
	if expectation.ExpectationDigest == wrongDomain {
		t.Fatal("expectation digest is not domain separated")
	}
}

type expectationTestFixture struct {
	plan     stablecampaign.Plan
	set      campaignmedia.ArtifactSet
	resolved stablecampaign.ResolvedPublicArtifacts
}

func runExpectationFixture(t *testing.T) expectationTestFixture {
	t.Helper()
	names := stablecampaign.RequiredPublicInputNames()
	inputs := make([]stablecampaign.ArtifactBinding, len(names))
	byName := make(map[string]stablecampaign.ArtifactBinding, len(names))
	for index, name := range names {
		binding := stablecampaign.ArtifactBinding{
			Name: name, Digest: expectationDigest("public input " + name), SizeBytes: uint64(100 + index),
		}
		inputs[index] = binding
		byName[name] = binding
	}

	componentTargets := map[string]string{
		"kernel": "release/kernel", "initramfs": "release/initramfs",
		"resolved-device-tree": "release/device-tree.dtb", "kernel-command-line": "release/cmdline.txt",
		"root-image": "release/root.img", "dm-verity-metadata": "release/dm-verity.json",
		"slot-metadata": "release/slot.txt", "overlay": "release/overlays/campaign.dtbo",
	}
	byteRecipes := make([]stablecampaign.ByteXORMutationRecipe, 0, 10)
	var rootImageBefore stablecampaign.ArtifactBinding
	for _, testCase := range stablecampaign.FixedCases() {
		for _, subcase := range testCase.Subcases {
			target := ""
			switch testCase.TestID {
			case "component-byte-mutations-rejected":
				target = componentTargets[subcase]
			case "dm-verity-corruption-rejected":
				target = "media/" + subcase
			default:
				continue
			}
			name := testCase.TestID + "-" + subcase
			before := stablecampaign.ArtifactBinding{Name: name, Digest: expectationDigest(name + " before"), SizeBytes: 4096}
			switch {
			case testCase.TestID == "component-byte-mutations-rejected" && subcase == "kernel-command-line":
				commandLine := []byte(expectationCommandLine() + "\n")
				before.Digest = bundle.Sum(commandLine)
				before.SizeBytes = uint64(len(commandLine))
			case testCase.TestID == "component-byte-mutations-rejected" && subcase == "root-image":
				rootImageBefore = before
			case testCase.TestID == "dm-verity-corruption-rejected" && subcase == "root-data":
				before.Digest = rootImageBefore.Digest
				before.SizeBytes = rootImageBefore.SizeBytes
			}
			after := stablecampaign.ArtifactBinding{Name: name, Digest: expectationDigest(name + " after"), SizeBytes: before.SizeBytes}
			recipe, err := stablecampaign.NewByteXORMutationRecipe(testCase.TestID, subcase, target, before, after)
			if err != nil {
				t.Fatalf("construct byte recipe %s: %v", name, err)
			}
			byteRecipes = append(byteRecipes, recipe)
		}
	}
	sort.Slice(byteRecipes, func(i, j int) bool { return byteRecipes[i].RecipeID < byteRecipes[j].RecipeID })

	replacementInput := func(testID, subcase string) string {
		switch testID {
		case "manifest-field-mutations-rejected":
			return "manifest-field-" + subcase
		case "delegated-key-replacement-boots":
			return "replacement-release-manifest"
		case "revoked-delegated-key-rejected":
			return "revoked-release-manifest"
		case "unsigned-release-rejected":
			return "unsigned-release-manifest"
		case "wrong-delegated-key-rejected":
			return "wrong-key-release-manifest"
		default:
			return ""
		}
	}
	replacements := make([]stablecampaign.BoundReplacementMutationRecipe, 0, 20)
	for _, testCase := range stablecampaign.FixedCases() {
		for _, subcase := range testCase.Subcases {
			inputName := replacementInput(testCase.TestID, subcase)
			if inputName == "" {
				continue
			}
			recipe, err := stablecampaign.NewBoundReplacementMutationRecipe(
				testCase.TestID, subcase, byName["positive-release-manifest"], byName[inputName],
			)
			if err != nil {
				t.Fatalf("construct replacement recipe %s:%s: %v", testCase.TestID, subcase, err)
			}
			replacements = append(replacements, recipe)
		}
	}
	sort.Slice(replacements, func(i, j int) bool { return replacements[i].RecipeID < replacements[j].RecipeID })

	plan, err := stablecampaign.NewPlan("rpi5-stable-verifier-qualification-test", inputs, byteRecipes, replacements)
	if err != nil {
		t.Fatal(err)
	}
	commandLineRecipe := findByteRecipe(plan, "component-byte-mutations-rejected:kernel-command-line")
	rootDataRecipe := findByteRecipe(plan, "dm-verity-corruption-rejected:root-data")
	rootHashRecipe := findByteRecipe(plan, "dm-verity-corruption-rejected:root-hash")
	canonicalPlan, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	file := func(binding stablecampaign.ArtifactBinding) campaignmedia.ArtifactFileBinding {
		return campaignmedia.ArtifactFileBinding{SHA256: binding.Digest, SizeBytes: binding.SizeBytes}
	}
	set := campaignmedia.ArtifactSet{
		Artifacts: []campaignmedia.ArtifactSetEntry{
			{Digest: expectationDigest("boot payload"), Name: "sd/boot-filesystem.img", Role: campaignmedia.PartitionBootFilesystem, SizeBytes: 4096},
			{Digest: expectationDigest("release payload"), Name: "nvme/release-filesystem.img", Role: campaignmedia.PartitionReleaseFilesystem, SizeBytes: 8192},
			{Digest: rootDataRecipe.Before.Digest, Name: "sd/root-data.img", Role: campaignmedia.PartitionRootData, SizeBytes: rootDataRecipe.Before.SizeBytes},
			{Digest: rootHashRecipe.Before.Digest, Name: "sd/root-hash.img", Role: campaignmedia.PartitionRootHash, SizeBytes: rootHashRecipe.Before.SizeBytes},
		},
		CampaignID: plan.CampaignID,
		CampaignPlanResolution: campaignmedia.CampaignPlanResolution{
			BoundReplacementCount: 20, ByteXORMutationCount: 10, PlanDigest: plan.PlanDigest,
			PublicInputCount: 27, Status: "resolved_against_exact_bytes",
		},
		Capabilities: campaignmedia.ArtifactSetCapabilities{
			DelegatedReleasePrivateKeyPEMMarkerScan: "passed_defense_in_depth_not_proof_of_absence",
		},
		PlanDigest: plan.PlanDigest,
		Provenance: campaignmedia.ArtifactSetProvenance{
			CampaignPlan: campaignmedia.ArtifactFileBinding{SHA256: bundle.Sum(canonicalPlan), SizeBytes: uint64(len(canonicalPlan))},
			DelegatedRelease: campaignmedia.ArtifactDelegatedReleaseBinding{
				ReleaseManifest:       file(byName["positive-release-manifest"]),
				ReleaseTreeDigest:     byName["positive-release-tree"].Digest,
				ReleaseTreeSizeBytes:  byName["positive-release-tree"].SizeBytes,
				SignatureVerification: "deferred_to_stable_verifier",
				WrapperManifest:       campaignmedia.ArtifactFileBinding{SHA256: expectationDigest("wrapper manifest"), SizeBytes: 123},
			},
			VerifiedSignedBoot: campaignmedia.ArtifactVerifiedBootBinding{
				BootImage:     file(byName["unsigned-verifier-boot"]),
				BootSignature: campaignmedia.ArtifactFileBinding{SHA256: expectationDigest("boot signature"), SizeBytes: 256},
				PublicKey: campaignmedia.ArtifactPublicKeyBinding{
					Fingerprint: expectationDigest("boot key fingerprint"),
					SHA256:      byName["customer-boot-public-key"].Digest,
					SizeBytes:   byName["customer-boot-public-key"].SizeBytes,
				},
				SignatureVerification: "reverified",
				SignerIndependentReview: campaignmedia.ArtifactFileBinding{
					SHA256: expectationDigest("signer review"), SizeBytes: 321,
				},
			},
		},
		RunID: "positive-baseline", SchemaVersion: campaignmedia.ArtifactSetSchemaV1Alpha1,
		StorageFormat: "partition-payload-set-not-whole-device",
		SemanticResolution: campaignmedia.ArtifactSetSemanticResolution{
			StableVerifierPolicy: campaignmedia.ArtifactSemanticBinding{
				File: file(byName["stable-verifier-policy"]), SemanticDigest: expectationDigest("policy semantics"),
			},
			PositiveReleaseManifest: campaignmedia.ArtifactSemanticBinding{
				File: file(byName["positive-release-manifest"]), SemanticDigest: expectationDigest("positive manifest semantics"),
			},
			ReplacementReleaseManifest: campaignmedia.ArtifactSemanticBinding{
				File: file(byName["replacement-release-manifest"]), SemanticDigest: expectationDigest("replacement manifest semantics"),
			},
			PositiveReleaseTree: file(byName["positive-release-tree"]),
			KernelCommandLine: campaignmedia.ArtifactCommandLineBinding{
				File: file(commandLineRecipe.Before), Value: expectationCommandLine(),
			},
		},
		Verity: campaignmedia.ArtifactSetVerity{
			Algorithm: "sha256", DataBlockSize: 4096, HashBlockSize: 4096,
			DataPartitionGUID: "11111111-2222-4333-8444-555555555555",
			HashPartitionGUID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
			DataDevice:        "PARTUUID=11111111-2222-4333-8444-555555555555",
			HashDevice:        "PARTUUID=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
			RootHash:          expectationDigest("verity root hash"),
		},
	}
	setDigest, err := set.DerivedDigest()
	if err != nil {
		t.Fatal(err)
	}
	set.ArtifactSetContentDigest = setDigest

	resolved := stablecampaign.ResolvedPublicArtifacts{
		PlanDigest: plan.PlanDigest, PublicInputs: append([]stablecampaign.ArtifactBinding(nil), plan.PublicInputs...),
		ByteXORMutations:  make([]stablecampaign.ResolvedByteXORMutation, len(plan.ByteXORMutations)),
		BoundReplacements: make([]stablecampaign.ResolvedBoundReplacement, len(plan.BoundReplacements)),
		Semantics: stablecampaign.ResolvedCampaignSemantics{
			StableVerifierPolicy: stablecampaign.ResolvedSemanticArtifact{
				File: byName["stable-verifier-policy"], SemanticDigest: set.SemanticResolution.StableVerifierPolicy.SemanticDigest,
			},
			PositiveReleaseManifest: stablecampaign.ResolvedSemanticArtifact{
				File: byName["positive-release-manifest"], SemanticDigest: set.SemanticResolution.PositiveReleaseManifest.SemanticDigest,
			},
			ReplacementReleaseManifest: stablecampaign.ResolvedSemanticArtifact{
				File: byName["replacement-release-manifest"], SemanticDigest: set.SemanticResolution.ReplacementReleaseManifest.SemanticDigest,
			},
			PositiveReleaseTree: byName["positive-release-tree"],
			KernelCommandLine: stablecampaign.ResolvedKernelCommandLine{
				File: commandLineRecipe.Before, Value: set.SemanticResolution.KernelCommandLine.Value,
			},
		},
	}
	for index, recipe := range plan.ByteXORMutations {
		resolved.ByteXORMutations[index] = stablecampaign.ResolvedByteXORMutation{
			RecipeID: recipe.RecipeID, Target: recipe.Target, Before: recipe.Before, After: recipe.After,
		}
	}
	for index, recipe := range plan.BoundReplacements {
		resolved.BoundReplacements[index] = stablecampaign.ResolvedBoundReplacement{
			RecipeID: recipe.RecipeID, ReplacementInput: recipe.ReplacementInput,
			DifferenceSelector: recipe.DifferenceSelector, Before: recipe.Before, After: recipe.After,
		}
	}
	if err := set.ValidateAgainstResolved(plan, resolved); err != nil {
		t.Fatalf("invalid run-expectation fixture: %v", err)
	}
	return expectationTestFixture{plan: plan, set: set, resolved: resolved}
}

func runTraceHasDetails(trace []stablecampaign.VerifierEventExpectation) bool {
	for _, event := range trace {
		if event.DetailStage != stablecampaign.VerifierDetailNone {
			return true
		}
	}
	return false
}

func findByteRecipe(plan stablecampaign.Plan, recipeID string) stablecampaign.ByteXORMutationRecipe {
	for _, recipe := range plan.ByteXORMutations {
		if recipe.RecipeID == recipeID {
			return recipe
		}
	}
	return stablecampaign.ByteXORMutationRecipe{}
}

func expectationDigest(label string) bundle.Digest { return bundle.Sum([]byte(label)) }

func expectationCommandLine() string {
	rootHash := strings.TrimPrefix(string(expectationDigest("verity root hash")), "sha256:")
	return "console=ttyAMA10,115200n8 rd.systemd.verity=1 root=fstab ro" +
		" roothash=" + rootHash +
		" systemd.verity_root_data=PARTUUID=11111111-2222-4333-8444-555555555555" +
		" systemd.verity_root_hash=PARTUUID=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
}
