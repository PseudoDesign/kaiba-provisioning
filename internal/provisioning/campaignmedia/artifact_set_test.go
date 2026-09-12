package campaignmedia

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

func mustStableCampaignPlan(t *testing.T) stablecampaign.Plan {
	t.Helper()
	names := stablecampaign.RequiredPublicInputNames()
	inputs := make([]stablecampaign.ArtifactBinding, len(names))
	byName := make(map[string]stablecampaign.ArtifactBinding, len(names))
	for index, name := range names {
		binding := stablecampaign.ArtifactBinding{
			Name: name, Digest: testDigest("stable campaign input " + name), SizeBytes: uint64(index + 1),
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
	var byteRecipes []stablecampaign.ByteXORMutationRecipe
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
			beforeDigest := testDigest(name + " before")
			beforeSize := uint64(4096)
			switch {
			case testCase.TestID == "component-byte-mutations-rejected" && subcase == "kernel-command-line":
				commandLineFile := []byte(artifactSetTestCommandLine() + "\n")
				beforeDigest = bundle.Sum(commandLineFile)
				beforeSize = uint64(len(commandLineFile))
			case testCase.TestID == "component-byte-mutations-rejected" && subcase == "root-image":
				beforeSize = MalakSDRootDataCapacityBytes
				rootImageBefore = stablecampaign.ArtifactBinding{Name: name, Digest: beforeDigest, SizeBytes: beforeSize}
			case testCase.TestID == "dm-verity-corruption-rejected" && subcase == "root-data":
				beforeDigest = rootImageBefore.Digest
				beforeSize = rootImageBefore.SizeBytes
			case testCase.TestID == "dm-verity-corruption-rejected" && subcase == "root-hash":
				beforeSize = MalakSDRootHashCapacityBytes
			}
			recipe, err := stablecampaign.NewByteXORMutationRecipe(
				testCase.TestID, subcase, target,
				stablecampaign.ArtifactBinding{Name: name, Digest: beforeDigest, SizeBytes: beforeSize},
				stablecampaign.ArtifactBinding{Name: name, Digest: testDigest(name + " after"), SizeBytes: beforeSize},
			)
			if err != nil {
				t.Fatalf("construct byte recipe %s: %v", name, err)
			}
			byteRecipes = append(byteRecipes, recipe)
		}
	}
	sort.Slice(byteRecipes, func(i, j int) bool { return byteRecipes[i].RecipeID < byteRecipes[j].RecipeID })

	replacementName := func(testID, subcase string) string {
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
	var replacements []stablecampaign.BoundReplacementMutationRecipe
	for _, testCase := range stablecampaign.FixedCases() {
		for _, subcase := range testCase.Subcases {
			inputName := replacementName(testCase.TestID, subcase)
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

	plan, err := stablecampaign.NewPlan("rpi5-stable-verifier-physical-20260911", inputs, byteRecipes, replacements)
	if err != nil {
		t.Fatalf("construct stable campaign plan: %v", err)
	}
	return plan
}

func campaignInput(t *testing.T, plan stablecampaign.Plan, name string) stablecampaign.ArtifactBinding {
	t.Helper()
	for _, input := range plan.PublicInputs {
		if input.Name == name {
			return input
		}
	}
	t.Fatalf("stable campaign input %q absent", name)
	return stablecampaign.ArtifactBinding{}
}

func mustArtifactSet(t *testing.T, plan stablecampaign.Plan) ArtifactSet {
	t.Helper()
	canonicalPlan, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	boot := campaignInput(t, plan, "unsigned-verifier-boot")
	publicKey := campaignInput(t, plan, "customer-boot-public-key")
	policy := campaignInput(t, plan, "stable-verifier-policy")
	positiveManifest := campaignInput(t, plan, "positive-release-manifest")
	replacementManifest := campaignInput(t, plan, "replacement-release-manifest")
	positiveTree := campaignInput(t, plan, "positive-release-tree")
	commandLineRecipe, ok := func() (stablecampaign.ByteXORMutationRecipe, bool) {
		for _, recipe := range plan.ByteXORMutations {
			if recipe.RecipeID == "component-byte-mutations-rejected:kernel-command-line" {
				return recipe, true
			}
		}
		return stablecampaign.ByteXORMutationRecipe{}, false
	}()
	if !ok {
		t.Fatal("missing command-line recipe")
	}
	rootDataRecipe := planByteMutationBinding(plan, "dm-verity-corruption-rejected:root-data")
	rootHashRecipe := planByteMutationBinding(plan, "dm-verity-corruption-rejected:root-hash")
	set := ArtifactSet{
		Artifacts: []ArtifactSetEntry{
			{Digest: testDigest("boot source"), Name: "sd/boot-filesystem.img", Role: PartitionBootFilesystem, SizeBytes: MalakSDBootCapacityBytes},
			{Digest: testDigest("release source"), Name: "nvme/release-filesystem.img", Role: PartitionReleaseFilesystem, SizeBytes: 64 * AlignmentBytes},
			{Digest: rootDataRecipe.Digest, Name: "sd/root-data.img", Role: PartitionRootData, SizeBytes: rootDataRecipe.SizeBytes},
			{Digest: rootHashRecipe.Digest, Name: "sd/root-hash.img", Role: PartitionRootHash, SizeBytes: rootHashRecipe.SizeBytes},
		},
		CampaignID: plan.CampaignID,
		CampaignPlanResolution: CampaignPlanResolution{
			BoundReplacementCount: artifactSetReplacementCount,
			ByteXORMutationCount:  artifactSetByteXORCount,
			PlanDigest:            plan.PlanDigest,
			PublicInputCount:      artifactSetPublicInputCount,
			Status:                artifactSetResolutionStatus,
		},
		Capabilities: ArtifactSetCapabilities{
			DelegatedReleasePrivateKeyPEMMarkerScan: artifactSetMarkerResult,
		},
		PhysicalLayoutBound: false,
		PlanDigest:          plan.PlanDigest,
		Provenance: ArtifactSetProvenance{
			CampaignPlan: ArtifactFileBinding{SHA256: bundle.Sum(canonicalPlan), SizeBytes: uint64(len(canonicalPlan))},
			DelegatedRelease: ArtifactDelegatedReleaseBinding{
				ReleaseManifest:   ArtifactFileBinding{SHA256: positiveManifest.Digest, SizeBytes: positiveManifest.SizeBytes},
				ReleaseTreeDigest: positiveTree.Digest, ReleaseTreeSizeBytes: positiveTree.SizeBytes,
				SignatureVerification: "deferred_to_stable_verifier",
				WrapperManifest:       ArtifactFileBinding{SHA256: testDigest("wrapper manifest"), SizeBytes: 101},
			},
			VerifiedSignedBoot: ArtifactVerifiedBootBinding{
				BootImage:     ArtifactFileBinding{SHA256: boot.Digest, SizeBytes: boot.SizeBytes},
				BootSignature: ArtifactFileBinding{SHA256: testDigest("boot signature"), SizeBytes: 600},
				PublicKey: ArtifactPublicKeyBinding{
					Fingerprint: testDigest("public key fingerprint"), SHA256: publicKey.Digest, SizeBytes: publicKey.SizeBytes,
				},
				SignatureVerification: "reverified",
				SignerIndependentReview: ArtifactFileBinding{
					SHA256: testDigest("signer independent review"), SizeBytes: 700,
				},
			},
		},
		RecipeID:      nil,
		RunID:         artifactSetRunID,
		SchemaVersion: ArtifactSetSchemaV1Alpha1,
		SemanticResolution: ArtifactSetSemanticResolution{
			StableVerifierPolicy: ArtifactSemanticBinding{
				File:           ArtifactFileBinding{SHA256: policy.Digest, SizeBytes: policy.SizeBytes},
				SemanticDigest: testDigest("policy semantic digest"),
			},
			PositiveReleaseManifest: ArtifactSemanticBinding{
				File:           ArtifactFileBinding{SHA256: positiveManifest.Digest, SizeBytes: positiveManifest.SizeBytes},
				SemanticDigest: testDigest("positive manifest semantic digest"),
			},
			ReplacementReleaseManifest: ArtifactSemanticBinding{
				File:           ArtifactFileBinding{SHA256: replacementManifest.Digest, SizeBytes: replacementManifest.SizeBytes},
				SemanticDigest: testDigest("replacement manifest semantic digest"),
			},
			PositiveReleaseTree: ArtifactFileBinding{SHA256: positiveTree.Digest, SizeBytes: positiveTree.SizeBytes},
			KernelCommandLine: ArtifactCommandLineBinding{
				File:  ArtifactFileBinding{SHA256: commandLineRecipe.Before.Digest, SizeBytes: commandLineRecipe.Before.SizeBytes},
				Value: artifactSetTestCommandLine(),
			},
		},
		StorageFormat: artifactSetStorageFormat,
		Verity: ArtifactSetVerity{
			Algorithm: "sha256", DataBlockSize: 4096,
			DataDevice: "PARTUUID=" + testSDRootDataGUID, DataPartitionGUID: testSDRootDataGUID,
			HashBlockSize: 4096, HashDevice: "PARTUUID=" + testSDRootHashGUID,
			HashPartitionGUID: testSDRootHashGUID, NoSuperblock: false, RootHash: testDigest("verity root hash"),
		},
	}
	digest, err := set.DerivedDigest()
	if err != nil {
		t.Fatalf("derive artifact-set digest: %v", err)
	}
	set.ArtifactSetContentDigest = digest
	if err := set.ValidateAgainst(plan); err != nil {
		t.Fatalf("validate artifact set: %v", err)
	}
	return set
}

func TestArtifactSetCanonicalRoundTripAndNixDigest(t *testing.T) {
	plan := mustStableCampaignPlan(t)
	set := mustArtifactSet(t, plan)
	encoded, err := set.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(encoded, []byte(`{"artifact_set_content_digest":`)) || !bytes.Contains(encoded, []byte(`"recipe_id":null`)) {
		t.Fatal("artifact-set encoding is not jq -cS compatible")
	}
	if !bytes.Contains(encoded, []byte(`"semantic_resolution":{"kernel_command_line":`)) {
		t.Fatal("artifact-set semantic-resolution keys are not in jq -S lexical order")
	}
	var generic any
	if err := json.Unmarshal(encoded, &generic); err != nil {
		t.Fatal(err)
	}
	lexical, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, lexical) {
		t.Fatal("artifact-set encoding differs from recursively lexically keyed JSON")
	}
	parsed, err := ParseArtifactSet(append(append([]byte(nil), encoded...), '\n'))
	if err != nil {
		t.Fatalf("parse artifact set: %v", err)
	}
	if err := parsed.ValidateAgainst(plan); err != nil {
		t.Fatalf("validate parsed artifact set: %v", err)
	}
}

func TestArtifactSetValidatesAgainstExactResolvedSemantics(t *testing.T) {
	plan := mustStableCampaignPlan(t)
	set := mustArtifactSet(t, plan)
	resolved := resolvedArtifactsForSet(plan, set)
	if err := set.ValidateAgainstResolved(plan, resolved); err != nil {
		t.Fatalf("validate resolved artifact set: %v", err)
	}

	t.Run("public input", func(t *testing.T) {
		detached := resolvedArtifactsForSet(plan, set)
		detached.PublicInputs[0].Digest = testDigest("detached resolved public input")
		if err := set.ValidateAgainstResolved(plan, detached); err == nil {
			t.Fatal("accepted resolved public inputs detached from the campaign plan")
		}
	})

	t.Run("byte recipe", func(t *testing.T) {
		detached := resolvedArtifactsForSet(plan, set)
		detached.ByteXORMutations[0].After.Digest = testDigest("detached resolved XOR result")
		if err := set.ValidateAgainstResolved(plan, detached); err == nil {
			t.Fatal("accepted a resolved byte mutation detached from the campaign plan")
		}
	})

	t.Run("replacement recipe", func(t *testing.T) {
		detached := resolvedArtifactsForSet(plan, set)
		detached.BoundReplacements[0].ReplacementInput = "detached-replacement-manifest"
		if err := set.ValidateAgainstResolved(plan, detached); err == nil {
			t.Fatal("accepted a resolved replacement detached from the campaign plan")
		}
	})

	t.Run("semantic digest", func(t *testing.T) {
		detached := resolvedArtifactsForSet(plan, set)
		detached.Semantics.PositiveReleaseManifest.SemanticDigest = testDigest("detached semantic manifest")
		if err := set.ValidateAgainstResolved(plan, detached); err == nil {
			t.Fatal("accepted semantic values detached from exact-byte resolution")
		}
	})
}

func TestStagingPlanRequiresIndependentCampaignAndArtifactSetBindings(t *testing.T) {
	campaignPlan := mustStableCampaignPlan(t)
	set := mustArtifactSet(t, campaignPlan)
	plan := mustTestPlan(t)
	plan.Campaign = CampaignBinding{
		CampaignID: campaignPlan.CampaignID, StableCampaignPlanDigest: campaignPlan.PlanDigest,
		CampaignArtifactSetContentDigest: set.ArtifactSetContentDigest,
	}
	for deviceIndex := range plan.Devices {
		plan.Devices[deviceIndex].Campaign = plan.Campaign
		for partitionIndex := range plan.Devices[deviceIndex].Partitions {
			partition := &plan.Devices[deviceIndex].Partitions[partitionIndex]
			for _, entry := range set.Artifacts {
				if entry.Role == partition.Role {
					partition.SourceSHA256 = entry.Digest
					partition.SourceSizeBytes = entry.SizeBytes
					partition.ZeroTailBytes = partition.CapacityBytes - entry.SizeBytes
					if partition.ZeroTailBytes == 0 {
						partition.ExpectedWholePartitionSHA256 = entry.Digest
					}
				}
			}
		}
	}
	plan.PlanDigest = ""
	plan, err := plan.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.ValidateAgainst(campaignPlan, set); err != nil {
		t.Fatalf("cross-bind staging plan: %v", err)
	}

	detached := plan
	detached.Devices = cloneDevicePlans(plan.Devices)
	detached.Devices[0].Partitions[0].SourceSHA256 = testDigest("substituted boot filesystem")
	detached.Devices[0].Partitions[0].ExpectedWholePartitionSHA256 = detached.Devices[0].Partitions[0].SourceSHA256
	detached.PlanDigest = ""
	detached, err = detached.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := detached.ValidateAgainst(campaignPlan, set); err == nil {
		t.Fatal("staging plan accepted payload bytes detached from the artifact set")
	}

	detached = plan
	detached.Devices = cloneDevicePlans(plan.Devices)
	detached.Devices[0].Partitions[1].UniqueGUID = "11111111-2222-4333-8444-555555555555"
	detached.PlanDigest = ""
	detached, err = detached.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := detached.ValidateAgainst(campaignPlan, set); err == nil {
		t.Fatal("staging plan accepted a root-data GUID detached from the artifact-set verity contract")
	}

	detachedSet := set
	detachedSet.Artifacts = append([]ArtifactSetEntry(nil), set.Artifacts...)
	detachedSet.Artifacts[0].Digest = testDigest("different artifact-set boot")
	detachedSet.ArtifactSetContentDigest = ""
	digest, err := detachedSet.DerivedDigest()
	if err != nil {
		t.Fatal(err)
	}
	detachedSet.ArtifactSetContentDigest = digest
	if err := plan.ValidateAgainst(campaignPlan, detachedSet); err == nil {
		t.Fatal("staging plan accepted a separately resealed but unbound artifact set")
	}
}

func TestArtifactSetRejectsCanonicalAndSemanticAmbiguity(t *testing.T) {
	plan := mustStableCampaignPlan(t)
	set := mustArtifactSet(t, plan)
	encoded, err := set.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"duplicate":       bytes.Replace(encoded, []byte(`{"artifact_set_content_digest":`), []byte(`{"artifact_set_content_digest":"duplicate","artifact_set_content_digest":`), 1),
		"unexpected null": bytes.Replace(encoded, []byte(`"run_id":"positive-baseline"`), []byte(`"run_id":null`), 1),
		"pretty":          bytes.Replace(encoded, []byte(`,"artifacts":`), []byte(",\n\"artifacts\":"), 1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseArtifactSet(input); err == nil {
				t.Fatal("ambiguous artifact-set encoding accepted")
			}
		})
	}

	tampered := set
	tampered.Capabilities.PrivateKeyOperationPerformed = true
	tampered.ArtifactSetContentDigest = ""
	if _, err := tampered.DerivedDigest(); err == nil {
		t.Fatal("artifact set accepted private-key operation capability")
	}

	tampered = set
	tampered.CampaignPlanResolution.ByteXORMutationCount--
	tampered.ArtifactSetContentDigest = ""
	if _, err := tampered.DerivedDigest(); err == nil {
		t.Fatal("artifact set accepted incomplete campaign-plan resolution")
	}

	for _, role := range []PartitionRole{PartitionRootData, PartitionRootHash} {
		t.Run("detached "+string(role), func(t *testing.T) {
			detached := set
			detached.Artifacts = append([]ArtifactSetEntry(nil), set.Artifacts...)
			for index := range detached.Artifacts {
				if detached.Artifacts[index].Role == role {
					detached.Artifacts[index].Digest = testDigest("detached " + string(role))
				}
			}
			detached.ArtifactSetContentDigest = ""
			digest, err := detached.DerivedDigest()
			if err != nil {
				t.Fatal(err)
			}
			detached.ArtifactSetContentDigest = digest
			if err := detached.ValidateAgainst(plan); err == nil {
				t.Fatal("artifact set accepted a baseline payload detached from its mutation recipe")
			}
		})
	}

	tampered = set
	tampered.Verity.RootHash = testDigest("verity digest detached from command line")
	tampered.ArtifactSetContentDigest = ""
	if _, err := tampered.DerivedDigest(); err == nil {
		t.Fatal("artifact set accepted verity metadata detached from its kernel command line")
	}

	tampered = set
	tampered.SemanticResolution.KernelCommandLine.Value += " debug_device=/dev/nvme0n1"
	commandLineFile := []byte(tampered.SemanticResolution.KernelCommandLine.Value + "\n")
	tampered.SemanticResolution.KernelCommandLine.File = ArtifactFileBinding{
		SHA256:    bundle.Sum(commandLineFile),
		SizeBytes: uint64(len(commandLineFile)),
	}
	tampered.ArtifactSetContentDigest = ""
	if _, err := tampered.DerivedDigest(); err == nil || !strings.Contains(err.Error(), "topology-dependent NVMe selector") {
		t.Fatalf("artifact set accepted a topology-dependent NVMe selector: %v", err)
	}
}

func resolvedArtifactsForSet(plan stablecampaign.Plan, set ArtifactSet) stablecampaign.ResolvedPublicArtifacts {
	resolved := stablecampaign.ResolvedPublicArtifacts{
		PlanDigest:        plan.PlanDigest,
		PublicInputs:      append([]stablecampaign.ArtifactBinding(nil), plan.PublicInputs...),
		ByteXORMutations:  make([]stablecampaign.ResolvedByteXORMutation, len(plan.ByteXORMutations)),
		BoundReplacements: make([]stablecampaign.ResolvedBoundReplacement, len(plan.BoundReplacements)),
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
	toPlanBinding := func(name string, file ArtifactFileBinding) stablecampaign.ArtifactBinding {
		return stablecampaign.ArtifactBinding{Name: name, Digest: file.SHA256, SizeBytes: file.SizeBytes}
	}
	semantic := set.SemanticResolution
	resolved.Semantics = stablecampaign.ResolvedCampaignSemantics{
		StableVerifierPolicy: stablecampaign.ResolvedSemanticArtifact{
			File:           toPlanBinding("stable-verifier-policy", semantic.StableVerifierPolicy.File),
			SemanticDigest: semantic.StableVerifierPolicy.SemanticDigest,
		},
		PositiveReleaseManifest: stablecampaign.ResolvedSemanticArtifact{
			File:           toPlanBinding("positive-release-manifest", semantic.PositiveReleaseManifest.File),
			SemanticDigest: semantic.PositiveReleaseManifest.SemanticDigest,
		},
		ReplacementReleaseManifest: stablecampaign.ResolvedSemanticArtifact{
			File:           toPlanBinding("replacement-release-manifest", semantic.ReplacementReleaseManifest.File),
			SemanticDigest: semantic.ReplacementReleaseManifest.SemanticDigest,
		},
		PositiveReleaseTree: toPlanBinding("positive-release-tree", semantic.PositiveReleaseTree),
		KernelCommandLine: stablecampaign.ResolvedKernelCommandLine{
			File:  planByteMutationBinding(plan, "component-byte-mutations-rejected:kernel-command-line"),
			Value: semantic.KernelCommandLine.Value,
		},
	}
	return resolved
}

func planByteMutationBinding(plan stablecampaign.Plan, recipeID string) stablecampaign.ArtifactBinding {
	for _, recipe := range plan.ByteXORMutations {
		if recipe.RecipeID == recipeID {
			return recipe.Before
		}
	}
	return stablecampaign.ArtifactBinding{}
}

func artifactSetTestCommandLine() string {
	rootHash := strings.TrimPrefix(string(testDigest("verity root hash")), "sha256:")
	return "console=ttyAMA10,115200n8 rd.systemd.verity=1 root=fstab ro" +
		" roothash=" + rootHash +
		" systemd.verity_root_data=PARTUUID=" + testSDRootDataGUID +
		" systemd.verity_root_hash=PARTUUID=" + testSDRootHashGUID
}
