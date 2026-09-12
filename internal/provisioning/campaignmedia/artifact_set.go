package campaignmedia

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5kexecinput"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

const (
	artifactSetRunID            = "positive-baseline"
	artifactSetStorageFormat    = "partition-payload-set-not-whole-device"
	artifactSetMarkerResult     = "passed_defense_in_depth_not_proof_of_absence"
	artifactSetResolutionStatus = "resolved_against_exact_bytes"
	artifactSetPublicInputCount = 27
	artifactSetByteXORCount     = 10
	artifactSetReplacementCount = 20
)

var fixedArtifactSetEntries = []struct {
	role PartitionRole
	name string
}{
	{PartitionBootFilesystem, "sd/boot-filesystem.img"},
	{PartitionReleaseFilesystem, "nvme/release-filesystem.img"},
	{PartitionRootData, "sd/root-data.img"},
	{PartitionRootHash, "sd/root-hash.img"},
}

func (binding ArtifactFileBinding) validate(label string) error {
	if err := validateDigest(label+".sha256", binding.SHA256); err != nil {
		return err
	}
	if binding.SizeBytes == 0 || binding.SizeBytes > math.MaxInt64 {
		return fmt.Errorf("%s.size_bytes must be between 1 and %d", label, int64(math.MaxInt64))
	}
	return nil
}

func (binding ArtifactPublicKeyBinding) validate() error {
	if err := validateDigest("provenance.verified_signed_boot.public_key.fingerprint", binding.Fingerprint); err != nil {
		return err
	}
	return ArtifactFileBinding{SHA256: binding.SHA256, SizeBytes: binding.SizeBytes}.validate("provenance.verified_signed_boot.public_key")
}

func (binding ArtifactSemanticBinding) validate(label string) error {
	if err := binding.File.validate(label + ".file"); err != nil {
		return err
	}
	if err := validateDigest(label+".semantic_digest", binding.SemanticDigest); err != nil {
		return err
	}
	return nil
}

func (binding ArtifactCommandLineBinding) validate() error {
	if err := binding.File.validate("semantic_resolution.kernel_command_line.file"); err != nil {
		return err
	}
	parsed, err := rpi5kexecinput.ParseCommandLineFile([]byte(binding.Value))
	if err != nil || parsed != binding.Value {
		return errors.New("semantic-resolution kernel command line is not a canonical parsed value")
	}
	plain := []byte(binding.Value)
	withLF := append(append([]byte(nil), plain...), '\n')
	plainMatches := binding.File.SizeBytes == uint64(len(plain)) && binding.File.SHA256 == bundle.Sum(plain)
	lfMatches := binding.File.SizeBytes == uint64(len(withLF)) && binding.File.SHA256 == bundle.Sum(withLF)
	if !plainMatches && !lfMatches {
		return errors.New("semantic-resolution kernel command-line file does not bind its parsed value")
	}
	return nil
}

func (binding ArtifactCommandLineBinding) validateVerity(verity ArtifactSetVerity) error {
	if strings.Contains(binding.Value, "/dev/nvme") {
		return errors.New("semantic-resolution kernel command line contains a topology-dependent NVMe selector")
	}
	expected := map[string]string{
		"rd.systemd.verity":        "rd.systemd.verity=1",
		"root":                     "root=fstab",
		"roothash":                 "roothash=" + strings.TrimPrefix(string(verity.RootHash), "sha256:"),
		"systemd.verity_root_data": "systemd.verity_root_data=" + verity.DataDevice,
		"systemd.verity_root_hash": "systemd.verity_root_hash=" + verity.HashDevice,
	}
	seen := make(map[string]struct{}, len(expected))
	readOnlyCount := 0
	for _, argument := range strings.Split(binding.Value, " ") {
		if argument == "ro" {
			readOnlyCount++
			continue
		}
		if argument == "rw" {
			return errors.New("semantic-resolution kernel command line enables a writable root")
		}
		key, _, _ := strings.Cut(argument, "=")
		if wanted, required := expected[key]; required {
			if argument != wanted {
				return fmt.Errorf("semantic-resolution kernel command line has a non-canonical %s selector", key)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("semantic-resolution kernel command line repeats %s", key)
			}
			seen[key] = struct{}{}
			continue
		}
		if key == "rootfstype" || key == "systemd.verity" || strings.HasPrefix(key, "systemd.verity_root_") ||
			strings.HasPrefix(key, "rd.systemd.verity_root_") {
			return fmt.Errorf("semantic-resolution kernel command line contains unsupported verity selector %q", key)
		}
	}
	if readOnlyCount != 1 {
		return errors.New("semantic-resolution kernel command line must contain ro exactly once")
	}
	if len(seen) != len(expected) {
		return errors.New("semantic-resolution kernel command line is missing a required root or verity selector")
	}
	return nil
}

func (resolution ArtifactSetSemanticResolution) validate() error {
	if err := resolution.StableVerifierPolicy.validate("semantic_resolution.stable_verifier_policy"); err != nil {
		return err
	}
	if err := resolution.PositiveReleaseManifest.validate("semantic_resolution.positive_release_manifest"); err != nil {
		return err
	}
	if err := resolution.ReplacementReleaseManifest.validate("semantic_resolution.replacement_release_manifest"); err != nil {
		return err
	}
	if err := resolution.PositiveReleaseTree.validate("semantic_resolution.positive_release_tree"); err != nil {
		return err
	}
	return resolution.KernelCommandLine.validate()
}

func (provenance ArtifactSetProvenance) validate() error {
	if err := provenance.CampaignPlan.validate("provenance.campaign_plan"); err != nil {
		return err
	}
	delegated := provenance.DelegatedRelease
	if err := delegated.ReleaseManifest.validate("provenance.delegated_release.release_manifest"); err != nil {
		return err
	}
	if err := validateDigest("provenance.delegated_release.release_tree_digest", delegated.ReleaseTreeDigest); err != nil {
		return err
	}
	if delegated.ReleaseTreeSizeBytes == 0 || delegated.ReleaseTreeSizeBytes > math.MaxInt64 {
		return fmt.Errorf("provenance.delegated_release.release_tree_size_bytes must be between 1 and %d", int64(math.MaxInt64))
	}
	if delegated.SignatureVerification != "deferred_to_stable_verifier" {
		return errors.New("delegated-release signature verification must remain deferred to the stable verifier")
	}
	if err := delegated.WrapperManifest.validate("provenance.delegated_release.wrapper_manifest"); err != nil {
		return err
	}
	boot := provenance.VerifiedSignedBoot
	if err := boot.BootImage.validate("provenance.verified_signed_boot.boot_image"); err != nil {
		return err
	}
	if err := boot.BootSignature.validate("provenance.verified_signed_boot.boot_signature"); err != nil {
		return err
	}
	if err := boot.PublicKey.validate(); err != nil {
		return err
	}
	if boot.SignatureVerification != "reverified" {
		return errors.New("verified signed-boot provenance must report reverified signature bytes")
	}
	return boot.SignerIndependentReview.validate("provenance.verified_signed_boot.signer_independent_review")
}

func (capabilities ArtifactSetCapabilities) validate() error {
	if capabilities.DelegatedReleasePrivateKeyPEMMarkerScan != artifactSetMarkerResult {
		return errors.New("artifact-set private-key marker scan result differs from its bounded defense-in-depth statement")
	}
	if capabilities.DeviceWritesPerformed || capabilities.HardwareObserved || capabilities.MutationPerformed ||
		capabilities.PrivateKeyOperationPerformed || capabilities.ProductionReady || capabilities.SigningPerformed {
		return errors.New("artifact-set capabilities must report no writes, hardware observation, mutation, private-key operation, production readiness, or signing")
	}
	return nil
}

func (resolution CampaignPlanResolution) validate(planDigest bundle.Digest) error {
	if resolution.Status != artifactSetResolutionStatus {
		return errors.New("artifact-set campaign plan resolution must report exact-byte resolution")
	}
	if resolution.PlanDigest != planDigest {
		return errors.New("artifact-set campaign plan resolution does not bind plan_digest")
	}
	if resolution.PublicInputCount != artifactSetPublicInputCount ||
		resolution.ByteXORMutationCount != artifactSetByteXORCount ||
		resolution.BoundReplacementCount != artifactSetReplacementCount {
		return errors.New("artifact-set campaign plan resolution does not cover the fixed input and mutation counts")
	}
	return nil
}

func (verity ArtifactSetVerity) validate() error {
	if verity.Algorithm != "sha256" || verity.DataBlockSize != 4096 || verity.HashBlockSize != 4096 || verity.NoSuperblock {
		return errors.New("artifact-set verity contract must use sha256, 4096-byte blocks, and a hash superblock")
	}
	if err := validateGUID("artifact-set verity data_partition_guid", verity.DataPartitionGUID); err != nil {
		return err
	}
	if err := validateGUID("artifact-set verity hash_partition_guid", verity.HashPartitionGUID); err != nil {
		return err
	}
	if verity.DataPartitionGUID == verity.HashPartitionGUID {
		return errors.New("artifact-set verity partition GUIDs must be distinct")
	}
	if verity.DataDevice != "PARTUUID="+verity.DataPartitionGUID || verity.HashDevice != "PARTUUID="+verity.HashPartitionGUID {
		return errors.New("artifact-set verity devices must be exact PARTUUID selectors for their partition GUIDs")
	}
	return validateDigest("artifact-set verity root_hash", verity.RootHash)
}

func (set ArtifactSet) validate(requireDigest bool) error {
	if set.SchemaVersion != ArtifactSetSchemaV1Alpha1 {
		return fmt.Errorf("unsupported artifact-set schema_version %q", set.SchemaVersion)
	}
	if !campaignIDPattern.MatchString(set.CampaignID) {
		return errors.New("artifact-set campaign_id must be a canonical lowercase campaign identifier")
	}
	if err := validateDigest("artifact-set plan_digest", set.PlanDigest); err != nil {
		return err
	}
	if err := set.CampaignPlanResolution.validate(set.PlanDigest); err != nil {
		return err
	}
	if set.RunID != artifactSetRunID || set.RecipeID != nil {
		return errors.New("artifact set must bind the unmutated positive-baseline run")
	}
	if set.StorageFormat != artifactSetStorageFormat || set.PhysicalLayoutBound {
		return errors.New("artifact set must remain a partition payload set with no physical-layout claim")
	}
	if len(set.Artifacts) != len(fixedArtifactSetEntries) {
		return errors.New("artifact set must contain exactly boot, release, root-data, and root-hash payloads")
	}
	for index, expected := range fixedArtifactSetEntries {
		entry := set.Artifacts[index]
		if entry.Role != expected.role || entry.Name != expected.name {
			return fmt.Errorf("artifact-set entry %d differs from the fixed role and name", index+1)
		}
		if err := validateDigest(fmt.Sprintf("artifact-set entry %d digest", index+1), entry.Digest); err != nil {
			return err
		}
		if entry.SizeBytes == 0 || entry.SizeBytes > math.MaxInt64 {
			return fmt.Errorf("artifact-set entry %d has an unsupported size", index+1)
		}
		if (entry.Role == PartitionRootData || entry.Role == PartitionRootHash) && entry.SizeBytes%4096 != 0 {
			return fmt.Errorf("artifact-set %q payload must contain whole dm-verity blocks", entry.Role)
		}
	}
	if err := set.Provenance.validate(); err != nil {
		return err
	}
	if err := set.Capabilities.validate(); err != nil {
		return err
	}
	if err := set.SemanticResolution.validate(); err != nil {
		return err
	}
	if err := set.Verity.validate(); err != nil {
		return err
	}
	if err := set.SemanticResolution.KernelCommandLine.validateVerity(set.Verity); err != nil {
		return err
	}
	if requireDigest {
		if err := validateDigest("artifact_set_content_digest", set.ArtifactSetContentDigest); err != nil {
			return err
		}
		derived, err := set.DerivedDigest()
		if err != nil {
			return err
		}
		if set.ArtifactSetContentDigest != derived {
			return errors.New("artifact_set_content_digest does not bind the canonical artifact set")
		}
	}
	return nil
}

// Validate checks the self-contained artifact-set structure and digest. It
// does not establish absence of private bytes and does not authorize I/O.
func (set ArtifactSet) Validate() error { return set.validate(true) }

// ValidateAgainst binds the artifact set to an independently parsed campaign
// plan, including the exact canonical plan file (with or without its one
// permitted transport LF) and the signed-boot public inputs used by Nix.
func (set ArtifactSet) ValidateAgainst(plan stablecampaign.Plan) error {
	if err := set.Validate(); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("stable campaign plan: %w", err)
	}
	if set.CampaignID != plan.CampaignID || set.PlanDigest != plan.PlanDigest {
		return errors.New("artifact set is detached from the supplied stable campaign plan")
	}
	canonical, err := plan.CanonicalJSON()
	if err != nil {
		return err
	}
	canonicalWithLF := append(append([]byte(nil), canonical...), '\n')
	plainMatches := set.Provenance.CampaignPlan.SizeBytes == uint64(len(canonical)) &&
		set.Provenance.CampaignPlan.SHA256 == bundle.Sum(canonical)
	lfMatches := set.Provenance.CampaignPlan.SizeBytes == uint64(len(canonicalWithLF)) &&
		set.Provenance.CampaignPlan.SHA256 == bundle.Sum(canonicalWithLF)
	if !plainMatches && !lfMatches {
		return errors.New("artifact-set campaign-plan provenance does not bind the canonical supplied plan")
	}
	publicInputs := make(map[string]stablecampaign.ArtifactBinding, len(plan.PublicInputs))
	for _, input := range plan.PublicInputs {
		publicInputs[input.Name] = input
	}
	boot, ok := publicInputs["unsigned-verifier-boot"]
	if !ok || boot.Digest != set.Provenance.VerifiedSignedBoot.BootImage.SHA256 ||
		boot.SizeBytes != set.Provenance.VerifiedSignedBoot.BootImage.SizeBytes {
		return errors.New("artifact-set signed-boot provenance differs from the campaign's unsigned-verifier-boot input")
	}
	publicKey, ok := publicInputs["customer-boot-public-key"]
	if !ok || publicKey.Digest != set.Provenance.VerifiedSignedBoot.PublicKey.SHA256 ||
		publicKey.SizeBytes != set.Provenance.VerifiedSignedBoot.PublicKey.SizeBytes {
		return errors.New("artifact-set public-key provenance differs from the campaign's customer-boot-public-key input")
	}
	policy, ok := publicInputs["stable-verifier-policy"]
	if !ok || !artifactFileMatchesPlan(set.SemanticResolution.StableVerifierPolicy.File, policy) {
		return errors.New("artifact-set stable-verifier policy differs from the campaign plan")
	}
	positiveManifest, ok := publicInputs["positive-release-manifest"]
	if !ok || !artifactFileMatchesPlan(set.SemanticResolution.PositiveReleaseManifest.File, positiveManifest) ||
		set.SemanticResolution.PositiveReleaseManifest.File != set.Provenance.DelegatedRelease.ReleaseManifest {
		return errors.New("artifact-set positive release manifest differs from the campaign plan or delegated-release provenance")
	}
	replacementManifest, ok := publicInputs["replacement-release-manifest"]
	if !ok || !artifactFileMatchesPlan(set.SemanticResolution.ReplacementReleaseManifest.File, replacementManifest) {
		return errors.New("artifact-set replacement release manifest differs from the campaign plan")
	}
	positiveTree, ok := publicInputs["positive-release-tree"]
	if !ok || !artifactFileMatchesPlan(set.SemanticResolution.PositiveReleaseTree, positiveTree) ||
		set.Provenance.DelegatedRelease.ReleaseTreeDigest != positiveTree.Digest ||
		set.Provenance.DelegatedRelease.ReleaseTreeSizeBytes != positiveTree.SizeBytes {
		return errors.New("artifact-set positive release tree differs from the campaign plan or delegated-release provenance")
	}
	commandLine, ok := planByteMutation(plan, "component-byte-mutations-rejected:kernel-command-line")
	if !ok || !artifactFileMatchesPlan(set.SemanticResolution.KernelCommandLine.File, commandLine.Before) {
		return errors.New("artifact-set kernel command line differs from the campaign plan target")
	}
	rootImage, rootImageOK := planByteMutation(plan, "component-byte-mutations-rejected:root-image")
	rootData, rootDataOK := planByteMutation(plan, "dm-verity-corruption-rejected:root-data")
	rootHash, rootHashOK := planByteMutation(plan, "dm-verity-corruption-rejected:root-hash")
	rootDataArtifact, rootDataArtifactOK := artifactForRole(set, PartitionRootData)
	rootHashArtifact, rootHashArtifactOK := artifactForRole(set, PartitionRootHash)
	if !rootImageOK || !rootDataOK || !rootDataArtifactOK ||
		!artifactEntryMatchesPlan(rootDataArtifact, rootImage.Before) ||
		!artifactEntryMatchesPlan(rootDataArtifact, rootData.Before) {
		return errors.New("artifact-set root-data payload differs from the campaign's release and dm-verity targets")
	}
	if !rootHashOK || !rootHashArtifactOK || !artifactEntryMatchesPlan(rootHashArtifact, rootHash.Before) {
		return errors.New("artifact-set root-hash payload differs from the campaign's dm-verity target")
	}
	return nil
}

// ValidateAgainstResolved additionally binds every semantic value to the
// direct result of resolving the exact public campaign bytes. It remains a
// descriptive, non-authorizing validation and is not physical evidence.
func (set ArtifactSet) ValidateAgainstResolved(
	plan stablecampaign.Plan,
	resolved stablecampaign.ResolvedPublicArtifacts,
) error {
	if err := set.ValidateAgainst(plan); err != nil {
		return err
	}
	if resolved.PlanDigest != plan.PlanDigest ||
		len(resolved.PublicInputs) != artifactSetPublicInputCount ||
		len(resolved.ByteXORMutations) != artifactSetByteXORCount ||
		len(resolved.BoundReplacements) != artifactSetReplacementCount {
		return errors.New("resolved public artifacts are detached from the complete campaign plan")
	}
	for index, binding := range plan.PublicInputs {
		if resolved.PublicInputs[index] != binding {
			return fmt.Errorf("resolved public input %d differs from the campaign plan", index+1)
		}
	}
	for index, recipe := range plan.ByteXORMutations {
		resolvedRecipe := resolved.ByteXORMutations[index]
		if resolvedRecipe.RecipeID != recipe.RecipeID ||
			resolvedRecipe.Target != recipe.Target ||
			resolvedRecipe.Before != recipe.Before ||
			resolvedRecipe.After != recipe.After {
			return fmt.Errorf("resolved byte-XOR mutation %d differs from the campaign plan", index+1)
		}
	}
	for index, recipe := range plan.BoundReplacements {
		resolvedRecipe := resolved.BoundReplacements[index]
		if resolvedRecipe.RecipeID != recipe.RecipeID ||
			resolvedRecipe.ReplacementInput != recipe.ReplacementInput ||
			resolvedRecipe.DifferenceSelector != recipe.DifferenceSelector ||
			resolvedRecipe.Before != recipe.Before ||
			resolvedRecipe.After != recipe.After {
			return fmt.Errorf("resolved bound replacement %d differs from the campaign plan", index+1)
		}
	}
	want := artifactSemanticsFromResolved(resolved.Semantics)
	if set.SemanticResolution != want {
		return errors.New("artifact-set semantic resolution differs from the independently resolved public bytes")
	}
	return nil
}

func artifactFileMatchesPlan(file ArtifactFileBinding, binding stablecampaign.ArtifactBinding) bool {
	return file.SHA256 == binding.Digest && file.SizeBytes == binding.SizeBytes
}

func artifactEntryMatchesPlan(entry ArtifactSetEntry, binding stablecampaign.ArtifactBinding) bool {
	return entry.Digest == binding.Digest && entry.SizeBytes == binding.SizeBytes
}

func artifactForRole(set ArtifactSet, role PartitionRole) (ArtifactSetEntry, bool) {
	for _, entry := range set.Artifacts {
		if entry.Role == role {
			return entry, true
		}
	}
	return ArtifactSetEntry{}, false
}

func artifactFileFromPlan(binding stablecampaign.ArtifactBinding) ArtifactFileBinding {
	return ArtifactFileBinding{SHA256: binding.Digest, SizeBytes: binding.SizeBytes}
}

func artifactSemanticsFromResolved(resolved stablecampaign.ResolvedCampaignSemantics) ArtifactSetSemanticResolution {
	return ArtifactSetSemanticResolution{
		StableVerifierPolicy: ArtifactSemanticBinding{
			File:           artifactFileFromPlan(resolved.StableVerifierPolicy.File),
			SemanticDigest: resolved.StableVerifierPolicy.SemanticDigest,
		},
		PositiveReleaseManifest: ArtifactSemanticBinding{
			File:           artifactFileFromPlan(resolved.PositiveReleaseManifest.File),
			SemanticDigest: resolved.PositiveReleaseManifest.SemanticDigest,
		},
		ReplacementReleaseManifest: ArtifactSemanticBinding{
			File:           artifactFileFromPlan(resolved.ReplacementReleaseManifest.File),
			SemanticDigest: resolved.ReplacementReleaseManifest.SemanticDigest,
		},
		PositiveReleaseTree: artifactFileFromPlan(resolved.PositiveReleaseTree),
		KernelCommandLine: ArtifactCommandLineBinding{
			File:  artifactFileFromPlan(resolved.KernelCommandLine.File),
			Value: resolved.KernelCommandLine.Value,
		},
	}
}

func planByteMutation(plan stablecampaign.Plan, recipeID string) (stablecampaign.ByteXORMutationRecipe, bool) {
	for _, recipe := range plan.ByteXORMutations {
		if recipe.RecipeID == recipeID {
			return recipe, true
		}
	}
	return stablecampaign.ByteXORMutationRecipe{}, false
}
