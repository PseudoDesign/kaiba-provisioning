package campaignmedia

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

const (
	RunArtifactMaterializationSchemaV1Alpha1 = "kaiba.provisioning.rpi5-stable-verifier-run-artifact-materialization/v1alpha1"

	RunArtifactCreationModeCreateNew   = "create-new"
	RunArtifactOutputScopeNixStoreOnly = "nix-store-only"

	runArtifactMaterializationDigestDomain = "kaiba.provisioning.rpi5-stable-verifier-run-artifact-materialization.v1alpha1"
)

// RunArtifactMutationKind distinguishes the two plan-owned mutation recipes.
// It does not grant authority to perform either mutation.
type RunArtifactMutationKind string

const (
	RunArtifactMutationByteXOR          RunArtifactMutationKind = "byte-xor"
	RunArtifactMutationBoundReplacement RunArtifactMutationKind = "bound-replacement"
)

// RunArtifactMaterializationCapabilities fixes the deliberately narrow build
// boundary represented by this contract. A materializer may create a new Nix
// store output; it may not access devices or turn build metadata into physical
// campaign evidence or authority.
type RunArtifactMaterializationCapabilities struct {
	ClaimClosurePerformed        bool   `json:"claim_closure_performed"`
	CreationMode                 string `json:"creation_mode"`
	DeviceAccessPerformed        bool   `json:"device_access_performed"`
	ExecutionPerformed           bool   `json:"execution_performed"`
	HardwareObserved             bool   `json:"hardware_observed"`
	OutputScope                  string `json:"output_scope"`
	PrivateKeyOperationPerformed bool   `json:"private_key_operation_performed"`
	ProductionReady              bool   `json:"production_ready"`
	SigningPerformed             bool   `json:"signing_performed"`
}

// RunArtifactSelectedTarget binds the exact plan-owned object selected for a
// mutation. For release/* recipes this target is a file inside the release
// filesystem, so neither digest is a digest of the enclosing partition
// payload. The separate MaterializedArtifacts field binds that resulting
// payload without asserting equality to After.
type RunArtifactSelectedTarget struct {
	After  stablecampaign.ArtifactBinding `json:"after"`
	Before stablecampaign.ArtifactBinding `json:"before"`
	Target string                         `json:"target"`
}

// RunArtifactMutationBinding is the complete selected recipe projection. The
// recipe is rederived from the fixed RunSpec and independently validated plan;
// callers cannot select a different recipe for a run.
type RunArtifactMutationBinding struct {
	AffectedArtifactRole PartitionRole             `json:"affected_artifact_role"`
	DifferenceSelector   string                    `json:"difference_selector,omitempty"`
	Kind                 RunArtifactMutationKind   `json:"kind"`
	OffsetBytes          *uint64                   `json:"offset_bytes,omitempty"`
	RecipeID             string                    `json:"recipe_id"`
	ReplacementInput     string                    `json:"replacement_input,omitempty"`
	SelectedTarget       RunArtifactSelectedTarget `json:"selected_target"`
	XORMask              *uint8                    `json:"xor_mask,omitempty"`
}

// RunArtifactMaterialization is a path-free, digest-sealed description of the
// four newly materialized partition payloads for exactly one fixed campaign
// RunSpec. ArtifactSetContentDigest refers to the independently validated
// positive-baseline ArtifactSet; that ArtifactSet remains unchanged.
//
// This contract records build output metadata only. It neither proves that a
// physical partition contains those bytes nor authorizes signing, device I/O,
// execution, hardware observation, or planned-claim closure.
type RunArtifactMaterialization struct {
	ArtifactSetContentDigest bundle.Digest                          `json:"artifact_set_content_digest"`
	CampaignID               string                                 `json:"campaign_id"`
	Capabilities             RunArtifactMaterializationCapabilities `json:"capabilities"`
	MaterializationDigest    bundle.Digest                          `json:"materialization_digest"`
	MaterializedArtifacts    []ArtifactSetEntry                     `json:"materialized_artifacts"`
	Mutation                 *RunArtifactMutationBinding            `json:"mutation,omitempty"`
	PlanDigest               bundle.Digest                          `json:"plan_digest"`
	RunID                    string                                 `json:"run_id"`
	RunIndex                 uint16                                 `json:"run_index"`
	SchemaVersion            string                                 `json:"schema_version"`
}

type runArtifactMaterializationDigestMaterial struct {
	ArtifactSetContentDigest bundle.Digest                          `json:"artifact_set_content_digest"`
	CampaignID               string                                 `json:"campaign_id"`
	Capabilities             RunArtifactMaterializationCapabilities `json:"capabilities"`
	MaterializedArtifacts    []ArtifactSetEntry                     `json:"materialized_artifacts"`
	Mutation                 *RunArtifactMutationBinding            `json:"mutation,omitempty"`
	PlanDigest               bundle.Digest                          `json:"plan_digest"`
	RunID                    string                                 `json:"run_id"`
	RunIndex                 uint16                                 `json:"run_index"`
	SchemaVersion            string                                 `json:"schema_version"`
}

func runArtifactMaterializationCapabilities() RunArtifactMaterializationCapabilities {
	return RunArtifactMaterializationCapabilities{
		CreationMode: RunArtifactCreationModeCreateNew,
		OutputScope:  RunArtifactOutputScopeNixStoreOnly,
	}
}

// NewRunArtifactMaterialization validates and cross-binds the independently
// supplied plan, positive-baseline ArtifactSet, and exact-byte public-artifact
// resolution; derives the fixed RunSpec and selected recipe for runIndex; and
// seals the supplied materialized payload bindings. It accepts no paths or
// bytes and performs no I/O.
func NewRunArtifactMaterialization(
	plan stablecampaign.Plan,
	baseline ArtifactSet,
	resolved stablecampaign.ResolvedPublicArtifacts,
	runIndex uint16,
	materializedArtifacts []ArtifactSetEntry,
) (RunArtifactMaterialization, error) {
	if err := baseline.ValidateAgainstResolved(plan, resolved); err != nil {
		return RunArtifactMaterialization{}, fmt.Errorf("construct run artifact materialization: %w", err)
	}
	run, err := fixedRunSpec(plan, runIndex)
	if err != nil {
		return RunArtifactMaterialization{}, fmt.Errorf("construct run artifact materialization: %w", err)
	}
	mutation, affectedRole, err := selectedRunMutation(plan, resolved, run)
	if err != nil {
		return RunArtifactMaterialization{}, fmt.Errorf("construct run artifact materialization: %w", err)
	}
	artifacts := append([]ArtifactSetEntry(nil), materializedArtifacts...)
	if err := validateMaterializedArtifacts(artifacts, baseline.Artifacts, mutation, affectedRole); err != nil {
		return RunArtifactMaterialization{}, fmt.Errorf("construct run artifact materialization: %w", err)
	}

	materialization := RunArtifactMaterialization{
		ArtifactSetContentDigest: baseline.ArtifactSetContentDigest,
		CampaignID:               plan.CampaignID,
		Capabilities:             runArtifactMaterializationCapabilities(),
		Mutation:                 mutation,
		PlanDigest:               plan.PlanDigest,
		MaterializedArtifacts:    artifacts,
		RunID:                    run.RunID,
		RunIndex:                 run.Index,
		SchemaVersion:            RunArtifactMaterializationSchemaV1Alpha1,
	}
	digest, err := materialization.DerivedDigest()
	if err != nil {
		return RunArtifactMaterialization{}, err
	}
	materialization.MaterializationDigest = digest
	if err := materialization.Validate(); err != nil {
		return RunArtifactMaterialization{}, err
	}
	return materialization, nil
}

// Validate checks the self-contained shape, capability boundary, and content
// digest. ValidateAgainst is still required to prove that the run, recipe, and
// baseline binding were independently derived from the supplied inputs.
func (materialization RunArtifactMaterialization) Validate() error {
	return materialization.validate(true)
}

func (materialization RunArtifactMaterialization) validate(requireDigest bool) error {
	if materialization.SchemaVersion != RunArtifactMaterializationSchemaV1Alpha1 {
		return fmt.Errorf("unsupported run artifact materialization schema_version %q", materialization.SchemaVersion)
	}
	if !campaignIDPattern.MatchString(materialization.CampaignID) {
		return errors.New("run artifact materialization campaign_id must be a canonical lowercase campaign identifier")
	}
	if err := validateDigest("run artifact materialization plan_digest", materialization.PlanDigest); err != nil {
		return err
	}
	if err := validateDigest("run artifact materialization artifact_set_content_digest", materialization.ArtifactSetContentDigest); err != nil {
		return err
	}
	if materialization.RunIndex == 0 || materialization.RunIndex > 33 {
		return errors.New("run artifact materialization run_index must be between 1 and 33")
	}
	if err := validateMaterializationRunID(materialization.RunID); err != nil {
		return err
	}
	if err := materialization.Capabilities.validate(); err != nil {
		return err
	}
	if err := validateMaterializedArtifactShape(materialization.MaterializedArtifacts); err != nil {
		return err
	}
	if materialization.Mutation != nil {
		if err := materialization.Mutation.validate(); err != nil {
			return err
		}
		if materialization.RunID != materialization.Mutation.RecipeID {
			return errors.New("run artifact materialization run_id must equal its selected mutation recipe_id")
		}
	}
	if requireDigest {
		if err := validateDigest("run artifact materialization materialization_digest", materialization.MaterializationDigest); err != nil {
			return err
		}
		derived, err := materialization.DerivedDigest()
		if err != nil {
			return err
		}
		if materialization.MaterializationDigest != derived {
			return errors.New("materialization_digest does not bind the canonical run artifact materialization")
		}
	}
	return nil
}

func (capabilities RunArtifactMaterializationCapabilities) validate() error {
	if capabilities.CreationMode != RunArtifactCreationModeCreateNew ||
		capabilities.OutputScope != RunArtifactOutputScopeNixStoreOnly {
		return errors.New("run artifact materialization must remain create-new with Nix-store-only output scope")
	}
	if capabilities.ClaimClosurePerformed || capabilities.DeviceAccessPerformed ||
		capabilities.ExecutionPerformed || capabilities.HardwareObserved ||
		capabilities.PrivateKeyOperationPerformed || capabilities.ProductionReady ||
		capabilities.SigningPerformed {
		return errors.New("run artifact materialization cannot perform device access, signing, private-key operations, hardware observation, execution, production qualification, or claim closure")
	}
	return nil
}

func (mutation RunArtifactMutationBinding) validate() error {
	testID, subcaseID, ok := strings.Cut(mutation.RecipeID, ":")
	if !ok || testID == "" || subcaseID == "" || strings.Contains(subcaseID, ":") {
		return errors.New("run artifact mutation recipe_id must identify one fixed test and subcase")
	}

	switch mutation.Kind {
	case RunArtifactMutationByteXOR:
		if mutation.OffsetBytes == nil || mutation.XORMask == nil ||
			mutation.ReplacementInput != "" || mutation.DifferenceSelector != "" {
			return errors.New("byte-XOR run artifact mutation has invalid kind-specific fields")
		}
		recipe, err := stablecampaign.NewByteXORMutationRecipe(
			testID,
			subcaseID,
			mutation.SelectedTarget.Target,
			mutation.SelectedTarget.Before,
			mutation.SelectedTarget.After,
		)
		if err != nil {
			return fmt.Errorf("run artifact byte-XOR mutation: %w", err)
		}
		if recipe.RecipeID != mutation.RecipeID || recipe.OffsetBytes != *mutation.OffsetBytes || recipe.XORMask != *mutation.XORMask {
			return errors.New("run artifact byte-XOR mutation differs from its fixed recipe")
		}
	case RunArtifactMutationBoundReplacement:
		if mutation.OffsetBytes != nil || mutation.XORMask != nil ||
			mutation.ReplacementInput == "" || mutation.DifferenceSelector == "" {
			return errors.New("bound-replacement run artifact mutation has invalid kind-specific fields")
		}
		recipe, err := stablecampaign.NewBoundReplacementMutationRecipe(
			testID,
			subcaseID,
			mutation.SelectedTarget.Before,
			mutation.SelectedTarget.After,
		)
		if err != nil {
			return fmt.Errorf("run artifact bound-replacement mutation: %w", err)
		}
		if recipe.RecipeID != mutation.RecipeID || recipe.Target != mutation.SelectedTarget.Target ||
			recipe.ReplacementInput != mutation.ReplacementInput || recipe.DifferenceSelector != mutation.DifferenceSelector {
			return errors.New("run artifact bound-replacement mutation differs from its fixed recipe")
		}
	default:
		return fmt.Errorf("unsupported run artifact mutation kind %q", mutation.Kind)
	}

	wantRole, err := artifactRoleForMutation(mutation.Kind, mutation.SelectedTarget.Target)
	if err != nil {
		return err
	}
	if mutation.AffectedArtifactRole != wantRole {
		return errors.New("run artifact mutation affected_artifact_role differs from its selected target")
	}
	return nil
}

func validateMaterializationRunID(runID string) error {
	parts := strings.Split(runID, ":")
	if len(parts) == 0 || len(parts) > 2 {
		return errors.New("run artifact materialization run_id is not canonical")
	}
	for _, part := range parts {
		if !campaignIDPattern.MatchString(part) || strings.Contains(part, "..") {
			return errors.New("run artifact materialization run_id is not canonical")
		}
	}
	return nil
}

func validateMaterializedArtifactShape(artifacts []ArtifactSetEntry) error {
	if len(artifacts) != len(fixedArtifactSetEntries) {
		return errors.New("materialized_artifacts must contain exactly boot, release, root-data, and root-hash payloads")
	}
	for index, expected := range fixedArtifactSetEntries {
		artifact := artifacts[index]
		if artifact.Role != expected.role || artifact.Name != expected.name {
			return fmt.Errorf("materialized artifact entry %d differs from the fixed role and name", index+1)
		}
		if err := validateDigest(fmt.Sprintf("materialized artifact entry %d digest", index+1), artifact.Digest); err != nil {
			return err
		}
		if artifact.SizeBytes == 0 || artifact.SizeBytes > math.MaxInt64 {
			return fmt.Errorf("materialized artifact entry %d has an unsupported size", index+1)
		}
		if (artifact.Role == PartitionRootData || artifact.Role == PartitionRootHash) && artifact.SizeBytes%4096 != 0 {
			return fmt.Errorf("materialized %q payload must contain whole dm-verity blocks", artifact.Role)
		}
	}
	return nil
}

func validateMaterializedArtifacts(
	materialized []ArtifactSetEntry,
	baseline []ArtifactSetEntry,
	mutation *RunArtifactMutationBinding,
	affectedRole *PartitionRole,
) error {
	if err := validateMaterializedArtifactShape(materialized); err != nil {
		return err
	}
	if len(baseline) != len(materialized) {
		return errors.New("positive-baseline artifact set does not contain the fixed materialized artifact roles")
	}
	for index := range materialized {
		actual := materialized[index]
		before := baseline[index]
		if actual.Name != before.Name || actual.Role != before.Role || actual.SizeBytes != before.SizeBytes {
			return fmt.Errorf("materialized %q payload must preserve its baseline name, role, and size", actual.Role)
		}
		changed := actual.Digest != before.Digest
		if affectedRole == nil {
			if changed {
				return fmt.Errorf("no-mutation run must use the positive-baseline %q payload byte-for-byte", actual.Role)
			}
			continue
		}
		if actual.Role == *affectedRole {
			if !changed {
				return fmt.Errorf("mutation run must change the materialized %q payload", actual.Role)
			}
			// media/root-data and media/root-hash name the exact partition
			// payload object materialized here, rather than a file inside an
			// enclosing filesystem. Only those direct-media recipes therefore
			// require the output binding to equal the selected target's after
			// binding. No such equality is asserted for release/* targets.
			if mutation != nil && strings.HasPrefix(mutation.SelectedTarget.Target, "media/") &&
				(actual.Digest != mutation.SelectedTarget.After.Digest ||
					actual.SizeBytes != mutation.SelectedTarget.After.SizeBytes) {
				return fmt.Errorf("direct-media mutation result for %q does not match selected_target.after", actual.Role)
			}
			continue
		}
		if changed {
			return fmt.Errorf("mutation run changed unrelated materialized %q payload", actual.Role)
		}
	}
	return nil
}

func fixedRunSpec(plan stablecampaign.Plan, runIndex uint16) (stablecampaign.RunSpec, error) {
	runs, err := stablecampaign.ExpectedRuns(plan)
	if err != nil {
		return stablecampaign.RunSpec{}, err
	}
	if runIndex == 0 || int(runIndex) > len(runs) {
		return stablecampaign.RunSpec{}, fmt.Errorf("run_index must be between 1 and %d", len(runs))
	}
	return runs[runIndex-1], nil
}

func selectedRunMutation(
	plan stablecampaign.Plan,
	resolved stablecampaign.ResolvedPublicArtifacts,
	run stablecampaign.RunSpec,
) (*RunArtifactMutationBinding, *PartitionRole, error) {
	if run.MutationRecipeID == "" {
		return nil, nil, nil
	}
	for index, recipe := range plan.ByteXORMutations {
		if recipe.RecipeID != run.MutationRecipeID {
			continue
		}
		if index >= len(resolved.ByteXORMutations) {
			return nil, nil, errors.New("resolved public artifacts omit the selected byte-XOR recipe")
		}
		resolvedRecipe := resolved.ByteXORMutations[index]
		if resolvedRecipe.RecipeID != recipe.RecipeID || resolvedRecipe.Target != recipe.Target ||
			resolvedRecipe.Before != recipe.Before || resolvedRecipe.After != recipe.After {
			return nil, nil, errors.New("selected byte-XOR recipe differs from the exact-byte resolution")
		}
		role, err := artifactRoleForMutation(RunArtifactMutationByteXOR, recipe.Target)
		if err != nil {
			return nil, nil, err
		}
		offset := recipe.OffsetBytes
		mask := recipe.XORMask
		return &RunArtifactMutationBinding{
			AffectedArtifactRole: role,
			Kind:                 RunArtifactMutationByteXOR,
			OffsetBytes:          &offset,
			RecipeID:             recipe.RecipeID,
			SelectedTarget: RunArtifactSelectedTarget{
				After: recipe.After, Before: recipe.Before, Target: recipe.Target,
			},
			XORMask: &mask,
		}, &role, nil
	}
	for index, recipe := range plan.BoundReplacements {
		if recipe.RecipeID != run.MutationRecipeID {
			continue
		}
		if index >= len(resolved.BoundReplacements) {
			return nil, nil, errors.New("resolved public artifacts omit the selected bound-replacement recipe")
		}
		resolvedRecipe := resolved.BoundReplacements[index]
		if resolvedRecipe.RecipeID != recipe.RecipeID ||
			resolvedRecipe.ReplacementInput != recipe.ReplacementInput ||
			resolvedRecipe.DifferenceSelector != recipe.DifferenceSelector ||
			resolvedRecipe.Before != recipe.Before || resolvedRecipe.After != recipe.After {
			return nil, nil, errors.New("selected bound-replacement recipe differs from the exact-byte resolution")
		}
		role, err := artifactRoleForMutation(RunArtifactMutationBoundReplacement, recipe.Target)
		if err != nil {
			return nil, nil, err
		}
		return &RunArtifactMutationBinding{
			AffectedArtifactRole: role,
			DifferenceSelector:   recipe.DifferenceSelector,
			Kind:                 RunArtifactMutationBoundReplacement,
			RecipeID:             recipe.RecipeID,
			ReplacementInput:     recipe.ReplacementInput,
			SelectedTarget: RunArtifactSelectedTarget{
				After: recipe.After, Before: recipe.Before, Target: recipe.Target,
			},
		}, &role, nil
	}
	return nil, nil, fmt.Errorf("fixed run %q selects recipe %q absent from the campaign plan", run.RunID, run.MutationRecipeID)
}

func artifactRoleForMutation(kind RunArtifactMutationKind, target string) (PartitionRole, error) {
	if kind == RunArtifactMutationBoundReplacement {
		if target != "release/release-manifest.json" {
			return "", errors.New("bound-replacement target must be inside the release filesystem")
		}
		return PartitionReleaseFilesystem, nil
	}
	if kind != RunArtifactMutationByteXOR {
		return "", fmt.Errorf("unsupported run artifact mutation kind %q", kind)
	}
	if strings.HasPrefix(target, "release/") {
		return PartitionReleaseFilesystem, nil
	}
	switch target {
	case "media/root-data":
		return PartitionRootData, nil
	case "media/root-hash":
		return PartitionRootHash, nil
	default:
		return "", fmt.Errorf("byte-XOR target %q has no materialized artifact role", target)
	}
}

// DerivedDigest returns the domain-separated digest of the complete contract
// with materialization_digest absent.
func (materialization RunArtifactMaterialization) DerivedDigest() (bundle.Digest, error) {
	if err := materialization.validate(false); err != nil {
		return "", err
	}
	material := runArtifactMaterializationDigestMaterial{
		ArtifactSetContentDigest: materialization.ArtifactSetContentDigest,
		CampaignID:               materialization.CampaignID,
		Capabilities:             materialization.Capabilities,
		Mutation:                 materialization.Mutation,
		PlanDigest:               materialization.PlanDigest,
		MaterializedArtifacts:    append([]ArtifactSetEntry(nil), materialization.MaterializedArtifacts...),
		RunID:                    materialization.RunID,
		RunIndex:                 materialization.RunIndex,
		SchemaVersion:            materialization.SchemaVersion,
	}
	return digestJSON(runArtifactMaterializationDigestDomain, material, "run artifact materialization")
}

// CanonicalJSON returns the unique compact encoding of a self-validating
// materialization. ValidateAgainst remains necessary at a trust boundary.
func (materialization RunArtifactMaterialization) CanonicalJSON() ([]byte, error) {
	if err := materialization.Validate(); err != nil {
		return nil, err
	}
	return marshalWithinLimit("run artifact materialization", materialization)
}

// ParseRunArtifactMaterialization accepts only strict canonical JSON,
// optionally followed by one LF. Unknown fields, duplicate keys, nulls, and
// alternate encodings are rejected. Call ValidateAgainst before use.
func ParseRunArtifactMaterialization(encoded []byte) (RunArtifactMaterialization, error) {
	var materialization RunArtifactMaterialization
	if err := strictCanonicalDecode(encoded, &materialization, func() ([]byte, error) {
		return materialization.CanonicalJSON()
	}); err != nil {
		return RunArtifactMaterialization{}, fmt.Errorf("parse run artifact materialization: %w", err)
	}
	return materialization, nil
}

// ValidateAgainst rederives the fixed RunSpec, selected recipe, capability
// boundary, role changes, and digest from the independently supplied inputs.
func (materialization RunArtifactMaterialization) ValidateAgainst(
	plan stablecampaign.Plan,
	baseline ArtifactSet,
	resolved stablecampaign.ResolvedPublicArtifacts,
) error {
	if err := materialization.Validate(); err != nil {
		return err
	}
	want, err := NewRunArtifactMaterialization(
		plan,
		baseline,
		resolved,
		materialization.RunIndex,
		materialization.MaterializedArtifacts,
	)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(materialization, want) {
		return errors.New("run artifact materialization differs from the independently derived contract")
	}
	return nil
}
