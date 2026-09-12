// Package stablequalification derives narrow verifier expectations from the
// independently supplied stable-campaign plan and campaign artifact set. It
// contains no filesystem, device, signing, authority, or execution API.
package stablequalification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

const (
	RunVerifierExpectationSchemaV1Alpha1 = "kaiba.provisioning.rpi5-stable-verifier-run-verifier-expectation/v1alpha1"
	runVerifierExpectationDigestDomain   = "kaiba.provisioning.rpi5-stable-verifier-run-verifier-expectation.v1alpha1"
)

// PlannedMutationKind distinguishes the two immutable mutation descriptions
// admitted by the campaign plan.
type PlannedMutationKind string

const (
	PlannedMutationByteXOR          PlannedMutationKind = "byte-xor"
	PlannedMutationBoundReplacement PlannedMutationKind = "bound-replacement"
)

// ExpectedVerifierEvent is one position in the complete code-derived event
// sequence. It describes expected data and never records an observation.
type ExpectedVerifierEvent struct {
	Event       string                             `json:"event"`
	FailureCode string                             `json:"failure_code,omitempty"`
	DetailStage stablecampaign.VerifierDetailStage `json:"detail_stage"`
}

// ExpectedReleaseDetails are present only when the expected verifier trace
// reaches the release-verified boundary. KernelCommandLine excludes its
// optional file LF.
type ExpectedReleaseDetails struct {
	PolicyDigest      bundle.Digest `json:"policy_digest"`
	ManifestDigest    bundle.Digest `json:"manifest_digest"`
	KernelCommandLine string        `json:"kernel_command_line"`
}

// PlannedMutationBinding copies the exact plan-derived target bindings for a
// mutated run. Fields unused by the selected mutation kind remain omitted.
type PlannedMutationBinding struct {
	Kind               PlannedMutationKind            `json:"kind"`
	RecipeID           string                         `json:"recipe_id"`
	Target             string                         `json:"target"`
	Before             stablecampaign.ArtifactBinding `json:"before"`
	After              stablecampaign.ArtifactBinding `json:"after"`
	OffsetBytes        *uint64                        `json:"offset_bytes,omitempty"`
	XORMask            *uint8                         `json:"xor_mask,omitempty"`
	ReplacementInput   string                         `json:"replacement_input,omitempty"`
	DifferenceSelector string                         `json:"difference_selector,omitempty"`
}

// ResolvedRunVerifierExpectation is a digest-sealed, run-specific projection
// of verifier trace, release-detail, and planned-mutation expectations. It is
// intentionally narrower than an exact run-media expectation and contains no
// execution result or action authorization.
type ResolvedRunVerifierExpectation struct {
	SchemaVersion            string                  `json:"schema_version"`
	CampaignID               string                  `json:"campaign_id"`
	PlanDigest               bundle.Digest           `json:"plan_digest"`
	ArtifactSetContentDigest bundle.Digest           `json:"artifact_set_content_digest"`
	RunIndex                 uint16                  `json:"run_index"`
	RunID                    string                  `json:"run_id"`
	RecipeID                 string                  `json:"recipe_id,omitempty"`
	ExpectedVerifierTrace    []ExpectedVerifierEvent `json:"expected_verifier_trace"`
	ReleaseDetails           *ExpectedReleaseDetails `json:"release_details,omitempty"`
	PlannedMutation          *PlannedMutationBinding `json:"planned_mutation,omitempty"`
	ExpectationDigest        bundle.Digest           `json:"expectation_digest"`
}

// ResolveRunVerifierExpectation derives and seals the only expectation
// accepted for runIndex after cross-binding the artifact set to the direct
// exact-byte resolution. The artifact set remains a baseline payload contract;
// this function does not infer mutated filesystem or whole-partition digests.
func ResolveRunVerifierExpectation(
	plan stablecampaign.Plan,
	set campaignmedia.ArtifactSet,
	resolved stablecampaign.ResolvedPublicArtifacts,
	runIndex uint16,
) (ResolvedRunVerifierExpectation, error) {
	expectation, err := deriveRunVerifierExpectation(plan, set, resolved, runIndex)
	if err != nil {
		return ResolvedRunVerifierExpectation{}, err
	}
	digest, err := expectation.derivedDigest()
	if err != nil {
		return ResolvedRunVerifierExpectation{}, err
	}
	expectation.ExpectationDigest = digest
	return expectation, nil
}

// ValidateAgainst recomputes every field from the independently supplied
// sealed plan, exact-byte resolution, and artifact set and rejects any
// caller-authored substitution.
func (expectation ResolvedRunVerifierExpectation) ValidateAgainst(
	plan stablecampaign.Plan,
	set campaignmedia.ArtifactSet,
	resolved stablecampaign.ResolvedPublicArtifacts,
) error {
	if err := expectation.ExpectationDigest.Validate(); err != nil {
		return fmt.Errorf("expectation_digest: %w", err)
	}
	want, err := ResolveRunVerifierExpectation(plan, set, resolved, expectation.RunIndex)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(expectation, want) {
		return errors.New("run verifier expectation differs from the independently derived expectation")
	}
	return nil
}

// CanonicalJSON returns the unique compact encoding after independent
// revalidation against the plan and artifact set.
func (expectation ResolvedRunVerifierExpectation) CanonicalJSON(
	plan stablecampaign.Plan,
	set campaignmedia.ArtifactSet,
	resolved stablecampaign.ResolvedPublicArtifacts,
) ([]byte, error) {
	if err := expectation.ValidateAgainst(plan, set, resolved); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(expectation)
	if err != nil {
		return nil, fmt.Errorf("encode run verifier expectation: %w", err)
	}
	return encoded, nil
}

func deriveRunVerifierExpectation(
	plan stablecampaign.Plan,
	set campaignmedia.ArtifactSet,
	resolved stablecampaign.ResolvedPublicArtifacts,
	runIndex uint16,
) (ResolvedRunVerifierExpectation, error) {
	if err := set.ValidateAgainstResolved(plan, resolved); err != nil {
		return ResolvedRunVerifierExpectation{}, fmt.Errorf("derive run verifier expectation: %w", err)
	}
	runs, err := stablecampaign.ExpectedRuns(plan)
	if err != nil {
		return ResolvedRunVerifierExpectation{}, err
	}
	if runIndex == 0 || int(runIndex) > len(runs) {
		return ResolvedRunVerifierExpectation{}, fmt.Errorf("run_index must be between 1 and %d", len(runs))
	}
	run := runs[runIndex-1]
	expectation := ResolvedRunVerifierExpectation{
		SchemaVersion:            RunVerifierExpectationSchemaV1Alpha1,
		CampaignID:               plan.CampaignID,
		PlanDigest:               plan.PlanDigest,
		ArtifactSetContentDigest: set.ArtifactSetContentDigest,
		RunIndex:                 run.Index,
		RunID:                    run.RunID,
		RecipeID:                 run.MutationRecipeID,
		ExpectedVerifierTrace:    make([]ExpectedVerifierEvent, len(run.VerifierTrace)),
	}
	for index, event := range run.VerifierTrace {
		expectation.ExpectedVerifierTrace[index] = ExpectedVerifierEvent{
			Event: event.Event, FailureCode: event.FailureCode, DetailStage: event.DetailStage,
		}
	}
	if traceHasReleaseDetails(run.VerifierTrace) {
		manifest := set.SemanticResolution.PositiveReleaseManifest.SemanticDigest
		if run.MutationRecipeID == "delegated-key-replacement-boots:replacement-manifest" {
			manifest = set.SemanticResolution.ReplacementReleaseManifest.SemanticDigest
		}
		expectation.ReleaseDetails = &ExpectedReleaseDetails{
			PolicyDigest:      set.SemanticResolution.StableVerifierPolicy.SemanticDigest,
			ManifestDigest:    manifest,
			KernelCommandLine: set.SemanticResolution.KernelCommandLine.Value,
		}
	}
	if run.MutationRecipeID != "" {
		mutation, err := plannedMutation(plan, run.MutationRecipeID)
		if err != nil {
			return ResolvedRunVerifierExpectation{}, err
		}
		expectation.PlannedMutation = &mutation
	}
	return expectation, nil
}

func traceHasReleaseDetails(trace []stablecampaign.VerifierEventExpectation) bool {
	for _, event := range trace {
		if event.DetailStage != stablecampaign.VerifierDetailNone {
			return true
		}
	}
	return false
}

func plannedMutation(plan stablecampaign.Plan, recipeID string) (PlannedMutationBinding, error) {
	for _, recipe := range plan.ByteXORMutations {
		if recipe.RecipeID == recipeID {
			offset := recipe.OffsetBytes
			mask := recipe.XORMask
			return PlannedMutationBinding{
				Kind: PlannedMutationByteXOR, RecipeID: recipe.RecipeID, Target: recipe.Target,
				Before: recipe.Before, After: recipe.After,
				OffsetBytes: &offset, XORMask: &mask,
			}, nil
		}
	}
	for _, recipe := range plan.BoundReplacements {
		if recipe.RecipeID == recipeID {
			return PlannedMutationBinding{
				Kind: PlannedMutationBoundReplacement, RecipeID: recipe.RecipeID, Target: recipe.Target,
				Before: recipe.Before, After: recipe.After,
				ReplacementInput: recipe.ReplacementInput, DifferenceSelector: recipe.DifferenceSelector,
			}, nil
		}
	}
	return PlannedMutationBinding{}, fmt.Errorf("run mutation recipe %q is absent from the campaign plan", recipeID)
}

func (expectation ResolvedRunVerifierExpectation) derivedDigest() (bundle.Digest, error) {
	material := expectation
	material.ExpectationDigest = ""
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", fmt.Errorf("encode run verifier expectation digest material: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(runVerifierExpectationDigestDomain + "\x00"))
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}
