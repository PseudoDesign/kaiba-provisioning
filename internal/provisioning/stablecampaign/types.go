// Package stablecampaign defines the public-only, non-production contract for
// the Raspberry Pi 5 stable-verifier physical campaign. It contains no private
// key, signer, block-device writer, authorization-server control, or UART
// capture implementation.
package stablecampaign

import "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"

const (
	PlanSchemaV1Alpha1        = "kaiba.provisioning.rpi5-stable-verifier-campaign-plan/v1alpha1"
	ByteXORSchemaV1Alpha1     = "kaiba.provisioning.rpi5-stable-verifier-byte-xor-recipe/v1alpha1"
	ReplacementSchemaV1Alpha1 = "kaiba.provisioning.rpi5-stable-verifier-bound-replacement-recipe/v1alpha1"

	CampaignProfile = "kaiba.provisioning.rpi5-stable-verifier-campaign/v1alpha1"
	DeviceClass     = "raspberry-pi-5-model-b-v1alpha1"
	Classification  = "development-only"

	maximumContractBytes = 1024 * 1024
	maximumJSONDepth     = 64
)

// SafetyBoundary makes the limitations of this contract machine-checkable.
// A campaign plan is descriptive: it does not authorize signing, device
// writes, or a production claim.
type SafetyBoundary struct {
	Classification                    string `json:"classification"`
	PrivateMaterialEmbeddedInContract bool   `json:"private_material_embedded_in_contract"`
	ProductionReady                   bool   `json:"production_ready"`
	SigningAuthorized                 bool   `json:"signing_authorized"`
	DeviceWritesAuthorized            bool   `json:"device_writes_authorized"`
}

// ArtifactBinding names public bytes only by their canonical SHA-256 digest
// and size. Host paths and file contents are deliberately absent.
type ArtifactBinding struct {
	Name      string        `json:"name"`
	Digest    bundle.Digest `json:"digest"`
	SizeBytes uint64        `json:"size_bytes"`
}

// LogicalCase is one result required by the campaign evidence profile. A
// logical result may require several separately executed subcases.
type LogicalCase struct {
	TestID   string   `json:"test_id"`
	Subcases []string `json:"subcases"`
}

// ByteXORMutationRecipe changes exactly one byte at a fixed offset. Before and
// After bind the complete target before and after the deterministic XOR. The
// recipe contains neither copy of those bytes.
type ByteXORMutationRecipe struct {
	SchemaVersion  string          `json:"schema_version"`
	RecipeID       string          `json:"recipe_id"`
	TestID         string          `json:"test_id"`
	SubcaseID      string          `json:"subcase_id"`
	SafetyBoundary SafetyBoundary  `json:"safety_boundary"`
	Target         string          `json:"target"`
	Before         ArtifactBinding `json:"before"`
	After          ArtifactBinding `json:"after"`
	OffsetBytes    uint64          `json:"offset_bytes"`
	XORMask        uint8           `json:"xor_mask"`
}

// BoundReplacementMutationRecipe performs one atomic replacement of Target
// using a separately supplied public artifact. DifferenceSelector is either a
// fixed JSON pointer for a one-field manifest test or "$" for a complete,
// separately signed manifest variant. The replacement bytes are not embedded.
type BoundReplacementMutationRecipe struct {
	SchemaVersion      string          `json:"schema_version"`
	RecipeID           string          `json:"recipe_id"`
	TestID             string          `json:"test_id"`
	SubcaseID          string          `json:"subcase_id"`
	SafetyBoundary     SafetyBoundary  `json:"safety_boundary"`
	Target             string          `json:"target"`
	Before             ArtifactBinding `json:"before"`
	After              ArtifactBinding `json:"after"`
	ReplacementInput   string          `json:"replacement_input"`
	DifferenceSelector string          `json:"difference_selector"`
}

// Plan binds every public campaign input, the exact logical test matrix, and
// every deterministic artifact mutation. Authority-offline, authorization-
// replay, and positive observation cases have no mutation recipe because they
// vary runtime state rather than artifact bytes.
type Plan struct {
	SchemaVersion     string                           `json:"schema_version"`
	CampaignID        string                           `json:"campaign_id"`
	CampaignProfile   string                           `json:"campaign_profile"`
	DeviceClass       string                           `json:"device_class"`
	SafetyBoundary    SafetyBoundary                   `json:"safety_boundary"`
	PublicInputs      []ArtifactBinding                `json:"public_inputs"`
	Cases             []LogicalCase                    `json:"cases"`
	ByteXORMutations  []ByteXORMutationRecipe          `json:"byte_xor_mutations"`
	BoundReplacements []BoundReplacementMutationRecipe `json:"bound_replacements"`
	PlanDigest        bundle.Digest                    `json:"plan_digest"`
}

func publicSafetyBoundary() SafetyBoundary {
	return SafetyBoundary{Classification: Classification}
}

// PublicSafetyBoundary returns the only safety boundary accepted by this
// public-only development contract.
func PublicSafetyBoundary() SafetyBoundary { return publicSafetyBoundary() }
