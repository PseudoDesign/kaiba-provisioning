package stablecampaign

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/verifierevents"
)

const (
	ExecutionResultSchemaV1Alpha2 = "kaiba.provisioning.rpi5-stable-verifier-campaign-execution-result/v1alpha2"
	ExecutionSetSchemaV1Alpha2    = "kaiba.provisioning.rpi5-stable-verifier-campaign-execution-set/v1alpha2"

	// MaximumUARTCaptureBytes bounds diagnostic noise surrounding the indexed
	// records. Auxiliary evidence is a canonical public record or record bundle
	// rather than an unbounded device image or log archive.
	MaximumUARTCaptureBytes       = 4 * 1024 * 1024
	MaximumAuxiliaryEvidenceBytes = 1024 * 1024

	executionResultDigestDomain = "kaiba.provisioning.rpi5-stable-verifier-campaign-execution-result.v1alpha2"
	executionSetDigestDomain    = "kaiba.provisioning.rpi5-stable-verifier-campaign-execution-set.v1alpha2"
	rawBindingDigestDomain      = "kaiba.provisioning.rpi5-stable-verifier-campaign-raw-binding.v1alpha2"
	recordBindingDigestDomain   = "kaiba.provisioning.rpi5-stable-verifier-campaign-record-binding.v1alpha2"
)

var captureIDPattern = regexp.MustCompile(`^capture:[0-9a-f]{64}$`)

// CaptureID is a caller-generated 256-bit random nonce represented as exactly
// 64 lowercase hexadecimal digits after the fixed "capture:" prefix. It is
// context-bound into the result and every raw and record binding. It is not a
// trusted timestamp or proof that the underlying device observation is fresh.
type CaptureID string

// Validate rejects IDs that do not carry the full canonical 256-bit nonce
// representation. Generating the nonce from a cryptographically secure random
// source remains the caller's responsibility.
func (captureID CaptureID) Validate() error {
	if !captureIDPattern.MatchString(string(captureID)) {
		return errors.New("capture_id must be capture: followed by exactly 64 lowercase hexadecimal digits")
	}
	return nil
}

// RawRole is a fixed filename-independent evidence role. Host paths, device
// paths, private material, and action authorization have no representation in
// the execution contracts.
type RawRole string

const (
	RawRoleMediaReadback    RawRole = "media-readback"
	RawRoleUARTCapture      RawRole = "uart-capture"
	RawRoleAuthorityAudit   RawRole = "authority-audit"
	RawRolePowerObservation RawRole = "power-observation"
)

// RecordKind chooses the strict parser for an indexed evidence range.
// ValidateRawEvidence deliberately parses only verifier events and reports the
// other kinds as mechanically bound but unparsed; CheckEvidenceConsistency
// applies their strict campaign-specific parsers and cross-record consistency
// checks.
type RecordKind string

const (
	RecordKindMediaReadback    RecordKind = "media-readback"
	RecordKindVerifierEvent    RecordKind = "verifier-event"
	RecordKindReleasedOSEvent  RecordKind = "released-os-event"
	RecordKindAuthorityAudit   RecordKind = "authority-audit"
	RecordKindPowerObservation RecordKind = "power-observation"
)

// RawBinding commits to one complete raw public-evidence file by digest and
// size. RawBindingDigest also binds those fields to the campaign, run, and
// capture context. The role maps to a fixed external filename; no path is
// serialized.
type RawBinding struct {
	CaptureID        CaptureID     `json:"capture_id"`
	Role             RawRole       `json:"role"`
	Digest           bundle.Digest `json:"digest"`
	SizeBytes        uint64        `json:"size_bytes"`
	RawBindingDigest bundle.Digest `json:"raw_binding_digest"`
}

// RecordRef binds one strict record to an exact byte range in a RawBinding.
// RawRangeDigest is the ordinary SHA-256 of those exact raw bytes.
// RecordDigest is the record contract's domain-separated digest, and
// RecordBindingDigest binds both to the campaign, run, capture, and raw file.
type RecordRef struct {
	CaptureID           CaptureID     `json:"capture_id"`
	Kind                RecordKind    `json:"kind"`
	RawRole             RawRole       `json:"raw_role"`
	OffsetBytes         uint64        `json:"offset_bytes"`
	SizeBytes           uint64        `json:"size_bytes"`
	RawRangeDigest      bundle.Digest `json:"raw_range_digest"`
	RecordDigest        bundle.Digest `json:"record_digest"`
	RecordBindingDigest bundle.Digest `json:"record_binding_digest"`
}

// ExecutionResult is the digest-sealed public evidence envelope for one
// physical run. Its identity, planned claims, mutation recipe, required raw
// roles, and required record layout must exactly match ExpectedRuns. Planned
// claims describe campaign intent only. A pass, observed outcome, disposition,
// or validated-claim result is intentionally absent.
type ExecutionResult struct {
	SchemaVersion string         `json:"schema_version"`
	CampaignID    string         `json:"campaign_id"`
	PlanDigest    bundle.Digest  `json:"plan_digest"`
	RunIndex      uint16         `json:"run_index"`
	RunID         string         `json:"run_id"`
	CaptureID     CaptureID      `json:"capture_id"`
	PlannedClaims []PlannedClaim `json:"planned_claims"`
	RecipeID      string         `json:"recipe_id,omitempty"`
	RawFiles      []RawBinding   `json:"raw_files"`
	RecordRefs    []RecordRef    `json:"record_refs"`
	ResultDigest  bundle.Digest  `json:"result_digest"`
}

// ExecutionSet is the complete canonical 33-run campaign envelope. Results
// are embedded so their sealed identity and evidence bindings cannot be
// detached from the aggregate.
type ExecutionSet struct {
	SchemaVersion      string            `json:"schema_version"`
	CampaignID         string            `json:"campaign_id"`
	PlanDigest         bundle.Digest     `json:"plan_digest"`
	Results            []ExecutionResult `json:"results"`
	ExecutionSetDigest bundle.Digest     `json:"execution_set_digest"`
}

// NewExecutionResult derives all semantic fields from runIndex and seals the
// supplied public raw-evidence bindings. captureID must be generated by the
// caller from a cryptographically secure random source. Inputs are not sorted;
// callers must present the exact canonical layout advertised by ExpectedRuns.
func NewExecutionResult(
	plan Plan,
	runIndex uint16,
	captureID CaptureID,
	rawFiles []RawBinding,
	recordRefs []RecordRef,
) (ExecutionResult, error) {
	runs, err := ExpectedRuns(plan)
	if err != nil {
		return ExecutionResult{}, err
	}
	if runIndex == 0 || int(runIndex) > len(runs) {
		return ExecutionResult{}, fmt.Errorf("run_index must be between 1 and %d", len(runs))
	}
	if err := captureID.Validate(); err != nil {
		return ExecutionResult{}, err
	}
	spec := runs[runIndex-1]
	result := ExecutionResult{
		SchemaVersion: ExecutionResultSchemaV1Alpha2,
		CampaignID:    plan.CampaignID,
		PlanDigest:    plan.PlanDigest,
		RunIndex:      spec.Index,
		RunID:         spec.RunID,
		CaptureID:     captureID,
		PlannedClaims: append([]PlannedClaim(nil), spec.PlannedClaims...),
		RecipeID:      spec.MutationRecipeID,
		RawFiles:      append([]RawBinding(nil), rawFiles...),
		RecordRefs:    append([]RecordRef(nil), recordRefs...),
	}
	context := newEvidenceBindingContext(plan, spec, captureID)
	for index := range result.RawFiles {
		if result.RawFiles[index].CaptureID != "" || result.RawFiles[index].RawBindingDigest != "" {
			return ExecutionResult{}, fmt.Errorf(
				"raw_files[%d] must be an unbound constructor input",
				index,
			)
		}
		result.RawFiles[index].CaptureID = captureID
		digest, err := deriveRawBindingDigest(context, result.RawFiles[index])
		if err != nil {
			return ExecutionResult{}, err
		}
		result.RawFiles[index].RawBindingDigest = digest
	}
	for index := range result.RecordRefs {
		if result.RecordRefs[index].CaptureID != "" || result.RecordRefs[index].RecordBindingDigest != "" {
			return ExecutionResult{}, fmt.Errorf(
				"record_refs[%d] must be an unbound constructor input",
				index,
			)
		}
		result.RecordRefs[index].CaptureID = captureID
		raw, ok := rawBindingByRole(result.RawFiles, result.RecordRefs[index].RawRole)
		if !ok {
			return ExecutionResult{}, fmt.Errorf("record_refs[%d] refers to an absent raw role", index)
		}
		digest, err := deriveRecordBindingDigest(context, result.RecordRefs[index], raw.RawBindingDigest)
		if err != nil {
			return ExecutionResult{}, err
		}
		result.RecordRefs[index].RecordBindingDigest = digest
	}
	return result.Seal(plan)
}

// ValidateAgainst validates a sealed result against its independently
// supplied campaign plan.
func (result ExecutionResult) ValidateAgainst(plan Plan) error {
	return result.validateAgainst(plan, true)
}

func (result ExecutionResult) validateAgainst(plan Plan, requireDigest bool) error {
	runs, err := ExpectedRuns(plan)
	if err != nil {
		return err
	}
	if result.SchemaVersion != ExecutionResultSchemaV1Alpha2 {
		return fmt.Errorf("unsupported execution result schema_version %q", result.SchemaVersion)
	}
	if result.CampaignID != plan.CampaignID || result.PlanDigest != plan.PlanDigest {
		return errors.New("execution result campaign_id or plan_digest differs from the campaign plan")
	}
	if result.RunIndex == 0 || int(result.RunIndex) > len(runs) {
		return fmt.Errorf("execution result run_index must be between 1 and %d", len(runs))
	}
	spec := runs[result.RunIndex-1]
	if result.RunID != spec.RunID {
		return fmt.Errorf("execution result run_id must be %q", spec.RunID)
	}
	if err := result.CaptureID.Validate(); err != nil {
		return err
	}
	if err := validatePlannedClaims(result.PlannedClaims, spec.PlannedClaims); err != nil {
		return err
	}
	if result.RecipeID != spec.MutationRecipeID {
		return fmt.Errorf("execution result recipe_id must be %q", spec.MutationRecipeID)
	}
	context := newEvidenceBindingContext(plan, spec, result.CaptureID)
	if err := validateRawFiles(result.RawFiles, spec.RequiredRawRoles, context); err != nil {
		return err
	}
	if err := validateRecordRefs(result.RecordRefs, result.RawFiles, spec.RequiredRecordKinds, context); err != nil {
		return err
	}
	if requireDigest {
		if err := result.ResultDigest.Validate(); err != nil {
			return fmt.Errorf("result_digest: %w", err)
		}
		derived, err := result.DerivedDigest(plan)
		if err != nil {
			return err
		}
		if result.ResultDigest != derived {
			return errors.New("result_digest does not bind the canonical execution result")
		}
	}
	return nil
}

func validatePlannedClaims(actual, expected []PlannedClaim) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("execution result planned_claims must contain the exact %d plan-derived entries", len(expected))
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return fmt.Errorf("execution result planned claim %d must be %#v", index, expected[index])
		}
	}
	return nil
}

type evidenceBindingContext struct {
	CampaignID string        `json:"campaign_id"`
	PlanDigest bundle.Digest `json:"plan_digest"`
	RunIndex   uint16        `json:"run_index"`
	RunID      string        `json:"run_id"`
	CaptureID  CaptureID     `json:"capture_id"`
}

func newEvidenceBindingContext(plan Plan, spec RunSpec, captureID CaptureID) evidenceBindingContext {
	return evidenceBindingContext{
		CampaignID: plan.CampaignID,
		PlanDigest: plan.PlanDigest,
		RunIndex:   spec.Index,
		RunID:      spec.RunID,
		CaptureID:  captureID,
	}
}

type rawBindingDigestMaterial struct {
	Context   evidenceBindingContext `json:"context"`
	CaptureID CaptureID              `json:"capture_id"`
	Role      RawRole                `json:"role"`
	Digest    bundle.Digest          `json:"digest"`
	SizeBytes uint64                 `json:"size_bytes"`
}

func deriveRawBindingDigest(context evidenceBindingContext, binding RawBinding) (bundle.Digest, error) {
	material := rawBindingDigestMaterial{
		Context:   context,
		CaptureID: binding.CaptureID,
		Role:      binding.Role,
		Digest:    binding.Digest,
		SizeBytes: binding.SizeBytes,
	}
	return digestExecutionContract(rawBindingDigestDomain, material, "raw binding")
}

type recordBindingDigestMaterial struct {
	Context          evidenceBindingContext `json:"context"`
	CaptureID        CaptureID              `json:"capture_id"`
	Kind             RecordKind             `json:"kind"`
	RawRole          RawRole                `json:"raw_role"`
	RawBindingDigest bundle.Digest          `json:"raw_binding_digest"`
	OffsetBytes      uint64                 `json:"offset_bytes"`
	SizeBytes        uint64                 `json:"size_bytes"`
	RawRangeDigest   bundle.Digest          `json:"raw_range_digest"`
	RecordDigest     bundle.Digest          `json:"record_digest"`
}

func deriveRecordBindingDigest(
	context evidenceBindingContext,
	reference RecordRef,
	rawBindingDigest bundle.Digest,
) (bundle.Digest, error) {
	material := recordBindingDigestMaterial{
		Context:          context,
		CaptureID:        reference.CaptureID,
		Kind:             reference.Kind,
		RawRole:          reference.RawRole,
		RawBindingDigest: rawBindingDigest,
		OffsetBytes:      reference.OffsetBytes,
		SizeBytes:        reference.SizeBytes,
		RawRangeDigest:   reference.RawRangeDigest,
		RecordDigest:     reference.RecordDigest,
	}
	return digestExecutionContract(recordBindingDigestDomain, material, "record binding")
}

func validateRawFiles(actual []RawBinding, expected []RawRole, context evidenceBindingContext) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("raw_files must contain the exact %d required roles", len(expected))
	}
	seenDigests := make(map[bundle.Digest]RawRole, len(actual))
	for index, expectedRole := range expected {
		binding := actual[index]
		if binding.CaptureID != context.CaptureID {
			return fmt.Errorf("raw_files[%d].capture_id must match the execution result", index)
		}
		if binding.Role != expectedRole {
			return fmt.Errorf("raw_files[%d].role must be %q", index, expectedRole)
		}
		if err := binding.Digest.Validate(); err != nil {
			return fmt.Errorf("raw_files[%d].digest: %w", index, err)
		}
		if previousRole, duplicate := seenDigests[binding.Digest]; duplicate {
			return fmt.Errorf("raw_files[%d] duplicates the digest bound to role %q", index, previousRole)
		}
		seenDigests[binding.Digest] = binding.Role
		maximum, ok := maximumRawBytes(binding.Role)
		if !ok {
			return fmt.Errorf("raw_files[%d].role is unsupported", index)
		}
		if binding.SizeBytes == 0 || binding.SizeBytes > maximum {
			return fmt.Errorf("raw_files[%d].size_bytes must be between 1 and %d", index, maximum)
		}
		if err := binding.RawBindingDigest.Validate(); err != nil {
			return fmt.Errorf("raw_files[%d].raw_binding_digest: %w", index, err)
		}
		derived, err := deriveRawBindingDigest(context, binding)
		if err != nil {
			return fmt.Errorf("raw_files[%d]: %w", index, err)
		}
		if binding.RawBindingDigest != derived {
			return fmt.Errorf("raw_files[%d].raw_binding_digest does not bind its campaign, run, capture, and content metadata", index)
		}
	}
	return nil
}

func validateRecordRefs(
	actual []RecordRef,
	rawFiles []RawBinding,
	expected []RecordKind,
	context evidenceBindingContext,
) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("record_refs must contain the exact %d derived records", len(expected))
	}
	rawByRole := make(map[RawRole]RawBinding, len(rawFiles))
	for _, raw := range rawFiles {
		rawByRole[raw.Role] = raw
	}
	lastEnd := make(map[RawRole]uint64, len(rawFiles))
	seen := make(map[RawRole]bool, len(rawFiles))
	seenDigests := make(map[bundle.Digest]int, len(actual))
	for index, expectedKind := range expected {
		reference := actual[index]
		if reference.CaptureID != context.CaptureID {
			return fmt.Errorf("record_refs[%d].capture_id must match the execution result", index)
		}
		if reference.Kind != expectedKind {
			return fmt.Errorf("record_refs[%d].kind must be %q", index, expectedKind)
		}
		expectedRole, ok := rawRoleForRecordKind(reference.Kind)
		if !ok || reference.RawRole != expectedRole {
			return fmt.Errorf("record_refs[%d] has an invalid kind-to-raw-role binding", index)
		}
		raw, exists := rawByRole[reference.RawRole]
		if !exists {
			return fmt.Errorf("record_refs[%d] refers to an absent raw role", index)
		}
		if err := reference.RecordDigest.Validate(); err != nil {
			return fmt.Errorf("record_refs[%d].record_digest: %w", index, err)
		}
		if err := reference.RawRangeDigest.Validate(); err != nil {
			return fmt.Errorf("record_refs[%d].raw_range_digest: %w", index, err)
		}
		if previousIndex, duplicate := seenDigests[reference.RecordDigest]; duplicate {
			return fmt.Errorf("record_refs[%d] duplicates record_refs[%d].record_digest", index, previousIndex)
		}
		seenDigests[reference.RecordDigest] = index
		maximum := maximumRecordBytes(reference.Kind)
		if reference.SizeBytes == 0 || reference.SizeBytes > maximum {
			return fmt.Errorf("record_refs[%d].size_bytes must be between 1 and %d", index, maximum)
		}
		if reference.OffsetBytes > raw.SizeBytes || reference.SizeBytes > raw.SizeBytes-reference.OffsetBytes {
			return fmt.Errorf("record_refs[%d] lies outside its raw evidence binding", index)
		}
		if seen[reference.RawRole] && reference.OffsetBytes < lastEnd[reference.RawRole] {
			return fmt.Errorf("record_refs[%d] overlaps or precedes a record in the same raw evidence", index)
		}
		lastEnd[reference.RawRole] = reference.OffsetBytes + reference.SizeBytes
		seen[reference.RawRole] = true
		if reference.RawRole != RawRoleUARTCapture &&
			(reference.OffsetBytes != 0 || reference.SizeBytes != raw.SizeBytes) {
			return fmt.Errorf("record_refs[%d] must cover its complete auxiliary raw evidence", index)
		}
		if err := reference.RecordBindingDigest.Validate(); err != nil {
			return fmt.Errorf("record_refs[%d].record_binding_digest: %w", index, err)
		}
		derived, err := deriveRecordBindingDigest(context, reference, raw.RawBindingDigest)
		if err != nil {
			return fmt.Errorf("record_refs[%d]: %w", index, err)
		}
		if reference.RecordBindingDigest != derived {
			return fmt.Errorf("record_refs[%d].record_binding_digest does not bind its campaign, run, capture, raw file, and byte range", index)
		}
	}
	return nil
}

func rawBindingByRole(bindings []RawBinding, role RawRole) (RawBinding, bool) {
	for _, binding := range bindings {
		if binding.Role == role {
			return binding, true
		}
	}
	return RawBinding{}, false
}

func maximumRawBytes(role RawRole) (uint64, bool) {
	switch role {
	case RawRoleUARTCapture:
		return MaximumUARTCaptureBytes, true
	case RawRoleMediaReadback, RawRoleAuthorityAudit, RawRolePowerObservation:
		return MaximumAuxiliaryEvidenceBytes, true
	default:
		return 0, false
	}
}

func maximumRecordBytes(kind RecordKind) uint64 {
	switch kind {
	case RecordKindVerifierEvent:
		return verifierevents.MaxRecordBytes + 1
	case RecordKindReleasedOSEvent:
		return verifierevents.MaxRecordBytes
	default:
		return MaximumAuxiliaryEvidenceBytes
	}
}

func rawRoleForRecordKind(kind RecordKind) (RawRole, bool) {
	switch kind {
	case RecordKindMediaReadback:
		return RawRoleMediaReadback, true
	case RecordKindVerifierEvent, RecordKindReleasedOSEvent:
		return RawRoleUARTCapture, true
	case RecordKindAuthorityAudit:
		return RawRoleAuthorityAudit, true
	case RecordKindPowerObservation:
		return RawRolePowerObservation, true
	default:
		return "", false
	}
}

// DerivedDigest returns the domain-separated digest of the result with its
// result_digest field empty.
func (result ExecutionResult) DerivedDigest(plan Plan) (bundle.Digest, error) {
	material := result
	material.ResultDigest = ""
	if err := material.validateAgainst(plan, false); err != nil {
		return "", err
	}
	return digestExecutionContract(executionResultDigestDomain, material, "execution result")
}

// Seal returns a copy with its derived ResultDigest populated.
func (result ExecutionResult) Seal(plan Plan) (ExecutionResult, error) {
	result.ResultDigest = ""
	digest, err := result.DerivedDigest(plan)
	if err != nil {
		return ExecutionResult{}, err
	}
	result.ResultDigest = digest
	if err := result.ValidateAgainst(plan); err != nil {
		return ExecutionResult{}, err
	}
	return result, nil
}

// CanonicalJSON returns the unique whitespace-free result encoding.
func (result ExecutionResult) CanonicalJSON(plan Plan) ([]byte, error) {
	if err := result.ValidateAgainst(plan); err != nil {
		return nil, err
	}
	return marshalWithinLimit("campaign execution result", result)
}

// ParseExecutionResult accepts strict canonical JSON, optionally followed by
// one LF, and validates it against plan.
func ParseExecutionResult(encoded []byte, plan Plan) (ExecutionResult, error) {
	var result ExecutionResult
	if err := strictCanonicalDecode(encoded, &result, func() ([]byte, error) {
		return result.CanonicalJSON(plan)
	}); err != nil {
		return ExecutionResult{}, fmt.Errorf("parse campaign execution result: %w", err)
	}
	return result, nil
}

// NewExecutionSet seals the exact canonical collection of all expected runs.
// Results are not sorted or repaired.
func NewExecutionSet(plan Plan, results []ExecutionResult) (ExecutionSet, error) {
	set := ExecutionSet{
		SchemaVersion: ExecutionSetSchemaV1Alpha2,
		CampaignID:    plan.CampaignID,
		PlanDigest:    plan.PlanDigest,
		Results:       cloneExecutionResults(results),
	}
	return set.Seal(plan)
}

// ValidateAgainst validates a sealed complete execution set against plan.
func (set ExecutionSet) ValidateAgainst(plan Plan) error {
	return set.validateAgainst(plan, true)
}

func (set ExecutionSet) validateAgainst(plan Plan, requireDigest bool) error {
	runs, err := ExpectedRuns(plan)
	if err != nil {
		return err
	}
	if set.SchemaVersion != ExecutionSetSchemaV1Alpha2 {
		return fmt.Errorf("unsupported execution set schema_version %q", set.SchemaVersion)
	}
	if set.CampaignID != plan.CampaignID || set.PlanDigest != plan.PlanDigest {
		return errors.New("execution set campaign_id or plan_digest differs from the campaign plan")
	}
	if len(set.Results) != len(runs) {
		return fmt.Errorf("execution set must contain the exact %d campaign results", len(runs))
	}
	seenDigests := make(map[bundle.Digest]struct{}, len(set.Results))
	seenCaptureIDs := make(map[CaptureID]int, len(set.Results))
	for index, result := range set.Results {
		if result.RunIndex != runs[index].Index || result.RunID != runs[index].RunID {
			return fmt.Errorf("execution set result %d is not the expected canonical run", index)
		}
		if err := result.ValidateAgainst(plan); err != nil {
			return fmt.Errorf("execution set result %d: %w", index, err)
		}
		if _, duplicate := seenDigests[result.ResultDigest]; duplicate {
			return fmt.Errorf("execution set result %d duplicates a result_digest", index)
		}
		seenDigests[result.ResultDigest] = struct{}{}
		if previousIndex, duplicate := seenCaptureIDs[result.CaptureID]; duplicate {
			return fmt.Errorf(
				"execution set result %d duplicates result %d capture_id",
				index,
				previousIndex,
			)
		}
		seenCaptureIDs[result.CaptureID] = index
	}
	if requireDigest {
		if err := set.ExecutionSetDigest.Validate(); err != nil {
			return fmt.Errorf("execution_set_digest: %w", err)
		}
		derived, err := set.DerivedDigest(plan)
		if err != nil {
			return err
		}
		if set.ExecutionSetDigest != derived {
			return errors.New("execution_set_digest does not bind the canonical execution set")
		}
	}
	return nil
}

// DerivedDigest returns the domain-separated digest of the set with its
// execution_set_digest field empty.
func (set ExecutionSet) DerivedDigest(plan Plan) (bundle.Digest, error) {
	material := set
	material.ExecutionSetDigest = ""
	if err := material.validateAgainst(plan, false); err != nil {
		return "", err
	}
	return digestExecutionContract(executionSetDigestDomain, material, "execution set")
}

// Seal returns a copy with its derived ExecutionSetDigest populated.
func (set ExecutionSet) Seal(plan Plan) (ExecutionSet, error) {
	set.ExecutionSetDigest = ""
	digest, err := set.DerivedDigest(plan)
	if err != nil {
		return ExecutionSet{}, err
	}
	set.ExecutionSetDigest = digest
	if err := set.ValidateAgainst(plan); err != nil {
		return ExecutionSet{}, err
	}
	return set, nil
}

// CanonicalJSON returns the unique whitespace-free execution-set encoding.
func (set ExecutionSet) CanonicalJSON(plan Plan) ([]byte, error) {
	if err := set.ValidateAgainst(plan); err != nil {
		return nil, err
	}
	return marshalWithinLimit("campaign execution set", set)
}

// ParseExecutionSet accepts strict canonical JSON, optionally followed by one
// LF, and validates all embedded results against plan.
func ParseExecutionSet(encoded []byte, plan Plan) (ExecutionSet, error) {
	var set ExecutionSet
	if err := strictCanonicalDecode(encoded, &set, func() ([]byte, error) {
		return set.CanonicalJSON(plan)
	}); err != nil {
		return ExecutionSet{}, fmt.Errorf("parse campaign execution set: %w", err)
	}
	return set, nil
}

func digestExecutionContract(domain string, value any, label string) (bundle.Digest, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode campaign %s digest material: %w", label, err)
	}
	if len(encoded) > maximumContractBytes {
		return "", fmt.Errorf("campaign %s exceeds %d bytes", label, maximumContractBytes)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain + "\x00"))
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

func cloneExecutionResults(results []ExecutionResult) []ExecutionResult {
	cloned := make([]ExecutionResult, len(results))
	for index, result := range results {
		cloned[index] = result
		cloned[index].PlannedClaims = append([]PlannedClaim(nil), result.PlannedClaims...)
		cloned[index].RawFiles = append([]RawBinding(nil), result.RawFiles...)
		cloned[index].RecordRefs = append([]RecordRef(nil), result.RecordRefs...)
	}
	return cloned
}
