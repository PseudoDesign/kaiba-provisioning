package campaignmedia

import (
	"bytes"
	"errors"
	"fmt"
	"math"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	RecoveryBackupRequirementsSchemaV1Alpha1 = "kaiba.provisioning.rpi5-stable-verifier-recovery-backup-requirements/v1alpha1"

	// RecoveryScopeCrossBoundInitialRanges describes a requirements catalog,
	// not a backup receipt or a staging authorization. The catalog binds every
	// range discovered by both initial-GPT envelopes to the independently
	// supplied staging plan.
	RecoveryScopeCrossBoundInitialRanges = "cross-bound-initial-gpt-and-planned-payload-recovery-ranges"

	recoveryBackupRequirementsDigestDomain = "kaiba.provisioning.rpi5-stable-verifier-recovery-backup-requirements.v1alpha1"
)

// RecoveryBackupOutstandingRequirement is one closed, deliberately
// unsatisfied prerequisite. A v1alpha1 requirements catalog cannot remove or
// satisfy any item in this list.
type RecoveryBackupOutstandingRequirement string

const (
	RecoveryBackupDurableCaptureRequired RecoveryBackupOutstandingRequirement = "durable-recovery-range-file-creation-and-fsync-required"
	RecoveryBackupReadbackRequired       RecoveryBackupOutstandingRequirement = "independent-reopened-backup-byte-readback-required"
	RecoveryBackupLiveRevalidation       RecoveryBackupOutstandingRequirement = "fresh-live-attachment-revalidation-required"
	RecoveryBackupOperatorApproval       RecoveryBackupOutstandingRequirement = "explicit-operator-approval-binding-required"
	RecoveryBackupReviewedWriter         RecoveryBackupOutstandingRequirement = "separately-reviewed-capability-separated-writer-required"
)

var fixedRecoveryBackupOutstandingRequirements = []RecoveryBackupOutstandingRequirement{
	RecoveryBackupDurableCaptureRequired,
	RecoveryBackupReadbackRequired,
	RecoveryBackupLiveRevalidation,
	RecoveryBackupOperatorApproval,
	RecoveryBackupReviewedWriter,
}

// RecoveryBackupRangeRequirement identifies one exact pre-write byte range
// that a later, separately reviewed backup tool must preserve. It contains no
// path, handle, action, or I/O capability.
type RecoveryBackupRangeRequirement struct {
	Purposes                   []InitialRecoveryRangePurpose `json:"purposes"`
	OffsetBytes                uint64                        `json:"offset_bytes"`
	SizeBytes                  uint64                        `json:"size_bytes"`
	ExpectedPreimageSHA256     bundle.Digest                 `json:"expected_preimage_sha256"`
	RecoveryRangeBindingDigest bundle.Digest                 `json:"recovery_range_binding_digest"`
}

// RecoveryBackupDeviceRequirements binds one fixed staging-plan device to the
// independently captured initial-GPT envelope from which its range catalog was
// derived. The identity itself remains in the independently supplied plan and
// envelope; only its digest is repeated here.
type RecoveryBackupDeviceRequirements struct {
	Leg                              Leg                              `json:"leg"`
	StagingDeviceDigest              bundle.Digest                    `json:"staging_device_digest"`
	CaptureID                        string                           `json:"capture_id"`
	InitialGPTRecoveryEnvelopeDigest bundle.Digest                    `json:"initial_gpt_recovery_envelope_digest"`
	DeviceIdentityDigest             bundle.Digest                    `json:"device_identity_digest"`
	Ranges                           []RecoveryBackupRangeRequirement `json:"ranges"`
}

// RecoveryBackupRequirements is a sealed, path-free catalog of the exact
// initial bytes which would need durable backup before staging. It is not a
// backup receipt, a readback receipt, an operator approval, or live attachment
// evidence. Every capability/readiness field is fixed false in v1alpha1.
type RecoveryBackupRequirements struct {
	SchemaVersion              string                                 `json:"schema_version"`
	Campaign                   CampaignBinding                        `json:"campaign"`
	StagingPlanDigest          bundle.Digest                          `json:"staging_plan_digest"`
	Devices                    []RecoveryBackupDeviceRequirements     `json:"devices"`
	RecoveryScope              string                                 `json:"recovery_scope"`
	OutstandingRequirements    []RecoveryBackupOutstandingRequirement `json:"outstanding_requirements"`
	BackupCapturePerformed     bool                                   `json:"backup_capture_performed"`
	BackupReadbackVerified     bool                                   `json:"backup_readback_verified"`
	OperatorApprovalBound      bool                                   `json:"operator_approval_bound"`
	BlockDeviceWritesPermitted bool                                   `json:"block_device_writes_permitted"`
	DestructiveStagingReady    bool                                   `json:"destructive_staging_ready"`
	RecoveryRequirementsDigest bundle.Digest                          `json:"recovery_requirements_digest"`
}

// NewRecoveryBackupRequirements cross-binds exactly one initial-GPT recovery
// envelope for each fixed staging-plan leg and seals the resulting descriptive
// range catalog. Envelopes must be supplied in plan order.
func NewRecoveryBackupRequirements(plan StagingPlan, envelopes []InitialGPTRecoveryEnvelope) (RecoveryBackupRequirements, error) {
	if err := validateRecoveryRequirementInputs(plan, envelopes); err != nil {
		return RecoveryBackupRequirements{}, err
	}
	devices := make([]RecoveryBackupDeviceRequirements, len(plan.Devices))
	for index := range plan.Devices {
		deviceDigest, err := plan.Devices[index].DerivedDigest()
		if err != nil {
			return RecoveryBackupRequirements{}, err
		}
		envelope := envelopes[index]
		ranges := make([]RecoveryBackupRangeRequirement, len(envelope.RecoveryRanges))
		for rangeIndex, recoveryRange := range envelope.RecoveryRanges {
			ranges[rangeIndex] = RecoveryBackupRangeRequirement{
				Purposes:                   append([]InitialRecoveryRangePurpose(nil), recoveryRange.Purposes...),
				OffsetBytes:                recoveryRange.OffsetBytes,
				SizeBytes:                  recoveryRange.SizeBytes,
				ExpectedPreimageSHA256:     recoveryRange.PreimageSHA256,
				RecoveryRangeBindingDigest: recoveryRange.BindingDigest,
			}
		}
		devices[index] = RecoveryBackupDeviceRequirements{
			Leg:                              plan.Devices[index].Identity.Leg,
			StagingDeviceDigest:              deviceDigest,
			CaptureID:                        envelope.CaptureID,
			InitialGPTRecoveryEnvelopeDigest: envelope.EnvelopeDigest,
			DeviceIdentityDigest:             envelope.DeviceIdentityDigest,
			Ranges:                           ranges,
		}
	}
	requirements := RecoveryBackupRequirements{
		SchemaVersion:           RecoveryBackupRequirementsSchemaV1Alpha1,
		Campaign:                plan.Campaign,
		StagingPlanDigest:       plan.PlanDigest,
		Devices:                 devices,
		RecoveryScope:           RecoveryScopeCrossBoundInitialRanges,
		OutstandingRequirements: append([]RecoveryBackupOutstandingRequirement(nil), fixedRecoveryBackupOutstandingRequirements...),
	}
	return requirements.Seal()
}

func validateRecoveryRequirementInputs(plan StagingPlan, envelopes []InitialGPTRecoveryEnvelope) error {
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("recovery backup requirements staging plan: %w", err)
	}
	if len(envelopes) != len(plan.Devices) {
		return errors.New("recovery backup requirements require exactly malak SD followed by Pi-local NVMe initial-GPT envelopes")
	}
	seenCaptures := make(map[string]struct{}, len(envelopes))
	seenEnvelopes := make(map[bundle.Digest]struct{}, len(envelopes))
	for index := range plan.Devices {
		envelope := envelopes[index]
		if err := envelope.Validate(); err != nil {
			return fmt.Errorf("recovery backup requirements envelope %d: %w", index+1, err)
		}
		device := plan.Devices[index]
		if envelope.Identity != device.Identity || envelope.Identity.Leg != device.Identity.Leg {
			return fmt.Errorf("recovery backup requirements envelope %d identity differs from staging-plan leg %q", index+1, device.Identity.Leg)
		}
		planned, err := PlannedPayloadRangesFromDevicePlan(device)
		if err != nil {
			return err
		}
		if !equalPlannedPayloadRanges(envelope.PlannedPayloadRanges, planned) {
			return fmt.Errorf("recovery backup requirements envelope %d payload ranges differ from staging-plan leg %q", index+1, device.Identity.Leg)
		}
		if _, duplicate := seenCaptures[envelope.CaptureID]; duplicate {
			return errors.New("recovery backup requirements initial-GPT envelopes reuse one capture_id")
		}
		seenCaptures[envelope.CaptureID] = struct{}{}
		if _, duplicate := seenEnvelopes[envelope.EnvelopeDigest]; duplicate {
			return errors.New("recovery backup requirements repeat one initial-GPT envelope digest")
		}
		seenEnvelopes[envelope.EnvelopeDigest] = struct{}{}
	}
	return nil
}

func equalPlannedPayloadRanges(left, right []PlannedPayloadRange) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// DerivedDigest returns the domain-separated digest of the complete
// requirements catalog with recovery_requirements_digest empty.
func (requirements RecoveryBackupRequirements) DerivedDigest() (bundle.Digest, error) {
	material := requirements
	material.RecoveryRequirementsDigest = ""
	if err := material.validate(false); err != nil {
		return "", err
	}
	return digestJSON(recoveryBackupRequirementsDigestDomain, material, "recovery backup requirements")
}

// Seal returns a copy with its derived recovery_requirements_digest populated.
func (requirements RecoveryBackupRequirements) Seal() (RecoveryBackupRequirements, error) {
	digest, err := requirements.DerivedDigest()
	if err != nil {
		return RecoveryBackupRequirements{}, err
	}
	requirements.RecoveryRequirementsDigest = digest
	if err := requirements.Validate(); err != nil {
		return RecoveryBackupRequirements{}, err
	}
	return requirements, nil
}

// Validate checks the self-contained sealed catalog. Because the catalog does
// not repeat the complete GPT snapshots, syntactically valid range geometry is
// not physical evidence. Callers MUST use ValidateAgainst to re-establish the
// exact relationship to the independently supplied staging plan and
// initial-GPT envelopes before treating the catalog as cross-bound evidence.
func (requirements RecoveryBackupRequirements) Validate() error {
	return requirements.validate(true)
}

func (requirements RecoveryBackupRequirements) validate(requireDigest bool) error {
	if requirements.SchemaVersion != RecoveryBackupRequirementsSchemaV1Alpha1 {
		return fmt.Errorf("unsupported recovery backup requirements schema_version %q", requirements.SchemaVersion)
	}
	if err := requirements.Campaign.Validate(); err != nil {
		return err
	}
	if err := validateDigest("recovery backup requirements staging_plan_digest", requirements.StagingPlanDigest); err != nil {
		return err
	}
	if len(requirements.Devices) != len(fixedIdentities) {
		return errors.New("recovery backup requirements devices must contain exactly malak SD followed by Pi-local NVMe")
	}
	seenCaptures := make(map[string]struct{}, len(requirements.Devices))
	seenDeviceDigests := make(map[bundle.Digest]struct{}, len(requirements.Devices))
	seenEnvelopeDigests := make(map[bundle.Digest]struct{}, len(requirements.Devices))
	seenIdentityDigests := make(map[bundle.Digest]struct{}, len(requirements.Devices))
	for index, fixed := range fixedIdentities {
		device := requirements.Devices[index]
		if device.Leg != fixed.leg {
			return errors.New("recovery backup requirements devices must contain exactly malak SD followed by Pi-local NVMe")
		}
		if !initialGPTCaptureIDPattern.MatchString(device.CaptureID) {
			return fmt.Errorf("recovery backup requirements leg %q capture_id is not canonical", device.Leg)
		}
		if err := validateDigest("recovery backup requirements staging_device_digest", device.StagingDeviceDigest); err != nil {
			return err
		}
		if err := validateDigest("recovery backup requirements initial envelope digest", device.InitialGPTRecoveryEnvelopeDigest); err != nil {
			return err
		}
		if err := validateDigest("recovery backup requirements device identity digest", device.DeviceIdentityDigest); err != nil {
			return err
		}
		if _, duplicate := seenCaptures[device.CaptureID]; duplicate {
			return errors.New("recovery backup requirements devices reuse one capture_id")
		}
		seenCaptures[device.CaptureID] = struct{}{}
		if _, duplicate := seenDeviceDigests[device.StagingDeviceDigest]; duplicate {
			return errors.New("recovery backup requirements repeat a staging device digest")
		}
		seenDeviceDigests[device.StagingDeviceDigest] = struct{}{}
		if _, duplicate := seenEnvelopeDigests[device.InitialGPTRecoveryEnvelopeDigest]; duplicate {
			return errors.New("recovery backup requirements repeat an initial-GPT envelope digest")
		}
		seenEnvelopeDigests[device.InitialGPTRecoveryEnvelopeDigest] = struct{}{}
		if _, duplicate := seenIdentityDigests[device.DeviceIdentityDigest]; duplicate {
			return errors.New("recovery backup requirements repeat a device identity digest")
		}
		seenIdentityDigests[device.DeviceIdentityDigest] = struct{}{}
		if err := validateRecoveryBackupRanges(device, fixed.capacity); err != nil {
			return fmt.Errorf("recovery backup requirements leg %q: %w", device.Leg, err)
		}
	}
	if requirements.RecoveryScope != RecoveryScopeCrossBoundInitialRanges {
		return errors.New("recovery backup requirements has an unsupported recovery scope")
	}
	if !equalOutstandingRecoveryRequirements(requirements.OutstandingRequirements, fixedRecoveryBackupOutstandingRequirements) {
		return errors.New("recovery backup requirements must retain every fixed unsatisfied prerequisite in canonical order")
	}
	if requirements.BackupCapturePerformed || requirements.BackupReadbackVerified || requirements.OperatorApprovalBound ||
		requirements.BlockDeviceWritesPermitted || requirements.DestructiveStagingReady {
		return errors.New("recovery backup requirements v1alpha1 must remain descriptive, unsatisfied, and ineligible for block-device writes")
	}
	if requireDigest {
		if err := validateDigest("recovery_requirements_digest", requirements.RecoveryRequirementsDigest); err != nil {
			return err
		}
		derived, err := requirements.DerivedDigest()
		if err != nil {
			return err
		}
		if requirements.RecoveryRequirementsDigest != derived {
			return errors.New("recovery_requirements_digest does not bind the canonical recovery backup requirements")
		}
	}
	return nil
}

func validateRecoveryBackupRanges(device RecoveryBackupDeviceRequirements, capacity uint64) error {
	expectedPurposes := expectedRecoveryPurposesForLeg(device.Leg)
	seenPurposes := make(map[InitialRecoveryRangePurpose]struct{}, len(expectedPurposes))
	seenBindings := make(map[bundle.Digest]struct{}, len(device.Ranges))
	var previousEnd uint64
	for index, recoveryRange := range device.Ranges {
		if recoveryRange.SizeBytes == 0 || recoveryRange.OffsetBytes%LogicalSectorSizeBytes != 0 ||
			recoveryRange.SizeBytes%LogicalSectorSizeBytes != 0 || recoveryRange.OffsetBytes > math.MaxUint64-recoveryRange.SizeBytes ||
			recoveryRange.OffsetBytes+recoveryRange.SizeBytes > capacity {
			return fmt.Errorf("range %d is not one positive, sector-aligned, in-bounds byte range", index+1)
		}
		if index > 0 && recoveryRange.OffsetBytes < previousEnd {
			return errors.New("recovery ranges overlap or are not in canonical byte order")
		}
		previousEnd = recoveryRange.OffsetBytes + recoveryRange.SizeBytes
		if !validRecoveryPurposeGroup(device.Leg, recoveryRange.Purposes) {
			return fmt.Errorf("range %d has an unsupported purpose group", index+1)
		}
		for _, purpose := range recoveryRange.Purposes {
			if !containsRecoveryPurpose(expectedPurposes, purpose) {
				return fmt.Errorf("range %d purpose %q does not belong to leg %q", index+1, purpose, device.Leg)
			}
			if _, duplicate := seenPurposes[purpose]; duplicate {
				return fmt.Errorf("recovery purpose %q appears more than once", purpose)
			}
			seenPurposes[purpose] = struct{}{}
		}
		if err := validateDigest("recovery expected preimage sha256", recoveryRange.ExpectedPreimageSHA256); err != nil {
			return err
		}
		if err := validateDigest("recovery range binding digest", recoveryRange.RecoveryRangeBindingDigest); err != nil {
			return err
		}
		boundRange := InitialRecoveryRange{
			CaptureID:            device.CaptureID,
			DeviceIdentityDigest: device.DeviceIdentityDigest,
			Purposes:             append([]InitialRecoveryRangePurpose(nil), recoveryRange.Purposes...),
			OffsetBytes:          recoveryRange.OffsetBytes,
			SizeBytes:            recoveryRange.SizeBytes,
			PreimageSHA256:       recoveryRange.ExpectedPreimageSHA256,
		}
		derivedBinding, err := boundRange.derivedBindingDigest()
		if err != nil {
			return err
		}
		if recoveryRange.RecoveryRangeBindingDigest != derivedBinding {
			return fmt.Errorf("range %d binding digest is detached from its capture, identity, purpose, geometry, or preimage", index+1)
		}
		if _, duplicate := seenBindings[recoveryRange.RecoveryRangeBindingDigest]; duplicate {
			return errors.New("recovery range binding digest appears more than once")
		}
		seenBindings[recoveryRange.RecoveryRangeBindingDigest] = struct{}{}
	}
	if len(seenPurposes) != len(expectedPurposes) {
		return errors.New("recovery ranges do not cover every required initial GPT and planned payload purpose")
	}
	return nil
}

func expectedRecoveryPurposesForLeg(leg Leg) []InitialRecoveryRangePurpose {
	common := []InitialRecoveryRangePurpose{
		InitialRecoveryProtectiveMBR,
		InitialRecoveryPrimaryHeader,
		InitialRecoveryPrimaryEntryArray,
		InitialRecoveryExistingBackupEntries,
		InitialRecoveryExistingBackupHeader,
		InitialRecoveryFinalBackupEntries,
		InitialRecoveryFinalBackupHeader,
	}
	switch leg {
	case LegMalakSD:
		return append(common, InitialRecoveryPlannedBoot, InitialRecoveryPlannedRootData, InitialRecoveryPlannedRootHash)
	case LegPiLocalNVMe:
		return append(common, InitialRecoveryPlannedRelease)
	default:
		return nil
	}
}

func validRecoveryPurposeGroup(leg Leg, purposes []InitialRecoveryRangePurpose) bool {
	if len(purposes) == 1 {
		return true
	}
	// Only a canonical whole-device NVMe can have its existing backup GPT at
	// the same physical-end ranges as the final layout. The image-sized SD's
	// existing and final backup GPT ranges are necessarily distinct.
	if leg != LegPiLocalNVMe || len(purposes) != 2 {
		return false
	}
	return (purposes[0] == InitialRecoveryExistingBackupEntries && purposes[1] == InitialRecoveryFinalBackupEntries) ||
		(purposes[0] == InitialRecoveryExistingBackupHeader && purposes[1] == InitialRecoveryFinalBackupHeader)
}

func containsRecoveryPurpose(haystack []InitialRecoveryRangePurpose, needle InitialRecoveryRangePurpose) bool {
	for _, candidate := range haystack {
		if candidate == needle {
			return true
		}
	}
	return false
}

func equalOutstandingRecoveryRequirements(left, right []RecoveryBackupOutstandingRequirement) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// ValidateAgainst requires an exact deterministic match to the requirements
// derived from the independently supplied plan and envelopes.
func (requirements RecoveryBackupRequirements) ValidateAgainst(plan StagingPlan, envelopes []InitialGPTRecoveryEnvelope) error {
	if err := requirements.Validate(); err != nil {
		return err
	}
	expected, err := NewRecoveryBackupRequirements(plan, envelopes)
	if err != nil {
		return err
	}
	actualJSON, err := requirements.CanonicalJSON()
	if err != nil {
		return err
	}
	expectedJSON, err := expected.CanonicalJSON()
	if err != nil {
		return err
	}
	if !bytes.Equal(actualJSON, expectedJSON) {
		return errors.New("recovery backup requirements differ from the independently supplied staging plan or initial-GPT envelopes")
	}
	return nil
}

// ValidateForDestructiveStaging always fails for v1alpha1. This catalog proves
// no durable backup, independent readback, live pre-write revalidation,
// operator approval, or reviewed writer capability.
func (requirements RecoveryBackupRequirements) ValidateForDestructiveStaging() error {
	if err := requirements.Validate(); err != nil {
		return err
	}
	return errors.New("recovery backup requirements v1alpha1 are intentionally ineligible for destructive staging: durable backup, independent readback, fresh attachment revalidation, explicit operator approval, and a reviewed writer remain outstanding")
}

// CanonicalJSON returns the unique whitespace-free requirements encoding.
func (requirements RecoveryBackupRequirements) CanonicalJSON() ([]byte, error) {
	if err := requirements.Validate(); err != nil {
		return nil, err
	}
	return marshalWithinLimit("recovery backup requirements", requirements)
}

// ParseRecoveryBackupRequirements accepts only strict canonical JSON,
// optionally followed by one LF. Call ValidateAgainst to bind the parsed
// catalog back to independently supplied plan and envelope values.
func ParseRecoveryBackupRequirements(encoded []byte) (RecoveryBackupRequirements, error) {
	var requirements RecoveryBackupRequirements
	if err := strictCanonicalDecode(encoded, &requirements, func() ([]byte, error) { return requirements.CanonicalJSON() }); err != nil {
		return RecoveryBackupRequirements{}, fmt.Errorf("parse recovery backup requirements: %w", err)
	}
	return requirements, nil
}
