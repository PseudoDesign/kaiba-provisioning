package campaignmedia

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	RecoveryBackupRequirementsSchemaV1Alpha2 = "kaiba.provisioning.rpi5-stable-verifier-recovery-backup-requirements/v1alpha2"

	// RecoveryScopeCrossBoundInitialLineages retains both selected and distinct
	// physical-end GPT lineages, when present, and every planned payload range.
	RecoveryScopeCrossBoundInitialLineages = "cross-bound-initial-gpt-lineages-and-planned-payload-recovery-ranges"

	recoveryBackupRequirementsDigestDomainV1Alpha2 = "kaiba.provisioning.rpi5-stable-verifier-recovery-backup-requirements.v1alpha2"
)

// RecoveryBackupDeviceRequirementsV1Alpha2 carries the complete initial
// envelope so both GPT lineages and every version-separated range binding are
// validated together. Its fixed selector remains descriptive configuration;
// the record has no open device, output path, or I/O capability.
type RecoveryBackupDeviceRequirementsV1Alpha2 struct {
	Leg                        Leg                                `json:"leg"`
	StagingDeviceDigest        bundle.Digest                      `json:"staging_device_digest"`
	InitialGPTRecoveryEnvelope InitialGPTRecoveryEnvelopeV1Alpha2 `json:"initial_gpt_recovery_envelope"`
}

// RecoveryBackupRequirementsV1Alpha2 binds a staging plan to its two complete
// v1alpha2 initial-GPT envelopes. All backup, approval, and write claims remain
// false: this contract describes what must be preserved, not completed work.
type RecoveryBackupRequirementsV1Alpha2 struct {
	SchemaVersion              string                                     `json:"schema_version"`
	Campaign                   CampaignBinding                            `json:"campaign"`
	StagingPlanDigest          bundle.Digest                              `json:"staging_plan_digest"`
	Devices                    []RecoveryBackupDeviceRequirementsV1Alpha2 `json:"devices"`
	RecoveryScope              string                                     `json:"recovery_scope"`
	OutstandingRequirements    []RecoveryBackupOutstandingRequirement     `json:"outstanding_requirements"`
	BackupCapturePerformed     bool                                       `json:"backup_capture_performed"`
	BackupReadbackVerified     bool                                       `json:"backup_readback_verified"`
	OperatorApprovalBound      bool                                       `json:"operator_approval_bound"`
	BlockDeviceWritesPermitted bool                                       `json:"block_device_writes_permitted"`
	DestructiveStagingReady    bool                                       `json:"destructive_staging_ready"`
	RecoveryRequirementsDigest bundle.Digest                              `json:"recovery_requirements_digest"`
}

// NewRecoveryBackupRequirementsV1Alpha2 cross-binds exactly the SD and NVMe
// envelopes, in staging-plan order. It owns copies of all nested input slices.
func NewRecoveryBackupRequirementsV1Alpha2(plan StagingPlan, envelopes []InitialGPTRecoveryEnvelopeV1Alpha2) (RecoveryBackupRequirementsV1Alpha2, error) {
	if err := plan.Validate(); err != nil {
		return RecoveryBackupRequirementsV1Alpha2{}, fmt.Errorf("recovery backup requirements v1alpha2 staging plan: %w", err)
	}
	if len(envelopes) != len(plan.Devices) {
		return RecoveryBackupRequirementsV1Alpha2{}, errors.New("recovery backup requirements v1alpha2 require exactly malak SD followed by Pi-local NVMe envelopes")
	}
	devices := make([]RecoveryBackupDeviceRequirementsV1Alpha2, len(plan.Devices))
	for index, device := range plan.Devices {
		envelope := envelopes[index]
		if err := envelope.Validate(); err != nil {
			return RecoveryBackupRequirementsV1Alpha2{}, fmt.Errorf("recovery backup requirements v1alpha2 envelope %d: %w", index+1, err)
		}
		if envelope.Identity != device.Identity {
			return RecoveryBackupRequirementsV1Alpha2{}, fmt.Errorf("recovery backup requirements v1alpha2 envelope %d identity differs from staging-plan leg %q", index+1, device.Identity.Leg)
		}
		planned, err := PlannedPayloadRangesFromDevicePlan(device)
		if err != nil {
			return RecoveryBackupRequirementsV1Alpha2{}, err
		}
		if !equalPlannedPayloadRanges(envelope.PlannedPayloadRanges, planned) {
			return RecoveryBackupRequirementsV1Alpha2{}, fmt.Errorf("recovery backup requirements v1alpha2 envelope %d payload ranges differ from staging-plan leg %q", index+1, device.Identity.Leg)
		}
		deviceDigest, err := device.DerivedDigest()
		if err != nil {
			return RecoveryBackupRequirementsV1Alpha2{}, err
		}
		devices[index] = RecoveryBackupDeviceRequirementsV1Alpha2{
			Leg: device.Identity.Leg, StagingDeviceDigest: deviceDigest,
			InitialGPTRecoveryEnvelope: copyInitialGPTRecoveryEnvelopeV1Alpha2(envelope),
		}
	}
	return (RecoveryBackupRequirementsV1Alpha2{
		SchemaVersion: RecoveryBackupRequirementsSchemaV1Alpha2,
		Campaign:      plan.Campaign, StagingPlanDigest: plan.PlanDigest,
		Devices: devices, RecoveryScope: RecoveryScopeCrossBoundInitialLineages,
		OutstandingRequirements: append([]RecoveryBackupOutstandingRequirement(nil), fixedRecoveryBackupOutstandingRequirements...),
	}).Seal()
}

func copyInitialGPTRecoveryEnvelopeV1Alpha2(source InitialGPTRecoveryEnvelopeV1Alpha2) InitialGPTRecoveryEnvelopeV1Alpha2 {
	result := source
	result.SelectedLineage.Partitions = append([]InitialGPTPartition(nil), source.SelectedLineage.Partitions...)
	if source.PhysicalEndBackupLineage != nil {
		lineage := *source.PhysicalEndBackupLineage
		lineage.Partitions = append([]InitialGPTPartition(nil), source.PhysicalEndBackupLineage.Partitions...)
		result.PhysicalEndBackupLineage = &lineage
	}
	result.PlannedPayloadRanges = append([]PlannedPayloadRange(nil), source.PlannedPayloadRanges...)
	result.RecoveryRanges = make([]InitialRecoveryRangeV1Alpha2, len(source.RecoveryRanges))
	for index, recoveryRange := range source.RecoveryRanges {
		result.RecoveryRanges[index] = recoveryRange
		result.RecoveryRanges[index].Purposes = append([]InitialRecoveryRangePurpose(nil), recoveryRange.Purposes...)
	}
	return result
}

// DerivedDigest uses the v1alpha2 domain and the complete catalog with its
// recovery_requirements_digest empty, including both nested sealed envelopes.
func (requirements RecoveryBackupRequirementsV1Alpha2) DerivedDigest() (bundle.Digest, error) {
	material := requirements
	material.RecoveryRequirementsDigest = ""
	if err := material.validate(false); err != nil {
		return "", err
	}
	return digestJSON(recoveryBackupRequirementsDigestDomainV1Alpha2, material, "recovery backup requirements v1alpha2")
}

// Seal returns a validated copy with its version-separated digest populated.
func (requirements RecoveryBackupRequirementsV1Alpha2) Seal() (RecoveryBackupRequirementsV1Alpha2, error) {
	digest, err := requirements.DerivedDigest()
	if err != nil {
		return RecoveryBackupRequirementsV1Alpha2{}, err
	}
	requirements.RecoveryRequirementsDigest = digest
	if err := requirements.Validate(); err != nil {
		return RecoveryBackupRequirementsV1Alpha2{}, err
	}
	return requirements, nil
}

// Validate checks the sealed catalog and complete nested envelopes, including
// their lineages and exact range geometry. ValidateAgainst is still required
// to bind these declarations to an independently supplied staging plan and
// envelopes; neither method authenticates captures or proves physical state.
func (requirements RecoveryBackupRequirementsV1Alpha2) Validate() error {
	return requirements.validate(true)
}

func (requirements RecoveryBackupRequirementsV1Alpha2) validate(requireDigest bool) error {
	if requirements.SchemaVersion != RecoveryBackupRequirementsSchemaV1Alpha2 {
		return fmt.Errorf("unsupported recovery backup requirements v1alpha2 schema_version %q", requirements.SchemaVersion)
	}
	if err := requirements.Campaign.Validate(); err != nil {
		return err
	}
	if err := validateDigest("recovery backup requirements v1alpha2 staging_plan_digest", requirements.StagingPlanDigest); err != nil {
		return err
	}
	if len(requirements.Devices) != len(fixedIdentities) {
		return errors.New("recovery backup requirements v1alpha2 devices must contain exactly malak SD followed by Pi-local NVMe")
	}
	seenCaptures := make(map[string]struct{}, len(requirements.Devices))
	seenDevices := make(map[bundle.Digest]struct{}, len(requirements.Devices))
	seenEnvelopes := make(map[bundle.Digest]struct{}, len(requirements.Devices))
	seenIdentities := make(map[bundle.Digest]struct{}, len(requirements.Devices))
	for index, device := range requirements.Devices {
		envelope := device.InitialGPTRecoveryEnvelope
		if device.Leg != fixedIdentities[index].leg || envelope.Identity.Leg != device.Leg {
			return errors.New("recovery backup requirements v1alpha2 devices must contain exactly malak SD followed by Pi-local NVMe")
		}
		if err := validateDigest("recovery backup requirements v1alpha2 staging_device_digest", device.StagingDeviceDigest); err != nil {
			return err
		}
		if err := envelope.Validate(); err != nil {
			return fmt.Errorf("recovery backup requirements v1alpha2 leg %q: %w", device.Leg, err)
		}
		if _, duplicate := seenCaptures[envelope.CaptureID]; duplicate {
			return errors.New("recovery backup requirements v1alpha2 repeat a capture_id")
		}
		seenCaptures[envelope.CaptureID] = struct{}{}
		for _, binding := range []struct {
			name   string
			digest bundle.Digest
			seen   map[bundle.Digest]struct{}
		}{
			{"staging device", device.StagingDeviceDigest, seenDevices},
			{"initial-GPT envelope", envelope.EnvelopeDigest, seenEnvelopes},
			{"device identity", envelope.DeviceIdentityDigest, seenIdentities},
		} {
			if _, duplicate := binding.seen[binding.digest]; duplicate {
				return fmt.Errorf("recovery backup requirements v1alpha2 repeat a %s digest", binding.name)
			}
			binding.seen[binding.digest] = struct{}{}
		}
	}
	if requirements.RecoveryScope != RecoveryScopeCrossBoundInitialLineages {
		return errors.New("recovery backup requirements v1alpha2 has an unsupported recovery scope")
	}
	if !equalOutstandingRecoveryRequirements(requirements.OutstandingRequirements, fixedRecoveryBackupOutstandingRequirements) {
		return errors.New("recovery backup requirements v1alpha2 must retain every fixed unsatisfied prerequisite in canonical order")
	}
	if requirements.BackupCapturePerformed || requirements.BackupReadbackVerified || requirements.OperatorApprovalBound ||
		requirements.BlockDeviceWritesPermitted || requirements.DestructiveStagingReady {
		return errors.New("recovery backup requirements v1alpha2 must remain descriptive, unsatisfied, and ineligible for block-device writes")
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
			return errors.New("recovery_requirements_digest does not bind the canonical recovery backup requirements v1alpha2")
		}
	}
	return nil
}

// ValidateAgainst requires an exact deterministic match to both independently
// supplied envelopes and the plan. A self-sealed substituted lineage, capture,
// preimage, or plan must not be treated as the original requirements.
func (requirements RecoveryBackupRequirementsV1Alpha2) ValidateAgainst(plan StagingPlan, envelopes []InitialGPTRecoveryEnvelopeV1Alpha2) error {
	if err := requirements.Validate(); err != nil {
		return err
	}
	expected, err := NewRecoveryBackupRequirementsV1Alpha2(plan, envelopes)
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
		return errors.New("recovery backup requirements v1alpha2 differ from the independently supplied staging plan or initial-GPT envelopes")
	}
	return nil
}

// ValidateForDestructiveStaging always fails: this requirements contract has
// no durable backup, readback, live-attachment, approval, or writer capability.
func (requirements RecoveryBackupRequirementsV1Alpha2) ValidateForDestructiveStaging() error {
	if err := requirements.Validate(); err != nil {
		return err
	}
	return errors.New("recovery backup requirements v1alpha2 are intentionally ineligible for destructive staging: durable backup, independent readback, fresh attachment revalidation, explicit operator approval, and a reviewed writer remain outstanding")
}

// CanonicalJSON returns the unique whitespace-free requirements encoding.
func (requirements RecoveryBackupRequirementsV1Alpha2) CanonicalJSON() ([]byte, error) {
	if err := requirements.Validate(); err != nil {
		return nil, err
	}
	return marshalWithinLimit("recovery backup requirements v1alpha2", requirements)
}

// ParseRecoveryBackupRequirementsV1Alpha2 accepts strict canonical JSON and at
// most one trailing LF. ValidateAgainst remains required for cross-binding.
func ParseRecoveryBackupRequirementsV1Alpha2(encoded []byte) (RecoveryBackupRequirementsV1Alpha2, error) {
	var requirements RecoveryBackupRequirementsV1Alpha2
	allowedNulls := map[string]struct{}{
		"$.devices[0].initial_gpt_recovery_envelope.physical_end_backup_lineage": {},
		"$.devices[1].initial_gpt_recovery_envelope.physical_end_backup_lineage": {},
	}
	if err := strictCanonicalDecodeWithNulls(encoded, &requirements, func() ([]byte, error) { return requirements.CanonicalJSON() }, allowedNulls); err != nil {
		return RecoveryBackupRequirementsV1Alpha2{}, fmt.Errorf("parse recovery backup requirements v1alpha2: %w", err)
	}
	return requirements, nil
}
