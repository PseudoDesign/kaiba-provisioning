package campaignmedia

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func mustTestInitialRecoveryEnvelope(t *testing.T, device DevicePlan, captureLabel string) InitialGPTRecoveryEnvelope {
	t.Helper()
	var fixture *initialGPTFixture
	switch device.Identity.Leg {
	case LegMalakSD:
		fixture = newInitialGPTFixture(t)
	case LegPiLocalNVMe:
		fixture = newInitialGPTNVMeFixture(t)
	default:
		t.Fatalf("unsupported test leg %q", device.Identity.Leg)
	}
	snapshot, _, err := captureInitialGPT(fixture.reader, device.Identity.CapacityBytes)
	if err != nil {
		t.Fatalf("captureInitialGPT(%s): %v", device.Identity.Leg, err)
	}
	planned, err := PlannedPayloadRangesFromDevicePlan(device)
	if err != nil {
		t.Fatalf("PlannedPayloadRangesFromDevicePlan(%s): %v", device.Identity.Leg, err)
	}
	specs, err := expectedInitialRecoveryRangeSpecs(device.Identity, snapshot, planned)
	if err != nil {
		t.Fatalf("expectedInitialRecoveryRangeSpecs(%s): %v", device.Identity.Leg, err)
	}
	identityDigest, err := deriveInitialGPTIdentityDigest(device.Identity)
	if err != nil {
		t.Fatal(err)
	}
	captureID := testInitialGPTCaptureID(captureLabel)
	ranges := make([]InitialRecoveryRange, len(specs))
	for index, spec := range specs {
		ranges[index] = InitialRecoveryRange{
			CaptureID:            captureID,
			DeviceIdentityDigest: identityDigest,
			Purposes:             append([]InitialRecoveryRangePurpose(nil), spec.purposes...),
			OffsetBytes:          spec.offsetBytes,
			SizeBytes:            spec.sizeBytes,
			PreimageSHA256:       testDigest(fmt.Sprintf("%s range %d preimage", device.Identity.Leg, index+1)),
		}
		ranges[index].BindingDigest, err = ranges[index].derivedBindingDigest()
		if err != nil {
			t.Fatal(err)
		}
	}
	envelope, err := (InitialGPTRecoveryEnvelope{
		SchemaVersion:        InitialGPTRecoveryEnvelopeSchemaV1Alpha1,
		CaptureID:            captureID,
		Identity:             device.Identity,
		DeviceIdentityDigest: identityDigest,
		Snapshot:             snapshot,
		PlannedPayloadRanges: planned,
		RecoveryScope:        RecoveryScopeInspectedInitialGPTAndPlannedPayloads,
		RecoveryRanges:       ranges,
	}).Seal()
	if err != nil {
		t.Fatalf("seal test initial-GPT envelope for %s: %v", device.Identity.Leg, err)
	}
	return envelope
}

func mustTestInitialRecoveryEnvelopes(t *testing.T, plan StagingPlan) []InitialGPTRecoveryEnvelope {
	t.Helper()
	return []InitialGPTRecoveryEnvelope{
		mustTestInitialRecoveryEnvelope(t, plan.Devices[0], "requirements-sd-capture"),
		mustTestInitialRecoveryEnvelope(t, plan.Devices[1], "requirements-nvme-capture"),
	}
}

func cloneInitialRecoveryEnvelope(source InitialGPTRecoveryEnvelope) InitialGPTRecoveryEnvelope {
	result := source
	result.Snapshot.Partitions = append([]InitialGPTPartition(nil), source.Snapshot.Partitions...)
	result.PlannedPayloadRanges = append([]PlannedPayloadRange(nil), source.PlannedPayloadRanges...)
	result.RecoveryRanges = make([]InitialRecoveryRange, len(source.RecoveryRanges))
	for index := range source.RecoveryRanges {
		result.RecoveryRanges[index] = source.RecoveryRanges[index]
		result.RecoveryRanges[index].Purposes = append([]InitialRecoveryRangePurpose(nil), source.RecoveryRanges[index].Purposes...)
	}
	return result
}

func mustTestRecoveryBackupRequirements(t *testing.T) (StagingPlan, []InitialGPTRecoveryEnvelope, RecoveryBackupRequirements) {
	t.Helper()
	plan := mustTestPlan(t)
	envelopes := mustTestInitialRecoveryEnvelopes(t, plan)
	requirements, err := NewRecoveryBackupRequirements(plan, envelopes)
	if err != nil {
		t.Fatalf("NewRecoveryBackupRequirements: %v", err)
	}
	return plan, envelopes, requirements
}

func cloneRecoveryBackupRequirements(source RecoveryBackupRequirements) RecoveryBackupRequirements {
	result := source
	result.OutstandingRequirements = append([]RecoveryBackupOutstandingRequirement(nil), source.OutstandingRequirements...)
	result.Devices = make([]RecoveryBackupDeviceRequirements, len(source.Devices))
	for deviceIndex := range source.Devices {
		result.Devices[deviceIndex] = source.Devices[deviceIndex]
		result.Devices[deviceIndex].Ranges = make([]RecoveryBackupRangeRequirement, len(source.Devices[deviceIndex].Ranges))
		for rangeIndex := range source.Devices[deviceIndex].Ranges {
			result.Devices[deviceIndex].Ranges[rangeIndex] = source.Devices[deviceIndex].Ranges[rangeIndex]
			result.Devices[deviceIndex].Ranges[rangeIndex].Purposes = append(
				[]InitialRecoveryRangePurpose(nil), source.Devices[deviceIndex].Ranges[rangeIndex].Purposes...,
			)
		}
	}
	return result
}

func TestRecoveryBackupRequirementsCrossBindEveryInitialRangeAndRemainHardFalse(t *testing.T) {
	plan, envelopes, requirements := mustTestRecoveryBackupRequirements(t)
	if err := requirements.ValidateAgainst(plan, envelopes); err != nil {
		t.Fatalf("ValidateAgainst: %v", err)
	}
	if requirements.BackupCapturePerformed || requirements.BackupReadbackVerified || requirements.OperatorApprovalBound ||
		requirements.BlockDeviceWritesPermitted || requirements.DestructiveStagingReady {
		t.Fatal("requirements catalog overstated backup, readback, approval, or staging state")
	}
	if !equalOutstandingRecoveryRequirements(requirements.OutstandingRequirements, fixedRecoveryBackupOutstandingRequirements) {
		t.Fatalf("outstanding requirements changed: %#v", requirements.OutstandingRequirements)
	}
	if len(requirements.Devices[0].Ranges) != 10 {
		t.Fatalf("image-sized SD range count = %d; want 10 distinct ranges", len(requirements.Devices[0].Ranges))
	}
	if len(requirements.Devices[1].Ranges) != 6 {
		t.Fatalf("canonical NVMe range count = %d; want 6 merged ranges", len(requirements.Devices[1].Ranges))
	}
	sdExistingEntries := findRecoveryRequirementRange(t, requirements.Devices[0], InitialRecoveryExistingBackupEntries)
	sdFinalEntries := findRecoveryRequirementRange(t, requirements.Devices[0], InitialRecoveryFinalBackupEntries)
	sdExistingHeader := findRecoveryRequirementRange(t, requirements.Devices[0], InitialRecoveryExistingBackupHeader)
	sdFinalHeader := findRecoveryRequirementRange(t, requirements.Devices[0], InitialRecoveryFinalBackupHeader)
	if sdExistingEntries.OffsetBytes == sdFinalEntries.OffsetBytes || sdExistingHeader.OffsetBytes == sdFinalHeader.OffsetBytes {
		t.Fatal("image-sized SD lost either its existing or physical-end backup GPT preimage")
	}
	nvmeExistingEntries := findRecoveryRequirementRange(t, requirements.Devices[1], InitialRecoveryExistingBackupEntries)
	nvmeFinalEntries := findRecoveryRequirementRange(t, requirements.Devices[1], InitialRecoveryFinalBackupEntries)
	if nvmeExistingEntries.RecoveryRangeBindingDigest != nvmeFinalEntries.RecoveryRangeBindingDigest || len(nvmeExistingEntries.Purposes) != 2 {
		t.Fatal("canonical NVMe did not retain the existing/final backup GPT alias as one range")
	}

	encoded, err := requirements.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"/dev/", "output_path", "target_path", "command", "executable", `"approved":true`, `"write_performed":true`} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("path-free descriptive requirements contain forbidden capability vocabulary %q", forbidden)
		}
	}
	parsed, err := ParseRecoveryBackupRequirements(append(append([]byte(nil), encoded...), '\n'))
	if err != nil {
		t.Fatalf("ParseRecoveryBackupRequirements: %v", err)
	}
	if err := parsed.ValidateAgainst(plan, envelopes); err != nil {
		t.Fatalf("parsed ValidateAgainst: %v", err)
	}
	if err := parsed.ValidateForDestructiveStaging(); err == nil || !strings.Contains(err.Error(), "explicit operator approval") {
		t.Fatalf("hard-false destructive-staging gate returned %v", err)
	}
	if err := plan.ValidateForDestructiveStaging(); err == nil {
		t.Fatal("adding recovery requirements changed the staging plan's hard-false gate")
	}
}

func findRecoveryRequirementRange(t *testing.T, device RecoveryBackupDeviceRequirements, purpose InitialRecoveryRangePurpose) RecoveryBackupRangeRequirement {
	t.Helper()
	for _, recoveryRange := range device.Ranges {
		if containsRecoveryPurpose(recoveryRange.Purposes, purpose) {
			return recoveryRange
		}
	}
	t.Fatalf("leg %q has no requirement for purpose %q", device.Leg, purpose)
	return RecoveryBackupRangeRequirement{}
}

func TestRecoveryBackupRequirementsRejectMissingReorderedOrReplayedInputs(t *testing.T) {
	plan := mustTestPlan(t)
	envelopes := mustTestInitialRecoveryEnvelopes(t, plan)
	if _, err := NewRecoveryBackupRequirements(plan, envelopes[:1]); err == nil {
		t.Fatal("missing NVMe initial-GPT envelope was accepted")
	}
	if _, err := NewRecoveryBackupRequirements(plan, []InitialGPTRecoveryEnvelope{envelopes[1], envelopes[0]}); err == nil {
		t.Fatal("reordered initial-GPT envelopes were accepted")
	}

	reusedCapture := cloneInitialRecoveryEnvelope(envelopes[1])
	reusedCapture.CaptureID = envelopes[0].CaptureID
	for index := range reusedCapture.RecoveryRanges {
		reusedCapture.RecoveryRanges[index].CaptureID = reusedCapture.CaptureID
		var err error
		reusedCapture.RecoveryRanges[index].BindingDigest, err = reusedCapture.RecoveryRanges[index].derivedBindingDigest()
		if err != nil {
			t.Fatal(err)
		}
	}
	reusedCapture.EnvelopeDigest = ""
	reusedCapture, err := reusedCapture.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRecoveryBackupRequirements(plan, []InitialGPTRecoveryEnvelope{envelopes[0], reusedCapture}); err == nil {
		t.Fatal("capture ID reuse across physical legs was accepted")
	}

	requirements, err := NewRecoveryBackupRequirements(plan, envelopes)
	if err != nil {
		t.Fatal(err)
	}
	changedEnvelope := cloneInitialRecoveryEnvelope(envelopes[0])
	changedEnvelope.RecoveryRanges[3].PreimageSHA256 = testDigest("different initial preimage")
	changedEnvelope.RecoveryRanges[3].BindingDigest, err = changedEnvelope.RecoveryRanges[3].derivedBindingDigest()
	if err != nil {
		t.Fatal(err)
	}
	changedEnvelope.EnvelopeDigest = ""
	changedEnvelope, err = changedEnvelope.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := requirements.ValidateAgainst(plan, []InitialGPTRecoveryEnvelope{changedEnvelope, envelopes[1]}); err == nil {
		t.Fatal("requirements were reusable after a valid envelope's preimage changed")
	}

	otherPlan := plan
	otherPlan.Campaign.CampaignArtifactSetContentDigest = testDigest("other requirements artifact set")
	otherPlan.Devices = cloneDevicePlans(plan.Devices)
	for index := range otherPlan.Devices {
		otherPlan.Devices[index].Campaign = otherPlan.Campaign
	}
	otherPlan.PlanDigest = ""
	otherPlan, err = otherPlan.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := requirements.ValidateAgainst(otherPlan, envelopes); err == nil {
		t.Fatal("requirements were reusable with a different sealed staging plan")
	}
}

func TestRecoveryBackupRequirementsRejectStructuralAndDetachedTampering(t *testing.T) {
	plan, envelopes, valid := mustTestRecoveryBackupRequirements(t)
	structural := map[string]func(*RecoveryBackupRequirements){
		"schema": func(value *RecoveryBackupRequirements) { value.SchemaVersion += "-other" },
		"device order": func(value *RecoveryBackupRequirements) {
			value.Devices[0], value.Devices[1] = value.Devices[1], value.Devices[0]
		},
		"missing range": func(value *RecoveryBackupRequirements) {
			value.Devices[0].Ranges = value.Devices[0].Ranges[1:]
		},
		"range order": func(value *RecoveryBackupRequirements) {
			value.Devices[0].Ranges[0], value.Devices[0].Ranges[1] = value.Devices[0].Ranges[1], value.Devices[0].Ranges[0]
		},
		"wrong leg purpose": func(value *RecoveryBackupRequirements) {
			value.Devices[0].Ranges[0].Purposes = []InitialRecoveryRangePurpose{InitialRecoveryPlannedRelease}
		},
		"duplicate purpose": func(value *RecoveryBackupRequirements) {
			value.Devices[0].Ranges[0].Purposes = append([]InitialRecoveryRangePurpose(nil), value.Devices[0].Ranges[1].Purposes...)
		},
		"reversed alias purpose": func(value *RecoveryBackupRequirements) {
			for index := range value.Devices[1].Ranges {
				if len(value.Devices[1].Ranges[index].Purposes) == 2 {
					value.Devices[1].Ranges[index].Purposes[0], value.Devices[1].Ranges[index].Purposes[1] =
						value.Devices[1].Ranges[index].Purposes[1], value.Devices[1].Ranges[index].Purposes[0]
					return
				}
			}
		},
		"out of bounds": func(value *RecoveryBackupRequirements) {
			value.Devices[0].Ranges[len(value.Devices[0].Ranges)-1].OffsetBytes = MalakSDCapacityBytes
		},
		"invalid preimage digest": func(value *RecoveryBackupRequirements) {
			value.Devices[0].Ranges[0].ExpectedPreimageSHA256 = "sha256:no"
		},
		"detached preimage digest": func(value *RecoveryBackupRequirements) {
			value.Devices[0].Ranges[0].ExpectedPreimageSHA256 = testDigest("detached preimage")
		},
		"detached range binding digest": func(value *RecoveryBackupRequirements) {
			value.Devices[0].Ranges[0].RecoveryRangeBindingDigest = testDigest("detached range binding")
		},
		"duplicate binding digest": func(value *RecoveryBackupRequirements) {
			value.Devices[0].Ranges[1].RecoveryRangeBindingDigest = value.Devices[0].Ranges[0].RecoveryRangeBindingDigest
		},
		"missing outstanding gate": func(value *RecoveryBackupRequirements) {
			value.OutstandingRequirements = value.OutstandingRequirements[1:]
		},
		"reordered outstanding gates": func(value *RecoveryBackupRequirements) {
			value.OutstandingRequirements[0], value.OutstandingRequirements[1] = value.OutstandingRequirements[1], value.OutstandingRequirements[0]
		},
		"backup capture claim":  func(value *RecoveryBackupRequirements) { value.BackupCapturePerformed = true },
		"backup readback claim": func(value *RecoveryBackupRequirements) { value.BackupReadbackVerified = true },
		"approval claim":        func(value *RecoveryBackupRequirements) { value.OperatorApprovalBound = true },
		"write permission":      func(value *RecoveryBackupRequirements) { value.BlockDeviceWritesPermitted = true },
		"staging ready":         func(value *RecoveryBackupRequirements) { value.DestructiveStagingReady = true },
	}
	for name, mutate := range structural {
		t.Run(name, func(t *testing.T) {
			changed := cloneRecoveryBackupRequirements(valid)
			mutate(&changed)
			changed.RecoveryRequirementsDigest = ""
			if _, err := changed.Seal(); err == nil {
				t.Fatal("structurally invalid requirements were accepted")
			}
		})
	}

	for name, mutate := range map[string]func(*RecoveryBackupRequirements){
		"plan digest": func(value *RecoveryBackupRequirements) { value.StagingPlanDigest = testDigest("detached staging plan") },
		"staging device digest": func(value *RecoveryBackupRequirements) {
			value.Devices[0].StagingDeviceDigest = testDigest("detached staging device")
		},
		"envelope digest": func(value *RecoveryBackupRequirements) {
			value.Devices[0].InitialGPTRecoveryEnvelopeDigest = testDigest("detached initial envelope")
		},
	} {
		t.Run("detached "+name, func(t *testing.T) {
			changed := cloneRecoveryBackupRequirements(valid)
			mutate(&changed)
			changed.RecoveryRequirementsDigest = ""
			changed, err := changed.Seal()
			if err != nil {
				t.Fatalf("detached but structurally valid catalog did not reseal: %v", err)
			}
			if err := changed.ValidateAgainst(plan, envelopes); err == nil {
				t.Fatal("detached requirements matched independently supplied inputs")
			}
		})
	}

	staleDigest := cloneRecoveryBackupRequirements(valid)
	staleDigest.StagingPlanDigest = testDigest("stale outer digest mutation")
	if err := staleDigest.Validate(); err == nil {
		t.Fatal("stale recovery requirements digest accepted changed content")
	}
}

func TestRecoveryBackupRequirementsRejectSDAliasAndRequireCrossBindingForGeometry(t *testing.T) {
	plan, envelopes, valid := mustTestRecoveryBackupRequirements(t)

	aliasedSD := cloneRecoveryBackupRequirements(valid)
	existingIndex, finalIndex := -1, -1
	for index, recoveryRange := range aliasedSD.Devices[0].Ranges {
		if containsRecoveryPurpose(recoveryRange.Purposes, InitialRecoveryExistingBackupEntries) {
			existingIndex = index
		}
		if containsRecoveryPurpose(recoveryRange.Purposes, InitialRecoveryFinalBackupEntries) {
			finalIndex = index
		}
	}
	if existingIndex < 0 || finalIndex < 0 || existingIndex >= finalIndex {
		t.Fatal("test fixture did not contain distinct ordered SD backup-entry ranges")
	}
	aliasedSD.Devices[0].Ranges[existingIndex].Purposes = []InitialRecoveryRangePurpose{
		InitialRecoveryExistingBackupEntries,
		InitialRecoveryFinalBackupEntries,
	}
	boundRange := InitialRecoveryRange{
		CaptureID:            aliasedSD.Devices[0].CaptureID,
		DeviceIdentityDigest: aliasedSD.Devices[0].DeviceIdentityDigest,
		Purposes:             append([]InitialRecoveryRangePurpose(nil), aliasedSD.Devices[0].Ranges[existingIndex].Purposes...),
		OffsetBytes:          aliasedSD.Devices[0].Ranges[existingIndex].OffsetBytes,
		SizeBytes:            aliasedSD.Devices[0].Ranges[existingIndex].SizeBytes,
		PreimageSHA256:       aliasedSD.Devices[0].Ranges[existingIndex].ExpectedPreimageSHA256,
	}
	var err error
	aliasedSD.Devices[0].Ranges[existingIndex].RecoveryRangeBindingDigest, err = boundRange.derivedBindingDigest()
	if err != nil {
		t.Fatal(err)
	}
	aliasedSD.Devices[0].Ranges = append(
		aliasedSD.Devices[0].Ranges[:finalIndex],
		aliasedSD.Devices[0].Ranges[finalIndex+1:]...,
	)
	aliasedSD.RecoveryRequirementsDigest = ""
	if _, err := aliasedSD.Seal(); err == nil {
		t.Fatal("image-sized SD existing/final backup GPT alias was accepted")
	}

	geometryOnly := cloneRecoveryBackupRequirements(valid)
	bootIndex := -1
	for index, recoveryRange := range geometryOnly.Devices[0].Ranges {
		if containsRecoveryPurpose(recoveryRange.Purposes, InitialRecoveryPlannedBoot) {
			bootIndex = index
			break
		}
	}
	if bootIndex < 0 || geometryOnly.Devices[0].Ranges[bootIndex].SizeBytes <= LogicalSectorSizeBytes {
		t.Fatal("test fixture has no shrinkable planned boot range")
	}
	geometryOnly.Devices[0].Ranges[bootIndex].SizeBytes -= LogicalSectorSizeBytes
	boundRange = InitialRecoveryRange{
		CaptureID:            geometryOnly.Devices[0].CaptureID,
		DeviceIdentityDigest: geometryOnly.Devices[0].DeviceIdentityDigest,
		Purposes:             append([]InitialRecoveryRangePurpose(nil), geometryOnly.Devices[0].Ranges[bootIndex].Purposes...),
		OffsetBytes:          geometryOnly.Devices[0].Ranges[bootIndex].OffsetBytes,
		SizeBytes:            geometryOnly.Devices[0].Ranges[bootIndex].SizeBytes,
		PreimageSHA256:       geometryOnly.Devices[0].Ranges[bootIndex].ExpectedPreimageSHA256,
	}
	geometryOnly.Devices[0].Ranges[bootIndex].RecoveryRangeBindingDigest, err = boundRange.derivedBindingDigest()
	if err != nil {
		t.Fatal(err)
	}
	geometryOnly.RecoveryRequirementsDigest = ""
	geometryOnly, err = geometryOnly.Seal()
	if err != nil {
		t.Fatalf("self-contained validation should accept otherwise valid detached geometry: %v", err)
	}
	if err := geometryOnly.ValidateAgainst(plan, envelopes); err == nil {
		t.Fatal("ValidateAgainst accepted range geometry detached from the initial-GPT envelopes")
	}
}

func TestRecoveryBackupRequirementsStrictCanonicalParserRejectsAmbiguity(t *testing.T) {
	_, _, requirements := mustTestRecoveryBackupRequirements(t)
	encoded, err := requirements.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, encoded, "", "  "); err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"empty":           {},
		"pretty":          pretty.Bytes(),
		"unknown field":   bytes.Replace(encoded, []byte(`{"schema_version":`), []byte(`{"unknown":1,"schema_version":`), 1),
		"duplicate field": bytes.Replace(encoded, []byte(`{"schema_version":`), []byte(`{"schema_version":"duplicate","schema_version":`), 1),
		"null":            bytes.Replace(encoded, []byte(`"backup_capture_performed":false`), []byte(`"backup_capture_performed":null`), 1),
		"trailing value":  append(append([]byte(nil), encoded...), []byte(`{}`)...),
		"two newlines":    append(append([]byte(nil), encoded...), '\n', '\n'),
		"oversized":       bytes.Repeat([]byte{' '}, maximumContractBytes+1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRecoveryBackupRequirements(input); err == nil {
				t.Fatal("ambiguous or non-canonical recovery requirements JSON was accepted")
			}
		})
	}
}
