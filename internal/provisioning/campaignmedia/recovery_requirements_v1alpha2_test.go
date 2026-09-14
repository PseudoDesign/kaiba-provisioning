package campaignmedia

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// These fixtures preserve real parser-produced GPT metadata, with synthetic
// payload hashes. They test contracts without reading gigabytes or hardware.
func mustTestInitialRecoveryEnvelopeV1Alpha2(t *testing.T, device DevicePlan, captureLabel string) InitialGPTRecoveryEnvelopeV1Alpha2 {
	t.Helper()
	var fixture *initialGPTFixture
	var physicalEnd *InitialGPTPhysicalEndBackupLineage
	state := InitialGPTPhysicalEndSelectedLineageBackup
	policy := initialGPTUsableRangeStrict
	switch device.Identity.Leg {
	case LegMalakSD:
		fixture = newInitialGPTFixture(t)
		installReviewedLegacyPhysicalEndGPTV1Alpha2(t, fixture)
		state = InitialGPTPhysicalEndDistinctBackupLineage
	case LegPiLocalNVMe:
		fixture = newInitialGPTAlignedNVMeFixture(t)
		policy = initialGPTUsableRangeV1Alpha2PiLocalNVMe
	default:
		t.Fatalf("unsupported test leg %q", device.Identity.Leg)
	}
	selected, captured, err := captureInitialGPTWithPhysicalEndPolicy(fixture.reader, device.Identity.CapacityBytes, false, policy)
	if err != nil {
		t.Fatal(err)
	}
	if state == InitialGPTPhysicalEndDistinctBackupLineage {
		header, ok := capturedInitialGPTBytes(captured, device.Identity.CapacityBytes-LogicalSectorSizeBytes, LogicalSectorSizeBytes)
		if !ok {
			t.Fatal("fixture has no physical-end header")
		}
		lineage, _, err := inspectPhysicalEndBackupLineage(fixture.reader, device.Identity, selected, header)
		if err != nil {
			t.Fatal(err)
		}
		physicalEnd = &lineage
	}
	planned, err := PlannedPayloadRangesFromDevicePlan(device)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := expectedInitialRecoveryRangeSpecsV1Alpha2(device.Identity, selected, planned, state)
	if err != nil {
		t.Fatal(err)
	}
	identityDigest, err := deriveInitialGPTIdentityDigestV1Alpha2(device.Identity)
	if err != nil {
		t.Fatal(err)
	}
	captureID := testInitialGPTCaptureID(captureLabel)
	ranges := make([]InitialRecoveryRangeV1Alpha2, len(specs))
	for index, spec := range specs {
		preimage := testDigest(fmt.Sprintf("synthetic v1alpha2 %s range %d", device.Identity.Leg, index+1))
		if physicalEnd != nil {
			if containsRecoveryPurpose(spec.purposes, InitialRecoveryPhysicalEndBackupHeader) {
				preimage = physicalEnd.HeaderSHA256
			}
			if containsRecoveryPurpose(spec.purposes, InitialRecoveryPhysicalEndBackupEntries) {
				preimage = physicalEnd.EntryArraySHA256
			}
		}
		ranges[index] = InitialRecoveryRangeV1Alpha2{
			CaptureID: captureID, DeviceIdentityDigest: identityDigest,
			Purposes:    append([]InitialRecoveryRangePurpose(nil), spec.purposes...),
			OffsetBytes: spec.offsetBytes, SizeBytes: spec.sizeBytes, PreimageSHA256: preimage,
		}
		ranges[index].BindingDigest, err = ranges[index].derivedBindingDigest()
		if err != nil {
			t.Fatal(err)
		}
	}
	envelope, err := (InitialGPTRecoveryEnvelopeV1Alpha2{
		SchemaVersion: InitialGPTRecoveryEnvelopeSchemaV1Alpha2,
		CaptureID:     captureID, Identity: device.Identity, DeviceIdentityDigest: identityDigest,
		SelectedLineage: selected, PhysicalEndState: state, PhysicalEndBackupLineage: physicalEnd,
		PlannedPayloadRanges: planned, RecoveryScope: RecoveryScopeInspectedInitialGPTLineagesAndPlannedPayloads,
		RecoveryRanges: ranges,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func mustTestRecoveryBackupRequirementsV1Alpha2(t *testing.T) (StagingPlan, []InitialGPTRecoveryEnvelopeV1Alpha2, RecoveryBackupRequirementsV1Alpha2) {
	t.Helper()
	plan := mustTestPlan(t)
	envelopes := []InitialGPTRecoveryEnvelopeV1Alpha2{
		mustTestInitialRecoveryEnvelopeV1Alpha2(t, plan.Devices[0], "requirements-v1alpha2-sd"),
		mustTestInitialRecoveryEnvelopeV1Alpha2(t, plan.Devices[1], "requirements-v1alpha2-nvme"),
	}
	requirements, err := NewRecoveryBackupRequirementsV1Alpha2(plan, envelopes)
	if err != nil {
		t.Fatal(err)
	}
	return plan, envelopes, requirements
}

func cloneRecoveryBackupRequirementsV1Alpha2(source RecoveryBackupRequirementsV1Alpha2) RecoveryBackupRequirementsV1Alpha2 {
	result := source
	result.OutstandingRequirements = append([]RecoveryBackupOutstandingRequirement(nil), source.OutstandingRequirements...)
	result.Devices = append([]RecoveryBackupDeviceRequirementsV1Alpha2(nil), source.Devices...)
	for index := range result.Devices {
		result.Devices[index].InitialGPTRecoveryEnvelope = copyInitialGPTRecoveryEnvelopeV1Alpha2(source.Devices[index].InitialGPTRecoveryEnvelope)
	}
	return result
}

func rebindRecoveryEnvelopeV1Alpha2(t *testing.T, envelope InitialGPTRecoveryEnvelopeV1Alpha2) InitialGPTRecoveryEnvelopeV1Alpha2 {
	t.Helper()
	var err error
	for index := range envelope.RecoveryRanges {
		envelope.RecoveryRanges[index].CaptureID = envelope.CaptureID
		envelope.RecoveryRanges[index].BindingDigest, err = envelope.RecoveryRanges[index].derivedBindingDigest()
		if err != nil {
			t.Fatal(err)
		}
	}
	envelope, err = envelope.Seal()
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestRecoveryBackupRequirementsV1Alpha2PreservesLineagesAndHardFalseBoundary(t *testing.T) {
	plan, envelopes, requirements := mustTestRecoveryBackupRequirementsV1Alpha2(t)
	if err := requirements.ValidateAgainst(plan, envelopes); err != nil {
		t.Fatal(err)
	}
	if requirements.BackupCapturePerformed || requirements.BackupReadbackVerified || requirements.OperatorApprovalBound ||
		requirements.BlockDeviceWritesPermitted || requirements.DestructiveStagingReady || requirements.ValidateForDestructiveStaging() == nil {
		t.Fatal("descriptive requirements acquired backup or staging authority")
	}
	for index := range envelopes {
		if !reflect.DeepEqual(requirements.Devices[index].InitialGPTRecoveryEnvelope, envelopes[index]) {
			t.Fatalf("leg %d did not retain the complete envelope", index)
		}
	}
	sd := requirements.Devices[0].InitialGPTRecoveryEnvelope
	if sd.PhysicalEndState != InitialGPTPhysicalEndDistinctBackupLineage || sd.PhysicalEndBackupLineage == nil ||
		sd.SelectedLineage.DiskGUID == sd.PhysicalEndBackupLineage.DiskGUID ||
		sd.SelectedLineage.Partitions[1].LastLBA == sd.PhysicalEndBackupLineage.Partitions[1].LastLBA {
		t.Fatal("distinct reviewed SD GPT histories were collapsed")
	}
	for _, purpose := range []InitialRecoveryRangePurpose{InitialRecoveryPhysicalEndBackupEntries, InitialRecoveryPhysicalEndBackupHeader} {
		rangeValue := findInitialRecoveryRangeV1Alpha2(t, sd, purpose)
		if len(rangeValue.Purposes) != 2 {
			t.Fatal("physical-end lineage lost its exact alias with the final backup range")
		}
	}
	if requirements.Devices[1].InitialGPTRecoveryEnvelope.SelectedLineage.FirstUsableLBA != 2048 {
		t.Fatal("v1alpha2 aligned NVMe fixture was not retained")
	}
	encoded, err := requirements.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{encoded, append(append([]byte(nil), encoded...), '\n')} {
		parsed, err := ParseRecoveryBackupRequirementsV1Alpha2(input)
		if err != nil || !reflect.DeepEqual(parsed, requirements) {
			t.Fatalf("canonical round trip failed: %v", err)
		}
	}
	if _, err := ParseRecoveryBackupRequirements(encoded); err == nil {
		t.Fatal("v1alpha1 parser accepted v1alpha2 requirements")
	}
	_, _, oldRequirements := mustTestRecoveryBackupRequirements(t)
	oldJSON, err := oldRequirements.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRecoveryBackupRequirements(oldJSON); err != nil {
		t.Fatalf("v1alpha1 compatibility failed: %v", err)
	}
	if _, err := ParseRecoveryBackupRequirementsV1Alpha2(oldJSON); err == nil {
		t.Fatal("v1alpha2 parser accepted v1alpha1 requirements")
	}
}

func TestRecoveryBackupRequirementsV1Alpha2OwnsNestedInputCopies(t *testing.T) {
	_, envelopes, requirements := mustTestRecoveryBackupRequirementsV1Alpha2(t)
	before, err := requirements.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	envelopes[0].SelectedLineage.Partitions[0].Name = "changed"
	envelopes[0].PhysicalEndBackupLineage.Partitions[0].Name = "changed"
	envelopes[0].PhysicalEndBackupLineage.DiskGUID = testSDDiskGUID
	envelopes[0].PlannedPayloadRanges[0].SizeBytes--
	envelopes[0].RecoveryRanges[0].Purposes[0] = InitialRecoveryPlannedRelease
	envelopes[0].RecoveryRanges[1].BindingDigest = testDigest("changed")
	after, err := requirements.CanonicalJSON()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("caller mutation altered sealed requirements: %v", err)
	}
}

func TestRecoveryBackupRequirementsV1Alpha2ParsesOnlyStateJustifiedNullLineages(t *testing.T) {
	plan, envelopes, _ := mustTestRecoveryBackupRequirementsV1Alpha2(t)
	withoutLegacy := copyInitialGPTRecoveryEnvelopeV1Alpha2(envelopes[0])
	withoutLegacy.PhysicalEndState = InitialGPTPhysicalEndNonGPTPreimage
	withoutLegacy.PhysicalEndBackupLineage = nil
	for index := range withoutLegacy.RecoveryRanges {
		r := &withoutLegacy.RecoveryRanges[index]
		if containsRecoveryPurpose(r.Purposes, InitialRecoveryPhysicalEndBackupEntries) || containsRecoveryPurpose(r.Purposes, InitialRecoveryPhysicalEndBackupHeader) {
			r.Purposes = r.Purposes[:1]
		}
	}
	withoutLegacy = rebindRecoveryEnvelopeV1Alpha2(t, withoutLegacy)
	for _, envelope := range []InitialGPTRecoveryEnvelopeV1Alpha2{envelopes[0], envelopes[1], withoutLegacy} {
		encoded, err := envelope.CanonicalJSON()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseInitialGPTRecoveryEnvelopeV1Alpha2(encoded)
		if err != nil || !reflect.DeepEqual(parsed, envelope) {
			t.Fatalf("direct %s envelope round trip: %v", envelope.PhysicalEndState, err)
		}
		wrongNull := bytes.Replace(encoded, []byte(`"destructive_staging_ready":false`), []byte(`"destructive_staging_ready":null`), 1)
		if _, err := ParseInitialGPTRecoveryEnvelopeV1Alpha2(wrongNull); err == nil {
			t.Fatal("nullable lineage exception permitted an unrelated null")
		}
	}
	requirements, err := NewRecoveryBackupRequirementsV1Alpha2(plan, []InitialGPTRecoveryEnvelopeV1Alpha2{withoutLegacy, envelopes[1]})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := requirements.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRecoveryBackupRequirementsV1Alpha2(encoded); err != nil {
		t.Fatalf("requirements with two justified null lineages rejected: %v", err)
	}
	missingLineage := copyInitialGPTRecoveryEnvelopeV1Alpha2(envelopes[0])
	missingLineage.PhysicalEndBackupLineage = nil
	encoded, err = json.Marshal(missingLineage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseInitialGPTRecoveryEnvelopeV1Alpha2(encoded); err == nil {
		t.Fatal("null lineage accepted for distinct-backup state")
	}
}

func TestRecoveryBackupRequirementsV1Alpha2RejectsMissingSwappedAndReusedInputs(t *testing.T) {
	plan, envelopes, _ := mustTestRecoveryBackupRequirementsV1Alpha2(t)
	for name, values := range map[string][]InitialGPTRecoveryEnvelopeV1Alpha2{
		"missing":  envelopes[:1],
		"extra":    append(append([]InitialGPTRecoveryEnvelopeV1Alpha2(nil), envelopes...), envelopes[0]),
		"swapped":  {envelopes[1], envelopes[0]},
		"repeated": {envelopes[0], envelopes[0]},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRecoveryBackupRequirementsV1Alpha2(plan, values); err == nil {
				t.Fatal("incorrect fixed envelope roles accepted")
			}
		})
	}
	reused := copyInitialGPTRecoveryEnvelopeV1Alpha2(envelopes[1])
	reused.CaptureID = envelopes[0].CaptureID
	reused = rebindRecoveryEnvelopeV1Alpha2(t, reused)
	if _, err := NewRecoveryBackupRequirementsV1Alpha2(plan, []InitialGPTRecoveryEnvelopeV1Alpha2{envelopes[0], reused}); err == nil {
		t.Fatal("same capture ID accepted for two physical legs")
	}
	badPlan := plan
	badPlan.PlanDigest = testDigest("invalid plan seal")
	if _, err := NewRecoveryBackupRequirementsV1Alpha2(badPlan, envelopes); err == nil {
		t.Fatal("invalid sealed staging plan accepted")
	}
}

func TestRecoveryBackupRequirementsV1Alpha2RejectsLineageRangeAndAuthorityTampering(t *testing.T) {
	_, _, valid := mustTestRecoveryBackupRequirementsV1Alpha2(t)
	mutations := map[string]func(*RecoveryBackupRequirementsV1Alpha2){
		"schema": func(v *RecoveryBackupRequirementsV1Alpha2) {
			v.SchemaVersion = RecoveryBackupRequirementsSchemaV1Alpha1
		},
		"scope":          func(v *RecoveryBackupRequirementsV1Alpha2) { v.RecoveryScope = RecoveryScopeCrossBoundInitialRanges },
		"missing device": func(v *RecoveryBackupRequirementsV1Alpha2) { v.Devices = v.Devices[:1] },
		"extra device":   func(v *RecoveryBackupRequirementsV1Alpha2) { v.Devices = append(v.Devices, v.Devices[0]) },
		"device order":   func(v *RecoveryBackupRequirementsV1Alpha2) { v.Devices[0], v.Devices[1] = v.Devices[1], v.Devices[0] },
		"leg":            func(v *RecoveryBackupRequirementsV1Alpha2) { v.Devices[0].Leg = LegPiLocalNVMe },
		"repeated device binding": func(v *RecoveryBackupRequirementsV1Alpha2) {
			v.Devices[0].StagingDeviceDigest = v.Devices[1].StagingDeviceDigest
		},
		"missing gate": func(v *RecoveryBackupRequirementsV1Alpha2) { v.OutstandingRequirements = v.OutstandingRequirements[1:] },
		"extra gate": func(v *RecoveryBackupRequirementsV1Alpha2) {
			v.OutstandingRequirements = append(v.OutstandingRequirements, RecoveryBackupReadbackRequired)
		},
		"reordered gates": func(v *RecoveryBackupRequirementsV1Alpha2) {
			v.OutstandingRequirements[0], v.OutstandingRequirements[1] = v.OutstandingRequirements[1], v.OutstandingRequirements[0]
		},
		"capture claim":  func(v *RecoveryBackupRequirementsV1Alpha2) { v.BackupCapturePerformed = true },
		"readback claim": func(v *RecoveryBackupRequirementsV1Alpha2) { v.BackupReadbackVerified = true },
		"approval claim": func(v *RecoveryBackupRequirementsV1Alpha2) { v.OperatorApprovalBound = true },
		"write claim":    func(v *RecoveryBackupRequirementsV1Alpha2) { v.BlockDeviceWritesPermitted = true },
		"staging claim":  func(v *RecoveryBackupRequirementsV1Alpha2) { v.DestructiveStagingReady = true },
	}
	for name, mutate := range map[string]func(*InitialGPTRecoveryEnvelopeV1Alpha2){
		"nested schema": func(e *InitialGPTRecoveryEnvelopeV1Alpha2) {
			e.SchemaVersion = InitialGPTRecoveryEnvelopeSchemaV1Alpha1
		},
		"lost physical lineage":  func(e *InitialGPTRecoveryEnvelopeV1Alpha2) { e.PhysicalEndBackupLineage = nil },
		"lost lineage state":     func(e *InitialGPTRecoveryEnvelopeV1Alpha2) { e.PhysicalEndState = InitialGPTPhysicalEndNonGPTPreimage },
		"stale selected lineage": func(e *InitialGPTRecoveryEnvelopeV1Alpha2) { e.SelectedLineage.Partitions[1].LastLBA-- },
		"stale physical lineage": func(e *InitialGPTRecoveryEnvelopeV1Alpha2) { e.PhysicalEndBackupLineage.DiskGUID = testSDDiskGUID },
		"stale lineage byte digest": func(e *InitialGPTRecoveryEnvelopeV1Alpha2) {
			e.PhysicalEndBackupLineage.HeaderSHA256 = testDigest("other header")
		},
		"stale capture": func(e *InitialGPTRecoveryEnvelopeV1Alpha2) { e.CaptureID = testInitialGPTCaptureID("other capture") },
		"missing range": func(e *InitialGPTRecoveryEnvelopeV1Alpha2) { e.RecoveryRanges = e.RecoveryRanges[1:] },
		"extra range": func(e *InitialGPTRecoveryEnvelopeV1Alpha2) {
			e.RecoveryRanges = append(e.RecoveryRanges, e.RecoveryRanges[0])
		},
		"swapped ranges": func(e *InitialGPTRecoveryEnvelopeV1Alpha2) {
			e.RecoveryRanges[0], e.RecoveryRanges[1] = e.RecoveryRanges[1], e.RecoveryRanges[0]
		},
		"range role": func(e *InitialGPTRecoveryEnvelopeV1Alpha2) {
			e.RecoveryRanges[0].Purposes[0] = InitialRecoveryPlannedRelease
		},
		"range geometry": func(e *InitialGPTRecoveryEnvelopeV1Alpha2) { e.RecoveryRanges[0].SizeBytes += LogicalSectorSizeBytes },
		"stale preimage": func(e *InitialGPTRecoveryEnvelopeV1Alpha2) {
			e.RecoveryRanges[0].PreimageSHA256 = testDigest("other bytes")
		},
		"nested write claim": func(e *InitialGPTRecoveryEnvelopeV1Alpha2) { e.DestructiveStagingReady = true },
		"reverse physical alias": func(e *InitialGPTRecoveryEnvelopeV1Alpha2) {
			for index := range e.RecoveryRanges {
				if len(e.RecoveryRanges[index].Purposes) == 2 {
					e.RecoveryRanges[index].Purposes[0], e.RecoveryRanges[index].Purposes[1] = e.RecoveryRanges[index].Purposes[1], e.RecoveryRanges[index].Purposes[0]
					return
				}
			}
		},
	} {
		mutations[name] = func(v *RecoveryBackupRequirementsV1Alpha2) { mutate(&v.Devices[0].InitialGPTRecoveryEnvelope) }
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := cloneRecoveryBackupRequirementsV1Alpha2(valid)
			mutate(&changed)
			if _, err := changed.Seal(); err == nil {
				t.Fatal("invalid nested contract or authority claim accepted")
			}
		})
	}
}

func TestRecoveryBackupRequirementsV1Alpha2RejectsVersionAndAliasTransplants(t *testing.T) {
	_, _, valid := mustTestRecoveryBackupRequirementsV1Alpha2(t)
	for _, deviceIndex := range []int{0, 1} {
		changed := cloneRecoveryBackupRequirementsV1Alpha2(valid)
		e := &changed.Devices[deviceIndex].InitialGPTRecoveryEnvelope
		r := e.RecoveryRanges[0]
		oldBinding, err := (InitialRecoveryRange{
			CaptureID: r.CaptureID, DeviceIdentityDigest: r.DeviceIdentityDigest, Purposes: r.Purposes,
			OffsetBytes: r.OffsetBytes, SizeBytes: r.SizeBytes, PreimageSHA256: r.PreimageSHA256,
		}).derivedBindingDigest()
		if err != nil {
			t.Fatal(err)
		}
		e.RecoveryRanges[0].BindingDigest = oldBinding
		if _, err := changed.Seal(); err == nil {
			t.Fatal("v1alpha1 range binding transplanted into v1alpha2")
		}
		for index := range e.RecoveryRanges {
			if len(e.RecoveryRanges[index].Purposes) == 2 {
				changed = cloneRecoveryBackupRequirementsV1Alpha2(valid)
				e = &changed.Devices[deviceIndex].InitialGPTRecoveryEnvelope
				e.RecoveryRanges[index].Purposes = e.RecoveryRanges[index].Purposes[:1]
				e.RecoveryRanges[index].BindingDigest, err = e.RecoveryRanges[index].derivedBindingDigest()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := changed.Seal(); err == nil {
					t.Fatal("recomputed binding concealed a missing required alias purpose")
				}
				break
			}
		}
	}
}

func TestRecoveryBackupRequirementsV1Alpha2RejectsResealedIndependentInputSubstitution(t *testing.T) {
	plan, envelopes, valid := mustTestRecoveryBackupRequirementsV1Alpha2(t)
	for name, mutate := range map[string]func(*RecoveryBackupRequirementsV1Alpha2){
		"plan digest": func(v *RecoveryBackupRequirementsV1Alpha2) { v.StagingPlanDigest = testDigest("another plan") },
		"device digest": func(v *RecoveryBackupRequirementsV1Alpha2) {
			v.Devices[0].StagingDeviceDigest = testDigest("another device plan")
		},
		"rebound preimage": func(v *RecoveryBackupRequirementsV1Alpha2) {
			e := &v.Devices[0].InitialGPTRecoveryEnvelope
			e.RecoveryRanges[0].PreimageSHA256 = testDigest("rebound bytes")
			*e = rebindRecoveryEnvelopeV1Alpha2(t, *e)
		},
		"rebound capture": func(v *RecoveryBackupRequirementsV1Alpha2) {
			e := &v.Devices[0].InitialGPTRecoveryEnvelope
			e.CaptureID = testInitialGPTCaptureID("new independent capture")
			*e = rebindRecoveryEnvelopeV1Alpha2(t, *e)
		},
		"rebound physical lineage": func(v *RecoveryBackupRequirementsV1Alpha2) {
			e := &v.Devices[0].InitialGPTRecoveryEnvelope
			e.PhysicalEndBackupLineage.HeaderSHA256 = testDigest("rebound physical-end header")
			var err error
			e.PhysicalEndBackupLineage.LineageDigest, err = e.PhysicalEndBackupLineage.derivedDigest()
			if err != nil {
				t.Fatal(err)
			}
			for index := range e.RecoveryRanges {
				if containsRecoveryPurpose(e.RecoveryRanges[index].Purposes, InitialRecoveryPhysicalEndBackupHeader) {
					e.RecoveryRanges[index].PreimageSHA256 = e.PhysicalEndBackupLineage.HeaderSHA256
				}
			}
			*e = rebindRecoveryEnvelopeV1Alpha2(t, *e)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneRecoveryBackupRequirementsV1Alpha2(valid)
			mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("stale outer digest accepted")
			}
			changed, err := changed.Seal()
			if err != nil {
				t.Fatalf("self-consistent substitution failed to seal: %v", err)
			}
			if err := changed.ValidateAgainst(plan, envelopes); err == nil {
				t.Fatal("substitution accepted against independent original inputs")
			}
		})
	}
	otherPlan := plan
	otherPlan.Campaign.CampaignArtifactSetContentDigest = testDigest("new artifact set")
	otherPlan.Devices = cloneDevicePlans(plan.Devices)
	for index := range otherPlan.Devices {
		otherPlan.Devices[index].Campaign = otherPlan.Campaign
	}
	otherPlan, err := otherPlan.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := valid.ValidateAgainst(otherPlan, envelopes); err == nil {
		t.Fatal("different sealed plan accepted")
	}
}

func TestRecoveryBackupRequirementsV1Alpha2StrictCanonicalParser(t *testing.T) {
	_, _, requirements := mustTestRecoveryBackupRequirementsV1Alpha2(t)
	encoded, err := requirements.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, encoded, "", "  "); err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string][]byte{
		"empty":                {},
		"pretty":               pretty.Bytes(),
		"unknown field":        bytes.Replace(encoded, []byte(`{"schema_version":`), []byte(`{"unknown":1,"schema_version":`), 1),
		"duplicate field":      bytes.Replace(encoded, []byte(`{"schema_version":`), []byte(`{"schema_version":"duplicate","schema_version":`), 1),
		"missing false field":  bytes.Replace(encoded, []byte(`"backup_capture_performed":false,`), nil, 1),
		"null false field":     bytes.Replace(encoded, []byte(`"backup_capture_performed":false`), []byte(`"backup_capture_performed":null`), 1),
		"unknown nested field": bytes.Replace(encoded, []byte(`"initial_gpt_recovery_envelope":{`), []byte(`"initial_gpt_recovery_envelope":{"unknown":true,`), 1),
		"missing nested null":  bytes.Replace(encoded, []byte(`"physical_end_backup_lineage":null,`), nil, 1),
		"trailing object":      append(append([]byte(nil), encoded...), []byte(`{}`)...),
		"two newlines":         append(append([]byte(nil), encoded...), '\n', '\n'),
		"oversized":            bytes.Repeat([]byte{' '}, maximumContractBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRecoveryBackupRequirementsV1Alpha2(input); err == nil {
				t.Fatal("ambiguous or noncanonical JSON accepted")
			}
		})
	}
}

func TestRecoveryBackupRequirementsV1Alpha2PublicFixtures(t *testing.T) {
	plan, envelopes, expected := mustTestRecoveryBackupRequirementsV1Alpha2(t)
	for name, value := range map[string]interface{ CanonicalJSON() ([]byte, error) }{
		"staging-plan": plan, "sd-envelope": envelopes[0], "nvme-envelope": envelopes[1],
	} {
		encoded, err := value.CanonicalJSON()
		if err != nil {
			t.Fatal(err)
		}
		fixture, err := os.ReadFile(filepath.Join("testdata", "recovery-v1alpha2", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(fixture, append(encoded, '\n')) {
			t.Fatalf("%s public fixture differs from the synthetic contract helper", name)
		}
	}
	if err := expected.ValidateAgainst(plan, envelopes); err != nil {
		t.Fatal(err)
	}
}
