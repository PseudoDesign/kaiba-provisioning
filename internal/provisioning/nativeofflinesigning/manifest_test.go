package nativeofflinesigning

import (
	"encoding/json"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stableverifiersigning"
)

func TestNativeAndVerifierIntentsCannotShareGrants(t *testing.T) {
	native := testIntent(t)
	encoded, _ := native.CanonicalJSON()
	if _, err := stableverifiersigning.ParseIntent(encoded); err == nil {
		t.Fatal("verifier accepted native intent")
	}
	verifier, err := stableverifiersigning.NewIntent(stableverifiersigning.IntentParameters{
		SourceRevision: native.SourceRevision, SourceDateEpoch: native.SourceDateEpoch,
		UnsignedManifestDigest: native.UnsignedManifestDigest, ExpectedCustomerKeyHash: native.ExpectedCustomerKeyHash,
		PublicKeyFileDigest: native.PublicKeyFileDigest, PublicKeyFingerprint: native.PublicKeyFingerprint,
		SignerPolicyDigest: native.SignerPolicyDigest, SigningInput: native.SigningInput,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = verifier.CanonicalJSON()
	if _, err := ParseIntent(encoded); err == nil {
		t.Fatal("native parser accepted verifier intent")
	}
	a, _ := NewAuthorization(native, "reviewer:test", testApprovedAt, testExpiresAt)
	b, _ := stableverifiersigning.NewAuthorization(verifier, "reviewer:test", testApprovedAt, testExpiresAt)
	if err := (Authorization{Approval: a.Approval, Registry: b.Registry}).Validate(native); err == nil {
		t.Fatal("accepted verifier grant for same boot bytes")
	}
	encoded, _ = b.Approval.CanonicalJSON()
	if _, err := ParseApproval(encoded); err == nil {
		t.Fatal("accepted verifier approval")
	}
	encoded, _ = a.Approval.CanonicalJSON()
	if _, err := stableverifiersigning.ParseApproval(encoded); err == nil {
		t.Fatal("verifier accepted native approval")
	}
}

func TestManifestRequiresExactNativeBindings(t *testing.T) {
	intent := testIntent(t)
	baseline := UnsignedManifest{
		SchemaVersion: UnsignedManifestSchemaV1Alpha1, SourceRevision: intent.SourceRevision,
		UnsignedArtifactsDigest: testDigest("1"), ReviewDigest: testDigest("2"),
		BootImage: InputFile{Digest: intent.SigningInput.Digest, SizeBytes: intent.SigningInput.SizeBytes},
		RootData:  InputFile{Digest: testDigest("3"), SizeBytes: 8192}, RootHashTree: InputFile{Digest: testDigest("4"), SizeBytes: 4096},
		RootIntegrityDigest: testDigest("5"), RootDataPARTUUID: RootDataPARTUUID, RootHashPARTUUID: RootHashPARTUUID,
		HardwareObserved: false, FleetAdmission: "unevaluated",
	}
	encode := func(m UnsignedManifest) []byte {
		data, _ := json.Marshal(m)
		var fields map[string]any
		_ = json.Unmarshal(data, &fields)
		data, _ = json.Marshal(fields)
		return append(data, '\n')
	}
	data := encode(baseline)
	intent.UnsignedManifestDigest = bundle.Sum(data)
	if err := ValidateUnsignedManifest(data, intent); err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*UnsignedManifest){
		"schema":       func(m *UnsignedManifest) { m.SchemaVersion = "wrong" },
		"source":       func(m *UnsignedManifest) { m.SourceRevision = "main" },
		"boot":         func(m *UnsignedManifest) { m.BootImage.Digest = testDigest("e") },
		"hardware":     func(m *UnsignedManifest) { m.HardwareObserved = true },
		"admission":    func(m *UnsignedManifest) { m.FleetAdmission = "passed" },
		"swapped GUID": func(m *UnsignedManifest) { m.RootHashPARTUUID = RootDataPARTUUID },
		"root size":    func(m *UnsignedManifest) { m.RootData.SizeBytes = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			m := baseline
			alter(&m)
			data := encode(m)
			intent.UnsignedManifestDigest = bundle.Sum(data)
			if err := ValidateUnsignedManifest(data, intent); err == nil {
				t.Fatal("accepted invalid rebound manifest")
			}
		})
	}
	var fields map[string]any
	_ = json.Unmarshal(encode(baseline), &fields)
	fields["HARDWARE_OBSERVED"] = fields["hardware_observed"]
	delete(fields, "hardware_observed")
	data, _ = json.Marshal(fields)
	data = append(data, '\n')
	intent.UnsignedManifestDigest = bundle.Sum(data)
	if err := ValidateUnsignedManifest(data, intent); err == nil {
		t.Fatal("accepted case-folded alias")
	}
}
