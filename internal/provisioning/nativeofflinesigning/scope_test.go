package nativeofflinesigning

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseintent"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaignsigning"
)

func TestNativeOfflineAndProvisionerContractsRejectEachOthersRecords(t *testing.T) {
	offline := testIntent(t)
	provisioner, err := stablecampaignsigning.NewIntent(stablecampaignsigning.IntentParameters{
		SourceRevision: offline.SourceRevision, SourceDateEpoch: offline.SourceDateEpoch,
		UnsignedManifestDigest: offline.UnsignedManifestDigest, UnsignedArtifactSetDigest: testDigest("8"),
		ExpectedCustomerKeyHash: offline.ExpectedCustomerKeyHash, PublicKeyFileDigest: offline.PublicKeyFileDigest,
		PublicKeyFingerprint: offline.PublicKeyFingerprint, SignerPolicyDigest: offline.SignerPolicyDigest,
		SigningInput: offline.SigningInput,
	})
	if err != nil {
		t.Fatal(err)
	}
	offlineJSON, _ := offline.CanonicalJSON()
	provisionerJSON, _ := provisioner.CanonicalJSON()
	if _, err := ParseIntent(provisionerJSON); err == nil {
		t.Fatal("offline parser accepted a provisioner intent")
	}
	if _, err := stablecampaignsigning.ParseIntent(offlineJSON); err == nil {
		t.Fatal("unchanged provisioner parser accepted a offline intent")
	}
	if _, err := releaseintent.Parse(offlineJSON); err == nil {
		t.Fatal("generic five-input parser accepted a offline intent")
	}
	if _, err := ParseIntent(bytes.Replace(offlineJSON, []byte(IntentSchemaV1Alpha1), []byte("kaiba.provisioning.rpi5-stable-offline-signing-intent/v1alpha1"), 1)); err == nil {
		t.Fatal("historical custom offline intent schema was reused")
	}
	offlineAuthorization, err := NewAuthorization(offline, "reviewer:alice", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	provisionerAuthorization, err := stablecampaignsigning.NewAuthorization(provisioner, "reviewer:alice", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	offlineApproval, _ := offlineAuthorization.Approval.CanonicalJSON()
	provisionerApproval, _ := provisionerAuthorization.Approval.CanonicalJSON()
	if _, err := ParseApproval(provisionerApproval); err == nil {
		t.Fatal("offline parser accepted a provisioner approval")
	}
	if _, err := stablecampaignsigning.ParseApproval(offlineApproval); err == nil {
		t.Fatal("unchanged provisioner parser accepted a offline approval")
	}
	if offlineAuthorization.Approval.ApprovalDigest == provisionerAuthorization.Approval.ApprovalDigest {
		t.Fatal("different scopes shared an approval/grant identity")
	}
	if err := (Authorization{Approval: offlineAuthorization.Approval, Registry: provisionerAuthorization.Registry}).Validate(offline); err == nil {
		t.Fatal("offline authorization accepted a provisioner registry for the same boot bytes")
	}
	if err := (stablecampaignsigning.Authorization{Approval: provisionerAuthorization.Approval, Registry: offlineAuthorization.Registry}).Validate(provisioner); err == nil {
		t.Fatal("provisioner authorization accepted a offline registry for the same boot bytes")
	}
	if bytes.Contains(offlineJSON, []byte("unsigned_artifact_set_digest")) {
		t.Fatal("offline intent invented an artifact-set identity")
	}
}

func TestApprovalBindsEveryNativeOfflineIdentity(t *testing.T) {
	intent := testIntent(t)
	authorization, err := NewAuthorization(intent, "reviewer:alice", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Intent){
		"source revision":    func(value *Intent) { value.SourceRevision = strings.Repeat("f", 40) },
		"source epoch":       func(value *Intent) { value.SourceDateEpoch++ },
		"manifest bytes":     func(value *Intent) { value.UnsignedManifestDigest = testDigest("f") },
		"customer key":       func(value *Intent) { value.ExpectedCustomerKeyHash = testDigest("f") },
		"public key file":    func(value *Intent) { value.PublicKeyFileDigest = testDigest("f") },
		"public fingerprint": func(value *Intent) { value.PublicKeyFingerprint = testDigest("f") },
		"signer policy":      func(value *Intent) { value.SignerPolicyDigest = testDigest("f") },
		"boot bytes":         func(value *Intent) { value.SigningInput.Digest = testDigest("f") },
		"boot size":          func(value *Intent) { value.SigningInput.SizeBytes-- },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := intent
			mutate(&candidate)
			if err := candidate.Validate(); err != nil {
				t.Fatalf("mutation is not a valid alternate intent: %v", err)
			}
			if err := authorization.Validate(candidate); err == nil {
				t.Fatal("approval accepted a changed offline identity")
			}
		})
	}
}

func TestNoAdditionalSigningInputCanBeEncoded(t *testing.T) {
	canonical, _ := testIntent(t).CanonicalJSON()
	for _, insertion := range []string{
		`,"signing_inputs":[{"role":"rpi5.eeprom_bootcode","digest":"` + string(testDigest("a")) + `","size_bytes":1}]`,
		`,"unsigned_artifact_set_digest":"` + string(testDigest("b")) + `"`,
	} {
		candidate := append(append([]byte(nil), canonical[:len(canonical)-1]...), []byte(insertion+"}")...)
		if _, err := ParseIntent(candidate); err == nil {
			t.Fatal("intent accepted an extra input or provisioner-only identity")
		}
	}
	for _, role := range []bundle.ArtifactRole{bundle.RoleEEPROMBootcode, bundle.RoleEEPROMBootsys, bundle.RoleEEPROMConfig, bundle.RoleOwnedRecoveryBootcode} {
		candidate := testIntent(t)
		candidate.SigningInput.Role = role
		encoded, _ := json.Marshal(candidate)
		if _, err := ParseIntent(encoded); err == nil {
			t.Fatalf("intent accepted role %s", role)
		}
	}
}
