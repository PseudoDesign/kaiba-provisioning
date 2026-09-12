package stablecampaignsigning

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signedboot"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

const testSourceRevision = "0123456789abcdef0123456789abcdef01234567"

func TestIntentCanonicalRoundTripAndDomainSeparatedDigest(t *testing.T) {
	first := testIntent(t)
	second := testIntent(t)
	firstJSON, err := first.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := second.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("identical public inputs did not produce identical canonical intents")
	}
	firstDigest, err := first.Digest()
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := second.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("intent digests differ: %s != %s", firstDigest, secondDigest)
	}
	if firstDigest == bundle.Sum(firstJSON) {
		t.Fatal("intent digest is not domain-separated from an ordinary JSON digest")
	}
	parsed, err := ParseIntent(firstJSON)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != first {
		t.Fatalf("round trip changed intent: %#v != %#v", parsed, first)
	}
}

func TestIntentRejectsEveryOpenOrInvalidField(t *testing.T) {
	valid := testIntent(t)
	tests := []struct {
		name  string
		match string
		alter func(*Intent)
	}{
		{"schema", "schema_version", func(value *Intent) { value.SchemaVersion = "v2" }},
		{"scope", "authorization_scope", func(value *Intent) { value.AuthorizationScope = "cohort_release" }},
		{"revision", "source_revision", func(value *Intent) { value.SourceRevision = strings.Repeat("A", 40) }},
		{"zero epoch", "source_date_epoch", func(value *Intent) { value.SourceDateEpoch = 0 }},
		{"manifest digest", "unsigned_manifest_digest", func(value *Intent) { value.UnsignedManifestDigest = "sha256:no" }},
		{"artifact set digest", "unsigned_artifact_set_digest", func(value *Intent) { value.UnsignedArtifactSetDigest = "sha256:no" }},
		{"customer key", "expected_customer_key_hash", func(value *Intent) { value.ExpectedCustomerKeyHash = "sha256:no" }},
		{"key file", "public_key_file_digest", func(value *Intent) { value.PublicKeyFileDigest = "sha256:no" }},
		{"key fingerprint", "public_key_fingerprint", func(value *Intent) { value.PublicKeyFingerprint = "sha256:no" }},
		{"policy", "signer_policy_digest", func(value *Intent) { value.SignerPolicyDigest = "sha256:no" }},
		{"wrong role", "signing_input.role", func(value *Intent) { value.SigningInput.Role = bundle.RoleEEPROMBootcode }},
		{"input digest", "signing_input.digest", func(value *Intent) { value.SigningInput.Digest = "sha256:no" }},
		{"zero input", "signing_input.size_bytes", func(value *Intent) { value.SigningInput.SizeBytes = 0 }},
		{"large input", "signing_input.size_bytes", func(value *Intent) { value.SigningInput.SizeBytes = uint64(signing.MaxArtifactBytes) + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.alter(&candidate)
			err := candidate.Validate()
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("Validate() error = %v, want match %q", err, test.match)
			}
		})
	}
}

func TestIntentStrictCanonicalJSON(t *testing.T) {
	canonical, err := testIntent(t).CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	valid := string(canonical)
	tests := []struct {
		name  string
		input string
		match string
	}{
		{"unknown", strings.Replace(valid, `"authorization_scope"`, `"unknown":true,"authorization_scope"`, 1), "unknown field"},
		{"duplicate", strings.Replace(valid, `"authorization_scope":"stable_campaign_provisioner_boot"`, `"authorization_scope":"stable_campaign_provisioner_boot","authorization_scope":"stable_campaign_provisioner_boot"`, 1), "duplicated"},
		{"null", strings.Replace(valid, `"source_revision":"`+testSourceRevision+`"`, `"source_revision":null`, 1), "null"},
		{"nested unknown", strings.Replace(valid, `"role":"rpi5.boot_image"`, `"role":"rpi5.boot_image","path":"/tmp/input"`, 1), "unknown field"},
		{"trailing", valid + `{}`, "trailing"},
		{"leading whitespace", " " + valid, "canonical"},
		{"newline", valid + "\n", "canonical"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseIntent([]byte(test.input))
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("ParseIntent() error = %v, want match %q", err, test.match)
			}
		})
	}
}

func TestValidateIntentForPlanBindsEveryPlanField(t *testing.T) {
	intent := testIntent(t)
	encoded, err := intent.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := intent.Digest()
	if err != nil {
		t.Fatal(err)
	}
	valid := signedboot.Plan{
		SchemaVersion: signedboot.PlanSchemaV1Alpha2,
		PlanID:        "stable:campaign:boot", ReleaseIntentDigest: digest,
		BootImageDigest: intent.SigningInput.Digest, BootImageSizeBytes: intent.SigningInput.SizeBytes,
		PublicKeyFingerprint: intent.PublicKeyFingerprint, SignerPolicyDigest: intent.SignerPolicyDigest,
		SourceDateEpoch: intent.SourceDateEpoch,
	}
	if _, err := ValidateIntentForPlan(append(encoded, '\n'), valid); err != nil {
		t.Fatalf("valid plan rejected: %v", err)
	}
	tests := []struct {
		name  string
		match string
		alter func(*signedboot.Plan)
	}{
		{"intent digest", "intent digest", func(value *signedboot.Plan) { value.ReleaseIntentDigest = testDigest("f") }},
		{"boot digest", "boot input", func(value *signedboot.Plan) { value.BootImageDigest = testDigest("f") }},
		{"boot size", "boot input", func(value *signedboot.Plan) { value.BootImageSizeBytes++ }},
		{"key", "public key", func(value *signedboot.Plan) { value.PublicKeyFingerprint = testDigest("f") }},
		{"policy", "signer policy", func(value *signedboot.Plan) { value.SignerPolicyDigest = testDigest("f") }},
		{"epoch", "timestamp", func(value *signedboot.Plan) { value.SourceDateEpoch++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.alter(&candidate)
			_, err := ValidateIntentForPlan(encoded, candidate)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("ValidateIntentForPlan() error = %v, want match %q", err, test.match)
			}
		})
	}
}

func testIntent(t *testing.T) Intent {
	t.Helper()
	intent, err := NewIntent(IntentParameters{
		SourceRevision: testSourceRevision, SourceDateEpoch: 1786968000,
		UnsignedManifestDigest: testDigest("1"), UnsignedArtifactSetDigest: testDigest("2"),
		ExpectedCustomerKeyHash: testDigest("3"), PublicKeyFileDigest: testDigest("4"),
		PublicKeyFingerprint: testDigest("5"), SignerPolicyDigest: testDigest("6"),
		SigningInput: bundle.Artifact{Role: bundle.RoleBootImage, Digest: testDigest("7"), SizeBytes: 100663296},
	})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func testDigest(character string) bundle.Digest {
	return bundle.Digest("sha256:" + strings.Repeat(character, 64))
}
