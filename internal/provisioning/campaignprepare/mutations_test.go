package campaignprepare

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stableverifier"
)

type mutationFixture struct {
	root                           *rsa.PrivateKey
	keys                           map[string]*rsa.PrivateKey
	policy                         stableverifier.Policy
	positive, replacement, revoked stableverifier.Manifest
	rootPEM                        []byte
}

func fixtureKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func fixturePublic(t *testing.T, key *rsa.PrivateKey) ([]byte, bundle.Digest) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), bundle.Sum(der)
}
func fixtureSignature(t *testing.T, key *rsa.PrivateKey, id string, preimage []byte) stableverifier.RSASignature {
	t.Helper()
	digest := sha256.Sum256(preimage)
	signature, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return stableverifier.RSASignature{KeyID: id, Algorithm: stableverifier.RSA2048SHA256Algorithm, Value: base64.StdEncoding.EncodeToString(signature)}
}
func newMutationFixture(t *testing.T) mutationFixture {
	t.Helper()
	root := fixtureKey(t)
	rootPEM, rootFingerprint := fixturePublic(t, root)
	fixture := mutationFixture{root: root, rootPEM: rootPEM, keys: make(map[string]*rsa.PrivateKey)}
	fixture.policy = stableverifier.Policy{SchemaVersion: stableverifier.PolicySchemaV1Alpha1, PolicyID: "policy:campaign-fixture", DeviceClass: stableverifier.DeviceClass, CohortID: "campaign-fixture", SecurityEpoch: 2, MinimumVerifierVersion: 1, ReleaseSignatureThreshold: 1, AllowedSlotIDs: []string{"a"}, RootKeyID: "root:fixture", RootKeyFingerprint: rootFingerprint, AuthorizationAuthorities: []stableverifier.AuthorizationAuthority{{KeyID: "authority:fixture", Algorithm: stableverifier.Ed25519Algorithm, PublicKey: "ed25519:" + strings.Repeat("1", 64)}}}
	for _, item := range []struct{ id, status string }{{"primary", "active"}, {"replacement", "active"}, {"revoked", "revoked"}} {
		key := fixtureKey(t)
		fixture.keys[item.id] = key
		public, fingerprint := fixturePublic(t, key)
		fixture.policy.DelegatedKeys = append(fixture.policy.DelegatedKeys, stableverifier.DelegatedKey{KeyID: item.id, Status: item.status, Algorithm: stableverifier.RSA2048SHA256Algorithm, PublicKeyPEM: string(public), PublicKeyFingerprint: fingerprint})
	}
	fixture.positive = stableverifier.Manifest{SchemaVersion: stableverifier.ManifestSchemaV1Alpha1, ReleaseID: "release:fixture", DeviceClass: stableverifier.DeviceClass, CohortID: fixture.policy.CohortID, SecurityEpoch: 2, SlotID: "a", Overlays: []stableverifier.Overlay{{Name: "dwc2", Digest: bundle.Sum([]byte("real-overlay-fixture")), SizeBytes: 20}}}
	for _, role := range stableverifier.ComponentRoles() {
		fixture.positive.Components = append(fixture.positive.Components, stableverifier.Component{Role: role, Digest: bundle.Sum([]byte(role)), SizeBytes: 32})
	}
	fixture.resign(t)
	return fixture
}
func (fixture *mutationFixture) resign(t *testing.T) {
	t.Helper()
	preimage, err := fixture.policy.SigningPreimage()
	if err != nil {
		t.Fatal(err)
	}
	fixture.policy.RootSignature = fixtureSignature(t, fixture.root, "root:fixture", preimage)
	fixture.positive.PolicyDigest, err = fixture.policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	fixture.positive.SecurityEpoch = fixture.policy.SecurityEpoch
	fixture.positive.Signatures = nil
	preimage, err = fixture.positive.SigningPreimage()
	if err != nil {
		t.Fatal(err)
	}
	fixture.positive.Signatures = []stableverifier.RSASignature{fixtureSignature(t, fixture.keys["primary"], "primary", preimage)}
	fixture.replacement = cloneMutationManifest(fixture.positive)
	fixture.replacement.Signatures = []stableverifier.RSASignature{fixtureSignature(t, fixture.keys["replacement"], "replacement", preimage)}
	fixture.revoked = cloneMutationManifest(fixture.positive)
	fixture.revoked.Signatures = []stableverifier.RSASignature{fixtureSignature(t, fixture.keys["revoked"], "revoked", preimage)}
}
func (fixture mutationFixture) input(t *testing.T) MutationInputs {
	t.Helper()
	policy, err := fixture.policy.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	positive, err := fixture.positive.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := fixture.replacement.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := fixture.revoked.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return MutationInputs{PolicyJSON: policy, RootPublicPEM: fixture.rootPEM, PositiveManifestJSON: positive, ReplacementManifestJSON: replacement, RevokedManifestJSON: revoked}
}

func TestBuildMutationsAuthenticatesThreeKeysAndExactSelectors(t *testing.T) {
	fixture := newMutationFixture(t)
	input := fixture.input(t)
	outputs, err := BuildMutations(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildMutations(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(outputs) != 20 {
		t.Fatalf("got %d outputs", len(outputs))
	}
	before := stablecampaign.ArtifactBinding{Name: "positive-release-manifest", Digest: bundle.Sum(input.PositiveManifestJSON), SizeBytes: uint64(len(input.PositiveManifestJSON))}
	for name, encoded := range outputs {
		if !bytes.Equal(encoded, second[name]) {
			t.Fatalf("non-deterministic output %s", name)
		}
	}
	for _, testCase := range stablecampaign.FixedCases() {
		if testCase.TestID != "manifest-field-mutations-rejected" {
			continue
		}
		for _, subcase := range testCase.Subcases {
			name := "manifest-field-" + subcase
			encoded := outputs[name+".json"]
			recipe, err := stablecampaign.NewBoundReplacementMutationRecipe(testCase.TestID, subcase, before, stablecampaign.ArtifactBinding{Name: name, Digest: bundle.Sum(encoded), SizeBytes: uint64(len(encoded))})
			if err != nil {
				t.Fatal(err)
			}
			if err := stablecampaign.ValidateBoundReplacement(recipe, input.PositiveManifestJSON, encoded); err != nil {
				t.Fatal(err)
			}
		}
	}
	var wrong, unsigned stableverifier.Manifest
	if err := json.Unmarshal(outputs["wrong-key-release-manifest.json"], &wrong); err != nil {
		t.Fatal(err)
	}
	if wrong.Signatures[0].KeyID != "primary" || wrong.Signatures[0].Value != fixture.replacement.Signatures[0].Value {
		t.Fatal("wrong-key mutation did not use independently verified replacement signature under primary identity")
	}
	if err := json.Unmarshal(outputs["unsigned-release-manifest.json"], &unsigned); err != nil {
		t.Fatal(err)
	}
	if unsigned.Signatures == nil || len(unsigned.Signatures) != 0 {
		t.Fatal("unsigned signatures must be an empty array")
	}
	if !bytes.Equal(outputs["replacement-release-manifest.json"], input.ReplacementManifestJSON) || !bytes.Equal(outputs["revoked-release-manifest.json"], input.RevokedManifestJSON) {
		t.Fatal("changed independently signed source manifests")
	}
	if !bytes.Equal(input.PositiveManifestJSON, fixture.input(t).PositiveManifestJSON) {
		t.Fatal("mutated caller input")
	}
	outputs["replacement-release-manifest.json"][0] = '!'
	if !bytes.Equal(input.ReplacementManifestJSON, fixture.input(t).ReplacementManifestJSON) {
		t.Fatal("output aliases caller input")
	}
}

func TestBuildMutationsRejectsFalseSignatureAndPolicyClaims(t *testing.T) {
	fixture := newMutationFixture(t)
	valid := fixture.input(t)
	for name, alter := range map[string]func(*MutationInputs){
		"wrong root": func(input *MutationInputs) { input.RootPublicPEM, _ = fixturePublic(t, fixture.keys["replacement"]) },
		"tampered root signature": func(input *MutationInputs) {
			var policy stableverifier.Policy
			json.Unmarshal(input.PolicyJSON, &policy)
			raw, _ := base64.StdEncoding.DecodeString(policy.RootSignature.Value)
			raw[0] ^= 1
			policy.RootSignature.Value = base64.StdEncoding.EncodeToString(raw)
			input.PolicyJSON, _ = policy.CanonicalJSON()
		},
		"replacement reuses primary": func(input *MutationInputs) { input.ReplacementManifestJSON = input.PositiveManifestJSON },
		"replacement key ID relabel": func(input *MutationInputs) {
			manifest := cloneMutationManifest(fixture.positive)
			manifest.Signatures[0].KeyID = "replacement"
			input.ReplacementManifestJSON, _ = manifest.CanonicalJSON()
		},
		"revoked key ID relabel": func(input *MutationInputs) {
			manifest := cloneMutationManifest(fixture.positive)
			manifest.Signatures[0].KeyID = "revoked"
			input.RevokedManifestJSON, _ = manifest.CanonicalJSON()
		},
		"active manifest supplied as revoked": func(input *MutationInputs) { input.RevokedManifestJSON = input.ReplacementManifestJSON },
		"replacement changes signed release": func(input *MutationInputs) {
			manifest := cloneMutationManifest(fixture.replacement)
			manifest.ReleaseID = "release:different"
			preimage, _ := manifest.SigningPreimage()
			manifest.Signatures[0] = fixtureSignature(t, fixture.keys["replacement"], "replacement", preimage)
			input.ReplacementManifestJSON, _ = manifest.CanonicalJSON()
		},
		"revoked changes signed release": func(input *MutationInputs) {
			manifest := cloneMutationManifest(fixture.revoked)
			manifest.ReleaseID = "release:different"
			preimage, _ := manifest.SigningPreimage()
			manifest.Signatures[0] = fixtureSignature(t, fixture.keys["revoked"], "revoked", preimage)
			input.RevokedManifestJSON, _ = manifest.CanonicalJSON()
		},
		"duplicate JSON key": func(input *MutationInputs) {
			input.PositiveManifestJSON = bytes.Replace(input.PositiveManifestJSON, []byte(`"slot_id":"a"`), []byte(`"slot_id":"a","slot_id":"a"`), 1)
		},
		"casefolded alias": func(input *MutationInputs) {
			input.PositiveManifestJSON = bytes.Replace(input.PositiveManifestJSON, []byte(`"slot_id"`), []byte(`"SLOT_ID"`), 1)
		},
		"private PEM": func(input *MutationInputs) {
			input.RootPublicPEM = []byte("-----BEGIN RSA PRIVATE KEY-----\nnot-public\n-----END RSA PRIVATE KEY-----\n")
		},
		"empty": func(input *MutationInputs) { input.PositiveManifestJSON = nil },
		"oversize": func(input *MutationInputs) {
			input.PositiveManifestJSON = bytes.Repeat([]byte("x"), MutationMetadataMaxBytes+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := valid
			alter(&input)
			if outputs, err := BuildMutations(input); err == nil || outputs != nil {
				t.Fatalf("accepted invalid source with outputs=%d error=%v", len(outputs), err)
			}
		})
	}
}

func TestBuildMutationsRequiresOverlayAndThresholdOne(t *testing.T) {
	fixture := newMutationFixture(t)
	fixture.policy.ReleaseSignatureThreshold = 2
	fixture.resign(t)
	if _, err := BuildMutations(fixture.input(t)); err == nil {
		t.Fatal("accepted threshold2")
	}
	fixture.policy.ReleaseSignatureThreshold = 1
	fixture.positive.Overlays = []stableverifier.Overlay{}
	fixture.resign(t)
	if _, err := BuildMutations(fixture.input(t)); err == nil {
		t.Fatal("accepted absent first overlay")
	}
}

func TestMutationValuesAvoidUintOverflowAndExistingCandidates(t *testing.T) {
	fixture := newMutationFixture(t)
	fixture.policy.SecurityEpoch = math.MaxUint64
	fixture.positive.ReleaseID = "campaign-mutation"
	fixture.positive.Overlays[0].Name = "campaign-mutation-0"
	fixture.resign(t)
	outputs, err := BuildMutations(fixture.input(t))
	if err != nil {
		t.Fatal(err)
	}
	var manifest stableverifier.Manifest
	json.Unmarshal(outputs["manifest-field-security-epoch.json"], &manifest)
	if manifest.SecurityEpoch != math.MaxUint64-1 {
		t.Fatalf("epoch wrapped to %d", manifest.SecurityEpoch)
	}
	json.Unmarshal(outputs["manifest-field-release-id.json"], &manifest)
	if manifest.ReleaseID == fixture.positive.ReleaseID {
		t.Fatal("release ID unchanged")
	}
	json.Unmarshal(outputs["manifest-field-overlay-name.json"], &manifest)
	if manifest.Overlays[0].Name == fixture.positive.Overlays[0].Name {
		t.Fatal("overlay name unchanged")
	}
}
