package stableverifier

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

type verifierTestKeys struct {
	root       *rsa.PrivateKey
	delegatedA *rsa.PrivateKey
	delegatedB *rsa.PrivateKey
}

type verifierFixture struct {
	base               string
	rootPEM            []byte
	policy             Policy
	manifest           Manifest
	components         map[ComponentRole][]byte
	overlays           map[string][]byte
	keys               verifierTestKeys
	writeExtra         func(Inputs) error
	replaceWithSymlink ComponentRole
}

func TestVerifyReleaseRetainsAuthenticatedClosure(t *testing.T) {
	keys := generateVerifierTestKeys(t)
	fixture := newVerifierFixture(t, keys)
	fixture.manifest.Overlays = []Overlay{
		{Name: "first", Digest: bundle.Sum([]byte("overlay-first")), SizeBytes: uint64(len("overlay-first"))},
		{Name: "second", Digest: bundle.Sum([]byte("overlay-second")), SizeBytes: uint64(len("overlay-second"))},
	}
	fixture.overlays = map[string][]byte{"first": []byte("overlay-first"), "second": []byte("overlay-second")}
	fixture.resignAll(t)
	inputs := fixture.write(t)

	verified, err := VerifyRelease(context.Background(), inputs, Requirements{
		VerifierVersion: 2, MinimumSecurityEpoch: 2, CohortID: "spike-cohort", SlotID: "spike",
	})
	if err != nil {
		t.Fatalf("VerifyRelease: %v", err)
	}
	defer verified.Close()
	if verified.PolicyDigest() != fixture.manifest.PolicyDigest {
		t.Fatalf("policy digest = %q, want %q", verified.PolicyDigest(), fixture.manifest.PolicyDigest)
	}
	wantManifestDigest, err := fixture.manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if verified.ManifestDigest() != wantManifestDigest {
		t.Fatalf("manifest digest = %q, want %q", verified.ManifestDigest(), wantManifestDigest)
	}
	if verified.KernelCommandLine() != "console=ttyAMA10 ro" {
		t.Fatalf("kernel command line = %q", verified.KernelCommandLine())
	}
	if got := verified.Components(); len(got) != len(componentRoles) || got[0].Role != RoleKernel || got[len(got)-1].Role != RoleSlotMetadata {
		t.Fatalf("components are not in canonical order: %#v", got)
	}
	if got := verified.Overlays(); len(got) != 2 || got[0].Name != "first" || got[1].Name != "second" {
		t.Fatalf("overlay order was not preserved: %#v", got)
	}
	kernel, err := verified.OpenComponent(RoleKernel)
	if err != nil {
		t.Fatal(err)
	}
	kernelBytes, err := io.ReadAll(kernel)
	kernel.Close()
	if err != nil || string(kernelBytes) != string(fixture.components[RoleKernel]) {
		t.Fatalf("retained kernel = %q, err %v", kernelBytes, err)
	}
	// Neither in-place mutation nor path replacement can alter a snapshotted
	// component after verification.
	kernelPath := filepath.Join(inputs.ReleaseDirectory, componentPaths[RoleKernel])
	if err := os.WriteFile(kernelPath, []byte("kernel-v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	frozenKernel, err := verified.OpenComponent(RoleKernel)
	if err != nil {
		t.Fatalf("OpenComponent after in-place mutation: %v", err)
	}
	frozenBytes, err := io.ReadAll(frozenKernel)
	if err != nil {
		frozenKernel.Close()
		t.Fatal(err)
	}
	if _, err := frozenKernel.WriteAt([]byte("mutation"), 0); err == nil {
		frozenKernel.Close()
		t.Fatal("sealed verified snapshot accepted a write")
	}
	frozenKernel.Close()
	if string(frozenBytes) != string(fixture.components[RoleKernel]) {
		t.Fatalf("in-place source mutation changed retained kernel to %q", frozenBytes)
	}
	if err := os.Rename(kernelPath, filepath.Join(fixture.base, "displaced-kernel")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kernelPath, []byte("attacker replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopenedKernel, err := verified.OpenComponent(RoleKernel)
	if err != nil {
		t.Fatalf("OpenComponent after path replacement: %v", err)
	}
	reopenedBytes, err := io.ReadAll(reopenedKernel)
	reopenedKernel.Close()
	if err != nil || string(reopenedBytes) != string(fixture.components[RoleKernel]) {
		t.Fatalf("path replacement changed retained kernel to %q, error %v", reopenedBytes, err)
	}

	if err := verified.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := verified.OpenComponent(RoleInitramfs); err == nil {
		t.Fatal("OpenComponent succeeded after Close")
	}
}

func TestVerifyReleaseAcceptsDelegatedKeyReplacement(t *testing.T) {
	keys := generateVerifierTestKeys(t)
	fixture := newVerifierFixture(t, keys)
	fixture.policy.DelegatedKeys[0].Status = "revoked"
	fixture.policy.DelegatedKeys[1].Status = "active"
	fixture.resignPolicy(t)
	fixture.bindAndSignManifest(t, "release-b", keys.delegatedB)
	inputs := fixture.write(t)

	verified, err := VerifyRelease(context.Background(), inputs, Requirements{
		VerifierVersion: 1, MinimumSecurityEpoch: 2, CohortID: "spike-cohort", SlotID: "spike",
	})
	if err != nil {
		t.Fatalf("replacement delegated key did not verify: %v", err)
	}
	verified.Close()
}

func TestVerifyReleaseAcceptsRequiredSignatureThreshold(t *testing.T) {
	keys := generateVerifierTestKeys(t)
	fixture := newVerifierFixture(t, keys)
	fixture.policy.DelegatedKeys[1].Status = "active"
	fixture.policy.ReleaseSignatureThreshold = 2
	fixture.resignPolicy(t)
	policyDigest, err := fixture.policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	fixture.manifest.PolicyDigest = policyDigest
	fixture.manifest.Signatures = nil
	preimage, err := fixture.manifest.SigningPreimage()
	if err != nil {
		t.Fatal(err)
	}
	fixture.manifest.Signatures = []RSASignature{
		{KeyID: "release-a", Algorithm: RSA2048SHA256Algorithm, Value: verifierSign(t, keys.delegatedA, preimage)},
		{KeyID: "release-b", Algorithm: RSA2048SHA256Algorithm, Value: verifierSign(t, keys.delegatedB, preimage)},
	}
	inputs := fixture.write(t)

	verified, err := VerifyRelease(context.Background(), inputs, Requirements{
		VerifierVersion: 1, MinimumSecurityEpoch: 2, CohortID: "spike-cohort", SlotID: "spike",
	})
	if err != nil {
		t.Fatalf("two-of-two delegated signatures did not verify: %v", err)
	}
	verified.Close()
}

func TestVerifyReleaseRejectsUntrustedInputs(t *testing.T) {
	keys := generateVerifierTestKeys(t)
	tests := []struct {
		name        string
		mutate      func(*testing.T, *verifierFixture)
		requirement Requirements
		want        string
	}{
		{
			name: "component mutation",
			mutate: func(t *testing.T, fixture *verifierFixture) {
				fixture.components[RoleKernel] = []byte("kernel-v2")
			},
			want: "file digest is",
		},
		{
			name: "noncanonical kernel command line",
			mutate: func(t *testing.T, fixture *verifierFixture) {
				fixture.components[RoleKernelCommandLine] = []byte("ro\ninit=/bin/sh\n")
				fixture.updateComponentBinding(RoleKernelCommandLine)
				fixture.signManifest(t, "release-a", keys.delegatedA)
			},
			want: "embedded line break",
		},
		{
			name: "extra release entry",
			mutate: func(t *testing.T, fixture *verifierFixture) {
				fixture.writeExtra = func(inputs Inputs) error {
					return os.WriteFile(filepath.Join(inputs.ReleaseDirectory, "recovery-shell"), []byte("no"), 0o600)
				}
			},
			want: "must contain exactly",
		},
		{
			name: "symlink component",
			mutate: func(t *testing.T, fixture *verifierFixture) {
				fixture.replaceWithSymlink = RoleKernel
			},
			want: "too many levels of symbolic links",
		},
		{
			name: "revoked signing key",
			mutate: func(t *testing.T, fixture *verifierFixture) {
				fixture.bindAndSignManifest(t, "release-b", keys.delegatedB)
			},
			want: "revoked delegated key",
		},
		{
			name: "unknown signing key",
			mutate: func(t *testing.T, fixture *verifierFixture) {
				fixture.manifest.Signatures[0].KeyID = "unknown"
			},
			want: "unknown delegated key",
		},
		{
			name: "bad delegated signature",
			mutate: func(t *testing.T, fixture *verifierFixture) {
				fixture.manifest.Signatures[0].Value = base64.StdEncoding.EncodeToString(make([]byte, 256))
			},
			want: "delegated signature",
		},
		{
			name: "bad root signature",
			mutate: func(t *testing.T, fixture *verifierFixture) {
				fixture.policy.RootSignature.Value = base64.StdEncoding.EncodeToString(make([]byte, 256))
				fixture.bindAndSignManifest(t, fixture.manifest.ReleaseID, keys.delegatedA)
			},
			want: "root policy signature",
		},
		{
			name: "signature threshold",
			mutate: func(t *testing.T, fixture *verifierFixture) {
				fixture.policy.DelegatedKeys[1].Status = "active"
				fixture.policy.ReleaseSignatureThreshold = 2
				fixture.resignAll(t)
			},
			want: "policy requires 2",
		},
		{
			name: "delegated key fingerprint",
			mutate: func(t *testing.T, fixture *verifierFixture) {
				fixture.policy.DelegatedKeys[0].PublicKeyFingerprint = bundle.Sum([]byte("wrong-key"))
				fixture.resignAll(t)
			},
			want: "fingerprint does not match",
		},
		{
			name: "minimum verifier version",
			mutate: func(t *testing.T, fixture *verifierFixture) {
				fixture.policy.MinimumVerifierVersion = 3
				fixture.resignAll(t)
			},
			requirement: Requirements{VerifierVersion: 2, MinimumSecurityEpoch: 2, CohortID: "spike-cohort", SlotID: "spike"},
			want:        "requires verifier version",
		},
		{
			name:        "security epoch rollback",
			requirement: Requirements{VerifierVersion: 2, MinimumSecurityEpoch: 3, CohortID: "spike-cohort", SlotID: "spike"},
			want:        "below required floor",
		},
		{
			name: "manifest policy epoch mismatch",
			mutate: func(t *testing.T, fixture *verifierFixture) {
				fixture.manifest.SecurityEpoch++
				fixture.signManifest(t, "release-a", keys.delegatedA)
			},
			want: "does not equal",
		},
		{
			name:        "selected slot mismatch",
			requirement: Requirements{VerifierVersion: 2, MinimumSecurityEpoch: 2, CohortID: "spike-cohort", SlotID: "other"},
			want:        "not authorized by policy",
		},
		{
			name: "slot metadata mismatch",
			mutate: func(t *testing.T, fixture *verifierFixture) {
				fixture.components[RoleSlotMetadata] = []byte("other\n")
				fixture.updateComponentBinding(RoleSlotMetadata)
				fixture.signManifest(t, "release-a", keys.delegatedA)
			},
			want: "slot metadata does not equal",
		},
		{
			name:        "cohort mismatch",
			requirement: Requirements{VerifierVersion: 2, MinimumSecurityEpoch: 2, CohortID: "other-cohort", SlotID: "spike"},
			want:        "policy cohort",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerifierFixture(t, keys)
			if test.mutate != nil {
				test.mutate(t, fixture)
			}
			inputs := fixture.write(t)
			requirements := test.requirement
			if requirements.VerifierVersion == 0 {
				requirements = Requirements{VerifierVersion: 2, MinimumSecurityEpoch: 2, CohortID: "spike-cohort", SlotID: "spike"}
			}
			verified, err := VerifyRelease(context.Background(), inputs, requirements)
			if verified != nil {
				verified.Close()
			}
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.want)) {
				t.Fatalf("VerifyRelease error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestStrictCanonicalJSON(t *testing.T) {
	keys := generateVerifierTestKeys(t)
	fixture := newVerifierFixture(t, keys)
	policyJSON, err := fixture.policy.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, err := fixture.manifest.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePolicy(append(policyJSON, '\n')); err != nil {
		t.Fatalf("canonical policy plus LF rejected: %v", err)
	}
	if _, err := ParseManifest(append(manifestJSON, '\n')); err != nil {
		t.Fatalf("canonical manifest plus LF rejected: %v", err)
	}
	if _, err := ParsePolicy(append([]byte(" "), policyJSON...)); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("noncanonical policy error = %v", err)
	}
	if _, err := ParseManifest(append([]byte(" "), manifestJSON...)); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("noncanonical manifest error = %v", err)
	}
	unknown := append([]byte(nil), manifestJSON[:len(manifestJSON)-1]...)
	unknown = append(unknown, []byte(`,"unknown":false}`)...)
	if _, err := ParseManifest(unknown); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown-field error = %v", err)
	}
	duplicate := strings.Replace(string(policyJSON), `"policy_id":"spike-policy"`, `"policy_id":"spike-policy","policy_id":"other"`, 1)
	if _, err := ParsePolicy([]byte(duplicate)); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate-field error = %v", err)
	}
	nullValue := strings.Replace(string(manifestJSON), `"overlays":[]`, `"overlays":null`, 1)
	if _, err := ParseManifest([]byte(nullValue)); err == nil || !strings.Contains(err.Error(), "null") {
		t.Fatalf("null-field error = %v", err)
	}
}

func TestSigningPreimagesDoNotRequireSignatures(t *testing.T) {
	keys := generateVerifierTestKeys(t)
	fixture := newVerifierFixture(t, keys)
	fixture.policy.RootSignature = RSASignature{}
	if _, err := fixture.policy.SigningPreimage(); err != nil {
		t.Fatalf("unsigned policy signing preimage: %v", err)
	}
	fixture.manifest.Signatures = nil
	if _, err := fixture.manifest.SigningPreimage(); err != nil {
		t.Fatalf("unsigned manifest signing preimage: %v", err)
	}
}

func generateVerifierTestKeys(t *testing.T) verifierTestKeys {
	t.Helper()
	generate := func() *rsa.PrivateKey {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	return verifierTestKeys{root: generate(), delegatedA: generate(), delegatedB: generate()}
}

func newVerifierFixture(t *testing.T, keys verifierTestKeys) *verifierFixture {
	t.Helper()
	components := map[ComponentRole][]byte{
		RoleKernel:             []byte("kernel-v1"),
		RoleInitramfs:          []byte("initramfs-v1"),
		RoleResolvedDeviceTree: []byte("resolved-device-tree-v1"),
		RoleKernelCommandLine:  []byte("console=ttyAMA10 ro\n"),
		RoleRootImage:          []byte("root-image-v1"),
		RoleDMVerityMetadata:   []byte(`{"root_hash":"test"}`),
		RoleSlotMetadata:       []byte("spike\n"),
	}
	rootPEM, rootFingerprint := verifierPublicKey(t, &keys.root.PublicKey)
	delegatedAPEM, delegatedAFingerprint := verifierPublicKey(t, &keys.delegatedA.PublicKey)
	delegatedBPEM, delegatedBFingerprint := verifierPublicKey(t, &keys.delegatedB.PublicKey)
	fixture := &verifierFixture{
		base: t.TempDir(), rootPEM: rootPEM, keys: keys, components: components,
		overlays: map[string][]byte{},
		policy: Policy{
			SchemaVersion: PolicySchemaV1Alpha1, PolicyID: "spike-policy", DeviceClass: DeviceClass,
			CohortID: "spike-cohort", SecurityEpoch: 2, MinimumVerifierVersion: 1,
			ReleaseSignatureThreshold: 1, AllowedSlotIDs: []string{"spike"},
			RootKeyID: "root-a", RootKeyFingerprint: rootFingerprint,
			DelegatedKeys: []DelegatedKey{
				{KeyID: "release-a", Algorithm: RSA2048SHA256Algorithm, PublicKeyPEM: string(delegatedAPEM), PublicKeyFingerprint: delegatedAFingerprint, Status: "active"},
				{KeyID: "release-b", Algorithm: RSA2048SHA256Algorithm, PublicKeyPEM: string(delegatedBPEM), PublicKeyFingerprint: delegatedBFingerprint, Status: "revoked"},
			},
			AuthorizationAuthorities: []AuthorizationAuthority{{
				KeyID: "authorization-a", Algorithm: Ed25519Algorithm, PublicKey: "ed25519:" + strings.Repeat("0", 64),
			}},
		},
	}
	fixture.manifest = Manifest{
		SchemaVersion: ManifestSchemaV1Alpha1, ReleaseID: "release-1", DeviceClass: DeviceClass,
		CohortID: "spike-cohort", SecurityEpoch: 2, SlotID: "spike",
		Components: make([]Component, 0, len(componentRoles)), Overlays: []Overlay{},
	}
	for _, role := range componentRoles {
		contents := fixture.components[role]
		fixture.manifest.Components = append(fixture.manifest.Components, Component{
			Role: role, Digest: bundle.Sum(contents), SizeBytes: uint64(len(contents)),
		})
	}
	fixture.resignAll(t)
	return fixture
}

func verifierPublicKey(t *testing.T, key *rsa.PublicKey) ([]byte, bundle.Digest) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), bundle.Sum(der)
}

func verifierSign(t *testing.T, key *rsa.PrivateKey, preimage []byte) string {
	t.Helper()
	digest := sha256.Sum256(preimage)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(signature)
}

func (fixture *verifierFixture) resignPolicy(t *testing.T) {
	t.Helper()
	preimage, err := fixture.policy.SigningPreimage()
	if err != nil {
		t.Fatal(err)
	}
	fixture.policy.RootSignature = RSASignature{
		KeyID: fixture.policy.RootKeyID, Algorithm: RSA2048SHA256Algorithm,
		Value: verifierSign(t, fixture.keys.root, preimage),
	}
}

func (fixture *verifierFixture) bindAndSignManifest(t *testing.T, keyID string, key *rsa.PrivateKey) {
	t.Helper()
	digest, err := fixture.policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	fixture.manifest.PolicyDigest = digest
	fixture.signManifest(t, keyID, key)
}

func (fixture *verifierFixture) signManifest(t *testing.T, keyID string, key *rsa.PrivateKey) {
	t.Helper()
	fixture.manifest.Signatures = nil
	preimage, err := fixture.manifest.SigningPreimage()
	if err != nil {
		t.Fatal(err)
	}
	fixture.manifest.Signatures = []RSASignature{{
		KeyID: keyID, Algorithm: RSA2048SHA256Algorithm, Value: verifierSign(t, key, preimage),
	}}
}

func (fixture *verifierFixture) resignAll(t *testing.T) {
	t.Helper()
	fixture.resignPolicy(t)
	fixture.bindAndSignManifest(t, "release-a", fixture.keys.delegatedA)
}

func (fixture *verifierFixture) updateComponentBinding(role ComponentRole) {
	for index := range fixture.manifest.Components {
		if fixture.manifest.Components[index].Role == role {
			contents := fixture.components[role]
			fixture.manifest.Components[index].Digest = bundle.Sum(contents)
			fixture.manifest.Components[index].SizeBytes = uint64(len(contents))
			return
		}
	}
}

func (fixture *verifierFixture) write(t *testing.T) Inputs {
	t.Helper()
	rootPath := filepath.Join(fixture.base, "root-public.pem")
	policyPath := filepath.Join(fixture.base, "policy.json")
	releaseDirectory := filepath.Join(fixture.base, "release")
	if err := os.Mkdir(releaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(releaseDirectory, overlayDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(path string, contents []byte) {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(rootPath, fixture.rootPEM)
	policyJSON, err := fixture.policy.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	write(policyPath, append(policyJSON, '\n'))
	manifestJSON, err := fixture.manifest.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(releaseDirectory, manifestFileName), append(manifestJSON, '\n'))
	for _, role := range componentRoles {
		path := filepath.Join(releaseDirectory, componentPaths[role])
		if role == fixture.replaceWithSymlink {
			target := filepath.Join(fixture.base, "symlink-target")
			write(target, fixture.components[role])
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			continue
		}
		write(path, fixture.components[role])
	}
	for name, contents := range fixture.overlays {
		write(filepath.Join(releaseDirectory, overlayDirectory, name+".dtbo"), contents)
	}
	inputs := Inputs{RootPublicKeyPath: rootPath, PolicyPath: policyPath, ReleaseDirectory: releaseDirectory}
	if fixture.writeExtra != nil {
		if err := fixture.writeExtra(inputs); err != nil {
			t.Fatal(err)
		}
	}
	return inputs
}
