package stableverifiersigning

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signedboot"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signingapproval"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signingreceipts"
)

type evidenceFixture struct {
	root, planPath, signedPath               string
	approvalPath, registryPath, receiptsPath string
	plan                                     signedboot.LoadedPlan
	result                                   signedboot.LoadedResult
	intent                                   Intent
	authorization                            Authorization
	approvalJSON, registryJSON, receiptsJSON []byte
}

// The fixture signs only synthetic bytes with a newly generated, test-local
// software key. Its descriptor digest is a source assertion; the separate
// manifest tests and Nix integration exercise actual verifier artifact shape.
func newEvidenceFixture(t *testing.T) evidenceFixture {
	t.Helper()
	return newEvidenceFixtureWithTimes(t, "2026-08-18T13:00:00Z", testApprovedAt)
}

func newEvidenceFixtureWithTimes(t *testing.T, signedAt, intentAt string) evidenceFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	fingerprint := bundle.Sum(der)
	policy, err := signing.NewDevelopmentYubiKeyPolicy("kaiba-development", "rpi5-development", "pkcs11:token=kaiba-development;id=%02;type=private", fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	boot := []byte("one synthetic verifier boot image")
	intent := testIntent(t)
	intent.PublicKeyFileDigest = bundle.Sum(publicPEM)
	intent.PublicKeyFingerprint = fingerprint
	intent.SignerPolicyDigest = policyDigest
	intent.SigningInput = bundle.Artifact{Role: bundle.RoleBootImage, Digest: bundle.Sum(boot), SizeBytes: uint64(len(boot))}
	intentJSON, err := intent.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	intentDigest, err := intent.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan := signedboot.Plan{SchemaVersion: signedboot.PlanSchemaV1Alpha2, PlanID: "verifier:synthetic", ReleaseIntentDigest: intentDigest, BootImageDigest: intent.SigningInput.Digest, BootImageSizeBytes: intent.SigningInput.SizeBytes, PublicKeyFingerprint: fingerprint, SignerPolicyDigest: policyDigest, SourceDateEpoch: intent.SourceDateEpoch}
	planJSON, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	planPath := filepath.Join(root, "plan")
	if err := os.Mkdir(planPath, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(planPath, "plan.json"), append(planJSON, '\n'))
	writeTestFile(t, filepath.Join(planPath, "release-intent.json"), append(intentJSON, '\n'))
	writeTestFile(t, filepath.Join(planPath, "public.pem"), publicPEM)
	writeTestFile(t, filepath.Join(planPath, "boot.img"), boot)
	authorization, err := NewAuthorization(intent, "reviewer:alice", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	approvalJSON, err := authorization.Approval.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	registryJSON, err := signingapproval.CanonicalRegistryJSON(authorization.Registry)
	if err != nil {
		t.Fatal(err)
	}
	grant := authorization.Registry.Grants[0]
	var state signinggate.DurableState
	requests := 0
	signedPath := filepath.Join(root, "signed")
	err = signedboot.SignWithLoader(context.Background(), planPath, signedPath, signedboot.SignConfig{
		GateSocketPath: "/run/kaiba/signing-gate.sock", SignerID: "kaiba-development", CohortID: "rpi5-development",
		PKCS11URI: "pkcs11:token=kaiba-development;id=%02;type=private", ExpectedPublicKeyPath: filepath.Join(planPath, "public.pem"), ExpectedPublicKeyFingerprint: fingerprint,
		RequestSignature: func(_ context.Context, socket string, artifact []byte) (signinggate.Result, error) {
			requests++
			if requests != 1 || socket != "/run/kaiba/signing-gate.sock" || !bytes.Equal(artifact, boot) {
				t.Fatal("signer was asked for bytes outside the sole approved boot input")
			}
			digest := sha256.Sum256(artifact)
			signature, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			requestDigest, err := grant.Request.Digest()
			if err != nil {
				t.Fatal(err)
			}
			receipt := signinggate.Receipt{SchemaVersion: signinggate.ReceiptSchemaV1Alpha3, Grant: grant, RequestDigest: requestDigest, BackendID: "backend:synthetic-verifier", SignatureHex: hex.EncodeToString(signature), SignatureDigest: bundle.Sum(signature), SignedAt: signedAt}
			attestation, err := receipt.CanonicalAttestation()
			if err != nil {
				t.Fatal(err)
			}
			attestationDigest := sha256.Sum256(attestation)
			attestationSignature, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, attestationDigest[:])
			if err != nil {
				t.Fatal(err)
			}
			receipt, err = receipt.WithAttestationSignature(attestationSignature)
			if err != nil {
				t.Fatal(err)
			}
			receiptDigest, err := receipt.Digest()
			if err != nil {
				t.Fatal(err)
			}
			state = signinggate.DurableState{SchemaVersion: signinggate.StateSchemaV1Alpha3, Status: signinggate.StateComplete, GrantID: grant.GrantID, RequestDigest: requestDigest, ArtifactDigest: grant.Request.ArtifactDigest, IntentAt: intentAt, Receipt: &receipt}
			return signinggate.Result{SignatureHex: receipt.SignatureHex, ReceiptDigest: receiptDigest, ReleaseIntentDigest: intentDigest, GrantID: grant.GrantID}, nil
		},
	}, LoadPlanDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("got %d signing requests", requests)
	}
	exported, err := signingreceipts.New(authorization.Registry, []signinggate.DurableState{state}, publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	receiptsJSON, err := exported.CanonicalJSON(authorization.Registry, publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	loadedPlan, err := LoadPlanDirectory(planPath)
	if err != nil {
		t.Fatal(err)
	}
	loadedResult, err := signedboot.LoadResultDirectory(signedPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture := evidenceFixture{root: root, planPath: planPath, signedPath: signedPath, approvalPath: filepath.Join(root, "approval.json"), registryPath: filepath.Join(root, "signing-grants.json"), receiptsPath: filepath.Join(root, "signing-receipts.json"), plan: loadedPlan, result: loadedResult, intent: intent, authorization: authorization, approvalJSON: approvalJSON, registryJSON: registryJSON, receiptsJSON: receiptsJSON}
	writeTestFile(t, fixture.approvalPath, append(approvalJSON, '\n'))
	writeTestFile(t, fixture.registryPath, append(registryJSON, '\n'))
	writeTestFile(t, fixture.receiptsPath, receiptsJSON)
	return fixture
}

func TestFinalizeAuthenticatesExactVerifierEvidence(t *testing.T) {
	fixture := newEvidenceFixture(t)
	out := filepath.Join(fixture.root, "final")
	if err := Finalize(fixture.planPath, fixture.signedPath, fixture.approvalPath, fixture.registryPath, fixture.receiptsPath, out); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 7 {
		t.Fatalf("final output has %d files, want seven", len(entries))
	}
	for _, name := range []string{"boot.img", "public.pem", "release-intent.json"} {
		original, err := os.ReadFile(filepath.Join(fixture.planPath, name))
		if err != nil {
			t.Fatal(err)
		}
		actual, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(original, actual) {
			t.Fatalf("published %s changed approved bytes", name)
		}
	}
	if err := Finalize(fixture.planPath, fixture.signedPath, fixture.approvalPath, fixture.registryPath, fixture.receiptsPath, out); err == nil {
		t.Fatal("finalizer replaced an existing output")
	}
}

func TestVerifyEvidenceRejectsForgedMissingAndUnselectedEvidence(t *testing.T) {
	fixture := newEvidenceFixture(t)
	for name, mutate := range map[string]func(*signedboot.Result, *[]byte, *[]byte, *[]byte){
		"missing approval":       func(_ *signedboot.Result, a, r, e *[]byte) { *a = nil },
		"missing registry":       func(_ *signedboot.Result, a, r, e *[]byte) { *r = nil },
		"missing receipts":       func(_ *signedboot.Result, a, r, e *[]byte) { *e = nil },
		"wrong receipt selected": func(result *signedboot.Result, a, r, e *[]byte) { result.GateReceiptDigest = testDigest("f") },
		"changed result input":   func(result *signedboot.Result, a, r, e *[]byte) { result.BootImageDigest = testDigest("f") },
		"changed registry identity": func(_ *signedboot.Result, a, r, e *[]byte) {
			*r = bytes.Replace(*r, []byte("grant:"), []byte("grant:changed:"), 1)
		},
		"forged attestation with matching digest": func(result *signedboot.Result, a, r, e *[]byte) {
			var exported signingreceipts.Export
			if err := json.Unmarshal(*e, &exported); err != nil {
				t.Fatal(err)
			}
			forged := make([]byte, 256)
			exported.Receipts[0].Receipt.AttestationSignatureHex = hex.EncodeToString(forged)
			exported.Receipts[0].Receipt.AttestationSignatureDigest = bundle.Sum(forged)
			// The receipt digest includes the forged attestation, so update
			// it too; cryptographic authentication must still fail.
			digest, err := exported.Receipts[0].Receipt.Digest()
			if err != nil {
				t.Fatal(err)
			}
			exported.Receipts[0].ReceiptDigest = digest
			result.GateReceiptDigest = digest
			*e, err = json.Marshal(exported)
			if err != nil {
				t.Fatal(err)
			}
			*e = append(*e, '\n')
		},
	} {
		t.Run(name, func(t *testing.T) {
			result := fixture.result.Result
			approval, registry, receipts := bytes.Clone(fixture.approvalJSON), bytes.Clone(fixture.registryJSON), bytes.Clone(fixture.receiptsJSON)
			mutate(&result, &approval, &registry, &receipts)
			err := VerifyEvidence(fixture.plan.Plan, result, fixture.plan.ReleaseIntentJSON, fixture.plan.PublicPEM, approval, registry, receipts)
			if err == nil {
				t.Fatal("accepted substituted or unauthenticated verifier evidence")
			}
			if name == "forged attestation with matching digest" && !strings.Contains(err.Error(), "attestation signature does not verify") {
				t.Fatalf("forged metadata failed for an unrelated reason: %v", err)
			}
		})
	}
}

func TestFinalizePublishesNothingForInvalidReceipt(t *testing.T) {
	fixture := newEvidenceFixture(t)
	writeTestFile(t, fixture.receiptsPath, []byte("{}"))
	out := filepath.Join(fixture.root, "refused")
	if err := Finalize(fixture.planPath, fixture.signedPath, fixture.approvalPath, fixture.registryPath, fixture.receiptsPath, out); err == nil {
		t.Fatal("finalizer accepted missing authenticated receipt")
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("failed finalizer published output: %v", err)
	}
}

func TestLoadPlanBindsPublicPEMBytesBeforeGate(t *testing.T) {
	fixture := newEvidenceFixture(t)
	intent := fixture.intent
	intent.PublicKeyFileDigest = testDigest("f")
	intentJSON, err := intent.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	plan := fixture.plan.Plan
	plan.ReleaseIntentDigest, err = intent.Digest()
	if err != nil {
		t.Fatal(err)
	}
	planJSON, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(fixture.planPath, "release-intent.json"), append(intentJSON, '\n'))
	writeTestFile(t, filepath.Join(fixture.planPath, "plan.json"), append(planJSON, '\n'))
	if _, err := LoadPlanDirectory(fixture.planPath); err == nil || !strings.Contains(err.Error(), "public.pem digest") {
		t.Fatalf("loader did not reject changed PEM identity: %v", err)
	}
}

func TestEvidenceReaderIsBoundedAndRejectsSpecialFiles(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "regular")
	writeTestFile(t, regular, []byte("bounded"))
	link := filepath.Join(directory, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(directory, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{directory, link, fifo} {
		t.Run(filepath.Base(name), func(t *testing.T) {
			done := make(chan error, 1)
			go func() { _, err := readEvidenceFile(name, 64, "test"); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("accepted a non-regular evidence file")
				}
			case <-time.After(time.Second):
				t.Fatal("blocked reading special evidence file")
			}
		})
	}
	if _, err := readEvidenceFile(regular, 3, "test"); err == nil {
		t.Fatal("accepted oversized evidence")
	}
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyEvidenceRejectsAuthenticatedReceiptBeforeApproval(t *testing.T) {
	fixture := newEvidenceFixtureWithTimes(t, "2026-08-18T11:59:59Z", "2026-08-18T11:00:00Z")
	err := VerifyEvidence(fixture.plan.Plan, fixture.result.Result, fixture.plan.ReleaseIntentJSON, fixture.plan.PublicPEM, fixture.approvalJSON, fixture.registryJSON, fixture.receiptsJSON)
	if err == nil || !strings.Contains(err.Error(), "predates the approval") {
		t.Fatalf("authenticated receipt outside approval window was not rejected: %v", err)
	}
}
