package signedboot

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
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseintent"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5bootsig"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
)

const testSourceDateEpoch uint64 = 1_700_000_000

type testFixture struct {
	root                string
	plan                string
	expectedKey         string
	privateKey          *rsa.PrivateKey
	publicPEM           []byte
	fingerprint         bundle.Digest
	bootImage           []byte
	releaseIntentDigest bundle.Digest
}

func TestSignAndFinalize(t *testing.T) {
	fixture := newTestFixture(t, "release-2026-08", []byte("complete boot image"))
	signedDirectory := filepath.Join(fixture.root, "signed")
	finalDirectory := filepath.Join(fixture.root, "final")
	requested := 0
	config := fixture.signConfig(func(ctx context.Context, socketPath string, artifact []byte) (signinggate.Result, error) {
		requested++
		if socketPath != "/run/kaiba/signing-gate.sock" || string(artifact) != string(fixture.bootImage) {
			t.Fatal("signer received an unexpected socket or artifact")
		}
		return signForTest(t, fixture.privateKey, artifact, fixture.releaseIntentDigest), nil
	})
	if err := Sign(context.Background(), fixture.plan, signedDirectory, config); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if requested != 1 {
		t.Fatalf("signature requests = %d, want 1", requested)
	}
	requireDirectoryEntries(t, signedDirectory, "boot.sig", "signing-result.json")
	loadedPlan, err := LoadPlanDirectory(fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	loadedResult, err := LoadResultDirectory(signedDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyBindings(loadedPlan, loadedResult); err != nil {
		t.Fatalf("verifyBindings() error = %v", err)
	}
	if err := Finalize(fixture.plan, signedDirectory, finalDirectory); err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	requireDirectoryEntries(t, finalDirectory,
		"boot.img", "boot.sig", "manifest.json", "public.pem", "release-intent.json", "signing-plan.json", "signing-result.json",
	)
	if got := mustRead(t, filepath.Join(finalDirectory, "boot.img")); string(got) != string(fixture.bootImage) {
		t.Fatal("final boot.img differs from planned bytes")
	}
	if got := mustRead(t, filepath.Join(finalDirectory, "public.pem")); string(got) != string(fixture.publicPEM) {
		t.Fatal("final public.pem differs from planned bytes")
	}
	manifest, err := bundle.ParseManifest(mustRead(t, filepath.Join(finalDirectory, "manifest.json")))
	if err != nil {
		t.Fatalf("parse final manifest: %v", err)
	}
	if manifest.ManifestID != loadedPlan.Plan.PlanID || len(manifest.Artifacts) != 3 || manifest.SigningPolicyDigest != loadedResult.Result.SignerPolicyDigest {
		t.Fatalf("unexpected final manifest: %+v", manifest)
	}
}

func TestLoadPlanDirectoryWithIntentValidator(t *testing.T) {
	t.Run("custom canonical intent", func(t *testing.T) {
		fixture := newTestFixture(t, "custom-intent", []byte("boot"))
		canonicalIntent := []byte(`{"schema_version":"custom.intent/v1"}`)
		intentDigest := installCustomIntent(t, fixture.plan, canonicalIntent)
		calls := 0
		loaded, err := LoadPlanDirectoryWithIntentValidator(fixture.plan, func(encoded []byte, plan Plan) ([]byte, error) {
			calls++
			if !bytes.Equal(encoded, jsonFile(canonicalIntent)) {
				t.Fatal("intent validator received unexpected file bytes")
			}
			if plan.ReleaseIntentDigest != intentDigest {
				t.Fatal("intent validator received an unexpected plan")
			}
			return append([]byte(nil), canonicalIntent...), nil
		})
		if err != nil {
			t.Fatalf("LoadPlanDirectoryWithIntentValidator() error = %v", err)
		}
		if calls != 1 {
			t.Fatalf("intent validator calls = %d, want 1", calls)
		}
		if !bytes.Equal(loaded.ReleaseIntentJSON, canonicalIntent) {
			t.Fatal("loaded release intent is not the validator's canonical snapshot")
		}
	})

	t.Run("validator required", func(t *testing.T) {
		fixture := newTestFixture(t, "nil-validator", []byte("boot"))
		if _, err := LoadPlanDirectoryWithIntentValidator(fixture.plan, nil); err == nil || !strings.Contains(err.Error(), "validator is required") {
			t.Fatalf("LoadPlanDirectoryWithIntentValidator() error = %v, want missing-validator rejection", err)
		}
	})

	t.Run("validator error", func(t *testing.T) {
		fixture := newTestFixture(t, "validator-error", []byte("boot"))
		want := errors.New("custom intent binding failed")
		if _, err := LoadPlanDirectoryWithIntentValidator(fixture.plan, func([]byte, Plan) ([]byte, error) {
			return nil, want
		}); !errors.Is(err, want) {
			t.Fatalf("LoadPlanDirectoryWithIntentValidator() error = %v, want %v", err, want)
		}
	})

	t.Run("canonical bytes enforced", func(t *testing.T) {
		fixture := newTestFixture(t, "noncanonical-custom-intent", []byte("boot"))
		canonicalIntent := []byte(`{"schema_version":"custom.intent/v1"}`)
		installCustomIntent(t, fixture.plan, canonicalIntent)
		mustWrite(t, filepath.Join(fixture.plan, "release-intent.json"), []byte(`{ "schema_version":"custom.intent/v1"}`+"\n"))
		if _, err := LoadPlanDirectoryWithIntentValidator(fixture.plan, func([]byte, Plan) ([]byte, error) {
			return canonicalIntent, nil
		}); err == nil || !strings.Contains(err.Error(), "not canonical JSON") {
			t.Fatalf("LoadPlanDirectoryWithIntentValidator() error = %v, want canonical rejection", err)
		}
	})

	t.Run("fixed artifact checks remain mandatory", func(t *testing.T) {
		fixture := newTestFixture(t, "custom-intent-artifact-check", []byte("boot"))
		canonicalIntent := []byte(`{"schema_version":"custom.intent/v1"}`)
		installCustomIntent(t, fixture.plan, canonicalIntent)
		mustWrite(t, filepath.Join(fixture.plan, "boot.img"), []byte("evil"))
		if _, err := LoadPlanDirectoryWithIntentValidator(fixture.plan, func([]byte, Plan) ([]byte, error) {
			return canonicalIntent, nil
		}); err == nil || !strings.Contains(err.Error(), "digest") {
			t.Fatalf("LoadPlanDirectoryWithIntentValidator() error = %v, want artifact-digest rejection", err)
		}
	})
}

func TestSignAndFinalizeWithCustomPlanLoader(t *testing.T) {
	fixture := newTestFixture(t, "custom-loader", []byte("custom loader boot image"))
	canonicalIntent := []byte(`{"schema_version":"custom.intent/v1"}`)
	intentDigest := installCustomIntent(t, fixture.plan, canonicalIntent)
	loadCalls := 0
	load := func(path string) (LoadedPlan, error) {
		loadCalls++
		return LoadPlanDirectoryWithIntentValidator(path, func(encoded []byte, plan Plan) ([]byte, error) {
			if !bytes.Equal(encoded, jsonFile(canonicalIntent)) || plan.ReleaseIntentDigest != intentDigest {
				return nil, errors.New("custom intent does not bind the plan")
			}
			return append([]byte(nil), canonicalIntent...), nil
		})
	}

	signedDirectory := filepath.Join(fixture.root, "custom-signed")
	requested := 0
	config := fixture.signConfig(func(_ context.Context, _ string, artifact []byte) (signinggate.Result, error) {
		requested++
		return signForTest(t, fixture.privateKey, artifact, intentDigest), nil
	})
	if err := SignWithLoader(context.Background(), fixture.plan, signedDirectory, config, load); err != nil {
		t.Fatalf("SignWithLoader() error = %v", err)
	}
	if requested != 1 || loadCalls != 2 {
		t.Fatalf("signature requests = %d, plan loads = %d, want 1 and 2", requested, loadCalls)
	}

	finalDirectory := filepath.Join(fixture.root, "custom-final")
	if err := FinalizeWithLoader(fixture.plan, signedDirectory, finalDirectory, load); err != nil {
		t.Fatalf("FinalizeWithLoader() error = %v", err)
	}
	if loadCalls != 4 {
		t.Fatalf("plan loads after finalize = %d, want 4", loadCalls)
	}
	if got := mustRead(t, filepath.Join(finalDirectory, "release-intent.json")); !bytes.Equal(got, jsonFile(canonicalIntent)) {
		t.Fatal("final bundle does not contain the canonical custom intent")
	}
}

func TestFinalizeWithEvidenceValidatorChecksBothSnapshotsBeforePublish(t *testing.T) {
	fixture := newTestFixture(t, "authenticated-finalize", []byte("authenticated boot image"))
	signedDirectory := filepath.Join(fixture.root, "signed")
	if err := Sign(
		context.Background(),
		fixture.plan,
		signedDirectory,
		fixture.signConfig(func(_ context.Context, _ string, artifact []byte) (signinggate.Result, error) {
			return signForTest(t, fixture.privateKey, artifact, fixture.releaseIntentDigest), nil
		}),
	); err != nil {
		t.Fatal(err)
	}

	validated := 0
	finalDirectory := filepath.Join(fixture.root, "final")
	err := FinalizeWithLoaderAndEvidenceValidator(
		fixture.plan,
		signedDirectory,
		finalDirectory,
		LoadPlanDirectory,
		func(plan Plan, result Result, releaseIntentJSON, publicPEM []byte) error {
			validated++
			if plan.ReleaseIntentDigest != fixture.releaseIntentDigest ||
				result.GateReceiptDigest != bundle.Sum([]byte("durable gate receipt")) ||
				!bytes.Equal(publicPEM, fixture.publicPEM) || len(releaseIntentJSON) == 0 {
				return errors.New("evidence validator received the wrong immutable snapshot")
			}
			// The callback receives defensive copies, so even a buggy validator
			// cannot mutate the exact bytes later published by the finalizer.
			releaseIntentJSON[0] ^= 1
			publicPEM[0] ^= 1
			return nil
		},
	)
	if err != nil {
		t.Fatalf("FinalizeWithLoaderAndEvidenceValidator() error = %v", err)
	}
	if validated != 2 {
		t.Fatalf("evidence validation calls = %d, want 2", validated)
	}
	if !bytes.Equal(mustRead(t, filepath.Join(finalDirectory, "public.pem")), fixture.publicPEM) {
		t.Fatal("evidence validator mutated published plan bytes")
	}

	rejectedOutput := filepath.Join(fixture.root, "rejected-final")
	want := errors.New("receipt export rejected")
	err = FinalizeWithLoaderAndEvidenceValidator(
		fixture.plan,
		signedDirectory,
		rejectedOutput,
		LoadPlanDirectory,
		func(Plan, Result, []byte, []byte) error { return want },
	)
	if !errors.Is(err, want) {
		t.Fatalf("evidence rejection error = %v, want %v", err, want)
	}
	requirePathAbsent(t, rejectedOutput)
}

func TestCustomPlanLoaderFailuresDoNotPublish(t *testing.T) {
	t.Run("sign loader error", func(t *testing.T) {
		fixture := newTestFixture(t, "custom-loader-error", []byte("boot"))
		output := filepath.Join(fixture.root, "signed")
		requested := false
		config := fixture.signConfig(func(context.Context, string, []byte) (signinggate.Result, error) {
			requested = true
			return signinggate.Result{}, nil
		})
		want := errors.New("custom plan rejected")
		err := SignWithLoader(context.Background(), fixture.plan, output, config, func(string) (LoadedPlan, error) {
			return LoadedPlan{}, want
		})
		if !errors.Is(err, want) {
			t.Fatalf("SignWithLoader() error = %v, want %v", err, want)
		}
		if requested {
			t.Fatal("signer was called after the custom loader rejected the plan")
		}
		requirePathAbsent(t, output)
	})

	t.Run("sign changed second snapshot", func(t *testing.T) {
		fixture := newTestFixture(t, "custom-loader-change", []byte("boot"))
		output := filepath.Join(fixture.root, "signed")
		loaded, err := LoadPlanDirectory(fixture.plan)
		if err != nil {
			t.Fatal(err)
		}
		loads := 0
		load := func(string) (LoadedPlan, error) {
			loads++
			snapshot := loaded
			if loads == 2 {
				snapshot.ReleaseIntentJSON = append([]byte(nil), loaded.ReleaseIntentJSON...)
				snapshot.ReleaseIntentJSON[0] ^= 1
			}
			return snapshot, nil
		}
		config := fixture.signConfig(func(_ context.Context, _ string, artifact []byte) (signinggate.Result, error) {
			return signForTest(t, fixture.privateKey, artifact, fixture.releaseIntentDigest), nil
		})
		if err := SignWithLoader(context.Background(), fixture.plan, output, config, load); err == nil || !strings.Contains(err.Error(), "changed") {
			t.Fatalf("SignWithLoader() error = %v, want changed-plan rejection", err)
		}
		requirePathAbsent(t, output)
	})

	t.Run("finalize changed second snapshot", func(t *testing.T) {
		fixture := newTestFixture(t, "custom-finalize-change", []byte("boot"))
		signed := filepath.Join(fixture.root, "signed")
		if err := Sign(context.Background(), fixture.plan, signed, fixture.signConfig(func(_ context.Context, _ string, artifact []byte) (signinggate.Result, error) {
			return signForTest(t, fixture.privateKey, artifact, fixture.releaseIntentDigest), nil
		})); err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadPlanDirectory(fixture.plan)
		if err != nil {
			t.Fatal(err)
		}
		loads := 0
		load := func(string) (LoadedPlan, error) {
			loads++
			snapshot := loaded
			if loads == 2 {
				snapshot.PlanJSON = append([]byte(nil), loaded.PlanJSON...)
				snapshot.PlanJSON[0] ^= 1
			}
			return snapshot, nil
		}
		output := filepath.Join(fixture.root, "final")
		if err := FinalizeWithLoader(fixture.plan, signed, output, load); err == nil || !strings.Contains(err.Error(), "changed") {
			t.Fatalf("FinalizeWithLoader() error = %v, want changed-input rejection", err)
		}
		requirePathAbsent(t, output)
	})

	t.Run("nil loaders", func(t *testing.T) {
		fixture := newTestFixture(t, "nil-loaders", []byte("boot"))
		if err := SignWithLoader(context.Background(), fixture.plan, filepath.Join(fixture.root, "signed"), fixture.signConfig(nil), nil); err == nil || !strings.Contains(err.Error(), "loader is required") {
			t.Fatalf("SignWithLoader() error = %v, want missing-loader rejection", err)
		}
		if err := FinalizeWithLoader(fixture.plan, filepath.Join(fixture.root, "signed"), filepath.Join(fixture.root, "final"), nil); err == nil || !strings.Contains(err.Error(), "loader is required") {
			t.Fatalf("FinalizeWithLoader() error = %v, want missing-loader rejection", err)
		}
	})
}

func TestLoadPlanDirectoryRejectsMalformedOrUnsafeInputs(t *testing.T) {
	t.Run("extra file", func(t *testing.T) {
		fixture := newTestFixture(t, "extra-file", []byte("boot"))
		mustWrite(t, filepath.Join(fixture.plan, "extra"), []byte("no"))
		if _, err := LoadPlanDirectory(fixture.plan); err == nil || !strings.Contains(err.Error(), "exactly") {
			t.Fatalf("LoadPlanDirectory() error = %v, want exact-directory rejection", err)
		}
	})
	t.Run("symlink artifact", func(t *testing.T) {
		fixture := newTestFixture(t, "symlink-file", []byte("boot"))
		target := filepath.Join(fixture.root, "other-boot.img")
		mustWrite(t, target, fixture.bootImage)
		if err := os.Remove(filepath.Join(fixture.plan, "boot.img")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(fixture.plan, "boot.img")); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPlanDirectory(fixture.plan); err == nil {
			t.Fatal("LoadPlanDirectory() accepted a symlink artifact")
		}
	})
	t.Run("symlink directory", func(t *testing.T) {
		fixture := newTestFixture(t, "symlink-directory", []byte("boot"))
		alias := filepath.Join(fixture.root, "plan-alias")
		if err := os.Symlink(fixture.plan, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPlanDirectory(alias); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("LoadPlanDirectory() error = %v, want symlink rejection", err)
		}
	})
	t.Run("digest mismatch", func(t *testing.T) {
		fixture := newTestFixture(t, "digest-mismatch", []byte("boot"))
		mustWrite(t, filepath.Join(fixture.plan, "boot.img"), []byte("evil"))
		if _, err := LoadPlanDirectory(fixture.plan); err == nil || !strings.Contains(err.Error(), "digest") {
			t.Fatalf("LoadPlanDirectory() error = %v, want digest mismatch", err)
		}
	})

	for _, malformed := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"duplicate key", func(encoded []byte) []byte {
			return []byte(strings.Replace(string(encoded), `"plan_id":`, `"plan_id":"other","plan_id":`, 1))
		}},
		{"unknown field", func(encoded []byte) []byte {
			return []byte(strings.TrimSuffix(string(encoded), "}") + `,"unknown":true}`)
		}},
		{"trailing value", func(encoded []byte) []byte { return append(encoded, []byte("{}")...) }},
		{"alternate whitespace", func(encoded []byte) []byte {
			return bytes.Replace(encoded, []byte("{"), []byte("{ "), 1)
		}},
	} {
		t.Run(malformed.name, func(t *testing.T) {
			fixture := newTestFixture(t, "malformed-json", []byte("boot"))
			planPath := filepath.Join(fixture.plan, "plan.json")
			mustWrite(t, planPath, malformed.change(mustRead(t, planPath)))
			if _, err := LoadPlanDirectory(fixture.plan); err == nil {
				t.Fatalf("LoadPlanDirectory() accepted %s", malformed.name)
			}
		})
	}
}

func TestSignRejectsSubstitutionWrongKeyAndExistingOutput(t *testing.T) {
	t.Run("plan changes during signature", func(t *testing.T) {
		fixture := newTestFixture(t, "changing-plan", []byte("boot"))
		output := filepath.Join(fixture.root, "signed")
		config := fixture.signConfig(func(_ context.Context, _ string, artifact []byte) (signinggate.Result, error) {
			mustWrite(t, filepath.Join(fixture.plan, "boot.img"), []byte("evil"))
			return signForTest(t, fixture.privateKey, artifact, fixture.releaseIntentDigest), nil
		})
		if err := Sign(context.Background(), fixture.plan, output, config); err == nil {
			t.Fatal("Sign() accepted a substituted boot image")
		}
		if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("output exists after rejected substitution: %v", err)
		}
	})
	t.Run("wrong configured public key", func(t *testing.T) {
		fixture := newTestFixture(t, "wrong-key", []byte("boot"))
		wrong := newTestFixture(t, "other-key", []byte("boot"))
		config := fixture.signConfig(func(context.Context, string, []byte) (signinggate.Result, error) {
			t.Fatal("signer must not be called for the wrong configured key")
			return signinggate.Result{}, nil
		})
		config.ExpectedPublicKeyPath = wrong.expectedKey
		config.ExpectedPublicKeyFingerprint = wrong.fingerprint
		if err := Sign(context.Background(), fixture.plan, filepath.Join(fixture.root, "signed"), config); err == nil {
			t.Fatal("Sign() accepted a different linker-fixed key")
		}
	})
	t.Run("wrong planned signer policy", func(t *testing.T) {
		fixture := newTestFixture(t, "wrong-policy", []byte("boot"))
		planPath := filepath.Join(fixture.plan, "plan.json")
		loaded, err := LoadPlanDirectory(fixture.plan)
		if err != nil {
			t.Fatal(err)
		}
		loaded.Plan.SignerPolicyDigest = bundle.Sum([]byte("different signer policy"))
		encoded, err := loaded.Plan.CanonicalJSON()
		if err != nil {
			t.Fatal(err)
		}
		mustWrite(t, planPath, jsonFile(encoded))
		config := fixture.signConfig(func(context.Context, string, []byte) (signinggate.Result, error) {
			t.Fatal("signer must not be called for a mismatched planned policy")
			return signinggate.Result{}, nil
		})
		if err := Sign(context.Background(), fixture.plan, filepath.Join(fixture.root, "signed"), config); err == nil || !strings.Contains(err.Error(), "signer policy") {
			t.Fatalf("Sign() error = %v, want signer policy mismatch", err)
		}
	})
	t.Run("invalid gate signature", func(t *testing.T) {
		fixture := newTestFixture(t, "wrong-signature", []byte("boot"))
		wrong := newTestFixture(t, "wrong-signature-key", []byte("boot"))
		config := fixture.signConfig(func(_ context.Context, _ string, artifact []byte) (signinggate.Result, error) {
			return signForTest(t, wrong.privateKey, artifact, fixture.releaseIntentDigest), nil
		})
		if err := Sign(context.Background(), fixture.plan, filepath.Join(fixture.root, "signed"), config); err == nil || !strings.Contains(err.Error(), "verify") {
			t.Fatalf("Sign() error = %v, want signature verification failure", err)
		}
	})
	t.Run("wrong gate release intent", func(t *testing.T) {
		fixture := newTestFixture(t, "wrong-gate-intent", []byte("boot"))
		config := fixture.signConfig(func(_ context.Context, _ string, artifact []byte) (signinggate.Result, error) {
			return signForTest(t, fixture.privateKey, artifact, bundle.Sum([]byte("other release intent"))), nil
		})
		if err := Sign(context.Background(), fixture.plan, filepath.Join(fixture.root, "signed"), config); err == nil || !strings.Contains(err.Error(), "release intent") {
			t.Fatalf("Sign() error = %v, want release-intent mismatch", err)
		}
	})
	t.Run("pre-existing output", func(t *testing.T) {
		fixture := newTestFixture(t, "existing-output", []byte("boot"))
		output := filepath.Join(fixture.root, "signed")
		if err := os.Mkdir(output, 0o755); err != nil {
			t.Fatal(err)
		}
		called := false
		config := fixture.signConfig(func(context.Context, string, []byte) (signinggate.Result, error) {
			called = true
			return signinggate.Result{}, nil
		})
		if err := Sign(context.Background(), fixture.plan, output, config); err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("Sign() error = %v, want existing output rejection", err)
		}
		if called {
			t.Fatal("signer called before pre-existing output was rejected")
		}
	})
}

func TestFinalizeRejectsRawSignatureTamperingReplayAndExistingOutput(t *testing.T) {
	fixture := newTestFixture(t, "original-plan", []byte("boot"))
	signed := filepath.Join(fixture.root, "signed")
	if err := Sign(context.Background(), fixture.plan, signed, fixture.signConfig(func(_ context.Context, _ string, artifact []byte) (signinggate.Result, error) {
		return signForTest(t, fixture.privateKey, artifact, fixture.releaseIntentDigest), nil
	})); err != nil {
		t.Fatal(err)
	}

	t.Run("raw signature confusion", func(t *testing.T) {
		mutated := copyResultDirectory(t, signed, filepath.Join(fixture.root, "raw"))
		document, err := rpi5bootsig.Parse(mustRead(t, filepath.Join(mutated, "boot.sig")))
		if err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(mutated, "boot.sig"), document.Signature)
		result := mustParseResult(t, filepath.Join(mutated, "signing-result.json"))
		result.BootSignatureDigest = bundle.Sum(document.Signature)
		result.BootSignatureSizeBytes = uint64(len(document.Signature))
		writeResult(t, filepath.Join(mutated, "signing-result.json"), result)
		if err := Finalize(fixture.plan, mutated, filepath.Join(fixture.root, "raw-final")); err == nil || !strings.Contains(err.Error(), "parse canonical") {
			t.Fatalf("Finalize() error = %v, want raw signature rejection", err)
		}
	})

	t.Run("signature tampering", func(t *testing.T) {
		mutated := copyResultDirectory(t, signed, filepath.Join(fixture.root, "tampered"))
		document, err := rpi5bootsig.Parse(mustRead(t, filepath.Join(mutated, "boot.sig")))
		if err != nil {
			t.Fatal(err)
		}
		document.Signature[0] ^= 0x80
		encoded, err := document.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(mutated, "boot.sig"), encoded)
		result := mustParseResult(t, filepath.Join(mutated, "signing-result.json"))
		result.BootSignatureDigest = bundle.Sum(encoded)
		result.BootSignatureSizeBytes = uint64(len(encoded))
		writeResult(t, filepath.Join(mutated, "signing-result.json"), result)
		if err := Finalize(fixture.plan, mutated, filepath.Join(fixture.root, "tampered-final")); err == nil || !strings.Contains(err.Error(), "verify") {
			t.Fatalf("Finalize() error = %v, want cryptographic rejection", err)
		}
	})

	t.Run("result digest binding", func(t *testing.T) {
		mutated := copyResultDirectory(t, signed, filepath.Join(fixture.root, "result-mismatch"))
		result := mustParseResult(t, filepath.Join(mutated, "signing-result.json"))
		result.PlanDigest = bundle.Sum([]byte("other plan"))
		writeResult(t, filepath.Join(mutated, "signing-result.json"), result)
		if err := Finalize(fixture.plan, mutated, filepath.Join(fixture.root, "result-final")); err == nil || !strings.Contains(err.Error(), "exact signing plan") {
			t.Fatalf("Finalize() error = %v, want plan binding rejection", err)
		}
	})

	t.Run("result signer policy binding", func(t *testing.T) {
		mutated := copyResultDirectory(t, signed, filepath.Join(fixture.root, "policy-mismatch"))
		result := mustParseResult(t, filepath.Join(mutated, "signing-result.json"))
		result.SignerPolicyDigest = bundle.Sum([]byte("other signer policy"))
		writeResult(t, filepath.Join(mutated, "signing-result.json"), result)
		if err := Finalize(fixture.plan, mutated, filepath.Join(fixture.root, "policy-final")); err == nil || !strings.Contains(err.Error(), "signer policy") {
			t.Fatalf("Finalize() error = %v, want signer policy binding rejection", err)
		}
	})

	t.Run("result replay across plan ids", func(t *testing.T) {
		replayedPlan := makePlanDirectory(t, filepath.Join(fixture.root, "replayed-plan"), fixture.privateKey, "different-plan", fixture.bootImage, testSourceDateEpoch)
		if err := Finalize(replayedPlan, signed, filepath.Join(fixture.root, "replayed-final")); err == nil || !strings.Contains(err.Error(), "exact signing plan") {
			t.Fatalf("Finalize() error = %v, want replay rejection", err)
		}
	})

	t.Run("malformed result", func(t *testing.T) {
		mutated := copyResultDirectory(t, signed, filepath.Join(fixture.root, "malformed-result"))
		path := filepath.Join(mutated, "signing-result.json")
		encoded := mustRead(t, path)
		mustWrite(t, path, []byte(strings.Replace(string(encoded), `"plan_id":`, `"plan_id":"other","plan_id":`, 1)))
		if err := Finalize(fixture.plan, mutated, filepath.Join(fixture.root, "malformed-final")); err == nil {
			t.Fatal("Finalize() accepted duplicate result fields")
		}
	})

	t.Run("noncanonical result", func(t *testing.T) {
		mutated := copyResultDirectory(t, signed, filepath.Join(fixture.root, "noncanonical-result"))
		path := filepath.Join(mutated, "signing-result.json")
		encoded := mustRead(t, path)
		mustWrite(t, path, bytes.Replace(encoded, []byte("{"), []byte("{ "), 1))
		if err := Finalize(fixture.plan, mutated, filepath.Join(fixture.root, "noncanonical-final")); err == nil || !strings.Contains(err.Error(), "canonical JSON") {
			t.Fatalf("Finalize() error = %v, want canonical JSON rejection", err)
		}
	})

	t.Run("signature symlink", func(t *testing.T) {
		mutated := copyResultDirectory(t, signed, filepath.Join(fixture.root, "symlink-result"))
		target := filepath.Join(fixture.root, "saved-boot.sig")
		mustWrite(t, target, mustRead(t, filepath.Join(mutated, "boot.sig")))
		if err := os.Remove(filepath.Join(mutated, "boot.sig")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(mutated, "boot.sig")); err != nil {
			t.Fatal(err)
		}
		if err := Finalize(fixture.plan, mutated, filepath.Join(fixture.root, "symlink-final")); err == nil {
			t.Fatal("Finalize() accepted a symlink boot.sig")
		}
	})

	t.Run("pre-existing output", func(t *testing.T) {
		output := filepath.Join(fixture.root, "existing-final")
		mustWrite(t, output, []byte("preserve"))
		if err := Finalize(fixture.plan, signed, output); err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("Finalize() error = %v, want existing output rejection", err)
		}
		if got := string(mustRead(t, output)); got != "preserve" {
			t.Fatalf("existing output changed to %q", got)
		}
	})
}

func newTestFixture(t *testing.T, planID string, bootImage []byte) testFixture {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	publicPEM, fingerprint := canonicalPublicKey(t, &privateKey.PublicKey)
	expectedKey := filepath.Join(root, "expected-public.pem")
	mustWrite(t, expectedKey, publicPEM)
	plan := makePlanDirectory(t, filepath.Join(root, "plan"), privateKey, planID, bootImage, testSourceDateEpoch)
	loadedPlan, err := LoadPlanDirectory(plan)
	if err != nil {
		t.Fatal(err)
	}
	return testFixture{
		root: root, plan: plan, expectedKey: expectedKey, privateKey: privateKey,
		publicPEM: publicPEM, fingerprint: fingerprint, bootImage: append([]byte(nil), bootImage...),
		releaseIntentDigest: loadedPlan.Plan.ReleaseIntentDigest,
	}
}

func makePlanDirectory(t *testing.T, path string, privateKey *rsa.PrivateKey, planID string, bootImage []byte, epoch uint64) string {
	t.Helper()
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	publicPEM, fingerprint := canonicalPublicKey(t, &privateKey.PublicKey)
	policy, err := signing.NewDevelopmentYubiKeyPolicy(
		"kaiba-development", "rpi5-development", "pkcs11:token=kaiba-development;id=%02;type=private", fingerprint,
	)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	intentInputs := []bundle.Artifact{
		{Role: bundle.RoleBootImage, Digest: bundle.Sum(bootImage), SizeBytes: uint64(len(bootImage))},
		{Role: bundle.RoleEEPROMBootcode, Digest: bundle.Sum([]byte("EEPROM bootcode preimage")), SizeBytes: uint64(len("EEPROM bootcode preimage"))},
		{Role: bundle.RoleEEPROMBootsys, Digest: bundle.Sum([]byte("EEPROM bootsys preimage")), SizeBytes: uint64(len("EEPROM bootsys preimage"))},
		{Role: bundle.RoleEEPROMConfig, Digest: bundle.Sum([]byte("EEPROM config")), SizeBytes: uint64(len("EEPROM config"))},
		{Role: bundle.RoleOwnedRecoveryBootcode, Digest: bundle.Sum([]byte("owned recovery preimage")), SizeBytes: uint64(len("owned recovery preimage"))},
	}
	intent, err := releaseintent.New(releaseintent.Parameters{
		ReleaseID:                   "release:" + planID,
		SourceRevision:              strings.Repeat("a", 40),
		SourceDateEpoch:             epoch,
		UnsignedArtifactSetDigest:   bundle.Sum([]byte("unsigned artifact set")),
		EEPROMReleaseManifestDigest: bundle.Sum([]byte("EEPROM release manifest")),
		PublicKeyFingerprint:        fingerprint,
		SigningPolicyDigest:         policyDigest,
		ExpectedCustomerKeyHash:     bundle.Sum([]byte("customer public key")),
		SigningInputs:               intentInputs,
	})
	if err != nil {
		t.Fatal(err)
	}
	intentJSON, err := intent.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	intentDigest, err := intent.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{
		SchemaVersion: PlanSchemaV1Alpha2, PlanID: planID, ReleaseIntentDigest: intentDigest,
		BootImageDigest: bundle.Sum(bootImage), BootImageSizeBytes: uint64(len(bootImage)),
		PublicKeyFingerprint: fingerprint, SignerPolicyDigest: policyDigest, SourceDateEpoch: epoch,
	}
	encoded, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(path, "plan.json"), jsonFile(encoded))
	mustWrite(t, filepath.Join(path, "release-intent.json"), jsonFile(intentJSON))
	mustWrite(t, filepath.Join(path, "boot.img"), bootImage)
	mustWrite(t, filepath.Join(path, "public.pem"), publicPEM)
	return path
}

func installCustomIntent(t *testing.T, planDirectory string, canonicalIntent []byte) bundle.Digest {
	t.Helper()
	loaded, err := LoadPlanDirectory(planDirectory)
	if err != nil {
		t.Fatal(err)
	}
	intentDigest := bundle.Sum(canonicalIntent)
	loaded.Plan.ReleaseIntentDigest = intentDigest
	encodedPlan, err := loaded.Plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(planDirectory, "plan.json"), jsonFile(encodedPlan))
	mustWrite(t, filepath.Join(planDirectory, "release-intent.json"), jsonFile(canonicalIntent))
	return intentDigest
}

func canonicalPublicKey(t *testing.T, publicKey *rsa.PublicKey) ([]byte, bundle.Digest) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), bundle.Sum(der)
}

func (fixture testFixture) signConfig(request SignatureRequester) SignConfig {
	return SignConfig{
		GateSocketPath: "/run/kaiba/signing-gate.sock", SignerID: "kaiba-development",
		CohortID: "rpi5-development", PKCS11URI: "pkcs11:token=kaiba-development;id=%02;type=private",
		ExpectedPublicKeyPath: fixture.expectedKey, ExpectedPublicKeyFingerprint: fixture.fingerprint,
		RequestSignature: request,
	}
}

func signForTest(t *testing.T, privateKey *rsa.PrivateKey, artifact []byte, releaseIntentDigest bundle.Digest) signinggate.Result {
	t.Helper()
	digest := sha256.Sum256(artifact)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signinggate.Result{
		SignatureHex: hex.EncodeToString(signature), ReceiptDigest: bundle.Sum([]byte("durable gate receipt")),
		ReleaseIntentDigest: releaseIntentDigest,
	}
}

func copyResultDirectory(t *testing.T, source, destination string) string {
	t.Helper()
	if err := os.Mkdir(destination, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"boot.sig", "signing-result.json"} {
		mustWrite(t, filepath.Join(destination, name), mustRead(t, filepath.Join(source, name)))
	}
	return destination
}

func mustParseResult(t *testing.T, path string) Result {
	t.Helper()
	result, err := parseResult(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func writeResult(t *testing.T, path string, result Result) {
	t.Helper()
	encoded, err := result.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, path, jsonFile(encoded))
}

func mustWrite(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func requirePathAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path %s exists after rejected operation: %v", path, err)
	}
}

func requireDirectoryEntries(t *testing.T, directory string, expected ...string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		actual = append(actual, entry.Name())
	}
	sort.Strings(actual)
	sort.Strings(expected)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("directory entries = %v, want %v", actual, expected)
	}
}

func TestPlanAndResultRejectNonCanonicalDigests(t *testing.T) {
	fixture := newTestFixture(t, "canonical-digest", []byte("boot"))
	planPath := filepath.Join(fixture.plan, "plan.json")
	var fields map[string]any
	if err := json.Unmarshal(mustRead(t, planPath), &fields); err != nil {
		t.Fatal(err)
	}
	fields["boot_image_digest"] = strings.ToUpper(fields["boot_image_digest"].(string))
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, planPath, encoded)
	if _, err := LoadPlanDirectory(fixture.plan); err == nil {
		t.Fatal("LoadPlanDirectory() accepted a non-canonical digest")
	}
}

func TestPlanAndResultRejectOutOfRangeSourceDateEpoch(t *testing.T) {
	fixture := newTestFixture(t, "bounded-epoch", []byte("boot"))
	loaded, err := LoadPlanDirectory(fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Plan.SourceDateEpoch = maxSourceDateEpoch + 1
	if _, err := loaded.Plan.CanonicalJSON(); err == nil || !strings.Contains(err.Error(), "source_date_epoch") {
		t.Fatalf("Plan.CanonicalJSON() error = %v, want source_date_epoch rejection", err)
	}

	result := Result{
		SchemaVersion: ResultSchemaV1Alpha2, PlanID: loaded.Plan.PlanID,
		PlanDigest: loaded.PlanDigest, ReleaseIntentDigest: loaded.Plan.ReleaseIntentDigest,
		BootImageDigest:     loaded.Plan.BootImageDigest,
		BootImageSizeBytes:  loaded.Plan.BootImageSizeBytes,
		BootSignatureDigest: bundle.Sum([]byte("signature")), BootSignatureSizeBytes: 1,
		PublicKeyFingerprint: loaded.Plan.PublicKeyFingerprint,
		SignerPolicyDigest:   loaded.Plan.SignerPolicyDigest,
		GateReceiptDigest:    bundle.Sum([]byte("receipt")), SourceDateEpoch: maxSourceDateEpoch + 1,
	}
	if _, err := result.CanonicalJSON(); err == nil || !strings.Contains(err.Error(), "source_date_epoch") {
		t.Fatalf("Result.CanonicalJSON() error = %v, want source_date_epoch rejection", err)
	}
}

func TestPlanAndResultRejectOutOfRangeSizes(t *testing.T) {
	fixture := newTestFixture(t, "bounded-sizes", []byte("boot"))
	loaded, err := LoadPlanDirectory(fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Plan.BootImageSizeBytes = uint64(signing.MaxArtifactBytes) + 1
	if _, err := loaded.Plan.CanonicalJSON(); err == nil || !strings.Contains(err.Error(), "boot_image_size_bytes") {
		t.Fatalf("Plan.CanonicalJSON() error = %v, want boot image size rejection", err)
	}

	validResult := Result{
		SchemaVersion: ResultSchemaV1Alpha2, PlanID: loaded.Plan.PlanID,
		PlanDigest: loaded.PlanDigest, ReleaseIntentDigest: loaded.Plan.ReleaseIntentDigest,
		BootImageDigest:     loaded.Plan.BootImageDigest,
		BootImageSizeBytes:  uint64(len(fixture.bootImage)),
		BootSignatureDigest: bundle.Sum([]byte("signature")), BootSignatureSizeBytes: 1,
		PublicKeyFingerprint: loaded.Plan.PublicKeyFingerprint,
		SignerPolicyDigest:   loaded.Plan.SignerPolicyDigest,
		GateReceiptDigest:    bundle.Sum([]byte("receipt")), SourceDateEpoch: testSourceDateEpoch,
	}
	oversizedImage := validResult
	oversizedImage.BootImageSizeBytes = uint64(signing.MaxArtifactBytes) + 1
	if _, err := oversizedImage.CanonicalJSON(); err == nil || !strings.Contains(err.Error(), "boot_image_size_bytes") {
		t.Fatalf("oversized image Result.CanonicalJSON() error = %v", err)
	}
	oversizedSignature := validResult
	oversizedSignature.BootSignatureSizeBytes = maxBootSigBytes + 1
	if _, err := oversizedSignature.CanonicalJSON(); err == nil || !strings.Contains(err.Error(), "boot_signature_size_bytes") {
		t.Fatalf("oversized signature Result.CanonicalJSON() error = %v", err)
	}
}

func TestRenameNoReplacePreservesConcurrentEmptyDirectory(t *testing.T) {
	parent := t.TempDir()
	source := filepath.Join(parent, "prepared-output")
	target := filepath.Join(parent, "concurrent-output")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(source, "artifact"), []byte("prepared"))
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	targetBefore, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}

	err = renameNoReplace(source, target)
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("renameNoReplace() error = %v, want EEXIST", err)
	}
	if got := string(mustRead(t, filepath.Join(source, "artifact"))); got != "prepared" {
		t.Fatalf("source artifact changed to %q", got)
	}
	targetAfter, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(targetBefore, targetAfter) {
		t.Fatal("concurrently created target directory was replaced")
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("concurrently created target contains %d entries, want 0", len(entries))
	}
}

func TestNixSignerPolicyDigestGolden(t *testing.T) {
	fingerprint, err := bundle.ParseDigest("sha256:21bfca39f5db869c81f1fdab5f1d2569bdd5e67ef07ccfe0e3b6ddd792a6cfe1")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := signing.NewDevelopmentYubiKeyPolicy(
		"signer:development-fixture", "cohort:development-fixture",
		"pkcs11:serial=12345678;id=%02;type=private", fingerprint,
	)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	want := bundle.Digest("sha256:498534e04cf7a511356fbec7fac4ad994a692e352fa0db65e99e8ba0bdbc5d61")
	if digest != want {
		t.Fatalf("YubiKey policy digest = %s, want Nix contract %s", digest, want)
	}
}
