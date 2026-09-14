package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signedboot"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signingapproval"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaignsigning"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stableverifiersigning"
)

func TestCanonicalReaderRejectsOpenSubstitution(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink", "regular file"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			path, replacement := filepath.Join(directory, "manifest.json"), filepath.Join(directory, "replacement")
			if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "fifo":
				if err := syscall.Mkfifo(replacement, 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(path, replacement); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(replacement, []byte("substitute"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			deps := productionDependencies()
			secureOpen := deps.open
			deps.open = func(name string) (*os.File, error) {
				if err := os.Rename(replacement, name); err != nil {
					return nil, err
				}
				return secureOpen(name)
			}
			result := make(chan error, 1)
			go func() {
				_, err := readCanonicalFile(path, 64, "manifest", deps)
				result <- err
			}()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("reader accepted a substituted input")
				}
			case <-time.After(time.Second):
				t.Fatal("reader blocked while opening a substituted input")
			}
		})
	}
}

func TestVerifierCommandRejectsProvisionerIntentBeforeAuthoring(t *testing.T) {
	loaded, intent := testLoadedPlan(t)
	provisioner, err := stablecampaignsigning.NewIntent(stablecampaignsigning.IntentParameters{
		SourceRevision: intent.SourceRevision, SourceDateEpoch: intent.SourceDateEpoch,
		UnsignedManifestDigest:    intent.UnsignedManifestDigest,
		UnsignedArtifactSetDigest: bundle.Sum([]byte("provisioner artifact set")),
		ExpectedCustomerKeyHash:   intent.ExpectedCustomerKeyHash, PublicKeyFileDigest: intent.PublicKeyFileDigest,
		PublicKeyFingerprint: intent.PublicKeyFingerprint, SignerPolicyDigest: intent.SignerPolicyDigest,
		SigningInput: intent.SigningInput,
	})
	if err != nil {
		t.Fatal(err)
	}
	loaded.ReleaseIntentJSON, err = provisioner.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	output := filepath.Join(parent, "authorization")
	var stdout, stderr bytes.Buffer
	status := run(context.Background(), []string{
		"author", "--plan", filepath.Join(parent, "plan"),
		"--reviewer-id", "reviewer:alice", "--approved-at", "2026-08-18T12:00:00Z",
		"--expires-at", "2026-08-18T16:00:00Z", "--output", output,
	}, &stdout, &stderr, testDependencies(loaded))
	if status != exitInvalid || stdout.Len() != 0 {
		t.Fatalf("provisioner author status/stdout/stderr = %d/%q/%q", status, stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("provisioner intent created authorization output: %v", err)
	}

	// Exercise the production loader too. Intent validation must fail before
	// accepting any public key or requesting a signature for the wrong profile.
	planDirectory := filepath.Join(parent, "plan")
	if err := os.Mkdir(planDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	loaded.Plan.ReleaseIntentDigest, err = provisioner.Digest()
	if err != nil {
		t.Fatal(err)
	}
	planJSON, err := loaded.Plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"plan.json": append(planJSON, '\n'), "release-intent.json": append(loaded.ReleaseIntentJSON, '\n'),
		"boot.img": []byte("unread wrong-profile fixture"), "public.pem": []byte("unread public-key fixture"),
	} {
		if err := os.WriteFile(filepath.Join(planDirectory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stdout.Reset()
	stderr.Reset()
	status = run(context.Background(), []string{"validate-plan", "--plan", planDirectory}, &stdout, &stderr, productionDependencies())
	if status != exitInvalid || stdout.Len() != 0 || !strings.Contains(stderr.String(), "signing intent") {
		t.Fatalf("production loader accepted wrong profile: %d/%q/%q", status, stdout.String(), stderr.String())
	}
}

func TestValidateAuthorizationRejectsBroadenedRegistry(t *testing.T) {
	loaded, intent := testLoadedPlan(t)
	authorization, err := stableverifiersigning.NewAuthorization(intent, "reviewer:alice", "2026-08-18T12:00:00Z", "2026-08-18T16:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	approvalJSON, err := authorization.Approval.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		alter func(*signinggate.Registry)
	}{
		{"second boot grant", func(registry *signinggate.Registry) {
			extra := registry.Grants[0]
			extra.GrantID = "grant:unapproved-second-boot"
			registry.Grants = append(registry.Grants, extra)
		}},
		{"different artifact", func(registry *signinggate.Registry) {
			registry.Grants[0].Request.ArtifactDigest = bundle.Sum([]byte("unapproved boot image"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry := authorization.Registry
			registry.Grants = append([]signinggate.Grant(nil), registry.Grants...)
			test.alter(&registry)
			registryJSON, err := json.Marshal(registry)
			if err != nil {
				t.Fatal(err)
			}
			parent := t.TempDir()
			approvalPath, registryPath := filepath.Join(parent, approvalFilename), filepath.Join(parent, registryFilename)
			if err := os.WriteFile(approvalPath, approvalJSON, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(registryPath, registryJSON, 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			status := run(context.Background(), []string{
				"validate-authorization", "--plan", filepath.Join(parent, "plan"),
				"--approval", approvalPath, "--registry", registryPath,
			}, &stdout, &stderr, testDependencies(loaded))
			if status != exitInvalid || stdout.Len() != 0 {
				t.Fatalf("broadened authorization accepted: %d/%q/%q", status, stdout.String(), stderr.String())
			}
		})
	}
}

func TestSigningAuthorityHasNoRuntimeOverrides(t *testing.T) {
	for _, option := range []string{
		"socket", "gate-socket", "signer-id", "cohort-id", "pkcs11-uri", "provider", "public-key", "private-key",
	} {
		t.Run(option, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			deps := dependencies{sign: func(context.Context, string, string) error {
				t.Fatal("signing ran despite an unsupported runtime authority override")
				return nil
			}}
			status := run(context.Background(), []string{
				"sign", "--plan", "/tmp/verifier-plan", "--output", "/tmp/signed-verifier",
				"--" + option, "unapproved-runtime-value",
			}, &stdout, &stderr, deps)
			if status != exitUsage || stdout.Len() != 0 {
				t.Fatalf("runtime override status/stdout/stderr = %d/%q/%q", status, stdout.String(), stderr.String())
			}
		})
	}
}

func TestUnconfiguredProductionSignerFailsBeforeOpeningInputs(t *testing.T) {
	if signingGateSocketPath != "" || signerID != "" || cohortID != "" || signingPKCS11URI != "" || expectedPublicKeyPath != "" || expectedPublicKeyFingerprint != "" {
		t.Skip("test requires the deliberately unconfigured source-build binary")
	}
	for _, name := range []string{"KAIBA_SIGNING_GATE_SOCKET", "KAIBA_SIGNER_ID", "KAIBA_COHORT_ID", "PKCS11_URI", "KAIBA_PUBLIC_KEY"} {
		t.Setenv(name, "not-an-authority-override")
	}
	parent := t.TempDir()
	output := filepath.Join(parent, "signed")
	err := productionSign(context.Background(), filepath.Join(parent, "missing-plan"), output)
	if err == nil || !strings.Contains(err.Error(), "linker-fixed public-key fingerprint") {
		t.Fatalf("unconfigured signer error = %v", err)
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unconfigured signer created output: %v", err)
	}
}

func TestValidateUnsignedBindsVerifierProfileAndExactManifestBytes(t *testing.T) {
	for _, test := range []struct {
		name       string
		alter      func(map[string]any)
		rebind     bool
		wantStatus int
	}{
		{"exact verifier manifest", func(map[string]any) {}, true, exitOK},
		{"substituted bytes", func(m map[string]any) { m["source_revision"] = strings.Repeat("b", 40) }, false, exitInvalid},
		{"provisioner profile", func(m map[string]any) {
			m["schema_version"] = "provisioning.kaiba.network/rpi5-stable-campaign-provisioner-artifact-set/v1alpha1"
		}, true, exitInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			loaded, intent := testLoadedPlan(t)
			manifest := map[string]any{
				"schema_version":     stableverifiersigning.UnsignedManifestSchemaV1Alpha1,
				"source_revision":    intent.SourceRevision,
				"pi_platform_source": map[string]any{"revision": strings.Repeat("a", 40), "nar_hash": "sha256-KT/OleUMpSKsWgi0eTuqS/0GD4ucPQcvLgmvlw8ZuCM="},
				"boot_image":         map[string]any{"path": "boot.img", "sha256": intent.SigningInput.Digest, "size_bytes": intent.SigningInput.SizeBytes},
				"files":              []string{"kaiba/authority-ca.pem", "kaiba/provenance.json", "kaiba/root-public.pem", "kaiba/stable-verifier", "kaiba/stable-verifier-policy.json", "kernel.img"},
				"hardware_observed":  false, "production_ready": false, "signing_status": "unsigned_requires_external_root_signature",
			}
			encoded, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			intent.UnsignedManifestDigest = bundle.Sum(encoded)
			test.alter(manifest)
			encoded, err = json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if test.rebind {
				intent.UnsignedManifestDigest = bundle.Sum(encoded)
			}
			loaded.ReleaseIntentJSON, err = intent.CanonicalJSON()
			if err != nil {
				t.Fatal(err)
			}
			loaded.Plan.ReleaseIntentDigest, err = intent.Digest()
			if err != nil {
				t.Fatal(err)
			}
			manifestPath := filepath.Join(t.TempDir(), "unsigned-manifest.json")
			if err := os.WriteFile(manifestPath, encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			status := run(context.Background(), []string{
				"validate-unsigned", "--plan", "/tmp/verifier-plan", "--manifest", manifestPath,
			}, &stdout, &stderr, testDependencies(loaded))
			if status != test.wantStatus || status != exitOK && stdout.Len() != 0 {
				t.Fatalf("validate-unsigned status/stdout/stderr = %d/%q/%q", status, stdout.String(), stderr.String())
			}
			if status == exitOK && !strings.Contains(stdout.String(), string(intent.UnsignedManifestDigest)) {
				t.Fatalf("valid manifest result omits its exact digest: %q", stdout.String())
			}
		})
	}
}

func TestAuthorAndValidateAuthorizationUseExactVerifierPlan(t *testing.T) {
	loaded, intent := testLoadedPlan(t)
	deps := testDependencies(loaded)
	parent := t.TempDir()
	output := filepath.Join(parent, "authorization")
	var stdout, stderr bytes.Buffer
	status := run(context.Background(), []string{
		"author", "--plan", filepath.Join(parent, "plan"),
		"--reviewer-id", "reviewer:alice", "--approved-at", "2026-08-18T12:00:00Z",
		"--expires-at", "2026-08-18T16:00:00Z", "--output", output,
	}, &stdout, &stderr, deps)
	if status != exitOK {
		t.Fatalf("author status = %d, stderr = %q", status, stderr.String())
	}
	var result struct {
		Status              string        `json:"status"`
		SigningIntentDigest bundle.Digest `json:"signing_intent_digest"`
		GrantCount          int           `json:"grant_count"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	intentDigest, _ := intent.Digest()
	if result.Status != "authored" || result.SigningIntentDigest != intentDigest || result.GrantCount != 1 {
		t.Fatalf("author result = %#v", result)
	}
	entries, err := os.ReadDir(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name() != approvalFilename || entries[1].Name() != registryFilename {
		t.Fatalf("authorization entries = %#v", entries)
	}
	approvalData, err := os.ReadFile(filepath.Join(output, approvalFilename))
	if err != nil {
		t.Fatal(err)
	}
	approval, err := stableverifiersigning.ParseApproval(approvalData)
	if err != nil {
		t.Fatal(err)
	}
	registryData, err := os.ReadFile(filepath.Join(output, registryFilename))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := signingapproval.ParseRegistry(registryData)
	if err != nil {
		t.Fatal(err)
	}
	if err := (stableverifiersigning.Authorization{Approval: approval, Registry: registry}).Validate(intent); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	status = run(context.Background(), []string{
		"validate-authorization", "--plan", filepath.Join(parent, "plan"),
		"--approval", filepath.Join(output, approvalFilename),
		"--registry", filepath.Join(output, registryFilename),
	}, &stdout, &stderr, deps)
	if status != exitOK || !strings.Contains(stdout.String(), `"grant_count":1`) {
		t.Fatalf("validate status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	status = run(context.Background(), []string{
		"author", "--plan", filepath.Join(parent, "plan"),
		"--reviewer-id", "reviewer:alice", "--approved-at", "2026-08-18T12:00:00Z",
		"--expires-at", "2026-08-18T16:00:00Z", "--output", output,
	}, &stdout, &stderr, deps)
	if status != exitInternal || !strings.Contains(stderr.String(), "file exists") {
		t.Fatalf("repeat author status = %d, stderr = %q", status, stderr.String())
	}
}

func TestAuthorRejectsInactiveApprovalBeforeWriting(t *testing.T) {
	loaded, _ := testLoadedPlan(t)
	parent := t.TempDir()
	for _, test := range []struct {
		name string
		now  string
		want string
	}{
		{"future", "2026-08-18T11:59:59Z", "future"},
		{"expired", "2026-08-18T16:00:00Z", "expired"},
	} {
		t.Run(test.name, func(t *testing.T) {
			deps := testDependencies(loaded)
			deps.now = func() time.Time {
				parsed, _ := time.Parse(time.RFC3339, test.now)
				return parsed
			}
			output := filepath.Join(parent, test.name)
			var stdout, stderr bytes.Buffer
			status := run(context.Background(), []string{
				"author", "--plan", filepath.Join(parent, "plan"),
				"--reviewer-id", "reviewer:alice", "--approved-at", "2026-08-18T12:00:00Z",
				"--expires-at", "2026-08-18T16:00:00Z", "--output", output,
			}, &stdout, &stderr, deps)
			if status != exitInvalid || !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("status = %d, stderr = %q", status, stderr.String())
			}
			if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("inactive approval created output: %v", err)
			}
		})
	}
}

func TestValidatePlanAndSigningCommandsDelegateExactDirectories(t *testing.T) {
	loaded, _ := testLoadedPlan(t)
	deps := testDependencies(loaded)
	var stdout, stderr bytes.Buffer
	status := run(context.Background(), []string{"validate-plan", "--plan", "/tmp/stable-plan"}, &stdout, &stderr, deps)
	if status != exitOK || !strings.Contains(stdout.String(), `"status":"valid"`) || !strings.Contains(stdout.String(), string(loaded.PlanDigest)) {
		t.Fatalf("validate-plan status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
	}

	var operation, plan, secondary, approval, registry, receiptExport, output string
	deps.sign = func(_ context.Context, planDirectory, outputDirectory string) error {
		operation, plan, output = "sign", planDirectory, outputDirectory
		return nil
	}
	status = run(context.Background(), []string{"sign", "--plan", "/tmp/plan", "--output", "/tmp/signed"}, &stdout, &stderr, deps)
	if status != exitOK || operation != "sign" || plan != "/tmp/plan" || output != "/tmp/signed" {
		t.Fatalf("sign delegation = %d/%q/%q/%q", status, operation, plan, output)
	}
	deps.finalize = func(
		planDirectory, signedDirectory, approvalPath, registryPath, receiptExportPath, outputDirectory string,
	) error {
		operation, plan, secondary = "finalize", planDirectory, signedDirectory
		approval, registry, receiptExport, output = approvalPath, registryPath, receiptExportPath, outputDirectory
		return nil
	}
	status = run(context.Background(), []string{
		"finalize", "--plan", "/tmp/plan", "--signed", "/tmp/signed",
		"--approval", "/tmp/approval.json", "--registry", "/tmp/signing-grants.json",
		"--receipt-export", "/tmp/signing-receipts.json", "--output", "/tmp/final",
	}, &stdout, &stderr, deps)
	if status != exitOK || operation != "finalize" || plan != "/tmp/plan" || secondary != "/tmp/signed" ||
		approval != "/tmp/approval.json" || registry != "/tmp/signing-grants.json" ||
		receiptExport != "/tmp/signing-receipts.json" || output != "/tmp/final" {
		t.Fatalf(
			"finalize delegation = %d/%q/%q/%q/%q/%q/%q/%q",
			status, operation, plan, secondary, approval, registry, receiptExport, output,
		)
	}
}

func TestFinalizeRequiresAuthenticatedEvidence(t *testing.T) {
	loaded, _ := testLoadedPlan(t)
	deps := testDependencies(loaded)
	deps.finalize = func(string, string, string, string, string, string) error {
		t.Fatal("finalizer ran without complete authenticated evidence")
		return nil
	}
	for _, omitted := range []string{"approval", "registry", "receipt-export"} {
		t.Run(omitted, func(t *testing.T) {
			arguments := []string{
				"finalize", "--plan", "/tmp/plan", "--signed", "/tmp/signed",
				"--approval", "/tmp/approval.json", "--registry", "/tmp/signing-grants.json",
				"--receipt-export", "/tmp/signing-receipts.json", "--output", "/tmp/final",
			}
			filtered := make([]string, 0, len(arguments))
			for index := 0; index < len(arguments); index++ {
				if arguments[index] == "--"+omitted {
					index++
					continue
				}
				filtered = append(filtered, arguments[index])
			}
			var stdout, stderr bytes.Buffer
			if status := run(context.Background(), filtered, &stdout, &stderr, deps); status != exitUsage {
				t.Fatalf("status = %d, stderr = %q", status, stderr.String())
			}
		})
	}
}

func TestCommandFailuresDoNotFallThrough(t *testing.T) {
	loaded, _ := testLoadedPlan(t)
	deps := testDependencies(loaded)
	deps.loadPlan = func(string) (signedboot.LoadedPlan, error) {
		return signedboot.LoadedPlan{}, errors.New("not canonical")
	}
	for _, args := range [][]string{
		{"validate-plan", "--plan", "/tmp/plan"},
		{"author", "--plan", "/tmp/plan", "--reviewer-id", "reviewer:alice", "--approved-at", "2026-08-18T12:00:00Z", "--expires-at", "2026-08-18T13:00:00Z", "--output", "/tmp/new"},
	} {
		var stdout, stderr bytes.Buffer
		if status := run(context.Background(), args, &stdout, &stderr, deps); status != exitInvalid || !strings.Contains(stderr.String(), "not canonical") {
			t.Fatalf("run(%q) status/stderr = %d/%q", args, status, stderr.String())
		}
	}
	deps.sign = func(context.Context, string, string) error { return errors.New("gate denied") }
	var stdout, stderr bytes.Buffer
	if status := run(context.Background(), []string{"sign", "--plan", "/tmp/plan", "--output", "/tmp/signed"}, &stdout, &stderr, deps); status != exitInternal || !strings.Contains(stderr.String(), "gate denied") {
		t.Fatalf("sign failure status/stderr = %d/%q", status, stderr.String())
	}
}

func testLoadedPlan(t *testing.T) (signedboot.LoadedPlan, stableverifiersigning.Intent) {
	t.Helper()
	digest := func(character string) bundle.Digest {
		return bundle.Digest("sha256:" + strings.Repeat(character, 64))
	}
	intent, err := stableverifiersigning.NewIntent(stableverifiersigning.IntentParameters{
		SourceRevision: "0123456789abcdef0123456789abcdef01234567", SourceDateEpoch: 1786968000,
		UnsignedManifestDigest:  digest("1"),
		ExpectedCustomerKeyHash: digest("3"), PublicKeyFileDigest: digest("4"),
		PublicKeyFingerprint: digest("5"), SignerPolicyDigest: digest("6"),
		SigningInput: bundle.Artifact{Role: bundle.RoleBootImage, Digest: digest("7"), SizeBytes: 100663296},
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
	plan := signedboot.Plan{
		SchemaVersion: signedboot.PlanSchemaV1Alpha2, PlanID: "stable:verifier:boot",
		ReleaseIntentDigest: intentDigest, BootImageDigest: intent.SigningInput.Digest,
		BootImageSizeBytes: intent.SigningInput.SizeBytes, PublicKeyFingerprint: intent.PublicKeyFingerprint,
		SignerPolicyDigest: intent.SignerPolicyDigest, SourceDateEpoch: intent.SourceDateEpoch,
	}
	planDigest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return signedboot.LoadedPlan{Plan: plan, ReleaseIntentJSON: intentJSON, PlanDigest: planDigest}, intent
}

func testDependencies(loaded signedboot.LoadedPlan) dependencies {
	now, _ := time.Parse(time.RFC3339, "2026-08-18T13:00:00Z")
	return dependencies{
		now: func() time.Time { return now },
		loadPlan: func(string) (signedboot.LoadedPlan, error) {
			return loaded, nil
		},
		lstat: os.Lstat, open: os.Open, mkdir: os.Mkdir,
		openFile: os.OpenFile, openDir: os.Open,
	}
}
