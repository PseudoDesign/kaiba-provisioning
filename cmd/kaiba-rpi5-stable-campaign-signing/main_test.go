package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signedboot"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signingapproval"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaignsigning"
)

func TestAuthorAndValidateAuthorizationUseExactStablePlan(t *testing.T) {
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
	approval, err := stablecampaignsigning.ParseApproval(approvalData)
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
	if err := (stablecampaignsigning.Authorization{Approval: approval, Registry: registry}).Validate(intent); err != nil {
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

func testLoadedPlan(t *testing.T) (signedboot.LoadedPlan, stablecampaignsigning.Intent) {
	t.Helper()
	digest := func(character string) bundle.Digest {
		return bundle.Digest("sha256:" + strings.Repeat(character, 64))
	}
	intent, err := stablecampaignsigning.NewIntent(stablecampaignsigning.IntentParameters{
		SourceRevision: "0123456789abcdef0123456789abcdef01234567", SourceDateEpoch: 1786968000,
		UnsignedManifestDigest: digest("1"), UnsignedArtifactSetDigest: digest("2"),
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
		SchemaVersion: signedboot.PlanSchemaV1Alpha2, PlanID: "stable:campaign:boot",
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
