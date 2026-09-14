package stableverifiersigning

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signedboot"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signingapproval"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signingreceipts"
)

// VerifyEvidence authenticates the exact one-grant approval and receipt export
// accompanying a verifier plan/result snapshot. The caller must separately
// validate boot.sig and the result against the actual boot bytes, as Finalize
// does. It does not authenticate source provenance or reviewer attribution.
func VerifyEvidence(
	plan signedboot.Plan, result signedboot.Result,
	intentJSON, publicPEM, approvalJSON, registryJSON, receiptExportJSON []byte,
) error {
	canonical, err := ValidateIntentForPlan(intentJSON, plan)
	if err != nil {
		return err
	}
	intent, err := ParseIntent(canonical)
	if err != nil {
		return err
	}
	if bundle.Sum(publicPEM) != intent.PublicKeyFileDigest {
		return fmt.Errorf("public.pem digest does not match the verifier signing intent")
	}
	_, fingerprint, err := signingreceipts.ParsePublicKey(publicPEM)
	if err != nil {
		return fmt.Errorf("public.pem: %w", err)
	}
	if fingerprint != intent.PublicKeyFingerprint {
		return fmt.Errorf("public.pem fingerprint does not match the verifier signing intent")
	}
	if err := result.Validate(); err != nil {
		return fmt.Errorf("signing result: %w", err)
	}
	planDigest, err := plan.Digest()
	if err != nil {
		return err
	}
	if result.PlanID != plan.PlanID || result.PlanDigest != planDigest ||
		result.ReleaseIntentDigest != plan.ReleaseIntentDigest ||
		result.BootImageDigest != plan.BootImageDigest || result.BootImageSizeBytes != plan.BootImageSizeBytes ||
		result.PublicKeyFingerprint != plan.PublicKeyFingerprint || result.SignerPolicyDigest != plan.SignerPolicyDigest ||
		result.SourceDateEpoch != plan.SourceDateEpoch {
		return fmt.Errorf("signing result does not match the verifier signing plan")
	}
	approval, err := ParseApproval(approvalJSON)
	if err != nil {
		return fmt.Errorf("approval: %w", err)
	}
	registry, err := signingapproval.ParseRegistry(registryJSON)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	if err := (Authorization{Approval: approval, Registry: registry}).Validate(intent); err != nil {
		return fmt.Errorf("verifier signing authorization: %w", err)
	}
	exported, _, err := signingreceipts.ParseAndVerify(
		receiptExportJSON, registry, publicPEM, []bundle.Digest{result.GateReceiptDigest},
	)
	if err != nil {
		return fmt.Errorf("authenticated signing receipt: %w", err)
	}
	approvedAt, _ := parseCanonicalTime(approval.ApprovedAt, "approved_at")
	for _, record := range exported.Receipts {
		signedAt, err := time.Parse(time.RFC3339, record.Receipt.SignedAt)
		if err != nil || signedAt.Before(approvedAt) {
			return fmt.Errorf("authenticated signing receipt predates the approval")
		}
	}
	return nil
}

// Finalize verifies the verifier-only plan, boot signature/result and exact
// authenticated authorization evidence before publishing the standard seven
// signedboot files. The caller retains the separate public evidence and checks
// its unsigned manifest with ValidateUnsignedManifest. In particular, this
// operation does not infer source/build provenance from an intent digest.
func Finalize(planDirectory, signedDirectory, approvalPath, registryPath, receiptExportPath, outputDirectory string) error {
	approval, err := readEvidenceFile(approvalPath, MaxApprovalBytes+1, "approval")
	if err != nil {
		return err
	}
	registry, err := readEvidenceFile(registryPath, signinggate.MaxRegistryBytes, "registry")
	if err != nil {
		return err
	}
	receipts, err := readEvidenceFile(receiptExportPath, signingreceipts.MaxExportBytes, "receipt export")
	if err != nil {
		return err
	}
	return signedboot.FinalizeWithLoaderAndEvidenceValidator(
		planDirectory, signedDirectory, outputDirectory, LoadPlanDirectory,
		func(plan signedboot.Plan, result signedboot.Result, intentJSON, publicPEM []byte) error {
			return VerifyEvidence(plan, result, intentJSON, publicPEM, approval, registry, receipts)
		},
	)
}

func readEvidenceFile(path string, maximum int, label string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, fmt.Errorf("%s path must be absolute and clean", label)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", label, err)
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > int64(maximum) {
		return nil, fmt.Errorf("%s must be a regular non-symlink file of 1 through %d bytes", label, maximum)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("%s changed while opening", label)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(data) == 0 || len(data) > maximum || int64(len(data)) != opened.Size() {
		return nil, fmt.Errorf("read bounded %s", label)
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(opened, after) || after.Size() != opened.Size() || after.ModTime() != opened.ModTime() {
		return nil, fmt.Errorf("%s changed while reading", label)
	}
	return data, nil
}
