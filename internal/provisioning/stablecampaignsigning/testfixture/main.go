// Command testfixture emits deterministic, public evidence for the stable
// campaign's one-artifact signing integration test. It is deliberately kept
// below internal/ and is not installed in any production package.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signedboot"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signingapproval"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signingreceipts"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaignsigning"
)

const (
	fixtureBackendID  = "backend:nix-stable-campaign-fixture"
	fixtureSocketPath = "/run/kaiba-stable-campaign-fixture/signing.sock"
	maxPrivateKeySize = 64 * 1024
)

type options struct {
	planDirectory string
	privateKey    string
	output        string
	signerID      string
	cohortID      string
	pkcs11URI     string
	reviewerID    string
	approvedAt    string
	expiresAt     string
	signedAt      string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	configuration, err := parseOptions(arguments)
	if err != nil {
		return err
	}
	loadedPlan, err := stablecampaignsigning.LoadPlanDirectory(configuration.planDirectory)
	if err != nil {
		return err
	}
	intent, err := stablecampaignsigning.ParseIntent(loadedPlan.ReleaseIntentJSON)
	if err != nil {
		return fmt.Errorf("parse stable signing intent: %w", err)
	}
	privateKey, publicPEM, err := loadPrivateKey(configuration.privateKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(publicPEM, loadedPlan.PublicPEM) {
		return errors.New("fixture private key does not match the stable signing plan public.pem")
	}

	authorization, err := stablecampaignsigning.NewAuthorization(
		intent, configuration.reviewerID, configuration.approvedAt, configuration.expiresAt,
	)
	if err != nil {
		return fmt.Errorf("construct stable fixture authorization: %w", err)
	}
	if err := validateSignedAt(configuration.approvedAt, configuration.expiresAt, configuration.signedAt); err != nil {
		return err
	}
	approvalJSON, err := authorization.Approval.CanonicalJSON()
	if err != nil {
		return err
	}
	registryJSON, err := signingapproval.CanonicalRegistryJSON(authorization.Registry)
	if err != nil {
		return err
	}

	if err := os.Mkdir(configuration.output, 0o755); err != nil {
		return fmt.Errorf("create stable fixture output: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(configuration.output)
		}
	}()
	authorizationDirectory := filepath.Join(configuration.output, "authorization")
	if err := os.Mkdir(authorizationDirectory, 0o755); err != nil {
		return fmt.Errorf("create fixture authorization directory: %w", err)
	}
	if err := writeNewFile(filepath.Join(authorizationDirectory, "approval.json"), append(approvalJSON, '\n')); err != nil {
		return err
	}
	if err := writeNewFile(filepath.Join(authorizationDirectory, "signing-grants.json"), append(registryJSON, '\n')); err != nil {
		return err
	}

	var completeState *signinggate.DurableState
	requestCount := 0
	requestSignature := func(_ context.Context, socketPath string, artifact []byte) (signinggate.Result, error) {
		requestCount++
		if requestCount != 1 {
			return signinggate.Result{}, errors.New("stable fixture signer received more than one request")
		}
		if socketPath != fixtureSocketPath {
			return signinggate.Result{}, errors.New("stable fixture signer received an unexpected socket path")
		}
		if !bytes.Equal(artifact, loadedPlan.BootImage) {
			return signinggate.Result{}, errors.New("stable fixture signer received bytes outside the signing plan")
		}
		state, result, err := signAndAttest(
			privateKey, authorization.Registry.Grants[0], artifact,
			configuration.approvedAt, configuration.signedAt,
		)
		if err != nil {
			return signinggate.Result{}, err
		}
		completeState = &state
		return result, nil
	}
	signedDirectory := filepath.Join(configuration.output, "signed")
	if err := signedboot.SignWithLoader(
		context.Background(), configuration.planDirectory, signedDirectory,
		signedboot.SignConfig{
			GateSocketPath:               fixtureSocketPath,
			SignerID:                     configuration.signerID,
			CohortID:                     configuration.cohortID,
			PKCS11URI:                    configuration.pkcs11URI,
			ExpectedPublicKeyPath:        filepath.Join(configuration.planDirectory, "public.pem"),
			ExpectedPublicKeyFingerprint: loadedPlan.Plan.PublicKeyFingerprint,
			RequestSignature:             requestSignature,
		},
		stablecampaignsigning.LoadPlanDirectory,
	); err != nil {
		return fmt.Errorf("produce stable fixture signing result: %w", err)
	}
	if requestCount != 1 || completeState == nil {
		return errors.New("stable fixture did not produce exactly one complete signing receipt")
	}

	loadedResult, err := signedboot.LoadResultDirectory(signedDirectory)
	if err != nil {
		return fmt.Errorf("reload stable fixture signing result: %w", err)
	}
	receiptDigest, err := completeState.Receipt.Digest()
	if err != nil {
		return err
	}
	if loadedResult.Result.GateReceiptDigest != receiptDigest {
		return errors.New("live signing-result receipt digest does not match the completed fixture receipt")
	}
	exported, err := signingreceipts.New(
		authorization.Registry, []signinggate.DurableState{*completeState}, loadedPlan.PublicPEM,
	)
	if err != nil {
		return fmt.Errorf("construct stable fixture receipt export: %w", err)
	}
	exportJSON, err := exported.CanonicalJSON(authorization.Registry, loadedPlan.PublicPEM)
	if err != nil {
		return err
	}
	if _, _, err := signingreceipts.ParseAndVerify(
		exportJSON, authorization.Registry, loadedPlan.PublicPEM,
		[]bundle.Digest{loadedResult.Result.GateReceiptDigest},
	); err != nil {
		return fmt.Errorf("self-verify stable fixture receipt export: %w", err)
	}
	if err := writeNewFile(filepath.Join(configuration.output, "signing-receipts.json"), exportJSON); err != nil {
		return err
	}
	committed = true
	return nil
}

func parseOptions(arguments []string) (options, error) {
	flags := flag.NewFlagSet("stable-campaign-signing-testfixture", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var configuration options
	flags.StringVar(&configuration.planDirectory, "plan", "", "absolute stable signing plan directory")
	flags.StringVar(&configuration.privateKey, "private-key", "", "absolute deterministic fixture RSA private key")
	flags.StringVar(&configuration.output, "output", "", "new fixture output directory")
	flags.StringVar(&configuration.signerID, "signer-id", "", "fixed fixture signer identity")
	flags.StringVar(&configuration.cohortID, "cohort-id", "", "fixed fixture cohort identity")
	flags.StringVar(&configuration.pkcs11URI, "pkcs11-uri", "", "fixed fixture PKCS#11 URI")
	flags.StringVar(&configuration.reviewerID, "reviewer-id", "", "fixed fixture reviewer identity")
	flags.StringVar(&configuration.approvedAt, "approved-at", "", "fixed canonical approval time")
	flags.StringVar(&configuration.expiresAt, "expires-at", "", "fixed canonical approval expiry")
	flags.StringVar(&configuration.signedAt, "signed-at", "", "fixed canonical receipt signing time")
	if err := flags.Parse(arguments); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, errors.New("positional arguments are not accepted")
	}
	for name, value := range map[string]string{
		"plan": configuration.planDirectory, "private-key": configuration.privateKey,
		"output": configuration.output, "signer-id": configuration.signerID,
		"cohort-id": configuration.cohortID, "pkcs11-uri": configuration.pkcs11URI,
		"reviewer-id": configuration.reviewerID, "approved-at": configuration.approvedAt,
		"expires-at": configuration.expiresAt, "signed-at": configuration.signedAt,
	} {
		if value == "" {
			return options{}, fmt.Errorf("--%s is required", name)
		}
	}
	for name, path := range map[string]string{
		"plan": configuration.planDirectory, "private-key": configuration.privateKey, "output": configuration.output,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
			return options{}, fmt.Errorf("--%s must be an absolute clean non-root path", name)
		}
	}
	if pathsOverlap(configuration.planDirectory, configuration.output) {
		return options{}, errors.New("--output must not overlap --plan")
	}
	return configuration, nil
}

func signAndAttest(
	privateKey *rsa.PrivateKey,
	grant signinggate.Grant,
	artifact []byte,
	intentAt, signedAt string,
) (signinggate.DurableState, signinggate.Result, error) {
	if bundle.Sum(artifact) != grant.Request.ArtifactDigest {
		return signinggate.DurableState{}, signinggate.Result{}, errors.New("fixture artifact does not match its exact grant")
	}
	digest := sha256.Sum256(artifact)
	signature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return signinggate.DurableState{}, signinggate.Result{}, fmt.Errorf("sign stable fixture artifact: %w", err)
	}
	requestDigest, err := grant.Request.Digest()
	if err != nil {
		return signinggate.DurableState{}, signinggate.Result{}, err
	}
	receipt := signinggate.Receipt{
		SchemaVersion:   signinggate.ReceiptSchemaV1Alpha3,
		Grant:           grant,
		RequestDigest:   requestDigest,
		BackendID:       fixtureBackendID,
		SignatureHex:    hex.EncodeToString(signature),
		SignatureDigest: bundle.Sum(signature),
		SignedAt:        signedAt,
	}
	attestation, err := receipt.CanonicalAttestation()
	if err != nil {
		return signinggate.DurableState{}, signinggate.Result{}, fmt.Errorf("construct stable fixture receipt attestation: %w", err)
	}
	attestationDigest := sha256.Sum256(attestation)
	attestationSignature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, attestationDigest[:])
	if err != nil {
		return signinggate.DurableState{}, signinggate.Result{}, fmt.Errorf("sign stable fixture receipt attestation: %w", err)
	}
	receipt, err = receipt.WithAttestationSignature(attestationSignature)
	if err != nil {
		return signinggate.DurableState{}, signinggate.Result{}, err
	}
	receiptDigest, err := receipt.Digest()
	if err != nil {
		return signinggate.DurableState{}, signinggate.Result{}, err
	}
	state := signinggate.DurableState{
		SchemaVersion:  signinggate.StateSchemaV1Alpha3,
		Status:         signinggate.StateComplete,
		GrantID:        grant.GrantID,
		RequestDigest:  requestDigest,
		ArtifactDigest: grant.Request.ArtifactDigest,
		IntentAt:       intentAt,
		Receipt:        &receipt,
	}
	return state, signinggate.Result{
		SignatureHex:        receipt.SignatureHex,
		ReceiptDigest:       receiptDigest,
		ReleaseIntentDigest: grant.Request.Approval.ReleaseIntentDigest,
		GrantID:             grant.GrantID,
	}, nil
}

func validateSignedAt(approvedAt, expiresAt, signedAt string) error {
	approved, err := parseCanonicalTime(approvedAt, "--approved-at")
	if err != nil {
		return err
	}
	expires, err := parseCanonicalTime(expiresAt, "--expires-at")
	if err != nil {
		return err
	}
	signed, err := parseCanonicalTime(signedAt, "--signed-at")
	if err != nil {
		return err
	}
	if signed.Before(approved) || !signed.Before(expires) {
		return errors.New("--signed-at must be at or after --approved-at and before --expires-at")
	}
	return nil
}

func parseCanonicalTime(value, name string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Truncate(time.Second).Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf("%s must use canonical UTC RFC3339 seconds", name)
	}
	return parsed, nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, []byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect fixture private key: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, nil, errors.New("fixture private key must be a regular non-symlink file")
	}
	if info.Size() <= 0 || info.Size() > maxPrivateKeySize {
		return nil, nil, fmt.Errorf("fixture private key size must be between 1 and %d bytes", maxPrivateKeySize)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read fixture private key: %w", err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "RSA PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, nil, errors.New("fixture private key must contain one canonical RSA PRIVATE KEY PEM block")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse fixture private key: %w", err)
	}
	if err := privateKey.Validate(); err != nil {
		return nil, nil, fmt.Errorf("validate fixture private key: %w", err)
	}
	if privateKey.N.BitLen() != 2048 || privateKey.E != 65537 || privateKey.Size() != 256 {
		return nil, nil, errors.New("fixture private key must be RSA-2048 with exponent 65537")
	}
	canonicalPrivatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if !bytes.Equal(encoded, canonicalPrivatePEM) {
		return nil, nil, errors.New("fixture private key is not canonical PKCS#1 PEM")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encode fixture public key: %w", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	return privateKey, publicPEM, nil
}

func writeNewFile(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return fmt.Errorf("create fixture file %s: %w", filepath.Base(path), err)
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return fmt.Errorf("write fixture file %s: %w", filepath.Base(path), err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close fixture file %s: %w", filepath.Base(path), err)
	}
	return nil
}

func pathsOverlap(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if left == right {
		return true
	}
	relative, err := filepath.Rel(left, right)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return true
	}
	relative, err = filepath.Rel(right, left)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
