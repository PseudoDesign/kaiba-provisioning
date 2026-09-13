package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signedboot"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signingapproval"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signingreceipts"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaignsigning"
)

const (
	exitOK       = 0
	exitInternal = 1
	exitUsage    = 2
	exitInvalid  = 3

	approvalFilename = "approval.json"
	registryFilename = "signing-grants.json"
)

// All signing authority and signer identity values are injected by the
// immutable build. No command flag or environment variable can select a
// socket, key, provider, URI, signer, or cohort at runtime.
var (
	signingGateSocketPath        string
	signerID                     string
	cohortID                     string
	signingPKCS11URI             string
	expectedPublicKeyPath        string
	expectedPublicKeyFingerprint string
)

type dependencies struct {
	now      func() time.Time
	loadPlan signedboot.PlanLoader
	sign     func(context.Context, string, string) error
	finalize func(string, string, string, string, string, string) error
	lstat    func(string) (os.FileInfo, error)
	open     func(string) (*os.File, error)
	mkdir    func(string, os.FileMode) error
	openFile func(string, int, os.FileMode) (*os.File, error)
	openDir  func(string) (*os.File, error)
}

func productionDependencies() dependencies {
	return dependencies{
		now: time.Now, loadPlan: stablecampaignsigning.LoadPlanDirectory,
		sign: productionSign, finalize: productionFinalize,
		lstat: os.Lstat, open: os.Open, mkdir: os.Mkdir,
		openFile: os.OpenFile, openDir: os.Open,
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, productionDependencies()))
}

func productionSign(ctx context.Context, planDirectory, outputDirectory string) error {
	fingerprint, err := bundle.ParseDigest(expectedPublicKeyFingerprint)
	if err != nil {
		return fmt.Errorf("linker-fixed public-key fingerprint: %w", err)
	}
	return signedboot.SignWithLoader(ctx, planDirectory, outputDirectory, signedboot.SignConfig{
		GateSocketPath: signingGateSocketPath, SignerID: signerID, CohortID: cohortID,
		PKCS11URI: signingPKCS11URI, ExpectedPublicKeyPath: expectedPublicKeyPath,
		ExpectedPublicKeyFingerprint: fingerprint,
	}, stablecampaignsigning.LoadPlanDirectory)
}

func productionFinalize(
	planDirectory, signedDirectory, approvalPath, registryPath, receiptExportPath, outputDirectory string,
) error {
	validateEvidence := func(
		_ signedboot.Plan,
		result signedboot.Result,
		releaseIntentJSON []byte,
		publicPEM []byte,
	) error {
		intent, err := stablecampaignsigning.ParseIntent(releaseIntentJSON)
		if err != nil {
			return fmt.Errorf("stable signing intent: %w", err)
		}
		readDependencies := dependencies{lstat: os.Lstat, open: os.Open}
		approvalData, err := readCanonicalFile(
			approvalPath, stablecampaignsigning.MaxApprovalBytes, "approval", readDependencies,
		)
		if err != nil {
			return err
		}
		approval, err := stablecampaignsigning.ParseApproval(approvalData)
		if err != nil {
			return fmt.Errorf("approval: %w", err)
		}
		registryData, err := readCanonicalFile(
			registryPath, signinggate.MaxRegistryBytes, "registry", readDependencies,
		)
		if err != nil {
			return err
		}
		registry, err := signingapproval.ParseRegistry(registryData)
		if err != nil {
			return fmt.Errorf("registry: %w", err)
		}
		if err := (stablecampaignsigning.Authorization{
			Approval: approval,
			Registry: registry,
		}).Validate(intent); err != nil {
			return fmt.Errorf("stable signing authorization: %w", err)
		}
		receiptExport, err := readCanonicalFile(
			receiptExportPath, signingreceipts.MaxExportBytes, "receipt export", readDependencies,
		)
		if err != nil {
			return err
		}
		if _, _, err := signingreceipts.ParseAndVerify(
			receiptExport,
			registry,
			publicPEM,
			[]bundle.Digest{result.GateReceiptDigest},
		); err != nil {
			return fmt.Errorf("authenticated signing receipt: %w", err)
		}
		return nil
	}
	return signedboot.FinalizeWithLoaderAndEvidenceValidator(
		planDirectory,
		signedDirectory,
		outputDirectory,
		stablecampaignsigning.LoadPlanDirectory,
		validateEvidence,
	)
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer, deps dependencies) int {
	if ctx == nil || stdout == nil || stderr == nil {
		return exitInternal
	}
	if len(arguments) == 0 {
		printUsage(stderr)
		return exitUsage
	}
	switch arguments[0] {
	case "author":
		return authorCommand(arguments[1:], stdout, stderr, deps)
	case "validate-plan":
		return validatePlanCommand(arguments[1:], stdout, stderr, deps)
	case "validate-authorization":
		return validateAuthorizationCommand(arguments[1:], stdout, stderr, deps)
	case "sign":
		return signCommand(ctx, arguments[1:], stderr, deps)
	case "finalize":
		return finalizeCommand(arguments[1:], stderr, deps)
	default:
		printUsage(stderr)
		return exitUsage
	}
}

func authorCommand(arguments []string, stdout, stderr io.Writer, deps dependencies) int {
	flags := newFlagSet("author", stderr)
	planPath := flags.String("plan", "", "absolute stable signing plan directory")
	reviewerID := flags.String("reviewer-id", "", "canonical reviewer attribution identifier")
	approvedAt := flags.String("approved-at", "", "canonical UTC RFC3339 approval time")
	expiresAt := flags.String("expires-at", "", "canonical UTC RFC3339 expiry, at most 24 hours later")
	outputPath := flags.String("output", "", "absolute new output directory")
	if status, done := parseFlags(flags, arguments); done {
		return status
	}
	if flags.NArg() != 0 || *planPath == "" || *reviewerID == "" || *approvedAt == "" || *expiresAt == "" || *outputPath == "" {
		flags.Usage()
		return exitUsage
	}
	if err := requireAbsoluteClean(*outputPath, "output"); err != nil {
		return commandError(stderr, exitInvalid, "author stable signing approval", err)
	}
	loaded, err := deps.loadPlan(*planPath)
	if err != nil {
		return commandError(stderr, exitInvalid, "author stable signing approval", err)
	}
	intent, err := stablecampaignsigning.ParseIntent(loaded.ReleaseIntentJSON)
	if err != nil {
		return commandError(stderr, exitInvalid, "author stable signing approval", err)
	}
	authorization, err := stablecampaignsigning.NewAuthorization(intent, *reviewerID, *approvedAt, *expiresAt)
	if err != nil {
		return commandError(stderr, exitInvalid, "author stable signing approval", err)
	}
	if deps.now == nil {
		return commandError(stderr, exitInternal, "author stable signing approval", errors.New("authoring clock is unavailable"))
	}
	if err := authorization.Approval.RequireCurrentlyActive(deps.now()); err != nil {
		return commandError(stderr, exitInvalid, "author stable signing approval", err)
	}
	approvalJSON, err := authorization.Approval.CanonicalJSON()
	if err != nil {
		return commandError(stderr, exitInternal, "author stable signing approval", err)
	}
	registryJSON, err := signingapproval.CanonicalRegistryJSON(authorization.Registry)
	if err != nil {
		return commandError(stderr, exitInternal, "author stable signing approval", err)
	}
	if err := writeOutputDirectory(*outputPath, approvalJSON, registryJSON, deps); err != nil {
		return commandError(stderr, exitInternal, "author stable signing approval", err)
	}
	return encodeResult(stdout, stderr, map[string]any{
		"status": "authored", "approval_id": authorization.Approval.ApprovalID,
		"approval_digest":       authorization.Approval.ApprovalDigest,
		"signing_intent_digest": authorization.Approval.SigningIntentDigest,
		"grant_count":           len(authorization.Registry.Grants),
	})
}

func validatePlanCommand(arguments []string, stdout, stderr io.Writer, deps dependencies) int {
	flags := newFlagSet("validate-plan", stderr)
	planPath := flags.String("plan", "", "absolute stable signing plan directory")
	if status, done := parseFlags(flags, arguments); done {
		return status
	}
	if flags.NArg() != 0 || *planPath == "" {
		flags.Usage()
		return exitUsage
	}
	loaded, err := deps.loadPlan(*planPath)
	if err != nil {
		return commandError(stderr, exitInvalid, "validate stable signing plan", err)
	}
	return encodeResult(stdout, stderr, map[string]any{
		"status": "valid", "plan_id": loaded.Plan.PlanID,
		"plan_digest":           loaded.PlanDigest,
		"signing_intent_digest": loaded.Plan.ReleaseIntentDigest,
		"boot_image_digest":     loaded.Plan.BootImageDigest,
	})
}

func validateAuthorizationCommand(arguments []string, stdout, stderr io.Writer, deps dependencies) int {
	flags := newFlagSet("validate-authorization", stderr)
	planPath := flags.String("plan", "", "absolute stable signing plan directory")
	approvalPath := flags.String("approval", "", "absolute canonical stable approval JSON path")
	registryPath := flags.String("registry", "", "absolute canonical v1alpha2 registry JSON path")
	if status, done := parseFlags(flags, arguments); done {
		return status
	}
	if flags.NArg() != 0 || *planPath == "" || *approvalPath == "" || *registryPath == "" {
		flags.Usage()
		return exitUsage
	}
	loaded, err := deps.loadPlan(*planPath)
	if err != nil {
		return commandError(stderr, exitInvalid, "validate stable signing authorization", err)
	}
	intent, err := stablecampaignsigning.ParseIntent(loaded.ReleaseIntentJSON)
	if err != nil {
		return commandError(stderr, exitInvalid, "validate stable signing authorization", err)
	}
	approvalData, err := readCanonicalFile(*approvalPath, stablecampaignsigning.MaxApprovalBytes+1, "approval", deps)
	if err != nil {
		return commandError(stderr, exitInvalid, "validate stable signing authorization", err)
	}
	approval, err := stablecampaignsigning.ParseApproval(approvalData)
	if err != nil {
		return commandError(stderr, exitInvalid, "validate stable signing authorization", err)
	}
	registryData, err := readCanonicalFile(*registryPath, signinggate.MaxRegistryBytes+1, "registry", deps)
	if err != nil {
		return commandError(stderr, exitInvalid, "validate stable signing authorization", err)
	}
	registry, err := signingapproval.ParseRegistry(registryData)
	if err != nil {
		return commandError(stderr, exitInvalid, "validate stable signing authorization", err)
	}
	if err := (stablecampaignsigning.Authorization{Approval: approval, Registry: registry}).Validate(intent); err != nil {
		return commandError(stderr, exitInvalid, "validate stable signing authorization", err)
	}
	return encodeResult(stdout, stderr, map[string]any{
		"status": "valid", "approval_id": approval.ApprovalID,
		"approval_digest":       approval.ApprovalDigest,
		"signing_intent_digest": approval.SigningIntentDigest,
		"grant_count":           len(registry.Grants),
	})
}

func signCommand(ctx context.Context, arguments []string, stderr io.Writer, deps dependencies) int {
	flags := newFlagSet("sign", stderr)
	planPath := flags.String("plan", "", "absolute stable signing plan directory")
	outputPath := flags.String("output", "", "absolute new signing-result directory")
	if status, done := parseFlags(flags, arguments); done {
		return status
	}
	if flags.NArg() != 0 || *planPath == "" || *outputPath == "" {
		flags.Usage()
		return exitUsage
	}
	if deps.sign == nil {
		return commandError(stderr, exitInternal, "sign stable boot", errors.New("signing adapter configuration is unavailable"))
	}
	if err := deps.sign(ctx, *planPath, *outputPath); err != nil {
		return commandError(stderr, exitInternal, "sign stable boot", err)
	}
	return exitOK
}

func finalizeCommand(arguments []string, stderr io.Writer, deps dependencies) int {
	flags := newFlagSet("finalize", stderr)
	planPath := flags.String("plan", "", "absolute stable signing plan directory")
	signedPath := flags.String("signed", "", "absolute stable signing-result directory")
	approvalPath := flags.String("approval", "", "absolute canonical stable approval JSON path")
	registryPath := flags.String("registry", "", "absolute canonical one-grant registry JSON path")
	receiptExportPath := flags.String("receipt-export", "", "absolute authenticated receipt-export path")
	outputPath := flags.String("output", "", "absolute new verified bundle directory")
	if status, done := parseFlags(flags, arguments); done {
		return status
	}
	if flags.NArg() != 0 || *planPath == "" || *signedPath == "" || *approvalPath == "" ||
		*registryPath == "" || *receiptExportPath == "" || *outputPath == "" {
		flags.Usage()
		return exitUsage
	}
	if deps.finalize == nil {
		return commandError(stderr, exitInternal, "finalize stable boot", errors.New("finalizer configuration is unavailable"))
	}
	if err := deps.finalize(
		*planPath,
		*signedPath,
		*approvalPath,
		*registryPath,
		*receiptExportPath,
		*outputPath,
	); err != nil {
		return commandError(stderr, exitInternal, "finalize stable boot", err)
	}
	return exitOK
}

func newFlagSet(command string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { printUsage(stderr) }
	return flags
}

func parseFlags(flags *flag.FlagSet, arguments []string) (int, bool) {
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK, true
		}
		return exitUsage, true
	}
	return 0, false
}

func readCanonicalFile(path string, maximum int, label string, deps dependencies) ([]byte, error) {
	if err := requireAbsoluteClean(path, label); err != nil {
		return nil, err
	}
	if deps.lstat == nil || deps.open == nil {
		return nil, errors.New("file reader is unavailable")
	}
	info, err := deps.lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular non-symlink file", label)
	}
	if info.Size() <= 0 || info.Size() > int64(maximum) {
		return nil, fmt.Errorf("%s size must be between 1 and %d bytes", label, maximum)
	}
	file, err := deps.open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%s changed while opening", label)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(data) == 0 || len(data) > maximum {
		return nil, fmt.Errorf("read bounded %s", label)
	}
	return data, nil
}

func writeOutputDirectory(path string, approvalJSON, registryJSON []byte, deps dependencies) error {
	if deps.mkdir == nil || deps.openFile == nil || deps.openDir == nil {
		return errors.New("output writer is unavailable")
	}
	if err := deps.mkdir(path, 0o700); err != nil {
		return fmt.Errorf("create new output directory: %w", err)
	}
	for _, output := range []struct {
		name string
		data []byte
	}{
		{approvalFilename, approvalJSON},
		{registryFilename, registryJSON},
	} {
		file, err := deps.openFile(filepath.Join(path, output.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("create %s: %w", output.name, err)
		}
		if _, err := file.Write(append(output.data, '\n')); err != nil {
			_ = file.Close()
			return fmt.Errorf("write %s: %w", output.name, err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return fmt.Errorf("sync %s: %w", output.name, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close %s: %w", output.name, err)
		}
	}
	directory, err := deps.openDir(path)
	if err != nil {
		return fmt.Errorf("open output directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync output directory: %w", err)
	}
	return nil
}

func requireAbsoluteClean(path, label string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return fmt.Errorf("%s path must be absolute and clean", label)
	}
	return nil
}

func commandError(stderr io.Writer, status int, operation string, err error) int {
	fmt.Fprintf(stderr, "%s: %v\n", operation, err)
	return status
}

func encodeResult(stdout, stderr io.Writer, result any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(stderr, "encode result: %v\n", err)
		return exitInternal
	}
	return exitOK
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-rpi5-stable-campaign-signing author --plan ABSOLUTE_PLAN_DIR --reviewer-id IDENTIFIER --approved-at UTC_RFC3339_SECONDS --expires-at UTC_RFC3339_SECONDS --output ABSOLUTE_NEW_DIRECTORY")
	fmt.Fprintln(output, "       kaiba-rpi5-stable-campaign-signing validate-plan --plan ABSOLUTE_PLAN_DIR")
	fmt.Fprintln(output, "       kaiba-rpi5-stable-campaign-signing validate-authorization --plan ABSOLUTE_PLAN_DIR --approval ABSOLUTE_PATH --registry ABSOLUTE_PATH")
	fmt.Fprintln(output, "       kaiba-rpi5-stable-campaign-signing sign --plan ABSOLUTE_PLAN_DIR --output ABSOLUTE_NEW_DIRECTORY")
	fmt.Fprintln(output, "       kaiba-rpi5-stable-campaign-signing finalize --plan ABSOLUTE_PLAN_DIR --signed ABSOLUTE_SIGNED_DIR --approval ABSOLUTE_PATH --registry ABSOLUTE_PATH --receipt-export ABSOLUTE_PATH --output ABSOLUTE_NEW_DIRECTORY")
}
