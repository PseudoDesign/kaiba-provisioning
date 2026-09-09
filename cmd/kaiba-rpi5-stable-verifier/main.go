//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseauthorization"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablehandoff"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stableverifier"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/verifierevents"
)

const (
	exitConfiguration = 2
	exitVerification  = 3
	exitAuthorization = 4
	exitHandoff       = 5
	exitOutput        = 6

	defaultRegistrationTimeout = 30 * time.Second
	defaultClientTimeout       = 5 * time.Second
	registrationRetryInterval  = 250 * time.Millisecond
	maxPublicInputBytes        = 1024 * 1024
)

type config struct {
	policyPath                   string
	rootPublicKeyPath            string
	releaseDirectory             string
	verifierVersion              uint64
	cohortID                     string
	slotID                       string
	minimumSecurityEpoch         uint64
	authorityURL                 string
	authorityCAPath              string
	authorityKeyID               string
	logicalIdentity              string
	audience                     string
	kexecPath                    string
	bootstrapRegistrationTimeout time.Duration
	clientTimeout                time.Duration
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout))
}

func run(ctx context.Context, arguments []string, output io.Writer) int {
	emitter, err := verifierevents.New(output)
	if err != nil {
		return exitOutput
	}
	if _, _, err := emitter.Emit(verifierevents.EventStarted, verifierevents.Details{}); err != nil {
		return exitOutput
	}
	cfg, err := parseConfig(arguments)
	if err != nil {
		return fail(emitter, verifierevents.Details{}, "configuration-invalid", exitConfiguration)
	}

	release, err := stableverifier.VerifyRelease(ctx, stableverifier.Inputs{
		RootPublicKeyPath: cfg.rootPublicKeyPath,
		PolicyPath:        cfg.policyPath,
		ReleaseDirectory:  cfg.releaseDirectory,
	}, stableverifier.Requirements{
		VerifierVersion:      cfg.verifierVersion,
		MinimumSecurityEpoch: cfg.minimumSecurityEpoch,
		CohortID:             cfg.cohortID,
		SlotID:               cfg.slotID,
	})
	if err != nil {
		return fail(emitter, verifierevents.Details{}, "release-verification-failed", exitVerification)
	}
	defer release.Close()
	details := verifierevents.Details{
		PolicyDigest: release.PolicyDigest(), ManifestDigest: release.ManifestDigest(),
	}
	if _, _, err := emitter.Emit(verifierevents.EventReleaseVerified, details); err != nil {
		return exitOutput
	}

	authorityPublicKey, err := selectedAuthorityKey(release.Policy(), cfg.authorityKeyID)
	if err != nil {
		return fail(emitter, details, "authority-policy-invalid", exitAuthorization)
	}
	rootPool, err := loadCAPool(cfg.authorityCAPath)
	if err != nil {
		return fail(emitter, details, "authority-tls-invalid", exitAuthorization)
	}
	client, err := releaseauthorization.NewNonProductionClient(releaseauthorization.NonProductionClientConfig{
		BaseURL: cfg.authorityURL, AuthorityKeyID: cfg.authorityKeyID,
		AuthorityPublicKey: authorityPublicKey,
		TLSConfig:          &tls.Config{RootCAs: rootPool, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
		Timeout:            cfg.clientTimeout,
	})
	if err != nil {
		return fail(emitter, details, "authority-client-invalid", exitAuthorization)
	}
	defer client.CloseIdleConnections()

	bootstrapPublicKey, bootstrapPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fail(emitter, details, "bootstrap-key-generation-failed", exitAuthorization)
	}
	defer clear(bootstrapPrivateKey)
	oneBootPublicKey, oneBootPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fail(emitter, details, "one-boot-key-generation-failed", exitAuthorization)
	}
	defer clear(oneBootPrivateKey)
	bootstrapEncoded, _ := releaseauthorization.EncodePublicKey(bootstrapPublicKey)
	oneBootEncoded, _ := releaseauthorization.EncodePublicKey(oneBootPublicKey)
	details.BootstrapPublicKey = bootstrapEncoded
	if _, _, err := emitter.Emit(verifierevents.EventBootstrapKeyReady, details); err != nil {
		return exitOutput
	}

	authorizationContext, cancelAuthorization := context.WithTimeout(ctx, cfg.bootstrapRegistrationTimeout)
	defer cancelAuthorization()
	challengeReceipt, err := client.IssueChallenge(authorizationContext)
	if err != nil {
		return fail(emitter, details, "challenge-request-failed", exitAuthorization)
	}
	authorizationRequest, err := releaseauthorization.NewAuthorizationRequest(
		challengeReceipt.Challenge,
		releaseauthorization.BootBinding{
			LogicalIdentity: cfg.logicalIdentity, StorageGeneration: 0,
			Audience:        cfg.audience,
			VerifierVersion: cfg.verifierVersion,
			PolicyDigest:    string(release.PolicyDigest()), ManifestDigest: string(release.ManifestDigest()),
			SecurityEpoch: release.Policy().SecurityEpoch,
		},
		bootstrapPrivateKey,
		oneBootPublicKey,
		authorityPublicKey,
		challengeReceipt.Elapsed(),
	)
	if err != nil {
		return fail(emitter, details, "authorization-request-invalid", exitAuthorization)
	}
	authorization, successfulAttemptStarted, err := awaitBootstrapRegistration(
		authorizationContext, client, authorizationRequest,
	)
	if err != nil {
		return fail(emitter, details, "authorization-denied", exitAuthorization)
	}
	if err := releaseauthorization.VerifyAuthorization(
		authorization, authorizationRequest, authorityPublicKey, time.Since(successfulAttemptStarted),
	); err != nil {
		return fail(emitter, details, "authorization-verification-failed", exitAuthorization)
	}
	authorizationJSON, err := authorization.CanonicalJSON()
	if err != nil {
		return fail(emitter, details, "authorization-encoding-failed", exitAuthorization)
	}
	defer clear(authorizationJSON)
	details.OneBootPublicKey = oneBootEncoded
	if _, _, err := emitter.Emit(verifierevents.EventAuthorizationReady, details); err != nil {
		return exitOutput
	}

	kernel, err := release.OpenComponent(stableverifier.RoleKernel)
	if err != nil {
		return fail(emitter, details, "kernel-handoff-open-failed", exitHandoff)
	}
	defer kernel.Close()
	baseInitramfs, err := release.OpenComponent(stableverifier.RoleInitramfs)
	if err != nil {
		return fail(emitter, details, "initramfs-handoff-open-failed", exitHandoff)
	}
	defer baseInitramfs.Close()
	deviceTree, err := release.OpenComponent(stableverifier.RoleResolvedDeviceTree)
	if err != nil {
		return fail(emitter, details, "device-tree-handoff-open-failed", exitHandoff)
	}
	defer deviceTree.Close()
	dmVerityMetadata, err := readRetained(release, stableverifier.RoleDMVerityMetadata, stablehandoff.MaxDMVerityBytes)
	if err != nil {
		return fail(emitter, details, "dm-verity-handoff-read-failed", exitHandoff)
	}
	defer clear(dmVerityMetadata)
	slotMetadata, err := readRetained(release, stableverifier.RoleSlotMetadata, stablehandoff.MaxSlotMetadataBytes)
	if err != nil {
		return fail(emitter, details, "slot-handoff-read-failed", exitHandoff)
	}
	defer clear(slotMetadata)
	preparedInitramfs, err := stablehandoff.PrepareInitramfs(baseInitramfs, stablehandoff.Credential{
		Authorization: authorizationJSON, OneBootPrivateKey: oneBootPrivateKey,
		DMVerityMetadata: dmVerityMetadata, SlotMetadata: slotMetadata,
	})
	if err != nil {
		return fail(emitter, details, "credential-initramfs-failed", exitHandoff)
	}
	defer preparedInitramfs.Close()
	clear(oneBootPrivateKey)

	if err := releaseauthorization.VerifyAuthorization(
		authorization, authorizationRequest, authorityPublicKey, time.Since(successfulAttemptStarted),
	); err != nil {
		return fail(emitter, details, "authorization-expired-before-load", exitAuthorization)
	}
	loaded, err := (stablehandoff.Plan{
		KexecPath: cfg.kexecPath, Kernel: kernel, Initramfs: preparedInitramfs,
		DeviceTree: deviceTree, CommandLine: release.KernelCommandLine(), Output: os.Stderr,
	}).Load(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stable verifier: kexec load failed: %v\n", err)
		return fail(emitter, details, "kexec-load-failed", exitHandoff)
	}
	if _, _, err := emitter.Emit(verifierevents.EventHandoffLoaded, details); err != nil {
		return exitOutput
	}
	if err := releaseauthorization.VerifyAuthorization(
		authorization, authorizationRequest, authorityPublicKey, time.Since(successfulAttemptStarted),
	); err != nil {
		return fail(emitter, details, "authorization-expired-before-execute", exitAuthorization)
	}
	if _, _, err := emitter.Emit(verifierevents.EventHandoffExecuting, details); err != nil {
		return exitOutput
	}
	// UART output can block. Recheck freshness immediately before crossing the
	// kexec boundary rather than relying only on the pre-event check.
	if err := releaseauthorization.VerifyAuthorization(
		authorization, authorizationRequest, authorityPublicKey, time.Since(successfulAttemptStarted),
	); err != nil {
		return fail(emitter, details, "authorization-expired-before-execute", exitAuthorization)
	}
	if err := loaded.Execute(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "stable verifier: kexec execute failed: %v\n", err)
		return fail(emitter, details, "kexec-execute-failed", exitHandoff)
	}
	return fail(emitter, details, "kexec-returned", exitHandoff)
}

func parseConfig(arguments []string) (config, error) {
	var cfg config
	flags := flag.NewFlagSet("kaiba-rpi5-stable-verifier", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&cfg.policyPath, "policy", "", "root-signed stable-verifier policy")
	flags.StringVar(&cfg.rootPublicKeyPath, "root-public-key", "", "stable-policy root public key")
	flags.StringVar(&cfg.releaseDirectory, "release-dir", "", "delegated release directory")
	flags.Uint64Var(&cfg.verifierVersion, "verifier-version", 0, "positive stable-verifier version")
	flags.StringVar(&cfg.cohortID, "cohort-id", "", "fixed delegated-release cohort")
	flags.StringVar(&cfg.slotID, "slot-id", "", "fixed delegated-release slot")
	flags.Uint64Var(&cfg.minimumSecurityEpoch, "minimum-security-epoch", 0, "minimum accepted policy epoch")
	flags.StringVar(&cfg.authorityURL, "authority-url", "", "non-production authorization origin")
	flags.StringVar(&cfg.authorityCAPath, "authority-ca", "", "explicit authorization TLS CA")
	flags.StringVar(&cfg.authorityKeyID, "authority-key-id", "", "authorization key selected from policy")
	flags.StringVar(&cfg.logicalIdentity, "logical-identity", "", "explicit non-production logical identity")
	flags.StringVar(&cfg.audience, "audience", "", "intended authorization audience")
	flags.StringVar(&cfg.kexecPath, "kexec", "", "pinned kexec executable")
	flags.DurationVar(
		&cfg.bootstrapRegistrationTimeout,
		"bootstrap-registration-timeout",
		defaultRegistrationTimeout,
		"maximum challenge and out-of-band registration interval",
	)
	flags.DurationVar(&cfg.clientTimeout, "authority-client-timeout", defaultClientTimeout, "per-request authority timeout")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return config{}, errors.New("invalid verifier arguments")
	}
	for name, value := range map[string]string{
		"policy": cfg.policyPath, "root-public-key": cfg.rootPublicKeyPath,
		"release-dir": cfg.releaseDirectory, "cohort-id": cfg.cohortID, "slot-id": cfg.slotID,
		"authority-url": cfg.authorityURL, "authority-ca": cfg.authorityCAPath,
		"authority-key-id": cfg.authorityKeyID, "logical-identity": cfg.logicalIdentity,
		"audience": cfg.audience, "kexec": cfg.kexecPath,
	} {
		if value == "" {
			return config{}, fmt.Errorf("--%s is required", name)
		}
	}
	if cfg.verifierVersion == 0 {
		return config{}, errors.New("--verifier-version must be positive")
	}
	if cfg.bootstrapRegistrationTimeout < time.Second || cfg.bootstrapRegistrationTimeout > 5*time.Minute {
		return config{}, errors.New("--bootstrap-registration-timeout must be between one second and five minutes")
	}
	if cfg.clientTimeout <= 0 || cfg.clientTimeout > 30*time.Second {
		return config{}, errors.New("--authority-client-timeout must be positive and at most 30 seconds")
	}
	return cfg, nil
}

func selectedAuthorityKey(policy stableverifier.Policy, keyID string) (ed25519.PublicKey, error) {
	for _, authority := range policy.AuthorizationAuthorities {
		if authority.KeyID != keyID {
			continue
		}
		return releaseauthorization.DecodePublicKey(authority.PublicKey)
	}
	return nil, errors.New("configured authorization key is absent from the verified policy")
}

func awaitBootstrapRegistration(
	ctx context.Context,
	client *releaseauthorization.NonProductionClient,
	request releaseauthorization.AuthorizationRequest,
) (releaseauthorization.Authorization, time.Time, error) {
	for {
		started := time.Now()
		authorization, err := client.Authorize(ctx, request)
		if err == nil {
			return authorization, started, nil
		}
		if !errors.Is(err, releaseauthorization.ErrUntrustedBootstrap) {
			return releaseauthorization.Authorization{}, time.Time{}, err
		}
		timer := time.NewTimer(registrationRetryInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return releaseauthorization.Authorization{}, time.Time{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func readRetained(release *stableverifier.VerifiedRelease, role stableverifier.ComponentRole, maximum int) ([]byte, error) {
	file, err := release.OpenComponent(role)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(contents) == 0 || len(contents) > maximum {
		return nil, errors.New("retained handoff metadata has an invalid size")
	}
	return contents, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return nil, errors.New("authority CA path must be clean and absolute")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxPublicInputBytes+1))
	if err != nil || len(contents) == 0 || len(contents) > maxPublicInputBytes {
		return nil, errors.New("authority CA is empty, oversized, or unreadable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(contents) {
		return nil, errors.New("authority CA does not contain a PEM certificate")
	}
	return pool, nil
}

func fail(emitter *verifierevents.Emitter, details verifierevents.Details, code string, exitCode int) int {
	details.FailureCode = code
	if _, _, err := emitter.Emit(verifierevents.EventFailed, details); err != nil {
		return exitOutput
	}
	return exitCode
}
