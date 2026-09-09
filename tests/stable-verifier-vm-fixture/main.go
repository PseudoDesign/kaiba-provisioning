// Command stable-verifier-vm-fixture creates non-production trust and release
// inputs for verifier tests. Its defaults are deterministic for the NixOS
// QEMU checks; hardware tests must supply independently generated authority
// and TLS keys. It is deliberately kept below tests/ and is not exported as a
// repository package.
package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseauthorization"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stableverifier"
)

const (
	fixtureSchema   = "kaiba.provisioning.rpi5-stable-verifier-test-fixture/v1alpha1"
	rootKeyID       = "root-vm"
	releaseKeyID    = "release-vm"
	authorityKeyID  = "authorization-vm"
	logicalIdentity = "rpi5-spike:vm"
	audience        = "verifier:vm"
	cohortID        = "spike-cohort"
	slotID          = "spike"
	securityEpoch   = uint64(2)
	verifierVersion = uint64(1)
)

type config struct {
	outputDir               string
	rootRSAPrivateKey       string
	delegatedRSAPrivateKey  string
	authorityPrivateKey     string
	authorityCA             string
	authorityTLSCertificate string
	authorityTLSPrivateKey  string
	authorityKeyID          string
	logicalIdentity         string
	audience                string
	cohortID                string
	slotID                  string
	policyID                string
	releaseID               string
	kernel                  string
	initramfs               string
	deviceTree              string
	commandLine             string
	rootImage               string
	dmVerity                string
	slot                    string
}

type fixtureMetadata struct {
	SchemaVersion      string `json:"schema_version"`
	AuthorityKeyID     string `json:"authority_key_id"`
	AuthorityPublicKey string `json:"authority_public_key"`
	LogicalIdentity    string `json:"logical_identity"`
	Audience           string `json:"audience"`
	VerifierVersion    uint64 `json:"verifier_version"`
	CohortID           string `json:"cohort_id"`
	SlotID             string `json:"slot_id"`
	SecurityEpoch      uint64 `json:"security_epoch"`
	PolicyDigest       string `json:"policy_digest"`
	ManifestDigest     string `json:"manifest_digest"`
}

func main() {
	var cfg config
	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flags.StringVar(&cfg.outputDir, "output", "", "output directory")
	flags.StringVar(&cfg.rootRSAPrivateKey, "root-rsa-private-key", "", "fixture-only root RSA-2048 private key")
	flags.StringVar(&cfg.delegatedRSAPrivateKey, "delegated-rsa-private-key", "", "fixture-only delegated RSA-2048 private key")
	flags.StringVar(&cfg.authorityPrivateKey, "authority-private-key", "", "optional externally generated fixture-only Ed25519 PKCS#8 private key")
	flags.StringVar(&cfg.authorityCA, "authority-ca", "", "optional externally generated fixture-only CA certificate")
	flags.StringVar(&cfg.authorityTLSCertificate, "authority-tls-cert", "", "optional externally generated fixture-only TLS certificate")
	flags.StringVar(&cfg.authorityTLSPrivateKey, "authority-tls-key", "", "optional externally generated fixture-only TLS private key")
	flags.StringVar(&cfg.authorityKeyID, "authority-key-id", authorityKeyID, "canonical authority key identifier")
	flags.StringVar(&cfg.logicalIdentity, "logical-identity", logicalIdentity, "canonical logical test identity")
	flags.StringVar(&cfg.audience, "audience", audience, "canonical authorization audience")
	flags.StringVar(&cfg.cohortID, "cohort-id", cohortID, "canonical verifier cohort")
	flags.StringVar(&cfg.slotID, "slot-id", slotID, "canonical release slot")
	flags.StringVar(&cfg.policyID, "policy-id", "policy:vm", "canonical stable-verifier policy identifier")
	flags.StringVar(&cfg.releaseID, "release-id", "release:vm", "canonical delegated release identifier")
	flags.StringVar(&cfg.kernel, "kernel", "", "second-stage kernel bytes")
	flags.StringVar(&cfg.initramfs, "initramfs", "", "second-stage initramfs bytes")
	flags.StringVar(&cfg.deviceTree, "device-tree", "", "second-stage device tree bytes")
	flags.StringVar(&cfg.commandLine, "command-line", "", "kernel command-line file")
	flags.StringVar(&cfg.rootImage, "root-image", "", "root image bytes")
	flags.StringVar(&cfg.dmVerity, "dm-verity", "", "dm-verity metadata")
	flags.StringVar(&cfg.slot, "slot", "", "slot metadata")
	flags.Parse(os.Args[1:])
	if flags.NArg() != 0 {
		fatal(errors.New("unexpected positional arguments"))
	}
	if err := run(cfg); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "stable-verifier-vm-fixture: %v\n", err)
	os.Exit(1)
}

func run(cfg config) error {
	for name, value := range map[string]string{
		"--output": cfg.outputDir, "--root-rsa-private-key": cfg.rootRSAPrivateKey,
		"--delegated-rsa-private-key": cfg.delegatedRSAPrivateKey,
		"--kernel":                    cfg.kernel, "--initramfs": cfg.initramfs,
		"--device-tree": cfg.deviceTree, "--command-line": cfg.commandLine,
		"--root-image": cfg.rootImage, "--dm-verity": cfg.dmVerity, "--slot": cfg.slot,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	externalAuthorityInputs := []string{
		cfg.authorityPrivateKey, cfg.authorityCA,
		cfg.authorityTLSCertificate, cfg.authorityTLSPrivateKey,
	}
	externalAuthorityCount := 0
	for _, value := range externalAuthorityInputs {
		if value != "" {
			externalAuthorityCount++
		}
	}
	if externalAuthorityCount != 0 && externalAuthorityCount != len(externalAuthorityInputs) {
		return errors.New("external authority inputs must be supplied together")
	}
	if !filepath.IsAbs(cfg.outputDir) || filepath.Clean(cfg.outputDir) != cfg.outputDir {
		return errors.New("--output must be a clean absolute path")
	}

	rootPrivate, err := loadRSAPrivateKey(cfg.rootRSAPrivateKey)
	if err != nil {
		return err
	}
	delegatedPrivate, err := loadRSAPrivateKey(cfg.delegatedRSAPrivateKey)
	if err != nil {
		return err
	}
	rootPublicPEM, rootFingerprint, err := publicKeyMaterial(&rootPrivate.PublicKey)
	if err != nil {
		return err
	}
	delegatedPublicPEM, delegatedFingerprint, err := publicKeyMaterial(&delegatedPrivate.PublicKey)
	if err != nil {
		return err
	}

	var authorityPrivate ed25519.PrivateKey
	if cfg.authorityPrivateKey == "" {
		authorityPrivate = deterministicEd25519("authorization")
	} else {
		authorityPrivate, err = loadEd25519PrivateKey(cfg.authorityPrivateKey)
		if err != nil {
			return err
		}
	}
	defer clear(authorityPrivate)
	authorityPublic := authorityPrivate.Public().(ed25519.PublicKey)
	encodedAuthorityPublic, err := releaseauthorization.EncodePublicKey(authorityPublic)
	if err != nil {
		return err
	}

	policy := stableverifier.Policy{
		SchemaVersion:             stableverifier.PolicySchemaV1Alpha1,
		PolicyID:                  cfg.policyID,
		DeviceClass:               stableverifier.DeviceClass,
		CohortID:                  cfg.cohortID,
		SecurityEpoch:             securityEpoch,
		MinimumVerifierVersion:    verifierVersion,
		ReleaseSignatureThreshold: 1,
		AllowedSlotIDs:            []string{cfg.slotID},
		RootKeyID:                 rootKeyID,
		RootKeyFingerprint:        rootFingerprint,
		DelegatedKeys: []stableverifier.DelegatedKey{{
			KeyID: releaseKeyID, Algorithm: stableverifier.RSA2048SHA256Algorithm,
			PublicKeyPEM: string(delegatedPublicPEM), PublicKeyFingerprint: delegatedFingerprint,
			Status: "active",
		}},
		AuthorizationAuthorities: []stableverifier.AuthorizationAuthority{{
			KeyID: cfg.authorityKeyID, Algorithm: stableverifier.Ed25519Algorithm,
			PublicKey: encodedAuthorityPublic,
		}},
	}
	policyPreimage, err := policy.SigningPreimage()
	if err != nil {
		return fmt.Errorf("construct policy signing preimage: %w", err)
	}
	policy.RootSignature = stableverifier.RSASignature{
		KeyID: rootKeyID, Algorithm: stableverifier.RSA2048SHA256Algorithm,
		Value: signRSA(rootPrivate, policyPreimage),
	}
	policyJSON, err := policy.CanonicalJSON()
	if err != nil {
		return fmt.Errorf("encode policy: %w", err)
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		return fmt.Errorf("digest policy: %w", err)
	}

	componentSources := map[stableverifier.ComponentRole]string{
		stableverifier.RoleKernel:             cfg.kernel,
		stableverifier.RoleInitramfs:          cfg.initramfs,
		stableverifier.RoleResolvedDeviceTree: cfg.deviceTree,
		stableverifier.RoleKernelCommandLine:  cfg.commandLine,
		stableverifier.RoleRootImage:          cfg.rootImage,
		stableverifier.RoleDMVerityMetadata:   cfg.dmVerity,
		stableverifier.RoleSlotMetadata:       cfg.slot,
	}
	components := make([]stableverifier.Component, 0, len(componentSources))
	componentData := make(map[stableverifier.ComponentRole][]byte, len(componentSources))
	for _, role := range stableverifier.ComponentRoles() {
		contents, readErr := os.ReadFile(componentSources[role])
		if readErr != nil {
			return fmt.Errorf("read %s: %w", role, readErr)
		}
		if len(contents) == 0 {
			return fmt.Errorf("%s fixture is empty", role)
		}
		componentData[role] = contents
		components = append(components, stableverifier.Component{
			Role: role, Digest: bundle.Sum(contents), SizeBytes: uint64(len(contents)),
		})
	}
	manifest := stableverifier.Manifest{
		SchemaVersion: stableverifier.ManifestSchemaV1Alpha1,
		ReleaseID:     cfg.releaseID, DeviceClass: stableverifier.DeviceClass,
		CohortID: cfg.cohortID, PolicyDigest: policyDigest,
		SecurityEpoch: securityEpoch, SlotID: cfg.slotID,
		Components: components, Overlays: []stableverifier.Overlay{},
	}
	manifestPreimage, err := manifest.SigningPreimage()
	if err != nil {
		return fmt.Errorf("construct manifest signing preimage: %w", err)
	}
	manifest.Signatures = []stableverifier.RSASignature{{
		KeyID: releaseKeyID, Algorithm: stableverifier.RSA2048SHA256Algorithm,
		Value: signRSA(delegatedPrivate, manifestPreimage),
	}}
	manifestJSON, err := manifest.CanonicalJSON()
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	manifestDigest, err := manifest.Digest()
	if err != nil {
		return fmt.Errorf("digest manifest: %w", err)
	}

	if err := os.MkdirAll(filepath.Join(cfg.outputDir, "authority"), 0o755); err != nil {
		return err
	}
	releaseDir := filepath.Join(cfg.outputDir, "release")
	if err := os.MkdirAll(filepath.Join(releaseDir, "overlays"), 0o755); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(cfg.outputDir, "root-public.pem"), rootPublicPEM, 0o644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(cfg.outputDir, "policy.json"), policyJSON, 0o644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(releaseDir, "release-manifest.json"), manifestJSON, 0o644); err != nil {
		return err
	}
	for _, role := range stableverifier.ComponentRoles() {
		name, _ := stableverifier.ComponentPath(role)
		if err := writeFile(filepath.Join(releaseDir, name), componentData[role], 0o644); err != nil {
			return err
		}
	}

	var caPEM, serverCertificatePEM, serverPrivatePEM []byte
	if cfg.authorityCA == "" {
		caPEM, serverCertificatePEM, serverPrivatePEM, err = tlsMaterial()
		if err != nil {
			return err
		}
	} else {
		caPEM, err = os.ReadFile(cfg.authorityCA)
		if err != nil {
			return fmt.Errorf("read authority CA: %w", err)
		}
		serverCertificatePEM, err = os.ReadFile(cfg.authorityTLSCertificate)
		if err != nil {
			return fmt.Errorf("read authority TLS certificate: %w", err)
		}
		serverPrivatePEM, err = os.ReadFile(cfg.authorityTLSPrivateKey)
		if err != nil {
			return fmt.Errorf("read authority TLS private key: %w", err)
		}
	}
	if err := writeFile(filepath.Join(cfg.outputDir, "authority-ca.pem"), caPEM, 0o644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(cfg.outputDir, "authority", "tls-cert.pem"), serverCertificatePEM, 0o644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(cfg.outputDir, "authority", "tls-key.pem"), serverPrivatePEM, 0o600); err != nil {
		return err
	}
	authorityDER, err := x509.MarshalPKCS8PrivateKey(authorityPrivate)
	if err != nil {
		return err
	}
	defer clear(authorityDER)
	authorityPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: authorityDER})
	if err := writeFile(filepath.Join(cfg.outputDir, "authority", "authority-key.pem"), authorityPEM, 0o600); err != nil {
		return err
	}

	metadataJSON, err := json.Marshal(fixtureMetadata{
		SchemaVersion: fixtureSchema, AuthorityKeyID: cfg.authorityKeyID,
		AuthorityPublicKey: encodedAuthorityPublic,
		LogicalIdentity:    cfg.logicalIdentity, Audience: cfg.audience,
		VerifierVersion: verifierVersion, CohortID: cfg.cohortID, SlotID: cfg.slotID,
		SecurityEpoch: securityEpoch, PolicyDigest: string(policyDigest),
		ManifestDigest: string(manifestDigest),
	})
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(cfg.outputDir, "fixture.json"), metadataJSON, 0o644)
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read RSA private key: %w", err)
	}
	defer clear(encoded)
	block, remainder := pem.Decode(encoded)
	if block == nil || len(remainder) != 0 {
		return nil, errors.New("RSA private key must be one PEM block")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool
			key, ok = parsed.(*rsa.PrivateKey)
			if !ok {
				err = errors.New("PKCS#8 key is not RSA")
			}
		}
	default:
		err = fmt.Errorf("unsupported RSA private-key PEM label %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse RSA private key: %w", err)
	}
	if key.N.BitLen() != 2048 || key.E != 65537 {
		return nil, errors.New("fixture RSA key must be RSA-2048 with exponent 65537")
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("validate RSA private key: %w", err)
	}
	return key, nil
}

func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authority private key: %w", err)
	}
	defer clear(encoded)
	block, remainder := pem.Decode(encoded)
	if block == nil || len(remainder) != 0 || block.Type != "PRIVATE KEY" {
		return nil, errors.New("authority private key must be one PKCS#8 PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse authority private key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("authority private key is not Ed25519")
	}
	return key, nil
}

func publicKeyMaterial(key *rsa.PublicKey) ([]byte, bundle.Digest, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), bundle.Sum(der), nil
}

func signRSA(key *rsa.PrivateKey, preimage []byte) string {
	digest := sha256.Sum256(preimage)
	signature, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(signature)
}

func deterministicEd25519(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("kaiba stable verifier VM fixture " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func tlsMaterial() ([]byte, []byte, []byte, error) {
	caPrivate := deterministicEd25519("tls ca")
	serverPrivate := deterministicEd25519("tls server")
	defer clear(caPrivate)
	defer clear(serverPrivate)
	notBefore := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Kaiba VM test CA"},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true, IsCA: true,
	}
	caDER, err := x509.CreateCertificate(nil, caTemplate, caTemplate, caPrivate.Public(), caPrivate)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create TLS CA: %w", err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, nil, err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "authority"},
		DNSNames: []string{"authority"}, IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("192.168.1.1"),
			net.ParseIP("10.0.2.2"),
		},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(nil, serverTemplate, caCertificate, serverPrivate.Public(), caPrivate)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create TLS server certificate: %w", err)
	}
	serverPrivateDER, err := x509.MarshalPKCS8PrivateKey(serverPrivate)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverPrivateDER}), nil
}

func writeFile(path string, contents []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, contents, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
