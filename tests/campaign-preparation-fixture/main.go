// This executable is test infrastructure only. It signs deterministic synthetic
// campaign fixtures with explicitly supplied temporary software keys. It is not
// installed in any production package and never emits private-key material.
package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignprepare"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stableverifier"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) error {
	flags := flag.NewFlagSet("campaign-preparation-fixture", flag.ContinueOnError)
	rootPath := flags.String("root-private-key", "", "test-only temporary RSA private key")
	primaryPath := flags.String("primary-private-key", "", "test-only temporary RSA private key")
	replacementPath := flags.String("replacement-private-key", "", "test-only temporary RSA private key")
	revokedPath := flags.String("revoked-private-key", "", "test-only temporary RSA private key")
	releasePath := flags.String("release", "", "actual test release component directory")
	caPath := flags.String("authority-ca", "", "test authority public CA certificate")
	outputPath := flags.String("output", "", "new fixture output directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("fixture does not accept positional arguments")
	}
	for _, path := range []string{*rootPath, *primaryPath, *replacementPath, *revokedPath, *releasePath, *caPath, *outputPath} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return errors.New("all seven fixture paths must be clean absolute non-root paths")
		}
	}
	keys := make([]*rsa.PrivateKey, 4)
	for index, path := range []string{*rootPath, *primaryPath, *replacementPath, *revokedPath} {
		key, err := readFixtureKey(path)
		if err != nil {
			return err
		}
		keys[index] = key
	}
	rootPEM, rootFingerprint, err := fixturePublic(keys[0])
	if err != nil {
		return err
	}
	authorityHash := sha256.Sum256([]byte("kaiba-campaign-preparation-authority-public-fixture"))
	policy := stableverifier.Policy{SchemaVersion: stableverifier.PolicySchemaV1Alpha1, PolicyID: "policy:campaign-preparation-fixture", DeviceClass: stableverifier.DeviceClass, CohortID: "development", SecurityEpoch: 1, MinimumVerifierVersion: 1, ReleaseSignatureThreshold: 1, AllowedSlotIDs: []string{"a"}, RootKeyID: "root:campaign-fixture", RootKeyFingerprint: rootFingerprint, AuthorizationAuthorities: []stableverifier.AuthorizationAuthority{{KeyID: "authorization-vm", Algorithm: stableverifier.Ed25519Algorithm, PublicKey: "ed25519:" + hex.EncodeToString(authorityHash[:])}}}
	ids := []string{"release-primary", "release-replacement", "release-revoked"}
	for index, id := range ids {
		public, fingerprint, err := fixturePublic(keys[index+1])
		if err != nil {
			return err
		}
		status := "active"
		if index == 2 {
			status = "revoked"
		}
		policy.DelegatedKeys = append(policy.DelegatedKeys, stableverifier.DelegatedKey{KeyID: id, Algorithm: stableverifier.RSA2048SHA256Algorithm, PublicKeyPEM: string(public), PublicKeyFingerprint: fingerprint, Status: status})
	}
	policyPreimage, err := policy.SigningPreimage()
	if err != nil {
		return err
	}
	policy.RootSignature, err = fixtureSign(keys[0], policy.RootKeyID, policyPreimage)
	if err != nil {
		return err
	}
	policyJSON, err := policy.CanonicalJSON()
	if err != nil {
		return err
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		return err
	}
	manifest := stableverifier.Manifest{SchemaVersion: stableverifier.ManifestSchemaV1Alpha1, ReleaseID: "campaign-media-fixture", DeviceClass: stableverifier.DeviceClass, CohortID: "development", PolicyDigest: policyDigest, SecurityEpoch: 1, SlotID: "a", Overlays: []stableverifier.Overlay{}}
	for _, role := range stableverifier.ComponentRoles() {
		name, _ := stableverifier.ComponentPath(role)
		digest, size, err := digestFixtureComponent(filepath.Join(*releasePath, name))
		if err != nil {
			return err
		}
		manifest.Components = append(manifest.Components, stableverifier.Component{Role: role, Digest: digest, SizeBytes: size})
	}
	overlayDirectory := filepath.Join(*releasePath, "overlays")
	entries, err := os.ReadDir(overlayDirectory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".dtbo") || entry.IsDir() {
			return errors.New("fixture overlay directory contains an unexpected entry")
		}
		digest, size, err := digestFixtureComponent(filepath.Join(overlayDirectory, entry.Name()))
		if err != nil {
			return err
		}
		manifest.Overlays = append(manifest.Overlays, stableverifier.Overlay{Name: strings.TrimSuffix(entry.Name(), ".dtbo"), Digest: digest, SizeBytes: size})
	}
	preimage, err := manifest.SigningPreimage()
	if err != nil {
		return err
	}
	manifests := make([][]byte, 3)
	for index, id := range ids {
		signature, err := fixtureSign(keys[index+1], id, preimage)
		if err != nil {
			return err
		}
		manifest.Signatures = []stableverifier.RSASignature{signature}
		manifests[index], err = manifest.CanonicalJSON()
		if err != nil {
			return err
		}
	}
	if _, err := campaignprepare.BuildMutations(campaignprepare.MutationInputs{PolicyJSON: policyJSON, RootPublicPEM: rootPEM, PositiveManifestJSON: manifests[0], ReplacementManifestJSON: manifests[1], RevokedManifestJSON: manifests[2]}); err != nil {
		return fmt.Errorf("self-verify fixture: %w", err)
	}
	ca, err := readFixtureBounded(*caPath, 65536)
	if err != nil {
		return err
	}
	block, rest := pem.Decode(ca)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("authority-ca must contain one public certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return err
	}
	if err := os.Mkdir(*outputPath, 0755); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"policy.json": policyJSON, "root-public.pem": rootPEM, "positive-manifest.json": manifests[0], "replacement-manifest.json": manifests[1], "revoked-manifest.json": manifests[2], "authority-ca.pem": ca} {
		file, err := os.OpenFile(filepath.Join(*outputPath, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
		if err != nil {
			return err
		}
		if _, err := file.Write(data); err != nil {
			file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	return nil
}

func readFixtureBounded(path string, maximum int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maximum {
		return nil, errors.New("fixture input is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != info.Size() {
		return nil, errors.New("fixture input changed while reading")
	}
	return data, nil
}
func readFixtureKey(path string) (*rsa.PrivateKey, error) {
	encoded, err := readFixtureBounded(path, 65536)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "RSA PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, errors.New("fixture key must be one RSA PRIVATE KEY PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	if key.N.BitLen() != 2048 || key.E != 65537 {
		return nil, errors.New("fixture key must be RSA-2048 e65537")
	}
	return key, nil
}
func fixturePublic(key *rsa.PrivateKey) ([]byte, bundle.Digest, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), bundle.Sum(der), nil
}
func fixtureSign(key *rsa.PrivateKey, id string, input []byte) (stableverifier.RSASignature, error) {
	digest := sha256.Sum256(input)
	signature, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
	if err != nil {
		return stableverifier.RSASignature{}, err
	}
	return stableverifier.RSASignature{KeyID: id, Algorithm: stableverifier.RSA2048SHA256Algorithm, Value: base64.StdEncoding.EncodeToString(signature)}, nil
}
func digestFixtureComponent(path string) (bundle.Digest, uint64, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 64*1024*1024*1024 {
		return "", 0, errors.New("fixture component is not a bounded regular file")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, info.Size()+1))
	if err != nil {
		return "", 0, err
	}
	if size != info.Size() {
		return "", 0, errors.New("fixture component changed size while hashing")
	}
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), uint64(size), nil
}
