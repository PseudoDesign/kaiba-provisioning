//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseauthorization"
)

func TestParseConfigUsesFixedHandoffDefaults(t *testing.T) {
	authorityPublic := testPrivateKey(1).Public().(ed25519.PublicKey)
	encodedAuthority, err := releaseauthorization.EncodePublicKey(authorityPublic)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseConfig([]string{
		"--authority-url", "https://192.0.2.10:8443",
		"--authority-ca", "/run/kaiba/authority-ca.pem",
		"--authority-key-id", "authority:test",
		"--authority-public-key", encodedAuthority,
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.authorizationPath != defaultAuthorizationPath || cfg.oneBootKeyPath != defaultOneBootKeyPath ||
		cfg.timeout != defaultRequestTimeout || !bytes.Equal(cfg.authorityPublicKey, authorityPublic) {
		t.Fatalf("unexpected config %#v", cfg)
	}
}

func TestParseConfigRejectsIncompleteOrUnsafeInputs(t *testing.T) {
	encodedAuthority, _ := releaseauthorization.EncodePublicKey(testPrivateKey(1).Public().(ed25519.PublicKey))
	valid := []string{
		"--authority-url", "https://192.0.2.10:8443",
		"--authority-ca", "/run/kaiba/authority-ca.pem",
		"--authority-key-id", "authority:test",
		"--authority-public-key", encodedAuthority,
	}
	for _, flagName := range []string{"--authority-url", "--authority-ca", "--authority-key-id", "--authority-public-key"} {
		t.Run("missing "+flagName, func(t *testing.T) {
			if _, err := parseConfig(removeFlag(valid, flagName), &bytes.Buffer{}); err == nil {
				t.Fatalf("accepted missing %s", flagName)
			}
		})
	}
	for name, arguments := range map[string][]string{
		"relative CA":       append(append([]string(nil), valid...), "--authority-ca", "authority.pem"),
		"unclean key path":  append(append([]string(nil), valid...), "--one-boot-key", "/run/kaiba/../key.pk8"),
		"bad public key":    replaceFlag(valid, "--authority-public-key", "ed25519:abcd"),
		"zero timeout":      append(append([]string(nil), valid...), "--timeout", "0s"),
		"oversized timeout": append(append([]string(nil), valid...), "--timeout", "31s"),
		"positional input":  append(append([]string(nil), valid...), "unexpected"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConfig(arguments, &bytes.Buffer{}); err == nil {
				t.Fatal("accepted invalid arguments")
			}
		})
	}
}

func TestPrepareOneBootProofAuthenticatesUnlinksAndSigns(t *testing.T) {
	authorization, authorityPublic, oneBootPrivate := issueAuthorization(t)
	directory := secureTempDir(t)
	authorizationPath := filepath.Join(directory, "authorization.json")
	keyPath := filepath.Join(directory, "one-boot.pk8")
	writeAuthorizationAndKey(t, authorizationPath, keyPath, authorization, oneBootPrivate)

	proof, err := prepareOneBootProof(authorizationPath, keyPath, authorization.AuthorityKeyID, authorityPublic)
	if err != nil {
		t.Fatal(err)
	}
	if err := releaseauthorization.VerifyOneBootProof(proof); err != nil {
		t.Fatalf("VerifyOneBootProof: %v", err)
	}
	if _, err := os.Lstat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("one-boot key still exists after proof preparation: %v", err)
	}
	if _, err := os.Lstat(authorizationPath); err != nil {
		t.Fatalf("authorization was unexpectedly removed: %v", err)
	}
}

func TestPrepareOneBootProofLeavesKeyOnAuthenticationOrBindingFailure(t *testing.T) {
	authorization, authorityPublic, oneBootPrivate := issueAuthorization(t)
	for _, test := range []struct {
		name         string
		authorityKey ed25519.PublicKey
		oneBootKey   ed25519.PrivateKey
		want         error
	}{
		{"wrong authority", testPrivateKey(9).Public().(ed25519.PublicKey), oneBootPrivate, releaseauthorization.ErrSignature},
		{"wrong one-boot key", authorityPublic, testPrivateKey(8), releaseauthorization.ErrBindingMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := secureTempDir(t)
			authorizationPath := filepath.Join(directory, "authorization.json")
			keyPath := filepath.Join(directory, "one-boot.pk8")
			writeAuthorizationAndKey(t, authorizationPath, keyPath, authorization, test.oneBootKey)
			if _, err := prepareOneBootProof(
				authorizationPath, keyPath, authorization.AuthorityKeyID, test.authorityKey,
			); !errors.Is(err, test.want) {
				t.Fatalf("prepareOneBootProof error = %v, want %v", err, test.want)
			}
			if _, err := os.Lstat(keyPath); err != nil {
				t.Fatalf("key removed before proof validation: %v", err)
			}
		})
	}
}

func TestOpenPinnedPrivateKeyRejectsSymlinkAndWritableParent(t *testing.T) {
	directory := secureTempDir(t)
	keyPath := filepath.Join(directory, "key.pk8")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(directory, "link.pk8")
	if err := os.Symlink(keyPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := openPinnedPrivateKey(symlinkPath); err == nil {
		t.Fatal("accepted symlink one-boot key")
	}
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := openPinnedPrivateKey(keyPath); err == nil {
		t.Fatal("accepted a key in a group/world-writable parent")
	}
}

func issueAuthorization(t *testing.T) (
	releaseauthorization.Authorization,
	ed25519.PublicKey,
	ed25519.PrivateKey,
) {
	t.Helper()
	authorityPrivate := testPrivateKey(1)
	authorityPublic := authorityPrivate.Public().(ed25519.PublicKey)
	bootstrapPrivate := testPrivateKey(2)
	bootstrapPublic := bootstrapPrivate.Public().(ed25519.PublicKey)
	oneBootPrivate := testPrivateKey(3)
	oneBootPublic := oneBootPrivate.Public().(ed25519.PublicKey)
	binding := releaseauthorization.BootBinding{
		LogicalIdentity: "pi-spike-1", Audience: "kaiba-rpi5-initramfs",
		StorageGeneration: 0, VerifierVersion: 7,
		PolicyDigest: testDigest('a'), ManifestDigest: testDigest('b'), SecurityEpoch: 9,
	}
	policy, err := releaseauthorization.NewExactBindingPolicy(binding)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := releaseauthorization.NewNonProductionAuthority(releaseauthorization.NonProductionAuthorityConfig{
		AuthorityKeyID: "authority:test", SigningKey: authorityPrivate,
		ChallengeMaxAge: 20 * time.Second, AuthorizationMaxAge: 20 * time.Second,
		BindingPolicy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	if err := authority.RegisterBootstrapKey(binding.LogicalIdentity, bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	challenge, err := authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	request, err := releaseauthorization.NewAuthorizationRequest(
		challenge, binding, append(ed25519.PrivateKey(nil), bootstrapPrivate...), oneBootPublic, authorityPublic, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := authority.Authorize(request)
	if err != nil {
		t.Fatal(err)
	}
	return authorization, append(ed25519.PublicKey(nil), authorityPublic...), append(ed25519.PrivateKey(nil), oneBootPrivate...)
}

func writeAuthorizationAndKey(
	t *testing.T,
	authorizationPath string,
	keyPath string,
	authorization releaseauthorization.Authorization,
	privateKey ed25519.PrivateKey,
) {
	t.Helper()
	encodedAuthorization, err := authorization.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authorizationPath, encodedAuthorization, 0o400); err != nil {
		t.Fatal(err)
	}
	encodedPrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, encodedPrivateKey, 0o400); err != nil {
		t.Fatal(err)
	}
}

func testPrivateKey(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
}

func testDigest(fill byte) string {
	return "sha256:" + strings.Repeat(string([]byte{fill}), 64)
}

func removeFlag(arguments []string, name string) []string {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name {
			return append(append([]string(nil), arguments[:index]...), arguments[index+2:]...)
		}
	}
	return append([]string(nil), arguments...)
}

func replaceFlag(arguments []string, name, value string) []string {
	result := append([]string(nil), arguments...)
	for index := 0; index+1 < len(result); index++ {
		if result[index] == name {
			result[index+1] = value
			return result
		}
	}
	return append(result, name, value)
}

func secureTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "kaiba-one-boot-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}
