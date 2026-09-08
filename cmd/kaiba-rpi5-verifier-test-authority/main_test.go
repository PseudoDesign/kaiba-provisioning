package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseauthorization"
)

func TestParseConfigRequiresExactPreloadedBindingAndTLS(t *testing.T) {
	arguments := validArguments(t)
	config, err := parseConfig(arguments, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if config.listen != "127.0.0.1:9443" || config.authorityKeyID != "test-authority-1" ||
		config.binding.LogicalIdentity != "pi-spike-1" || config.binding.StorageGeneration != 0 ||
		config.binding.Audience != "kaiba-rpi5-initramfs" ||
		config.binding.VerifierVersion != 7 || config.binding.SecurityEpoch != 9 ||
		config.challengeMaxAge != 20*time.Second || config.authorizationMaxAge != 10*time.Second ||
		config.maxOutstanding != 12 {
		t.Fatalf("config = %#v", config)
	}
	encoded, err := releaseauthorization.EncodePublicKey(config.bootstrapPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if encoded != arguments[valueIndex(arguments, "--bootstrap-public-key")] {
		t.Fatalf("bootstrap key = %q", encoded)
	}
}

func TestParseConfigRejectsMissingOrInvalidSecurityInputs(t *testing.T) {
	for _, flagName := range []string{
		"--tls-cert", "--tls-key", "--authority-key", "--authority-key-id", "--admin-socket",
		"--logical-identity", "--verifier-version", "--policy-digest", "--manifest-digest", "--security-epoch",
		"--audience",
	} {
		t.Run("missing "+flagName, func(t *testing.T) {
			arguments := removeFlag(validArguments(t), flagName)
			if _, err := parseConfig(arguments, &bytes.Buffer{}); err == nil {
				t.Fatalf("parseConfig accepted missing %s", flagName)
			}
		})
	}
	tests := []struct {
		name  string
		flag  string
		value string
	}{
		{"wildcard listener", "--listen", "0.0.0.0:9443"},
		{"hostname listener", "--listen", "localhost:9443"},
		{"bad bootstrap key", "--bootstrap-public-key", "ed25519:abcd"},
		{"bad policy digest", "--policy-digest", "sha256:abcd"},
		{"bad manifest digest", "--manifest-digest", "sha256:abcd"},
		{"zero verifier version", "--verifier-version", "0"},
		{"zero epoch", "--security-epoch", "0"},
		{"fractional challenge age", "--challenge-max-age", "1500ms"},
		{"long authorization age", "--authorization-max-age", "301s"},
		{"zero capacity", "--max-outstanding-challenges", "0"},
		{"relative TLS certificate", "--tls-cert", "server.crt"},
		{"unclean authority key path", "--authority-key", "/tmp/keys/../authority.pem"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arguments := validArguments(t)
			arguments[valueIndex(arguments, test.flag)] = test.value
			if _, err := parseConfig(arguments, &bytes.Buffer{}); err == nil {
				t.Fatal("parseConfig accepted invalid input")
			}
		})
	}
	if _, err := parseConfig(append(validArguments(t), "unexpected"), &bytes.Buffer{}); err == nil {
		t.Fatal("parseConfig accepted positional argument")
	}
	withoutPreload := removeFlag(validArguments(t), "--bootstrap-public-key")
	if config, err := parseConfig(withoutPreload, &bytes.Buffer{}); err != nil || len(config.bootstrapPublicKey) != 0 {
		t.Fatalf("optional bootstrap preload config = %#v, %v", config, err)
	}
}

func TestLoadAuthorityPrivateKeyRequiresOneSecureEd25519PKCS8File(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	validPath := filepath.Join(directory, "authority.pem")
	if err := os.WriteFile(validPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadAuthorityPrivateKey(validPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, privateKey) {
		t.Fatal("loaded private key differs")
	}

	insecurePath := filepath.Join(directory, "insecure.pem")
	if err := os.WriteFile(insecurePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuthorityPrivateKey(insecurePath); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Fatalf("insecure permissions error = %v", err)
	}
	malformedPath := filepath.Join(directory, "malformed.pem")
	if err := os.WriteFile(malformedPath, []byte("not a private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuthorityPrivateKey(malformedPath); err == nil {
		t.Fatal("malformed private key was accepted")
	}
	symlinkPath := filepath.Join(directory, "authority-link.pem")
	if err := os.Symlink(validPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuthorityPrivateKey(symlinkPath); err == nil {
		t.Fatalf("symlink private key error = %v", err)
	}
}

func TestListenProtectedAdminSocketCreatesMode0600AndUnlinks(t *testing.T) {
	socketPath := filepath.Join(shortSocketDirectory(t), "authority.sock")
	listener, err := listenProtectedAdminSocket(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("admin socket mode = %v", info.Mode())
	}
	if _, err := listenProtectedAdminSocket(socketPath); err == nil {
		t.Fatal("second listener accepted an existing socket path")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("closed socket still exists: %v", err)
	}
}

func TestListenProtectedAdminSocketRejectsWritableParent(t *testing.T) {
	directory := shortSocketDirectory(t)
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := listenProtectedAdminSocket(filepath.Join(directory, "authority.sock")); err == nil {
		t.Fatal("admin listener accepted a group/world-writable parent")
	}
}

func shortSocketDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "kaiba-auth-")
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

func validArguments(t *testing.T) []string {
	t.Helper()
	publicKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	encoded, err := releaseauthorization.EncodePublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return []string{
		"--listen", "127.0.0.1:9443",
		"--admin-socket", "/tmp/kaiba-rpi5-test-authority.sock",
		"--tls-cert", "/tmp/server.crt",
		"--tls-key", "/tmp/server.key",
		"--authority-key", "/tmp/authority.pem",
		"--authority-key-id", "test-authority-1",
		"--bootstrap-public-key", encoded,
		"--logical-identity", "pi-spike-1",
		"--audience", "kaiba-rpi5-initramfs",
		"--verifier-version", "7",
		"--policy-digest", testCommandDigest('a'),
		"--manifest-digest", testCommandDigest('b'),
		"--security-epoch", "9",
		"--challenge-max-age", "20s",
		"--authorization-max-age", "10s",
		"--max-outstanding-challenges", "12",
	}
}

func valueIndex(arguments []string, flagName string) int {
	for index := range arguments {
		if arguments[index] == flagName {
			return index + 1
		}
	}
	return -1
}

func removeFlag(arguments []string, flagName string) []string {
	index := valueIndex(arguments, flagName) - 1
	if index < 0 {
		return arguments
	}
	return append(append([]string(nil), arguments[:index]...), arguments[index+2:]...)
}

func testCommandDigest(fill byte) string {
	return "sha256:" + strings.Repeat(string([]byte{fill}), 64)
}
