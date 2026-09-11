//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseauthorization"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5kexecinput"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablehandoff"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stableverifier"
)

func TestRunFailsClosedWithStructuredEvents(t *testing.T) {
	var output bytes.Buffer
	if exitCode := run(context.Background(), nil, &output); exitCode != exitConfiguration {
		t.Fatalf("run exit code = %d, want %d", exitCode, exitConfiguration)
	}
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"event":"verifier-started"`) ||
		!strings.Contains(lines[1], `"event":"verifier-failed"`) ||
		!strings.Contains(lines[1], `"failure_code":"configuration-invalid"`) {
		t.Fatalf("unexpected output %q", output.String())
	}
	if strings.Contains(output.String(), "--policy is required") {
		t.Fatal("structured failure output leaked internal configuration detail")
	}
}

func TestParseConfigAcceptsCompleteFixedConfiguration(t *testing.T) {
	parsed, err := parseConfig(completeVerifierArguments())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.verifierVersion != 1 || parsed.bootstrapRegistrationTimeout != defaultRegistrationTimeout ||
		parsed.clientTimeout != defaultClientTimeout ||
		parsed.kexecMode != stablehandoff.KexecModeLegacyExplicitDeviceTree {
		t.Fatalf("unexpected parsed configuration %#v", parsed)
	}
}

func TestParseConfigMapsExplicitKexecModes(t *testing.T) {
	for _, test := range []struct {
		value string
		want  stablehandoff.KexecMode
	}{
		{kexecModeLegacyExplicitDTB, stablehandoff.KexecModeLegacyExplicitDeviceTree},
		{kexecModeExperimentalFileLiveFDT, stablehandoff.KexecModeExperimentalFileLiveDeviceTree},
	} {
		t.Run(test.value, func(t *testing.T) {
			arguments := append(completeVerifierArguments(), "--kexec-mode", test.value)
			parsed, err := parseConfig(arguments)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.kexecMode != test.want {
				t.Fatalf("kexec mode = %d, want %d", parsed.kexecMode, test.want)
			}
		})
	}
}

func TestParseConfigRejectsUnsafeTimeoutsAndTrailingArguments(t *testing.T) {
	base := []string{
		"--policy", "/policy", "--root-public-key", "/root.pem", "--release-dir", "/release",
		"--verifier-version", "1", "--cohort-id", "cohort", "--slot-id", "a",
		"--authority-url", "https://example.invalid", "--authority-ca", "/ca.pem",
		"--authority-key-id", "authority", "--logical-identity", "test",
		"--audience", "kaiba-rpi5-release", "--kexec", "/kexec",
	}
	for name, arguments := range map[string][]string{
		"zero registration timeout": append(append([]string(nil), base...), "--bootstrap-registration-timeout", "0s"),
		"oversized client timeout":  append(append([]string(nil), base...), "--authority-client-timeout", "31s"),
		"unknown kexec mode":        append(append([]string(nil), base...), "--kexec-mode", "file-live-fdt"),
		"trailing argument":         append(append([]string(nil), base...), "unexpected"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConfig(arguments); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func TestValidateKexecPlatformLegacySkipsLiveDeviceTree(t *testing.T) {
	if err := validateKexecPlatform(
		stablehandoff.KexecModeLegacyExplicitDeviceTree,
		"authenticated command line",
		nil,
		nil,
	); err != nil {
		t.Fatalf("legacy platform validation = %v", err)
	}
}

func TestValidateKexecPlatformExperimentalUsesFixedBoundedInput(t *testing.T) {
	deviceTree := []byte("live firmware device tree")
	commandLine := "authenticated release command line"
	readCalls := 0
	validateCalls := 0
	err := validateKexecPlatform(
		stablehandoff.KexecModeExperimentalFileLiveDeviceTree,
		commandLine,
		func(path string, maximum int) ([]byte, error) {
			readCalls++
			if path != liveDeviceTreePath {
				t.Fatalf("live device-tree path = %q, want %q", path, liveDeviceTreePath)
			}
			if maximum != rpi5kexecinput.MaxDeviceTreeBytes {
				t.Fatalf("live device-tree bound = %d, want %d", maximum, rpi5kexecinput.MaxDeviceTreeBytes)
			}
			return append([]byte(nil), deviceTree...), nil
		},
		func(gotDeviceTree []byte, gotCommandLine string) error {
			validateCalls++
			if !bytes.Equal(gotDeviceTree, deviceTree) || gotCommandLine != commandLine {
				t.Fatalf("validator inputs = %q, %q", gotDeviceTree, gotCommandLine)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if readCalls != 1 || validateCalls != 1 {
		t.Fatalf("read calls = %d, validation calls = %d", readCalls, validateCalls)
	}
}

func TestValidateKexecPlatformExperimentalFailsWithoutValidLivePiDeviceTree(t *testing.T) {
	readFailure := errors.New("live device tree is unavailable")
	if err := validateKexecPlatform(
		stablehandoff.KexecModeExperimentalFileLiveDeviceTree,
		"authenticated command line",
		func(string, int) ([]byte, error) { return nil, readFailure },
		func([]byte, string) error { t.Fatal("validator called after read failure"); return nil },
	); !errors.Is(err, readFailure) {
		t.Fatalf("missing live device-tree error = %v", err)
	}

	err := validateKexecPlatform(
		stablehandoff.KexecModeExperimentalFileLiveDeviceTree,
		"console=ttyAMA10,115200n8 earlycon=pl011,0x107d001000,115200n8",
		func(string, int) ([]byte, error) { return []byte("not an FDT"), nil },
		rpi5kexecinput.Validate,
	)
	if err == nil || !strings.Contains(err.Error(), "validate live firmware device tree") {
		t.Fatalf("malformed live device-tree error = %v", err)
	}

	if err := validateKexecPlatform(
		stablehandoff.KexecModeExperimentalFileLiveDeviceTree,
		"authenticated command line",
		nil,
		nil,
	); err == nil {
		t.Fatal("experimental mode accepted missing validation dependencies")
	}
}

func TestOpenHandoffDeviceTreeFollowsKexecMode(t *testing.T) {
	deviceTree, err := os.CreateTemp(t.TempDir(), "release-dtb")
	if err != nil {
		t.Fatal(err)
	}
	defer deviceTree.Close()
	openCalls := 0
	got, err := openHandoffDeviceTree(
		stablehandoff.KexecModeLegacyExplicitDeviceTree,
		func(role stableverifier.ComponentRole) (*os.File, error) {
			openCalls++
			if role != stableverifier.RoleResolvedDeviceTree {
				t.Fatalf("opened role %q", role)
			}
			return deviceTree, nil
		},
	)
	if err != nil || got != deviceTree || openCalls != 1 {
		t.Fatalf("legacy device tree = %p, calls = %d, error = %v", got, openCalls, err)
	}

	got, err = openHandoffDeviceTree(
		stablehandoff.KexecModeExperimentalFileLiveDeviceTree,
		func(stableverifier.ComponentRole) (*os.File, error) {
			t.Fatal("experimental mode opened the authenticated release DTB")
			return nil, nil
		},
	)
	if err != nil || got != nil {
		t.Fatalf("experimental device tree = %p, error = %v", got, err)
	}
}

func TestReadBoundedFileRejectsMissingEmptyAndOversizedInputs(t *testing.T) {
	directory := t.TempDir()
	if _, err := readBoundedFile(filepath.Join(directory, "missing"), 4); err == nil {
		t.Fatal("missing file was accepted")
	}

	emptyPath := filepath.Join(directory, "empty")
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(emptyPath, 4); err == nil {
		t.Fatal("empty file was accepted")
	}

	exactPath := filepath.Join(directory, "exact")
	if err := os.WriteFile(exactPath, []byte("four"), 0o600); err != nil {
		t.Fatal(err)
	}
	contents, err := readBoundedFile(exactPath, 4)
	if err != nil || string(contents) != "four" {
		t.Fatalf("exact-bound read = %q, %v", contents, err)
	}

	oversizedPath := filepath.Join(directory, "oversized")
	if err := os.WriteFile(oversizedPath, []byte("five!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(oversizedPath, 4); err == nil {
		t.Fatal("oversized file was accepted")
	}
	if _, err := readBoundedFile(exactPath, 0); err == nil {
		t.Fatal("non-positive bound was accepted")
	}
}

func TestSelectedAuthorityKeyRequiresPolicyMembership(t *testing.T) {
	policy := stableverifier.Policy{AuthorizationAuthorities: []stableverifier.AuthorizationAuthority{{
		KeyID: "authority:one", PublicKey: "ed25519:" + strings.Repeat("a", 64),
	}}}
	key, err := selectedAuthorityKey(policy, "authority:one")
	if err != nil || len(key) != 32 {
		t.Fatalf("selectedAuthorityKey() = %x, %v", key, err)
	}
	if _, err := selectedAuthorityKey(policy, "authority:two"); err == nil {
		t.Fatal("authority absent from policy was accepted")
	}
}

func TestAwaitBootstrapRegistrationStopsOnContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, _, err := awaitBootstrapRegistration(ctx, nil, structAuthorizationRequest())
	if err == nil {
		t.Fatal("nil authorization client was accepted")
	}
}

// A zero request is sufficient here: the nil client must fail before it can
// consume or validate protocol input.
func structAuthorizationRequest() releaseauthorization.AuthorizationRequest {
	return releaseauthorization.AuthorizationRequest{}
}

func completeVerifierArguments() []string {
	return []string{
		"--policy", "/boot/kaiba/policy.json",
		"--root-public-key", "/boot/kaiba/root-public.pem",
		"--release-dir", "/run/kaiba-release",
		"--verifier-version", "1",
		"--cohort-id", "cohort:test",
		"--slot-id", "a",
		"--minimum-security-epoch", "0",
		"--authority-url", "https://192.0.2.10:8443",
		"--authority-ca", "/boot/kaiba/authority-ca.pem",
		"--authority-key-id", "authority:test",
		"--logical-identity", "rpi5-spike:test",
		"--audience", "kaiba-rpi5-release",
		"--kexec", "/nix/store/test/bin/kexec",
	}
}
