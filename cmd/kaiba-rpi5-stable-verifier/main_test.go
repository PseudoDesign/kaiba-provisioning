//go:build linux

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseauthorization"
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
	parsed, err := parseConfig([]string{
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
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.verifierVersion != 1 || parsed.bootstrapRegistrationTimeout != defaultRegistrationTimeout ||
		parsed.clientTimeout != defaultClientTimeout {
		t.Fatalf("unexpected parsed configuration %#v", parsed)
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
		"trailing argument":         append(append([]string(nil), base...), "unexpected"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConfig(arguments); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
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
