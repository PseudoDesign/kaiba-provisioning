package yubikeysigner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func providerDiagnostic(code uint64, reason string) string {
	return fmt.Sprintf("40ABCDEF00000000:error:%08X:pkcs11::%s:../src/session.c:123:private diagnostic text\n", 0x40800000|code, reason)
}

func TestPKCS11FailureCodes(t *testing.T) {
	pin := providerDiagnostic(0xa0, "The specified PIN is incorrect")
	removed := providerDiagnostic(0x32, "The token was removed from its slot during the execution of the function")
	for _, test := range []struct{ name, stderr, want string }{
		{"pin", pin, "CKR_PIN_INCORRECT"},
		{"multiple and duplicate", pin + removed + pin, "CKR_DEVICE_REMOVED,CKR_PIN_INCORRECT"},
		{"dynamic library number", strings.Replace(pin, "408000A0", "428000A0", 1), "CKR_PIN_INCORRECT"},
		{"unknown reason", providerDiagnostic(0xff, "unrecognized secret text"), "unclassified"},
		{"mismatched reason and code", providerDiagnostic(0x30, "The specified PIN is incorrect"), "unclassified"},
		{"wrong library", strings.Replace(pin, ":pkcs11:", ":SSL routines:", 1), "unclassified"},
		{"plain text", "The specified PIN is incorrect CKR_PIN_INCORRECT", "unclassified"},
		{"code in arbitrary data", "error from command: " + pin, "unclassified"},
		{"embedded null", strings.Replace(pin, "incorrect", "incorrect\x00", 1), "unclassified"},
		{"bad thread field", strings.Replace(pin, "40ABCDEF00000000", "pin-value=654321", 1), "unclassified"},
		{"bad packed code", strings.Replace(pin, "408000A0", "408000ZZ", 1), "unclassified"},
		{"incomplete line", "40AA:error:408000A0:pkcs11::The specified PIN is incorrect", "unclassified"},
		{"oversized", pin + strings.Repeat("x", maxDiagnosticBytes), "unclassified"},
		{"empty", "", "unclassified"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := pkcs11FailureCodes([]byte(test.stderr)); got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestCommandFailureExitStatus(t *testing.T) {
	if os.Getenv("KAIBA_DIAGNOSTIC_EXIT_FIXTURE") == "1" {
		os.Exit(7)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestCommandFailureExitStatus$")
	command.Env = append(os.Environ(), "KAIBA_DIAGNOSTIC_EXIT_FIXTURE=1")
	err := command.Run()
	if err == nil {
		t.Fatal("fixture process unexpectedly succeeded")
	}
	got := commandFailure("YubiKey signing", Result{}, fmt.Errorf("private wrapper error: %w", err)).Error()
	want := "YubiKey signing command failed (exit_status=7; pkcs11=unclassified; raw diagnostics withheld)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSignerFailureRedactsAllProviderAndRunnerOutput(t *testing.T) {
	const secret = "PIN=654321 pkcs11:serial=12345678;id=%02?pin-value=654321 /private/credential"
	for _, phase := range []string{"sign", "verify"} {
		t.Run(phase, func(t *testing.T) {
			var fake *fakeOpenSSL
			calls := 0
			fixture := newFixture(t, runnerFunc(func(ctx context.Context, invocation Invocation) (Result, error) {
				calls++
				if phase == "verify" && calls == 1 {
					return fake.Run(ctx, invocation)
				}
				diagnostic := providerDiagnostic(0x30, "Some problem has occurred with the token and/or slot")
				return Result{Stdout: []byte(secret), Stderr: []byte(secret + "\n" + diagnostic + secret)}, errors.New(secret)
			}))
			fake = &fakeOpenSSL{privateKey: fixture.privateKey}
			signer := newTestSigner(t, fixture.config)
			signature, err := signer.Sign(context.Background(), fixture.inputPath)
			if err == nil || signature != nil {
				t.Fatal("failed command must return only an error")
			}
			stage, wantCalls := "YubiKey signing", 1
			if phase == "verify" {
				stage, wantCalls = "signature verification", 2
			}
			want := stage + " command failed (process_failure; pkcs11=CKR_DEVICE_ERROR; raw diagnostics withheld)"
			if err.Error() != want || calls != wantCalls {
				t.Fatalf("error/calls = %q/%d, want %q/%d", err, calls, want, wantCalls)
			}
		})
	}
}

func FuzzPKCS11FailureCodesAreAllowlisted(f *testing.F) {
	f.Add([]byte(providerDiagnostic(0xa0, "The specified PIN is incorrect")))
	f.Add([]byte("PIN=654321\x00\nsecret"))
	f.Fuzz(func(t *testing.T, diagnostic []byte) {
		got := pkcs11FailureCodes(diagnostic)
		if got == "unclassified" {
			return
		}
		seen := make(map[string]bool)
		for _, name := range strings.Split(got, ",") {
			allowed := false
			for _, known := range knownPKCS11Reasons {
				allowed = allowed || name == known.name
			}
			if !allowed || seen[name] {
				t.Fatalf("unexpected or duplicate output %q", got)
			}
			seen[name] = true
		}
	})
}
