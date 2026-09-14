//go:build linux

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
)

func fixtureArguments(t *testing.T) []string {
	t.Helper()
	root, err := filepath.Abs("../../internal/provisioning/campaignmedia/testdata/recovery-v1alpha2")
	if err != nil {
		t.Fatal(err)
	}
	return []string{"--staging-plan", filepath.Join(root, "staging-plan.json"), "--sd-envelope", filepath.Join(root, "sd-envelope.json"), "--nvme-envelope", filepath.Join(root, "nvme-envelope.json")}
}

func TestCapturedEnvelopesProduceStrictDescriptiveCatalog(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(fixtureArguments(t), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	requirements, err := campaignmedia.ParseRecoveryBackupRequirementsV1Alpha2(stdout.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if requirements.DestructiveStagingReady || requirements.BlockDeviceWritesPermitted || requirements.BackupCapturePerformed {
		t.Fatal("descriptive catalog claimed physical progress")
	}
	if err := requirements.ValidateForDestructiveStaging(); err == nil {
		t.Fatal("catalog enabled physical staging")
	}
	if stderr.Len() != 0 || bytes.Count(stdout.Bytes(), []byte{'\n'}) != 1 {
		t.Fatal("stdout is not a single canonical record or success emitted diagnostics")
	}
}

func TestRejectsSwappedLegsAndNoncanonicalCapture(t *testing.T) {
	for _, mutation := range []string{"swapped", "noncanonical"} {
		t.Run(mutation, func(t *testing.T) {
			arguments := fixtureArguments(t)
			if mutation == "swapped" {
				arguments[3], arguments[5] = arguments[5], arguments[3]
			} else {
				encoded, err := os.ReadFile(arguments[3])
				if err != nil {
					t.Fatal(err)
				}
				arguments[3] = filepath.Join(t.TempDir(), "capture.json")
				if err := os.WriteFile(arguments[3], append([]byte(" "), encoded...), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var stdout, stderr bytes.Buffer
			if code := run(arguments, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestInputFilesExcludeStreamsLinksAndOversizedObjects(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "regular")
	if err := os.WriteFile(regular, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(directory, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	oversized := filepath.Join(directory, "oversized")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte{'x'}, maximumInputBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{directory, link, fifo, oversized, "/dev/null"} {
		if _, err := readInput(path); err == nil {
			t.Errorf("accepted non-input %q", path)
		}
	}
}

func TestUsageAndOutputFailure(t *testing.T) {
	for _, arguments := range [][]string{nil, {"--staging-plan", "relative"}, {"--device", "/dev/null"}, append(fixtureArguments(t), "--sd-envelope", "/tmp/repeated"), append(fixtureArguments(t), "extra")} {
		var stdout, stderr bytes.Buffer
		if code := run(arguments, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Errorf("arguments %q: exit=%d stdout=%s", arguments, code, stdout.String())
		}
	}
	var help bytes.Buffer
	if code := run([]string{"--help"}, io.Discard, &help); code != 0 || !strings.Contains(help.String(), "descriptive") {
		t.Fatalf("help exit=%d: %s", code, help.String())
	}
	if code := run(fixtureArguments(t), failedWriter{}, io.Discard); code != 1 {
		t.Fatalf("failed stdout returned %d", code)
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("closed output") }
