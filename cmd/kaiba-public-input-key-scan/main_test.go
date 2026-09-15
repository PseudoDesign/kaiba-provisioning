//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/pemmarkers"
)

func invoke(arguments ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(arguments, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}
func TestDefaultStrictAndExplicitRootMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.img")
	literal := []byte("-----BEGIN PRIVATE KEY-----\x00")
	if err := os.WriteFile(path, literal, 0600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := invoke("--input", path)
	if code == 0 || stdout != "" || !strings.Contains(stderr, "scoped defense in depth") {
		t.Fatal("strict default did not reject marker")
	}
	code, stdout, stderr = invoke("--input", path, "--mode", "reviewed-root-literals")
	if code != 0 || stderr != "" {
		t.Fatal("explicit reviewed mode failed", stderr)
	}
	var report pemmarkers.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "passed" || report.Mode != pemmarkers.ReviewedRootLiterals || report.BytesScanned != uint64(len(literal)) || len(report.PublicLiteralMatches) != 1 || report.ProofOfPrivateMaterialAbsence || report.PrivateKeyOperationPerformed {
		t.Fatal("wrong bounded scan report")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, literal) {
		t.Fatal("scanner modified input")
	}
}

func TestEmptyRegularAndNixStyleHardlinkedFiles(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "input")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := invoke("--input", path); code != 0 {
		t.Fatal(stderr)
	}
	if err := os.WriteFile(path, []byte("ordinary public data"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "hardlink")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := invoke("--input", link); code != 0 {
		t.Fatal("Nix store hardlink refused", stderr)
	}
}

func TestRejectsUnsupportedPathsWithoutReadingSpecialFiles(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "regular")
	if err := os.WriteFile(regular, []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(directory, "parent-link")
	if err := os.Symlink(directory, parentLink); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(directory, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", "/", "/dev/null", directory, directory + "/../escape", link, filepath.Join(parentLink, "regular"), fifo} {
		code, stdout, _ := invoke("--input", path)
		if code == 0 || stdout != "" {
			t.Fatal("unsupported input accepted", path)
		}
	}
}

func TestArgumentFailuresAndNoBodyDiagnostics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	contents := "-----BEGIN PRIVATE KEY-----\nDO-NOT-PRINT-INPUT-BODY\x00"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{nil, {"--input", path, "--input", path}, {"--input", path, "--mode", "strict", "--mode", "reviewed-root-literals"}, {"--input", path, "--mode", "arbitrary"}, {"--input", path, "--catalog", "caller.json"}, {"--input", path, "extra"}} {
		code, stdout, _ := invoke(args...)
		if code == 0 || stdout != "" {
			t.Fatal("unexpected flags accepted")
		}
	}
	code, stdout, stderr := invoke("--input", path, "--mode", "reviewed-root-literals")
	if code == 0 || stdout != "" || strings.Contains(stderr, "DO-NOT-PRINT") || strings.Contains(stderr, "-----BEGIN") {
		t.Fatal("unknown literal accepted or input bytes disclosed")
	}
}
