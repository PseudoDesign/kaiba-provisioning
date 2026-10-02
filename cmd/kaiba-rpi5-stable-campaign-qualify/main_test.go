//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignqualification"
)

func TestPublicReaderRejectsSymlinksDevicesAndFIFOsWithoutOpeningThem(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "public.json")
	if err := os.WriteFile(file, []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPublic(file, 6); err != nil {
		t.Fatal(err)
	}
	if _, err := readPublic(file, 5); err == nil {
		t.Fatal("oversized file accepted")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	directoryLink := filepath.Join(root, "directory-link")
	if err := os.Symlink(root, directoryLink); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, filepath.Join(directoryLink, "public.json"), fifo, "/dev/null", root, "relative.json"} {
		if _, err := readPublic(path, 1024); err == nil {
			t.Fatalf("unsafe public source accepted: %s", path)
		}
	}
}

func TestPreimageUsesOnlyPublicStatementAndRoleDomain(t *testing.T) {
	witness := campaignqualification.SignedWitness{Statement: campaignqualification.WitnessStatement{SchemaVersion: campaignqualification.WitnessSchema}}
	encoded, err := witness.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "witness.json")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{campaignqualification.CollectorRole, campaignqualification.ReviewerRole} {
		var stdout, stderr bytes.Buffer
		if status := run([]string{"preimage", "--witness", path, "--role", role}, &stdout, &stderr); status != 0 {
			t.Fatalf("status %d: %s", status, &stderr)
		}
		expected, _ := witness.Statement.SigningBytes(role)
		if !bytes.Equal(stdout.Bytes(), expected) {
			t.Fatal("signing preimage changed or acquired a transport newline")
		}
	}
}

func TestRepeatedAuthorityAndInputOptionsAreRejected(t *testing.T) {
	for _, option := range []string{"request", "session", "trust-policy", "admission-directory", "witness", "role"} {
		var stdout, stderr bytes.Buffer
		status := run([]string{"validate", "--" + option, "first", "--" + option + "=second"}, &stdout, &stderr)
		if status != 2 || stdout.Len() != 0 || !bytes.Contains(stderr.Bytes(), []byte("only once")) {
			t.Fatalf("repeated %s option was not rejected before opening inputs: status %d, %s", option, status, &stderr)
		}
	}
}

func TestMalformedRequestsNeverEmitAcceptance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{}, {"unknown"}, {"prepare"}, {"validate", "--request", path}, {"prepare", "--request", path}, {"prepare", "--request", "/dev/null"}, {"preimage", "--witness", path, "--role", "signer"}} {
		var stdout, stderr bytes.Buffer
		if status := run(args, &stdout, &stderr); status == 0 {
			t.Fatalf("malformed request accepted: %v", args)
		}
		if stdout.Len() != 0 {
			t.Fatal("failure emitted an acceptance result")
		}
	}
}

func TestFileStateIgnoresReadAccessTimeButDetectsContentChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "public")
	os.WriteFile(path, []byte("first"), 0600)
	before, _ := os.Stat(path)
	after := *before.Sys().(*syscall.Stat_t)
	after.Atim.Sec++
	copyInfo := testFileInfo{FileInfo: before, stat: &after}
	if !sameFileState(before, copyInfo) {
		t.Fatal("ordinary read atime change was rejected")
	}
	after.Mtim.Nsec++
	if sameFileState(before, copyInfo) {
		t.Fatal("content mtime change was accepted")
	}
}

type testFileInfo struct {
	os.FileInfo
	stat *syscall.Stat_t
}

func (info testFileInfo) Sys() any { return info.stat }
