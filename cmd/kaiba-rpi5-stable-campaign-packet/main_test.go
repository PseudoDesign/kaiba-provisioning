//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestHelpDescribesPreparationBoundary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help returned %d", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "preparation-only") || !strings.Contains(stderr.String(), "No signing, device access") {
		t.Fatalf("incorrect help boundary: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestCLIRejectsMissingDuplicateAndDeviceArguments(t *testing.T) {
	for _, arguments := range [][]string{
		{}, {"extra"}, {"--source-revision", "main", "--source-revision", "other"},
		{"--campaign-plan", "relative"}, {"--campaign-plan", "/dev/null"},
		{"--campaign-plan", "/tmp/../plan.json"}, {"--execute"}, {"--output", "/tmp/output"},
		{"--public-input", "same=/tmp/a", "--public-input", "same=/tmp/b"},
		{"--public-input", "missing-separator"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(arguments, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Fatalf("arguments %v returned %d: %s", arguments, code, stderr.String())
		}
	}
}

func TestOpeningPinsOnlyBoundedRegularInputs(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "public.json")
	if err := os.WriteFile(regular, []byte("public input"), 0600); err != nil {
		t.Fatal(err)
	}
	input, err := openRegular(regular, maximumJSONBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer input.file.Close()
	if err := input.revalidate(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(regular, []byte("changed input"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := input.revalidate(); err == nil {
		t.Fatal("accepted source changed during verification")
	}
	for name, create := range map[string]func(string) error{
		"symlink":   func(path string) error { return os.Symlink(regular, path) },
		"fifo":      func(path string) error { return syscall.Mkfifo(path, 0600) },
		"empty":     func(path string) error { return os.WriteFile(path, nil, 0600) },
		"directory": func(path string) error { return os.Mkdir(path, 0700) },
	} {
		path := filepath.Join(directory, name)
		if err := create(path); err != nil {
			t.Fatal(err)
		}
		if file, err := openRegular(path, maximumJSONBytes); err == nil {
			file.file.Close()
			t.Fatalf("accepted %s", name)
		}
	}
	if file, err := openRegular(regular, 1); err == nil {
		file.file.Close()
		t.Fatal("accepted oversized source")
	}
	hardlink := filepath.Join(directory, "hardlink")
	if err := os.Link(regular, hardlink); err != nil {
		t.Fatal(err)
	}
	if file, err := openRegular(hardlink, maximumJSONBytes); err == nil {
		file.file.Close()
		t.Fatal("accepted multiply linked source")
	}
	parent := filepath.Join(directory, "parent")
	if err := os.Symlink(directory, parent); err != nil {
		t.Fatal(err)
	}
	if file, err := openRegular(filepath.Join(parent, "public.json"), maximumJSONBytes); err == nil {
		file.file.Close()
		t.Fatal("followed parent symlink")
	}
}

func TestPathReplacementDoesNotRedirectPinnedReads(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "original")
	if err := os.WriteFile(path, []byte("pinned bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	input, err := openRegular(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer input.file.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len("pinned bytes"))
	if _, err := input.file.ReadAt(buffer, 0); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "pinned bytes" {
		t.Fatal("replacement redirected pinned input")
	}
	if err := input.revalidate(); err == nil {
		t.Fatal("accepted unlinked input after replacement")
	}
}

func TestContractParsingRequiresActualCanonicalPlan(t *testing.T) {
	for _, encoded := range []string{"{}", "null", `{\"plan_digest\":\"fake\",\"plan_digest\":\"fake\"}`, "[]", "{}\n{}"} {
		if _, err := parseContracts(map[string][]byte{"campaign-plan": []byte(encoded)}); err == nil {
			t.Fatalf("accepted %s", encoded)
		}
	}
}
