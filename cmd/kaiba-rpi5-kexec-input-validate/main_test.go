package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRequiresBothNamedInputs(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{"--device-tree", "/tmp/tree.dtb"},
		{"--command-line", "/tmp/cmdline.txt"},
		{"positional"},
	} {
		var output, errorOutput bytes.Buffer
		if exit := run(arguments, &output, &errorOutput); exit != exitUsage {
			t.Fatalf("run(%q) exit = %d, want %d", arguments, exit, exitUsage)
		}
		if output.Len() != 0 || errorOutput.Len() == 0 {
			t.Fatalf("run(%q) output = %q, error = %q", arguments, output.String(), errorOutput.String())
		}
	}
}

func TestRunReportsInvalidInputsWithoutSuccessOutput(t *testing.T) {
	directory := t.TempDir()
	deviceTreePath := filepath.Join(directory, "tree.dtb")
	commandLinePath := filepath.Join(directory, "cmdline.txt")
	if err := os.WriteFile(deviceTreePath, []byte("not a DTB"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(commandLinePath, []byte("console=serial0,115200n8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output, errorOutput bytes.Buffer
	exit := run([]string{"--device-tree", deviceTreePath, "--command-line", commandLinePath}, &output, &errorOutput)
	if exit != exitInvalid {
		t.Fatalf("exit = %d, want %d (%s)", exit, exitInvalid, errorOutput.String())
	}
	if output.Len() != 0 || !strings.Contains(errorOutput.String(), "device tree: header is truncated") {
		t.Fatalf("output = %q, error = %q", output.String(), errorOutput.String())
	}
}

func TestReadBoundedRegularRejectsDirectoriesAndBounds(t *testing.T) {
	directory := t.TempDir()
	if _, err := readBoundedRegular(directory, 10); err == nil {
		t.Fatal("accepted directory input")
	}
	empty := filepath.Join(directory, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRegular(empty, 10); err == nil {
		t.Fatal("accepted empty input")
	}
	large := filepath.Join(directory, "large")
	if err := os.WriteFile(large, bytes.Repeat([]byte{'x'}, 11), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRegular(large, 10); err == nil {
		t.Fatal("accepted oversized input")
	}
}
