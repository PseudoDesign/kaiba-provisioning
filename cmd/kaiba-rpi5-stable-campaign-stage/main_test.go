//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestGenericHasNoDeviceAuthority(t *testing.T) {
	prior := configurationPath
	configurationPath = ""
	t.Cleanup(func() { configurationPath = prior })
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"execute", "--directory", "/absent", "--approval", "/absent", "--requirements", "/absent", "--sd-envelope", "/absent", "--nvme-envelope", "/absent"}, &stdout, &stderr)
	if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "generic build has no linker-fixed") {
		t.Fatalf("generic execution: code=%d stdout=%s stderr=%s", code, &stdout, &stderr)
	}
}

func TestNoRuntimeConfigurationOverride(t *testing.T) {
	for _, args := range [][]string{
		{"verify", "--device", "/dev/null"},
		{"verify", "--configuration", "/tmp/config.json"},
		{"execute", "--force"},
		{"approve", "--preview", "/a", "--preview", "/b"},
		{"verify", "positional"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Fatalf("args=%v code=%d stdout=%s stderr=%s", args, code, &stdout, &stderr)
		}
	}
}

func TestReadJSONRejectsSpecialFilesAndLinksBeforeRead(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular.json")
	if err := os.WriteFile(regular, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(dir, "parent")
	if err := os.Symlink(dir, parentLink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, link, filepath.Join(parentLink, "regular.json"), dir, "/dev/null", "relative.json"} {
		if _, err := readJSON(path); err == nil {
			t.Fatalf("accepted %s", path)
		}
	}
	data, err := readJSON(regular)
	if err != nil || string(data) != "{}\n" {
		t.Fatalf("regular input %q: %v", data, err)
	}
	if err := os.Truncate(regular, maximumJSONBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := readJSON(regular); err == nil {
		t.Fatal("oversize input accepted")
	}
}

func TestConfigurationRequiresStorePath(t *testing.T) {
	for _, path := range []string{"", "/tmp/config.json", "/nix/storeevil/config", "/nix/store/../config"} {
		if _, err := loadConfiguration(path); err == nil {
			t.Fatalf("accepted %q", path)
		}
	}
}

func TestApprovalRejectsMalformedRecordWithoutOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "preview.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"approve", "--preview", path, "--expected-preview-digest", "sha256:" + strings.Repeat("a", 64), "--reviewer", "operator"}, &stdout, &stderr)
	if code != 1 || stdout.Len() != 0 {
		t.Fatalf("malformed approval code=%d stdout=%s", code, &stdout)
	}
}
