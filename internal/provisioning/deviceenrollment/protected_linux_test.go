//go:build linux

package deviceenrollment

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedStateRejectsPlainDirectoryBeforeKeyCreation(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	r := f.runtime
	r.CheckStorage = nil // Exercise the real Linux boundary on this plain directory.
	if _, err := Initialize(dir, f.config, r); !errors.Is(err, ErrStorage) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("key state created: %v", err)
	}
}

func TestProtectedStateRechecksMountBeforeUsingExistingKey(t *testing.T) {
	f := newFixture(t)
	f.client.Close()
	f.client = nil
	before, err := os.ReadFile(filepath.Join(f.dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := f.runtime
	r.CheckStorage = func(*os.File, string) error { return ErrStorage }
	if _, err := Open(f.dir, r); !errors.Is(err, ErrStorage) {
		t.Fatalf("got %v", err)
	}
	if _, err := Initialize(f.dir, f.config, r); !errors.Is(err, ErrStorage) {
		t.Fatalf("got %v", err)
	}
	after, err := os.ReadFile(filepath.Join(f.dir, "state.json"))
	if err != nil || string(before) != string(after) {
		t.Fatal("private state changed")
	}
	clear(before)
	clear(after)
}

func TestBootEnrollmentRequiresProtectedVolumeBinding(t *testing.T) {
	f := newFixture(t)
	f.config.ProtectedVolume = ""
	if err := f.config.validate(); !errors.Is(err, ErrInput) {
		t.Fatalf("got %v", err)
	}
	f.config.Restart = "process"
	if err := f.config.validate(); err != nil {
		t.Fatal(err)
	}
	f.config.ProtectedVolume = "00000000-0000-0000-0000-000000000000"
	if err := f.config.validate(); !errors.Is(err, ErrInput) {
		t.Fatalf("got %v", err)
	}
}
