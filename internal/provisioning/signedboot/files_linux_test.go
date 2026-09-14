//go:build linux

package signedboot

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLoadPlanRejectsExpectedFIFOFilesPromptly(t *testing.T) {
	for _, name := range []string{"boot.img", "plan.json", "public.pem", "release-intent.json"} {
		t.Run(name, func(t *testing.T) {
			fixture := newTestFixture(t, "fifo-plan", []byte("complete boot image"))
			input := filepath.Join(fixture.plan, name)
			if err := os.Remove(input); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(input, 0o600); err != nil {
				t.Fatal(err)
			}
			// The names still form an exact four-file plan. Each reader must
			// open without blocking before it can reject the FIFO's type.
			requirePromptInputRefusal(t, input, func() error {
				_, err := LoadPlanDirectory(fixture.plan)
				return err
			})
		})
	}
}

func TestExpectedPublicKeyReaderKeepsRegularAndSymlinkBoundaries(t *testing.T) {
	fixture := newTestFixture(t, "absolute-key", []byte("complete boot image"))
	if _, fingerprint, err := readExpectedPublicKey(fixture.expectedKey); err != nil || fingerprint != fixture.fingerprint {
		t.Fatalf("regular expected public key failed: fingerprint=%s error=%v", fingerprint, err)
	}
	link := filepath.Join(fixture.root, "key-link.pem")
	if err := os.Symlink(fixture.expectedKey, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readExpectedPublicKey(link); err == nil {
		t.Fatal("expected public key reader followed a symlink")
	}
	fifo := filepath.Join(fixture.root, "key-fifo.pem")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	requirePromptInputRefusal(t, fifo, func() error {
		_, _, err := readExpectedPublicKey(fifo)
		return err
	})
}

func requirePromptInputRefusal(t *testing.T, fifoPath string, read func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- read() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("regular-file-only reader accepted a FIFO")
		}
	case <-time.After(time.Second):
		// Release a regressed blocking reader before reporting failure, so
		// it cannot outlive the test's temporary directory indefinitely.
		unblock, err := os.OpenFile(fifoPath, os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err == nil {
			defer unblock.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
			}
		}
		t.Fatal("regular-file-only reader blocked while opening a FIFO")
	}
}
