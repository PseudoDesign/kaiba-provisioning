//go:build linux

package campaignqualification

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestFileAdmissionRejectsReplayAcrossInstancesAndConcurrentCalls(t *testing.T) {
	f := newFixture(t, 2)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	const attempts = 12
	errors := make(chan error, attempts)
	var group sync.WaitGroup
	for range attempts {
		group.Add(1)
		go func() {
			defer group.Done()
			errors <- (FileAdmission{Directory: directory}).Consume(f.session, f.result.ResultDigest)
		}()
	}
	group.Wait()
	close(errors)
	successes := 0
	for err := range errors {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("got %d successful admissions, want exactly one", successes)
	}
	if err := (FileAdmission{Directory: directory}).Consume(f.session, digest("changed-result")); err == nil {
		t.Fatal("reused capture accepted after restart")
	}
}

func TestFileAdmissionRejectsSymlinksAndPublicDirectories(t *testing.T) {
	f := newFixture(t, 2)
	root := t.TempDir()
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if err := (FileAdmission{Directory: link}).Consume(f.session, f.result.ResultDigest); err == nil {
		t.Fatal("symlink directory accepted")
	}
	for _, mode := range []os.FileMode{0755, 0500} {
		if err := os.Chmod(private, mode); err != nil {
			t.Fatal(err)
		}
		if err := (FileAdmission{Directory: private}).Consume(f.session, f.result.ResultDigest); err == nil {
			t.Fatalf("admission directory with mode %o accepted", mode)
		}
	}
	os.Chmod(private, 0700)
}

func TestUncertainReservationCannotBeReused(t *testing.T) {
	f := newFixture(t, 2)
	directory := t.TempDir()
	os.Chmod(directory, 0700)
	name := string(f.session.Context.CaptureID)[len("capture:"):] + ".json"
	if err := os.WriteFile(filepath.Join(directory, name), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := (FileAdmission{Directory: directory}).Consume(f.session, f.result.ResultDigest); err == nil {
		t.Fatal("incomplete durable reservation was reset")
	}
}
