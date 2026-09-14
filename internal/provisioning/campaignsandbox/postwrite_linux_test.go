//go:build linux

package campaignsandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Assert the fault is injected after a real destination write, while its
// durable execution marker already binds the preview and approval.
func requireFirstChunkWritten(t *testing.T, f tinyFixture) {
	t.Helper()
	disk := f.preview.Disks[0]
	span := disk.Writes[0]
	got, err := os.ReadFile(filepath.Join(f.path, disk.Name))
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(f.path, span.Name))
	if err != nil {
		t.Fatal(err)
	}
	const sample = 64
	if bytes.Equal(got, f.originals[0]) || !bytes.Equal(got[span.Offset:span.Offset+sample], source[:sample]) {
		t.Fatal("post-write fault hook ran before the first real destination chunk")
	}
	journal, err := os.ReadFile(filepath.Join(f.path, "execution-started.json"))
	if err != nil || !bytes.Contains(journal, []byte(f.preview.PreviewDigest)) || !bytes.Contains(journal, []byte(f.approval.ApprovalDigest)) {
		t.Fatalf("first write lacked the bound execution marker: %s, %v", journal, err)
	}
}

func mutateSnapshotByte(t *testing.T, path string, offset int64) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	value := []byte{0}
	if _, err := file.ReadAt(value, offset); err != nil {
		t.Fatal(err)
	}
	value[0] ^= 0xff
	if _, err := file.WriteAt(value, offset); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
}

func requireConsumedWithoutCompletionAfterReopen(t *testing.T, f tinyFixture, report Report, executionErr error) {
	t.Helper()
	if executionErr == nil || !strings.Contains(executionErr.Error(), "do not retry") {
		t.Fatalf("post-write failure did not retain its consumed outcome: %v", executionErr)
	}
	if report.Outcome != "" || report.FinalReadbackVerified || report.BackupReadbackVerified {
		t.Fatalf("post-write failure returned a success report: %#v", report)
	}
	markerPath := filepath.Join(f.path, "execution-started.json")
	before, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("post-write failure lost its consumed marker: %v", err)
	}
	completionPath := filepath.Join(f.path, "execution-complete.json")
	if _, err := os.Lstat(completionPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("post-write failure published completion: %v", err)
	}
	if err := f.dir.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := ownedDirectory(f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	retryChunks := 0
	_, err = executeFiles(context.Background(), reopened, f.preview, f.approval, func() error {
		retryChunks++
		return nil
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "already started") || retryChunks != 0 {
		t.Fatalf("reopened sandbox retried consumed execution: chunks=%d err=%v", retryChunks, err)
	}
	after, err := os.ReadFile(markerPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("restart refusal replaced its original marker: %v", err)
	}
	if _, err := os.Lstat(completionPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restart refusal published completion: %v", err)
	}
}

func TestPostwriteSourceAndBackupMutationConsumeAttempt(t *testing.T) {
	for _, kind := range []string{"already-copied-source", "not-yet-copied-source", "backup"} {
		t.Run(kind, func(t *testing.T) {
			f := tiny(t)
			calls := 0
			report, err := executeFiles(context.Background(), f.dir, f.preview, f.approval, func() error {
				calls++
				if calls != 1 {
					return nil
				}
				requireFirstChunkWritten(t, f)
				disk := f.preview.Disks[0]
				name, offset := disk.Writes[0].Name, int64(0)
				switch kind {
				case "not-yet-copied-source":
					offset = 1024*1024 + 17
				case "backup":
					name = disk.Backups[0].Name
				}
				mutateSnapshotByte(t, filepath.Join(f.path, name), offset)
				return nil
			}, nil)
			if calls == 0 {
				t.Fatal("fault was never injected after a real write")
			}
			if err == nil || !strings.Contains(err.Error(), "byte readback digest differs") {
				t.Fatalf("modified bytes escaped post-write digest verification: %v", err)
			}
			requireConsumedWithoutCompletionAfterReopen(t, f, report, err)
		})
	}
}

func TestPostwriteDestinationReplacementCannotRedirectWritesOrComplete(t *testing.T) {
	f := tiny(t)
	diskPath := filepath.Join(f.path, f.preview.Disks[0].Name)
	retainedPath := filepath.Join(f.path, "retained-original-disk.img")
	calls := 0
	report, err := executeFiles(context.Background(), f.dir, f.preview, f.approval, func() error {
		calls++
		if calls != 1 {
			return nil
		}
		requireFirstChunkWritten(t, f)
		if err := os.Rename(diskPath, retainedPath); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(diskPath, f.originals[0], 0o600); err != nil {
			t.Fatal(err)
		}
		return nil
	}, nil)
	if calls == 0 {
		t.Fatal("destination replacement was never injected after a real write")
	}
	if err == nil || !strings.Contains(err.Error(), "path attachment changed") {
		t.Fatalf("replaced destination escaped attachment verification: %v", err)
	}
	replacement, readErr := os.ReadFile(diskPath)
	if readErr != nil || !bytes.Equal(replacement, f.originals[0]) {
		t.Fatalf("remaining writes were redirected into replacement inode: %v", readErr)
	}
	retained, readErr := os.ReadFile(retainedPath)
	if readErr != nil || bytes.Equal(retained, f.originals[0]) {
		t.Fatalf("test failed to retain the already-written original inode: %v", readErr)
	}
	requireConsumedWithoutCompletionAfterReopen(t, f, report, err)
}
