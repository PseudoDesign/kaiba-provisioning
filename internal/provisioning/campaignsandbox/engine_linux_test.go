//go:build linux

package campaignsandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
)

type tinyFixture struct {
	dir       *os.File
	path      string
	preview   Preview
	approval  Approval
	recipe    recipe
	originals [][]byte
}

func tiny(t *testing.T) tinyFixture {
	t.Helper()
	root := t.TempDir()
	sandbox := filepath.Join(root, "sandbox")
	r := recipe{planDigest: bundle.Sum([]byte("synthetic-plan")), requirementsDigest: bundle.Sum([]byte("synthetic-requirements"))}
	paths := map[string]string{}
	var originals [][]byte
	for i, leg := range []campaignmedia.Leg{campaignmedia.LegMalakSD, campaignmedia.LegPiLocalNVMe} {
		original := bytes.Repeat([]byte{byte(21 + i)}, 3*1024*1024+4096)
		source := bytes.Repeat([]byte{byte(81 + i)}, 2*1024*1024+17)
		padded := append(append([]byte(nil), source...), make([]byte, 127)...)
		initialPath := filepath.Join(root, fmt.Sprintf("initial-%d.img", i))
		sourcePath := filepath.Join(root, fmt.Sprintf("payload-%d.img", i))
		if err := os.WriteFile(initialPath, original, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sourcePath, source, 0600); err != nil {
			t.Fatal(err)
		}
		paths["disk:"+string(leg)] = initialPath
		paths[string(leg)+":payload"] = sourcePath
		d := diskRecipe{leg: leg, size: uint64(len(original)), backups: []Range{{Name: fmt.Sprintf("backup-%d-0.img", i), Size: uint64(len(original)), SHA256: bundle.Sum(original)}}, writes: []writeRecipe{
			{role: "payload", offset: 1024, size: uint64(len(padded)), sourceSize: uint64(len(source)), sourceDigest: bundle.Sum(source), digest: bundle.Sum(padded)},
			{role: "backup-gpt", offset: uint64(len(original) - 512), size: 512, sourceSize: 512, data: bytes.Repeat([]byte{0xb4}, 512), digest: bundle.Sum(bytes.Repeat([]byte{0xb4}, 512))},
			{role: "primary-gpt", offset: 0, size: 512, sourceSize: 512, data: bytes.Repeat([]byte{0xc1}, 512), digest: bundle.Sum(bytes.Repeat([]byte{0xc1}, 512))},
		}}
		r.disks = append(r.disks, d)
		originals = append(originals, original)
	}
	dir, err := createDirectory(sandbox)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	p, err := prepareFiles(context.Background(), dir, r, paths, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Approve(p, "fixture-reviewer")
	if err != nil {
		t.Fatal(err)
	}
	return tinyFixture{dir: dir, path: sandbox, preview: p, approval: a, recipe: r, originals: originals}
}

func TestSyntheticWritesBackupsAndIndependentReadback(t *testing.T) {
	f := tiny(t)
	for _, d := range f.preview.Disks {
		for _, b := range d.Backups {
			if err := verifySnapshot(context.Background(), f.dir, b); err != nil {
				t.Fatal(err)
			}
		}
	}
	report, err := executeFiles(context.Background(), f.dir, f.preview, f.approval, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.PhysicalStagingReady || report.HardwareObserved || !report.FinalReadbackVerified || report.Scope != Scope {
		t.Fatal("synthetic boundary lost")
	}
	for i, d := range f.preview.Disks {
		got, err := os.ReadFile(filepath.Join(f.path, d.Name))
		if err != nil {
			t.Fatal(err)
		}
		want := append([]byte(nil), f.originals[i]...)
		for _, w := range d.Writes {
			source, err := os.ReadFile(filepath.Join(f.path, w.Name))
			if err != nil {
				t.Fatal(err)
			}
			copy(want[w.Offset:w.Offset+w.Size], source)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("actual bytes differ, including untouched extents or zero tail")
		}
	}
	if _, err := executeFiles(context.Background(), f.dir, f.preview, f.approval, nil, nil); err == nil || !strings.Contains(err.Error(), "already started") {
		t.Fatalf("completed sandbox accepted retry: %v", err)
	}
	encoded, err := report.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseReport(encoded); err != nil {
		t.Fatal(err)
	}
}

func TestPartialWriteConsumesAttemptAndBackupsReconstructPreimage(t *testing.T) {
	f := tiny(t)
	injected := errors.New("simulated write interruption")
	_, err := executeFiles(context.Background(), f.dir, f.preview, f.approval, func() error {
		if _, err := os.Stat(filepath.Join(f.path, "execution-started.json")); err != nil {
			t.Fatal("write happened before durable intent marker")
		}
		return injected
	}, nil)
	if !errors.Is(err, injected) || !strings.Contains(err.Error(), "do not retry") {
		t.Fatalf("unexpected partial outcome: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(f.path, f.preview.Disks[0].Name))
	if bytes.Equal(got, f.originals[0]) {
		t.Fatal("injected interruption did not follow a real partial write")
	}
	if _, err := os.Stat(filepath.Join(f.path, "execution-complete.json")); !os.IsNotExist(err) {
		t.Fatal("partial run created completion")
	}
	f.dir.Close()
	reopened, err := ownedDirectory(f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := executeFiles(context.Background(), reopened, f.preview, f.approval, nil, nil); err == nil || !strings.Contains(err.Error(), "already started") {
		t.Fatalf("restart accepted blind retry: %v", err)
	}
	// Restore into new disposable files, never into the ambiguous target. This
	// demonstrates the backups preserve the actual bytes needed to reconcile.
	for i, d := range f.preview.Disks {
		restored, err := os.CreateTemp(t.TempDir(), "restored")
		if err != nil {
			t.Fatal(err)
		}
		if err := restored.Truncate(int64(d.Attachment.Size)); err != nil {
			t.Fatal(err)
		}
		for _, b := range d.Backups {
			backup, err := openAt(reopened, b.Name, syscall.O_RDONLY)
			if err != nil {
				t.Fatal(err)
			}
			if err := copyRange(context.Background(), restored, b.Offset, backup, 0, b.Size, false, nil); err != nil {
				t.Fatal(err)
			}
			backup.Close()
		}
		if err := restored.Sync(); err != nil {
			t.Fatal(err)
		}
		path := restored.Name()
		restored.Close()
		result, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(result, f.originals[i]) {
			t.Fatal("backups failed to reconstruct every captured original byte")
		}
	}
}

func TestPrewriteChangesRefuseWithoutConsumedJournal(t *testing.T) {
	for _, kind := range []string{"source", "backup", "preimage", "attachment", "approval", "source-hardlink", "disk-symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			f := tiny(t)
			a := f.approval
			p := f.preview
			mutate := func(name string) {
				path := filepath.Join(f.path, name)
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
				out, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := out.WriteAt([]byte{0xef}, 0); err != nil {
					t.Fatal(err)
				}
				out.Close()
			}
			switch kind {
			case "source":
				mutate(p.Disks[0].Writes[0].Name)
			case "backup":
				mutate(p.Disks[0].Backups[0].Name)
			case "preimage":
				mutate(p.Disks[0].Name)
			case "attachment":
				name := filepath.Join(f.path, p.Disks[0].Name)
				if err := os.Rename(name, name+".previous"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, f.originals[0], 0600); err != nil {
					t.Fatal(err)
				}
			case "approval":
				p2 := p
				p2.SandboxID = strings.Repeat("d", 64)
				p2.PreviewDigest = ""
				p2.PreviewDigest = digest(PreviewSchema, p2)
				var err error
				a, err = Approve(p2, "other-reviewer")
				if err != nil {
					t.Fatal(err)
				}
			case "source-hardlink":
				if err := os.Link(filepath.Join(f.path, p.Disks[0].Writes[0].Name), filepath.Join(f.path, "alias")); err != nil {
					t.Fatal(err)
				}
			case "disk-symlink":
				name := filepath.Join(f.path, p.Disks[0].Name)
				if err := os.Rename(name, name+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(name+".old", name); err != nil {
					t.Fatal(err)
				}
			case "directory":
				p.Directory.Inode++
				p.PreviewDigest = ""
				p.PreviewDigest = digest(PreviewSchema, p)
				var err error
				a, err = Approve(p, "reviewer")
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := executeFiles(context.Background(), f.dir, p, a, nil, nil); err == nil {
				t.Fatal("prewrite change accepted")
			}
			if _, err := os.Stat(filepath.Join(f.path, "execution-started.json")); !os.IsNotExist(err) {
				t.Fatal("prewrite refusal consumed journal")
			}
		})
	}
}

func TestCancellationAndDirectoryReattachmentStayAmbiguous(t *testing.T) {
	for _, kind := range []string{"cancel", "directory"} {
		t.Run(kind, func(t *testing.T) {
			f := tiny(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			check := func() error {
				calls++
				if kind == "directory" && calls > 2 {
					return errors.New("directory attachment replaced")
				}
				return nil
			}
			_, err := executeFiles(ctx, f.dir, f.preview, f.approval, func() error {
				if kind == "cancel" {
					cancel()
				}
				return nil
			}, check)
			if err == nil || !strings.Contains(err.Error(), "do not retry") {
				t.Fatalf("failure not ambiguous: %v", err)
			}
			if _, err := executeFiles(context.Background(), f.dir, f.preview, f.approval, nil, nil); err == nil {
				t.Fatal("failure allowed retry")
			}
		})
	}
}

func TestDirectoryNamespaceReplacementDuringWriteRefusesCompletion(t *testing.T) {
	f := tiny(t)
	detached := f.path + ".detached"
	moved := false
	_, err := executeFiles(context.Background(), f.dir, f.preview, f.approval, func() error {
		if !moved {
			if err := os.Rename(f.path, detached); err != nil {
				return err
			}
			if err := os.Mkdir(f.path, 0700); err != nil {
				return err
			}
			moved = true
		}
		return nil
	}, func() error { return checkDirectoryPath(f.path, f.preview.Directory) })
	if err == nil || !strings.Contains(err.Error(), "do not retry") || !moved {
		t.Fatalf("directory replacement accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(detached, "execution-complete.json")); !os.IsNotExist(err) {
		t.Fatal("detached target produced completion")
	}
	f.dir.Close()
	reopened, err := ownedDirectory(detached)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := executeFiles(context.Background(), reopened, f.preview, f.approval, nil, nil); err == nil || !strings.Contains(err.Error(), "already started") {
		t.Fatalf("detached journal accepted restart: %v", err)
	}
}

func TestInputBoundaryRejectsSpecialFilesParentsAndAliases(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "regular")
	if err := os.WriteFile(file, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"symlink", "hardlink", "fifo", "device", "directory", "parent-symlink"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(root, kind)
			switch kind {
			case "symlink":
				if err := os.Symlink(file, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(file, path); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(path)
			case "fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "device":
				path = "/dev/null"
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink":
				if err := os.Symlink(root, path); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(path, "regular")
			}
			if f, err := openInput(path); err == nil {
				f.Close()
				t.Fatal("invalid file input accepted")
			}
		})
	}
}

func TestPreviewBindingsAndCanonicalParsersRejectForgedMetadata(t *testing.T) {
	f := tiny(t)
	encoded, err := f.preview.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePreview(encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePreview(bytes.Replace(encoded, []byte(`"schema_version":`), []byte(`"schema_version":"ignored","schema_version":`), 1)); err == nil {
		t.Fatal("duplicate key accepted")
	}
	for _, kind := range []string{"escape", "overlap", "coverage", "alias", "physical", "recipe"} {
		t.Run(kind, func(t *testing.T) {
			p, err := ParsePreview(encoded)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "escape":
				p.Disks[0].Writes[0].Name = "../escape"
			case "overlap":
				p.Disks[0].Writes[1].Offset = p.Disks[0].Writes[0].Offset
			case "coverage":
				p.Disks[0].Backups[0].Size--
				p.Disks[0].Backups[0].Attachment.Size--
			case "alias":
				p.Disks[0].Writes[0].Attachment = p.Disks[0].Backups[0].Attachment
			case "physical":
				p.PhysicalStagingReady = true
			case "recipe":
				p.PlanDigest = bundle.Sum([]byte("detached plan"))
			}
			p.PreviewDigest = ""
			p.PreviewDigest = digest(PreviewSchema, p)
			if err := validatePreviewAgainst(p, f.recipe); err == nil {
				t.Fatal("forged preview was accepted")
			}
		})
	}
	if _, err := Prepare(context.Background(), filepath.Join(t.TempDir(), "must-not-exist"), Input{}); err == nil {
		t.Fatal("unvalidated public contracts accepted")
	}
}
