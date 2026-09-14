//go:build linux

package campaignstaging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediainventory"
)

// The public API always derives fixed full-capacity campaign geometry. Tiny
// private recipes let failure tests exercise the identical I/O engine quickly;
// the opt-in VM integration covers real geometry and real Linux block ioctls.
type fixtureOpener struct {
	path, directory                                     string
	facts                                               mediainventory.TargetFacts
	opens                                               []bool
	writes                                              int
	syncs                                               int
	partialWrite, shortWrite, syncFailure, closeFailure bool
	onWrite                                             func(*fixtureTarget)
	onOpen                                              func(bool)
}
type fixtureTarget struct {
	file     *os.File
	owner    *fixtureOpener
	facts    mediainventory.TargetFacts
	writable bool
}

func (o *fixtureOpener) Open(ctx context.Context, writable bool, expected *mediainventory.TargetFacts) (Target, error) {
	o.opens = append(o.opens, writable)
	if o.onOpen != nil {
		o.onOpen(writable)
	}
	if writable {
		if _, err := os.Lstat(filepath.Join(o.directory, "execution-started.json")); err != nil {
			return nil, errors.New("writer requested before durable marker")
		}
	}
	flags := os.O_RDONLY
	if writable {
		flags = os.O_RDWR
	}
	f, err := os.OpenFile(o.path, flags, 0)
	if err != nil {
		return nil, err
	}
	return &fixtureTarget{file: f, owner: o, facts: o.facts, writable: writable}, nil
}
func (t *fixtureTarget) ReadAt(b []byte, off int64) (int, error) { return t.file.ReadAt(b, off) }
func (t *fixtureTarget) WriteAt(b []byte, off int64) (int, error) {
	if !t.writable {
		return 0, errors.New("attempted write through read-only target")
	}
	t.owner.writes++
	if t.owner.partialWrite {
		n, e := t.file.WriteAt(b[:len(b)/2], off)
		if e != nil {
			return n, e
		}
		return n, errors.New("injected partial device write")
	}
	if t.owner.shortWrite {
		return t.file.WriteAt(b[:len(b)/2], off)
	}
	n, e := t.file.WriteAt(b, off)
	if t.owner.onWrite != nil {
		t.owner.onWrite(t)
	}
	return n, e
}
func (t *fixtureTarget) Sync() error {
	t.owner.syncs++
	if t.owner.syncFailure {
		return errors.New("injected device sync failure")
	}
	return t.file.Sync()
}
func (t *fixtureTarget) Close() error {
	err := t.file.Close()
	if t.writable && t.owner.closeFailure {
		return errors.New("injected device close failure")
	}
	return err
}
func (t *fixtureTarget) Facts() mediainventory.TargetFacts { return t.facts }
func (t *fixtureTarget) Revalidate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if t.facts != t.owner.facts {
		return errors.New("injected attachment replacement")
	}
	return nil
}

type tinyFixture struct {
	directory         string
	r                 recipe
	p                 Preview
	a                 Approval
	o                 *fixtureOpener
	original, payload []byte
}

func tinyFixtureInput(t *testing.T) tinyFixture {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	original := bytes.Repeat([]byte{0x31}, 3*1024*1024+4096)
	payload := bytes.Repeat([]byte{0x83}, 2*1024*1024+17)
	source := filepath.Join(root, "payload.img")
	target := filepath.Join(root, "target.img")
	directory := filepath.Join(root, "evidence")
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, original, 0600); err != nil {
		t.Fatal(err)
	}
	padded := append(append([]byte(nil), payload...), make([]byte, 127)...)
	backupGPT := bytes.Repeat([]byte{0xb4}, 512)
	primaryGPT := bytes.Repeat([]byte{0xc1}, 512)
	r := recipe{configDigest: bundle.Sum([]byte("config")), planDigest: bundle.Sum([]byte("plan")), requirementsDigest: bundle.Sum([]byte("requirements")), identity: campaignmedia.DeviceIdentity{Leg: campaignmedia.LegMalakSD, Selector: "/dev/candidate-test", CapacityBytes: uint64(len(original))}, backups: []Range{{Role: "recovery-range-0", Name: "backup-0.img", Size: uint64(len(original)), SHA256: bundle.Sum(original)}}, writes: []writeRecipe{
		{role: "payload", offset: 1024, size: uint64(len(padded)), sourceSize: uint64(len(payload)), sourceDigest: bundle.Sum(payload), sha256: bundle.Sum(padded), path: source},
		{role: "backup-gpt", offset: uint64(len(original) - 512), size: 512, sourceSize: 512, sourceDigest: bundle.Sum(backupGPT), sha256: bundle.Sum(backupGPT), data: backupGPT},
		{role: "primary-gpt", offset: 0, size: 512, sourceSize: 512, sourceDigest: bundle.Sum(primaryGPT), sha256: bundle.Sum(primaryGPT), data: primaryGPT},
	}}
	o := &fixtureOpener{path: target, directory: directory, facts: mediainventory.TargetFacts{RequestedPath: r.identity.Selector, ResolvedPath: r.identity.Selector, Identity: "candidate-test", SizeBytes: uint64(len(original)), Kind: mediainventory.TargetBlockDevice, WholeDevice: true, DeviceNumber: 9000, DiskSequence: 17, BootID: "12345678-1234-1234-1234-123456789abc", SysfsPath: "/sys/devices/virtual/block/candidate-test"}}
	return tinyFixture{directory: directory, r: r, o: o, original: original, payload: payload}
}
func preparedTiny(t *testing.T) tinyFixture {
	t.Helper()
	f := tinyFixtureInput(t)
	p, err := prepare(context.Background(), f.directory, f.r, f.o)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Approve(p, p.PreviewDigest, "development-operator")
	if err != nil {
		t.Fatal(err)
	}
	f.p = p
	f.a = a
	return f
}

func assertConsumed(t *testing.T, f tinyFixture) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(f.directory, "execution-started.json")); err != nil {
		t.Fatal("attempt marker missing:", err)
	}
	if _, err := os.Lstat(filepath.Join(f.directory, "execution-complete.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed attempt published completion")
	}
	opens := len(f.o.opens)
	writes := f.o.writes
	if _, err := execute(context.Background(), f.directory, f.r, f.a, f.o); err == nil || !strings.Contains(err.Error(), "consumed") {
		t.Fatal("retry was not refused:", err)
	}
	if len(f.o.opens) != opens || f.o.writes != writes {
		t.Fatal("retry reopened or rewrote target")
	}
}
func mutateFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{0xee}, 0); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateStagesAllBytesAndReopensForReadback(t *testing.T) {
	f := preparedTiny(t)
	if len(f.o.opens) != 1 || f.o.opens[0] || f.o.writes != 0 {
		t.Fatal("prepare requested a writer")
	}
	backup, err := os.ReadFile(filepath.Join(f.directory, "backup-0.img"))
	if err != nil || !bytes.Equal(backup, f.original) {
		t.Fatal("recovery bytes differ", err)
	}
	r, err := execute(context.Background(), f.directory, f.r, f.a, f.o)
	if err != nil {
		t.Fatal(err)
	}
	if !r.BackupReadbackVerified || !r.Readback.CompleteRangesVerified || r.HardwareQualified || r.CampaignClaimsClosed || r.Readback.HardwareQualified {
		t.Fatal("mechanical result boundary changed")
	}
	if fmt.Sprint(f.o.opens) != "[false false true false]" {
		t.Fatalf("expected read-only preparation/preflight, writer, fresh readback; got %v", f.o.opens)
	}
	got, err := os.ReadFile(f.o.path)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), f.original...)
	for _, w := range f.r.writes {
		if len(w.data) > 0 {
			copy(want[w.offset:w.offset+w.size], w.data)
		} else {
			clear(want[w.offset : w.offset+w.size])
			copy(want[w.offset:], f.payload)
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatal("written bytes, old zero tail, or untouched extents differ")
	}
	if _, err := verify(context.Background(), f.r, f.o, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := execute(context.Background(), f.directory, f.r, f.a, f.o); err == nil {
		t.Fatal("successful attempt retried")
	}
	for _, v := range []interface{ CanonicalJSON() ([]byte, error) }{f.p, f.a, r, r.Readback} {
		if _, err := v.CanonicalJSON(); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := r.CanonicalJSON()
	if _, err := ParseReport(b); err != nil {
		t.Fatal(err)
	}
	b, _ = r.Readback.CanonicalJSON()
	if _, err := ParseReadback(b); err != nil {
		t.Fatal(err)
	}
}

func TestFailuresAfterAttemptConsumptionRefuseRetry(t *testing.T) {
	for _, kind := range []string{"partial-write", "short-write", "sync", "close", "replace-after-first-write", "cancel-after-first-write", "readback-reopen-replacement"} {
		t.Run(kind, func(t *testing.T) {
			f := preparedTiny(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "partial-write":
				f.o.partialWrite = true
			case "short-write":
				f.o.shortWrite = true
			case "sync":
				f.o.syncFailure = true
			case "close":
				f.o.closeFailure = true
			case "replace-after-first-write":
				f.o.onWrite = func(*fixtureTarget) { f.o.facts.DiskSequence++ }
			case "cancel-after-first-write":
				f.o.onWrite = func(*fixtureTarget) { cancel() }
			case "readback-reopen-replacement":
				f.o.onOpen = func(w bool) {
					if !w && f.o.writes > 0 {
						f.o.facts.DiskSequence++
					}
				}
			}
			if _, err := execute(ctx, f.directory, f.r, f.a, f.o); err == nil {
				t.Fatal("injected failure succeeded")
			}
			if f.o.writes == 0 {
				t.Fatal("test did not reach real writes")
			}
			assertConsumed(t, f)
		})
	}
}

func TestEvidenceTamperingAfterActualWriteSuppressesCompletion(t *testing.T) {
	for _, name := range []string{"backup-0.img", "source-0.img", "source-1.img"} {
		t.Run(name, func(t *testing.T) {
			f := preparedTiny(t)
			f.o.onWrite = func(*fixtureTarget) {
				if f.o.writes == 1 {
					mutateFile(t, filepath.Join(f.directory, name))
				}
			}
			if _, err := execute(context.Background(), f.directory, f.r, f.a, f.o); err == nil {
				t.Fatal("tampered evidence accepted")
			}
			if f.o.writes == 0 {
				t.Fatal("no actual write occurred")
			}
			assertConsumed(t, f)
		})
	}
}

func TestPreflightFailuresNeverRequestWriter(t *testing.T) {
	for _, kind := range []string{"backup", "source", "preimage", "attachment", "approval", "configuration", "replaced-evidence", "hardlinked-evidence"} {
		t.Run(kind, func(t *testing.T) {
			f := preparedTiny(t)
			switch kind {
			case "backup":
				mutateFile(t, filepath.Join(f.directory, "backup-0.img"))
			case "source":
				mutateFile(t, filepath.Join(f.directory, "source-0.img"))
			case "preimage":
				mutateFile(t, f.o.path)
			case "attachment":
				f.o.facts.DiskSequence++
			case "approval":
				f.a.PreviewDigest = bundle.Sum([]byte("other"))
				f.a.ApprovalDigest = ""
				f.a.ApprovalDigest = digest(ApprovalSchema, f.a)
			case "configuration":
				f.r.configDigest = bundle.Sum([]byte("other"))
			case "replaced-evidence":
				p := filepath.Join(f.directory, "backup-0.img")
				b, _ := os.ReadFile(p)
				if err := os.Rename(p, p+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, b, 0400); err != nil {
					t.Fatal(err)
				}
			case "hardlinked-evidence":
				if err := os.Link(filepath.Join(f.directory, "backup-0.img"), filepath.Join(filepath.Dir(f.directory), "alias.img")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := execute(context.Background(), f.directory, f.r, f.a, f.o); err == nil {
				t.Fatal("invalid preflight accepted")
			}
			for _, w := range f.o.opens {
				if w {
					t.Fatal("preflight failure requested writable target")
				}
			}
			if _, err := os.Lstat(filepath.Join(f.directory, "execution-started.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("preflight failure consumed attempt")
			}
		})
	}
}

func TestMarkerExistenceAlwaysConsumesAttempt(t *testing.T) {
	for _, kind := range []string{"malformed", "fifo", "symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			f := preparedTiny(t)
			p := filepath.Join(f.directory, "execution-started.json")
			var err error
			switch kind {
			case "malformed":
				err = os.WriteFile(p, []byte("not JSON"), 0400)
			case "fifo":
				err = syscall.Mkfifo(p, 0600)
			case "symlink":
				err = os.Symlink("absent", p)
			case "directory":
				err = os.Mkdir(p, 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := len(f.o.opens)
			if _, err := execute(context.Background(), f.directory, f.r, f.a, f.o); err == nil || !strings.Contains(err.Error(), "consumed") {
				t.Fatal("existing marker was not refused", err)
			}
			if len(f.o.opens) != before {
				t.Fatal("consumed attempt opened target")
			}
		})
	}
}

func TestDirectoryReplacementStopsPartialExecution(t *testing.T) {
	f := preparedTiny(t)
	moved := f.directory + "-retained"
	f.o.onWrite = func(*fixtureTarget) {
		if f.o.writes == 1 {
			if err := os.Rename(f.directory, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(f.directory, 0700); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := execute(context.Background(), f.directory, f.r, f.a, f.o); err == nil {
		t.Fatal("renamed evidence directory accepted")
	}
	if _, err := os.Stat(filepath.Join(moved, "execution-started.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(moved, "execution-complete.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("replacement published completion")
	}
	if f.o.writes != 1 {
		t.Fatal("did not stop after namespace replacement")
	}
}

func TestParserAndResealedRangeChecks(t *testing.T) {
	f := preparedTiny(t)
	b, _ := f.p.CanonicalJSON()
	for _, bad := range [][]byte{b[:len(b)-1], append(append([]byte(nil), b...), '\n'), append([]byte(`{"extra":1,`), b[1:]...)} {
		if _, err := ParsePreview(bad); err == nil {
			t.Fatal("noncanonical preview accepted")
		}
	}
	if _, err := Approve(f.p, bundle.Sum([]byte("different preview")), "reviewer"); err == nil {
		t.Fatal("implicit approval allowed")
	}
	p := f.p
	p.Writes = append([]Range(nil), p.Writes...)
	p.Writes[0].Offset++
	p.PreviewDigest = ""
	p.PreviewDigest = digest(PreviewSchema, p)
	encoded, err := p.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.directory, "prepared.json")
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	a, err := Approve(p, p.PreviewDigest, "reviewer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := execute(context.Background(), f.directory, f.r, a, f.o); err == nil {
		t.Fatal("resealed geometry detached from independent config")
	}
}

func TestUnsafeInputFilesAndEvidenceParents(t *testing.T) {
	for _, kind := range []string{"source-symlink", "source-fifo", "source-device", "parent-symlink", "parent-writable"} {
		t.Run(kind, func(t *testing.T) {
			f := tinyFixtureInput(t)
			source := f.r.writes[0].path
			switch kind {
			case "source-symlink":
				if err := os.Rename(source, source+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(source+"-real", source); err != nil {
					t.Fatal(err)
				}
			case "source-fifo":
				os.Remove(source)
				if err := syscall.Mkfifo(source, 0600); err != nil {
					t.Fatal(err)
				}
			case "source-device":
				f.r.writes[0].path = "/dev/null"
			case "parent-symlink":
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(filepath.Dir(f.directory), alias); err != nil {
					t.Fatal(err)
				}
				f.directory = filepath.Join(alias, "evidence")
			case "parent-writable":
				if err := os.Chmod(filepath.Dir(f.directory), 0777); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := prepare(context.Background(), f.directory, f.r, f.o); err == nil {
				t.Fatal("unsafe input accepted")
			}
			for _, w := range f.o.opens {
				if w {
					t.Fatal("prepare opened writable target")
				}
			}
		})
	}
}

func TestReadonlySourceHardlinksSupported(t *testing.T) {
	f := tinyFixtureInput(t)
	if err := os.Link(f.r.writes[0].path, f.r.writes[0].path+"-store-alias"); err != nil {
		t.Fatal(err)
	}
	if _, err := prepare(context.Background(), f.directory, f.r, f.o); err != nil {
		t.Fatal("immutable store hardlink rejected:", err)
	}
}

func TestPublicAPIsRejectInvalidConfigurationBeforeOpening(t *testing.T) {
	o := &fixtureOpener{}
	if _, err := Prepare(context.Background(), filepath.Join(t.TempDir(), "evidence"), Config{}, o); err == nil {
		t.Fatal("invalid config prepared")
	}
	if _, err := Execute(context.Background(), "/absent", Config{}, Approval{}, o); err == nil {
		t.Fatal("invalid config executed")
	}
	if _, err := Verify(context.Background(), Config{}, o); err == nil {
		t.Fatal("invalid config verified")
	}
	if len(o.opens) != 0 {
		t.Fatal("invalid config opened device")
	}
	if _, err := Prepare(nil, "/absent", Config{}, o); err == nil {
		t.Fatal("nil context accepted")
	}
}

func TestCopyRangeRejectsShortReadAndWrite(t *testing.T) {
	_, err := copyRange(context.Background(), discardAt{}, 0, shortReader{}, 0, 512, false, nil)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
}

type shortReader struct{}

func (shortReader) ReadAt(b []byte, off int64) (int, error) { return len(b) - 1, nil }

type discardAt struct{}

func (discardAt) WriteAt(b []byte, off int64) (int, error) { return len(b), nil }
