//go:build linux

package campaignsandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
)

type preparedRecord struct {
	Plan         campaignmedia.StagingPlan                          `json:"plan"`
	Envelopes    []campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2 `json:"envelopes"`
	Requirements campaignmedia.RecoveryBackupRequirementsV1Alpha2   `json:"requirements"`
	Preview      Preview                                            `json:"preview"`
}

// Prepare validates the complete fixed campaign contracts, then creates new
// sparse synthetic disks, snapshots and independently verified recovery files.
// A partial preparation is retained for diagnosis and never reused.
func Prepare(ctx context.Context, directory string, input Input) (Preview, error) {
	r, err := derive(input)
	if err != nil {
		return Preview{}, err
	}
	if len(input.Disks) != len(r.disks) {
		return Preview{}, errors.New("provide exactly one regular-file fixture for each campaign leg")
	}
	payloadCount := 0
	for _, d := range r.disks {
		for _, w := range d.writes {
			if w.data == nil {
				payloadCount++
			}
		}
	}
	if len(input.Payloads) != payloadCount {
		return Preview{}, errors.New("provide exactly the four campaign partition payload sources")
	}
	paths := make(map[string]string)
	for i, d := range input.Disks {
		if d.Leg != r.disks[i].leg {
			return Preview{}, errors.New("disk fixtures must follow the exact campaign leg order")
		}
		paths["disk:"+string(d.Leg)] = d.Path
	}
	for _, p := range input.Payloads {
		key := string(p.Leg) + ":" + string(p.Role)
		if _, ok := paths[key]; ok {
			return Preview{}, errors.New("duplicate payload role")
		}
		paths[key] = p.Path
	}
	dir, err := createDirectory(directory)
	if err != nil {
		return Preview{}, err
	}
	defer dir.Close()
	verifyInitial := func(i int, f *os.File) error { return input.Envelopes[i].VerifyAgainst(f) }
	p, err := prepareFiles(ctx, dir, r, paths, verifyInitial)
	if err != nil {
		return Preview{}, fmt.Errorf("synthetic preparation incomplete; preserve new directory: %w", err)
	}
	record := preparedRecord{Plan: input.Plan, Envelopes: input.Envelopes, Requirements: input.Requirements, Preview: p}
	b, err := canonical(record)
	if err != nil {
		return Preview{}, err
	}
	if err := createBytes(dir, "prepared.json", b, true); err != nil {
		return Preview{}, err
	}
	return p, nil
}

func prepareFiles(ctx context.Context, dir *os.File, r recipe, paths map[string]string, verifyInitial func(int, *os.File) error) (Preview, error) {
	if err := validateRecipe(r); err != nil {
		return Preview{}, err
	}
	p := Preview{SchemaVersion: PreviewSchema, Scope: Scope, PlanDigest: r.planDigest, RecoveryRequirementsDigest: r.requirementsDigest}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return Preview{}, err
	}
	p.SandboxID = hex.EncodeToString(id)
	var err error
	p.Directory, err = dirAttachment(dir)
	if err != nil {
		return Preview{}, err
	}
	seen := make(map[[2]uint64]bool)
	openDistinct := func(path string) (*os.File, error) {
		f, err := openInput(path)
		if err != nil {
			return nil, err
		}
		a, err := attachment(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		key := [2]uint64{a.Device, a.Inode}
		if seen[key] {
			f.Close()
			return nil, errors.New("one fixture inode was reused across input roles")
		}
		seen[key] = true
		return f, nil
	}
	for i, d := range r.disks {
		original, err := openDistinct(paths["disk:"+string(d.leg)])
		if err != nil {
			return Preview{}, err
		}
		defer original.Close()
		a, err := attachment(original)
		if err != nil {
			return Preview{}, err
		}
		if a.Size != d.size {
			return Preview{}, errors.New("initial fixture capacity differs from fixed plan")
		}
		name := fmt.Sprintf("disk-%d.img", i)
		disk, err := openAt(dir, name, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL)
		if err != nil {
			return Preview{}, err
		}
		defer disk.Close()
		if err := disk.Truncate(int64(d.size)); err != nil {
			return Preview{}, err
		}
		for _, span := range d.backups {
			if err := copyRange(ctx, disk, span.Offset, original, span.Offset, span.Size, true, nil); err != nil {
				return Preview{}, err
			}
			if err := verifyRange(ctx, disk, span.Offset, span.Size, span.SHA256); err != nil {
				return Preview{}, fmt.Errorf("initial fixture: %w", err)
			}
		}
		if err := disk.Sync(); err != nil {
			return Preview{}, err
		}
		if verifyInitial != nil {
			if err := verifyInitial(i, disk); err != nil {
				return Preview{}, fmt.Errorf("independent initial GPT inspection: %w", err)
			}
		}
		item := Disk{Leg: d.leg, Name: name}
		item.Attachment, err = attachment(disk)
		if err != nil {
			return Preview{}, err
		}
		for _, span := range d.backups {
			backup, err := openAt(dir, span.Name, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL)
			if err != nil {
				return Preview{}, err
			}
			copyErr := backup.Truncate(int64(span.Size))
			if copyErr == nil {
				copyErr = copyRange(ctx, backup, 0, disk, span.Offset, span.Size, true, nil)
			}
			if copyErr == nil {
				copyErr = backup.Chmod(0400)
			}
			if copyErr == nil {
				copyErr = backup.Sync()
			}
			if copyErr == nil {
				span.Attachment, copyErr = attachment(backup)
			}
			backup.Close()
			if copyErr != nil {
				return Preview{}, copyErr
			}
			if err := verifySnapshot(ctx, dir, span); err != nil {
				return Preview{}, fmt.Errorf("independent reopened backup verification: %w", err)
			}
			item.Backups = append(item.Backups, span)
		}
		for j, w := range d.writes {
			span := Range{Name: fmt.Sprintf("source-%d-%d.img", i, j), Offset: w.offset, Size: w.size, SHA256: w.digest}
			if w.data != nil {
				if err := createBytes(dir, span.Name, w.data, true); err != nil {
					return Preview{}, err
				}
			} else {
				source, err := openDistinct(paths[string(d.leg)+":"+w.role])
				if err != nil {
					return Preview{}, err
				}
				defer source.Close()
				sourceAttachment, err := attachment(source)
				if err != nil {
					return Preview{}, err
				}
				if sourceAttachment.Size != w.sourceSize {
					return Preview{}, errors.New("payload source size differs from plan")
				}
				if err := verifyRange(ctx, source, 0, w.sourceSize, w.sourceDigest); err != nil {
					return Preview{}, fmt.Errorf("payload source: %w", err)
				}
				snapshot, err := openAt(dir, span.Name, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL)
				if err != nil {
					return Preview{}, err
				}
				copyErr := snapshot.Truncate(int64(w.size))
				if copyErr == nil {
					copyErr = copyRange(ctx, snapshot, 0, source, 0, w.sourceSize, true, nil)
				}
				if copyErr == nil {
					copyErr = snapshot.Chmod(0400)
				}
				if copyErr == nil {
					copyErr = snapshot.Sync()
				}
				snapshot.Close()
				if copyErr != nil {
					return Preview{}, copyErr
				}
			}
			f, err := openAt(dir, span.Name, syscall.O_RDONLY)
			if err != nil {
				return Preview{}, err
			}
			span.Attachment, err = attachment(f)
			f.Close()
			if err != nil {
				return Preview{}, err
			}
			if err := verifySnapshot(ctx, dir, span); err != nil {
				return Preview{}, fmt.Errorf("padded partition/GPT snapshot: %w", err)
			}
			item.Writes = append(item.Writes, span)
		}
		p.Disks = append(p.Disks, item)
	}
	if err := dir.Sync(); err != nil {
		return Preview{}, err
	}
	p.PreviewDigest = digest(PreviewSchema, p)
	return p, p.Validate()
}

func verifySnapshot(ctx context.Context, dir *os.File, span Range) error {
	f, err := openAt(dir, span.Name, syscall.O_RDONLY)
	if err != nil {
		return err
	}
	defer f.Close()
	if span.Attachment.Size != span.Size {
		return errors.New("snapshot size differs from range")
	}
	if err := revalidate(dir, span.Name, f, span.Attachment); err != nil {
		return err
	}
	if err := verifyRange(ctx, f, 0, span.Size, span.SHA256); err != nil {
		return err
	}
	return revalidate(dir, span.Name, f, span.Attachment)
}

func validatePreviewAgainst(p Preview, r recipe) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.PlanDigest != r.planDigest || p.RecoveryRequirementsDigest != r.requirementsDigest || len(p.Disks) != len(r.disks) {
		return errors.New("preview differs from independently validated contracts")
	}
	for i, d := range r.disks {
		got := p.Disks[i]
		if got.Leg != d.leg || got.Name != fmt.Sprintf("disk-%d.img", i) || got.Attachment.Size != d.size || len(got.Backups) != len(d.backups) || len(got.Writes) != len(d.writes) {
			return errors.New("preview disk geometry differs from plan")
		}
		for j, b := range d.backups {
			g := got.Backups[j]
			g.Attachment = Attachment{}
			if g != b {
				return errors.New("preview backup differs from independent recovery requirements")
			}
		}
		for j, w := range d.writes {
			g := got.Writes[j]
			if g.Name != fmt.Sprintf("source-%d-%d.img", i, j) || g.Offset != w.offset || g.Size != w.size || g.SHA256 != w.digest {
				return errors.New("preview write differs from independently validated plan")
			}
		}
	}
	return nil
}

// Execute writes only the private sandbox's regular-file inodes bound by the
// preview. These caller-controlled synthetic records do not authenticate
// creation provenance against the local operator.
// Every started attempt is permanently consumed, including interrupted or
// failed attempts. Recovery/reconciliation is deliberately not an automatic
// retry or a physical restoration operation.
func Execute(ctx context.Context, directory string, approval Approval) (Report, error) {
	dir, err := ownedDirectory(directory)
	if err != nil {
		return Report{}, err
	}
	defer dir.Close()
	b, err := readBytes(dir, "prepared.json")
	if err != nil {
		return Report{}, err
	}
	var record preparedRecord
	if err := parse(b, &record); err != nil {
		return Report{}, err
	}
	r, err := derive(Input{Plan: record.Plan, Envelopes: record.Envelopes, Requirements: record.Requirements})
	if err != nil {
		return Report{}, err
	}
	if err := validatePreviewAgainst(record.Preview, r); err != nil {
		return Report{}, err
	}
	checkDirectory := func() error { return checkDirectoryPath(directory, record.Preview.Directory) }
	return executeFiles(ctx, dir, record.Preview, approval, nil, checkDirectory)
}

func checkDirectoryPath(directory string, expected Attachment) error {
	fresh, err := ownedDirectory(directory)
	if err != nil {
		return err
	}
	defer fresh.Close()
	identity, err := dirAttachment(fresh)
	if err != nil {
		return err
	}
	if identity != expected {
		return errors.New("sandbox directory pathname attachment changed")
	}
	return nil
}

func openWritableOwned(dir *os.File, name string, expected Attachment) (*os.File, error) {
	// Validate a read-only opened inode, then reopen that pinned inode through
	// the kernel-owned descriptor namespace. A pathname race cannot redirect
	// the writable open to a device or another attachment.
	ro, err := openAt(dir, name, syscall.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer ro.Close()
	if err := revalidate(dir, name, ro, expected); err != nil {
		return nil, err
	}
	st, err := ro.Stat()
	if err != nil {
		return nil, err
	}
	if st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("synthetic disk is not owned by this user")
	}
	f, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", ro.Fd()), os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if err := revalidate(dir, name, f, expected); err != nil {
		f.Close()
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func executeFiles(ctx context.Context, dir *os.File, p Preview, a Approval, afterChunk func() error, checkDirectory func() error) (report Report, err error) {
	if err := p.Validate(); err != nil {
		return Report{}, err
	}
	if err := a.Validate(); err != nil {
		return Report{}, err
	}
	if a.PreviewDigest != p.PreviewDigest {
		return Report{}, errors.New("approval is bound to another exact sandbox preview")
	}
	actual, err := dirAttachment(dir)
	if err != nil {
		return Report{}, err
	}
	if actual != p.Directory {
		return Report{}, errors.New("sandbox directory attachment changed")
	}
	if err := syscall.Flock(int(dir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return Report{}, err
	}
	defer syscall.Flock(int(dir.Fd()), syscall.LOCK_UN)
	// Read via a pinned directory; even an invalid, substituted started marker
	// consumes this sandbox. O_EXCL below also closes the concurrent-create race.
	if marker, err := syscall.Openat(int(dir.Fd()), "execution-started.json", 0x200000|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0); err == nil {
		syscall.Close(marker)
		return Report{}, errors.New("execution already started; outcome may be ambiguous; reconciliation is required, never retry")
	} else if !errors.Is(err, syscall.ENOENT) {
		return Report{}, err
	}
	disks := make([]*os.File, len(p.Disks))
	defer func() {
		for _, f := range disks {
			if f != nil {
				f.Close()
			}
		}
	}()
	for i, d := range p.Disks {
		f, err := openWritableOwned(dir, d.Name, d.Attachment)
		if err != nil {
			return Report{}, err
		}
		disks[i] = f
		for _, b := range d.Backups {
			if err := verifySnapshot(ctx, dir, b); err != nil {
				return Report{}, fmt.Errorf("backup changed: %w", err)
			}
			if err := verifyRange(ctx, f, b.Offset, b.Size, b.SHA256); err != nil {
				return Report{}, fmt.Errorf("initial preimage changed: %w", err)
			}
		}
		for _, w := range d.Writes {
			if err := verifySnapshot(ctx, dir, w); err != nil {
				return Report{}, fmt.Errorf("source snapshot changed: %w", err)
			}
		}
		if err := revalidate(dir, d.Name, f, d.Attachment); err != nil {
			return Report{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	if checkDirectory != nil {
		if err := checkDirectory(); err != nil {
			return Report{}, err
		}
	}
	journal, _ := canonical(struct{ PreviewDigest, ApprovalDigest string }{string(p.PreviewDigest), string(a.ApprovalDigest)})
	if err := createBytes(dir, "execution-started.json", journal, true); err != nil {
		return Report{}, err
	}
	defer func() {
		if err != nil {
			err = fmt.Errorf("synthetic execution consumed; preserve journal and backups; do not retry: %w", err)
		}
	}()
	for i, d := range p.Disks {
		for _, w := range d.Writes {
			if checkDirectory != nil {
				if err := checkDirectory(); err != nil {
					return Report{}, err
				}
			}
			if err := revalidate(dir, d.Name, disks[i], d.Attachment); err != nil {
				return Report{}, err
			}
			source, err := openAt(dir, w.Name, syscall.O_RDONLY)
			if err != nil {
				return Report{}, err
			}
			copyErr := revalidate(dir, w.Name, source, w.Attachment)
			if copyErr == nil {
				copyErr = verifyRange(ctx, source, 0, w.Size, w.SHA256)
			}
			if copyErr == nil {
				copyErr = copyRange(ctx, disks[i], w.Offset, source, 0, w.Size, false, afterChunk)
			}
			if copyErr == nil {
				copyErr = verifyRange(ctx, source, 0, w.Size, w.SHA256)
			}
			if copyErr == nil {
				copyErr = revalidate(dir, w.Name, source, w.Attachment)
			}
			source.Close()
			if copyErr != nil {
				return Report{}, copyErr
			}
			// Persist each complete payload before publishing backup GPT, and
			// persist backup metadata before primary headers/PMBR. Per-range
			// barriers also leave a bounded durable boundary after interruption.
			if err := disks[i].Sync(); err != nil {
				return Report{}, err
			}
		}
		if err := disks[i].Sync(); err != nil {
			return Report{}, err
		}
	}
	// Independent descriptor readback is required even after every write/fsync
	// succeeds. No writer-local success result substitutes for this pass.
	for _, d := range p.Disks {
		f, err := openAt(dir, d.Name, syscall.O_RDONLY)
		if err != nil {
			return Report{}, err
		}
		checkErr := revalidate(dir, d.Name, f, d.Attachment)
		for _, w := range d.Writes {
			if checkErr == nil {
				checkErr = verifyRange(ctx, f, w.Offset, w.Size, w.SHA256)
			}
		}
		if checkErr == nil {
			checkErr = revalidate(dir, d.Name, f, d.Attachment)
		}
		f.Close()
		if checkErr != nil {
			return Report{}, checkErr
		}
		for _, b := range d.Backups {
			if err := verifySnapshot(ctx, dir, b); err != nil {
				return Report{}, err
			}
		}
	}
	if checkDirectory != nil {
		if err := checkDirectory(); err != nil {
			return Report{}, err
		}
	}
	report = Report{SchemaVersion: ReportSchema, Scope: Scope, PreviewDigest: p.PreviewDigest, ApprovalDigest: a.ApprovalDigest, Outcome: "synthetic-staging-complete", BackupReadbackVerified: true, FinalReadbackVerified: true}
	b, err := report.CanonicalJSON()
	if err != nil {
		return Report{}, err
	}
	if err := createBytes(dir, "execution-complete.json", b, true); err != nil {
		return Report{}, err
	}
	return report, nil
}
