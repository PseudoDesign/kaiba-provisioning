//go:build linux

package campaignstaging

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediainventory"
)

// Prepare creates a new durable recovery directory without ever requesting a
// writable target. Supplied captures must match the current attachment bytes.
func Prepare(ctx context.Context, directory string, config Config, opener Opener) (Preview, error) {
	if ctx == nil {
		return Preview{}, errors.New("nil staging context")
	}
	r, err := derive(config)
	if err != nil {
		return Preview{}, err
	}
	return prepare(ctx, directory, r, opener)
}

func prepare(ctx context.Context, directory string, r recipe, opener Opener) (Preview, error) {
	if err := validateRecipe(r); err != nil {
		return Preview{}, err
	}
	if err := ctx.Err(); err != nil {
		return Preview{}, err
	}
	target, err := openTarget(ctx, opener, false, nil, r)
	if err != nil {
		return Preview{}, err
	}
	closed := false
	defer func() {
		if !closed {
			target.Close()
		}
	}()
	if r.envelope != nil {
		if err := r.envelope.VerifyAgainst(contextReader{ctx: ctx, reader: target}); err != nil {
			return Preview{}, fmt.Errorf("fresh initial GPT capture verification: %w", err)
		}
		if err := target.Revalidate(ctx); err != nil {
			return Preview{}, err
		}
	}
	d, err := createDirectory(directory)
	if err != nil {
		return Preview{}, err
	}
	defer d.Close()
	if err := syscall.Flock(int(d.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return Preview{}, err
	}
	di, err := directoryIdentity(d)
	if err != nil {
		return Preview{}, err
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return revalidateDirectory(directory, d, di)
	}
	id := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		return Preview{}, err
	}
	p := Preview{SchemaVersion: PreviewSchema, Scope: Scope, AttemptID: hex.EncodeToString(id), ConfigDigest: r.configDigest, PlanDigest: r.planDigest, RecoveryRequirementsDigest: r.requirementsDigest, Leg: r.identity.Leg, Attachment: target.Facts(), Directory: di}
	for _, b := range r.backups {
		if err := check(); err != nil {
			return Preview{}, err
		}
		if err := target.Revalidate(ctx); err != nil {
			return Preview{}, err
		}
		stored, err := createSnapshot(ctx, d, b, target, b.Offset, check)
		if err != nil {
			return Preview{}, fmt.Errorf("capture recovery %s: %w", b.Name, err)
		}
		if err := target.Revalidate(ctx); err != nil {
			return Preview{}, err
		}
		p.Backups = append(p.Backups, stored)
	}
	seen := map[[2]uint64]bool{}
	for i, w := range r.writes {
		if err := check(); err != nil {
			return Preview{}, err
		}
		span := Range{Role: w.role, Name: fmt.Sprintf("source-%d.img", i), Offset: w.offset, Size: w.size, SHA256: w.sha256}
		if len(w.data) != 0 {
			stored, err := createSnapshot(ctx, d, span, bytes.NewReader(w.data), 0, check)
			if err != nil {
				return Preview{}, err
			}
			p.Writes = append(p.Writes, stored)
			continue
		}
		source, err := openSource(w.path)
		if err != nil {
			return Preview{}, err
		}
		stored, err := snapshotSource(ctx, d, span, w, source, seen, check)
		closeErr := source.Close()
		if err != nil {
			return Preview{}, err
		}
		if closeErr != nil {
			return Preview{}, closeErr
		}
		p.Writes = append(p.Writes, stored)
	}
	// Inputs can change while the other ranges are captured. Recheck every
	// preimage and attachment before publishing the prepared record.
	if err := verifyPreimages(ctx, target, r.backups); err != nil {
		return Preview{}, err
	}
	if err := target.Revalidate(ctx); err != nil {
		return Preview{}, err
	}
	if target.Facts() != p.Attachment {
		return Preview{}, errors.New("prepared attachment facts changed")
	}
	if err := target.Close(); err != nil {
		return Preview{}, err
	}
	closed = true
	if err := check(); err != nil {
		return Preview{}, err
	}
	p.PreviewDigest = digest(PreviewSchema, p)
	encoded, err := p.CanonicalJSON()
	if err != nil {
		return Preview{}, err
	}
	if err := createBytes(d, "prepared.json", encoded); err != nil {
		return Preview{}, err
	}
	if err := check(); err != nil {
		return Preview{}, err
	}
	return p, nil
}

func snapshotSource(ctx context.Context, d *os.File, span Range, w writeRecipe, source *os.File, seen map[[2]uint64]bool, check func() error) (Range, error) {
	id, err := fileIdentity(source, false)
	if err != nil {
		return span, err
	}
	if id.Size != w.sourceSize {
		return span, errors.New("payload source size differs from plan")
	}
	key := [2]uint64{id.Device, id.Inode}
	if seen[key] {
		return span, errors.New("payload source inode reused across roles")
	}
	seen[key] = true
	if err := verifyRange(ctx, source, 0, w.sourceSize, w.sourceDigest); err != nil {
		return span, err
	}
	stored, err := createSnapshot(ctx, d, span, paddedReader{source: source, size: w.sourceSize}, 0, check)
	if err != nil {
		return span, err
	}
	if err := verifyRange(ctx, source, 0, w.sourceSize, w.sourceDigest); err != nil {
		return span, err
	}
	current, err := fileIdentity(source, false)
	if err != nil || current != id {
		return span, errors.New("opened source identity changed")
	}
	fresh, err := openSource(w.path)
	if err != nil {
		return span, err
	}
	defer fresh.Close()
	current, err = fileIdentity(fresh, false)
	if err != nil || current != id {
		return span, errors.New("source path attachment changed")
	}
	return stored, nil
}

// Execute consumes the prepared attempt before requesting a writable target.
// Every later error leaves the durable marker and backups in place. It cannot
// restore, reset, or automatically resume that attempt. The operator controls
// the local evidence directory, so these public digest-sealed records are not
// an authentication boundary against that same operator.
func Execute(ctx context.Context, directory string, config Config, approval Approval, opener Opener) (Report, error) {
	if ctx == nil {
		return Report{}, errors.New("nil staging context")
	}
	r, err := derive(config)
	if err != nil {
		return Report{}, err
	}
	return execute(ctx, directory, r, approval, opener)
}

func execute(ctx context.Context, directory string, r recipe, approval Approval, opener Opener) (Report, error) {
	d, err := ownedDirectory(directory)
	if err != nil {
		return Report{}, err
	}
	defer d.Close()
	if err := syscall.Flock(int(d.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return Report{}, err
	}
	if err := requireUnused(d); err != nil {
		return Report{}, err
	}
	encoded, err := readBytes(d, "prepared.json")
	if err != nil {
		return Report{}, err
	}
	p, err := ParsePreview(encoded)
	if err != nil {
		return Report{}, err
	}
	if err := matchRecipe(p, r); err != nil {
		return Report{}, err
	}
	if err := approval.Validate(); err != nil {
		return Report{}, err
	}
	if approval.PreviewDigest != p.PreviewDigest {
		return Report{}, errors.New("acknowledgement belongs to another preview")
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return revalidateDirectory(directory, d, p.Directory)
	}
	if err := check(); err != nil {
		return Report{}, err
	}
	// All backup, source and target preimages are checked before the attempt
	// journal is committed and before any writable target open is requested.
	if err := verifyEvidence(ctx, d, p); err != nil {
		return Report{}, err
	}
	initial, err := openTarget(ctx, opener, false, &p.Attachment, r)
	if err != nil {
		return Report{}, err
	}
	err = verifyPreimages(ctx, initial, p.Backups)
	closeErr := initial.Close()
	if err != nil {
		return Report{}, err
	}
	if closeErr != nil {
		return Report{}, closeErr
	}
	if err := check(); err != nil {
		return Report{}, err
	}
	marker, err := canonical(struct {
		Preview  Preview  `json:"preview"`
		Approval Approval `json:"approval"`
	}{p, approval})
	if err != nil {
		return Report{}, err
	}
	if err := createBytes(d, "execution-started.json", marker); err != nil {
		return Report{}, err
	}
	if err := check(); err != nil {
		return Report{}, err
	}
	target, err := openTarget(ctx, opener, true, &p.Attachment, r)
	if err != nil {
		return Report{}, err
	}
	closed := false
	defer func() {
		if !closed {
			target.Close()
		}
	}()
	// Closing the read-only descriptor and opening the writer is an explicit
	// attachment transition. Repeat preimages on this exact descriptor too.
	if err := verifyPreimages(ctx, target, p.Backups); err != nil {
		return Report{}, err
	}
	for _, span := range p.Writes {
		if err := check(); err != nil {
			return Report{}, err
		}
		if err := verifySnapshot(ctx, d, span); err != nil {
			return Report{}, err
		}
		if err := target.Revalidate(ctx); err != nil {
			return Report{}, err
		}
		f, err := openAt(d, span.Name, false)
		if err != nil {
			return Report{}, err
		}
		copied, copyErr := copyRange(ctx, target, span.Offset, f, 0, span.Size, false, func() error {
			if err := check(); err != nil {
				return err
			}
			return target.Revalidate(ctx)
		})
		if copyErr == nil {
			copyErr = revalidateFile(d, span, f)
		}
		if copyErr == nil && copied != span.SHA256 {
			copyErr = errors.New("bytes copied to target differ from approved payload")
		}
		if copyErr == nil {
			copyErr = verifyRange(ctx, f, 0, span.Size, span.SHA256)
		}
		closeErr := f.Close()
		if copyErr != nil {
			return Report{}, copyErr
		}
		if closeErr != nil {
			return Report{}, closeErr
		}
		if err := target.Sync(); err != nil {
			return Report{}, fmt.Errorf("sync target after %s: %w", span.Role, err)
		}
		if err := target.Revalidate(ctx); err != nil {
			return Report{}, err
		}
	}
	if err := target.Close(); err != nil {
		return Report{}, err
	}
	closed = true
	if err := check(); err != nil {
		return Report{}, err
	}
	readback, err := verify(ctx, r, opener, &p.Attachment)
	if err != nil {
		return Report{}, err
	}
	// Changes to an already copied source or a recovery file suppress success,
	// even if final target bytes happen still to match the write plan.
	if err := verifyEvidence(ctx, d, p); err != nil {
		return Report{}, err
	}
	if err := check(); err != nil {
		return Report{}, err
	}
	report := Report{SchemaVersion: ReportSchema, Scope: Scope, PreviewDigest: p.PreviewDigest, ApprovalDigest: approval.ApprovalDigest, Readback: readback, BackupReadbackVerified: true}
	report.ReportDigest = digest(ReportSchema, report)
	b, err := report.CanonicalJSON()
	if err != nil {
		return Report{}, err
	}
	if err := createBytes(d, "execution-complete.json", b); err != nil {
		return Report{}, err
	}
	if err := check(); err != nil {
		return Report{}, err
	}
	return report, nil
}

// Verify independently opens the current selected attachment read-only and
// checks every complete final partition/GPT range. It does not require the
// old prestate or attachment boot ID: cold readback is a separate observation.
func Verify(ctx context.Context, config Config, opener Opener) (Readback, error) {
	if ctx == nil {
		return Readback{}, errors.New("nil readback context")
	}
	r, err := derive(config)
	if err != nil {
		return Readback{}, err
	}
	return verify(ctx, r, opener, nil)
}

func verify(ctx context.Context, r recipe, opener Opener, expected *mediainventory.TargetFacts) (Readback, error) {
	target, err := openTarget(ctx, opener, false, expected, r)
	if err != nil {
		return Readback{}, err
	}
	closed := false
	defer func() {
		if !closed {
			target.Close()
		}
	}()
	result := Readback{SchemaVersion: ReadbackSchema, Scope: Scope, ConfigDigest: r.configDigest, PlanDigest: r.planDigest, Leg: r.identity.Leg, Attachment: target.Facts(), CompleteRangesVerified: true}
	for _, w := range r.writes {
		if err := target.Revalidate(ctx); err != nil {
			return Readback{}, err
		}
		if err := verifyRange(ctx, target, w.offset, w.size, w.sha256); err != nil {
			return Readback{}, err
		}
		if err := target.Revalidate(ctx); err != nil {
			return Readback{}, err
		}
		result.Ranges = append(result.Ranges, campaignmedia.ByteRangeDigest{OffsetBytes: w.offset, SizeBytes: w.size, SHA256: w.sha256})
	}
	if target.Facts() != result.Attachment {
		return Readback{}, errors.New("readback attachment facts changed")
	}
	if err := target.Close(); err != nil {
		return Readback{}, err
	}
	closed = true
	result.ReadbackDigest = digest(ReadbackSchema, result)
	return result, result.Validate()
}

func verifyPreimages(ctx context.Context, t Target, ranges []Range) error {
	for _, b := range ranges {
		if err := t.Revalidate(ctx); err != nil {
			return err
		}
		if err := verifyRange(ctx, t, b.Offset, b.Size, b.SHA256); err != nil {
			return fmt.Errorf("target preimage %s: %w", b.Name, err)
		}
		if err := t.Revalidate(ctx); err != nil {
			return err
		}
	}
	return nil
}
func verifyEvidence(ctx context.Context, d *os.File, p Preview) error {
	for _, ranges := range [][]Range{p.Backups, p.Writes} {
		for _, r := range ranges {
			if err := verifySnapshot(ctx, d, r); err != nil {
				return fmt.Errorf("verify evidence %s: %w", r.Name, err)
			}
		}
	}
	return nil
}

func openTarget(ctx context.Context, opener Opener, writable bool, expected *mediainventory.TargetFacts, r recipe) (Target, error) {
	if opener == nil {
		return nil, errors.New("target opener is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var supplied *mediainventory.TargetFacts
	if expected != nil {
		v := *expected
		supplied = &v
	}
	t, err := opener.Open(ctx, writable, supplied)
	if err != nil {
		if t != nil {
			t.Close()
		}
		return nil, err
	}
	if t == nil {
		return nil, errors.New("target opener returned no attachment")
	}
	f := t.Facts()
	if err := validateFacts(f); err != nil {
		t.Close()
		return nil, err
	}
	if f.RequestedPath != r.identity.Selector || f.SizeBytes != r.identity.CapacityBytes || (expected != nil && f != *expected) {
		t.Close()
		return nil, errors.New("opened attachment differs from independent target binding")
	}
	if err := t.Revalidate(ctx); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.ReaderAt
}

func (r contextReader) ReadAt(b []byte, off int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.ReadAt(b, off)
}
