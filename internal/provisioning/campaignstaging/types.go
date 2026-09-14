// Package campaignstaging implements the candidate per-leg recovery and
// staging sequence. Its receipts describe local mechanical checks, not
// authenticated hardware observations or campaign claim closure. The caller
// supplies a separately reviewed device opener and independently fixed inputs.
package campaignstaging

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path/filepath"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediainventory"
)

const (
	PreviewSchema      = "kaiba.provisioning.candidate-campaign-staging-preview/v1alpha1"
	ApprovalSchema     = "kaiba.provisioning.candidate-campaign-staging-acknowledgement/v1alpha1"
	ReportSchema       = "kaiba.provisioning.candidate-campaign-staging-report/v1alpha1"
	ReadbackSchema     = "kaiba.provisioning.candidate-campaign-readback/v1alpha1"
	Scope              = "local-mechanical-checks-no-authenticated-campaign-closure"
	maximumRecordBytes = 4 * 1024 * 1024
)

type Config struct {
	Plan         campaignmedia.StagingPlan                          `json:"plan"`
	Requirements campaignmedia.RecoveryBackupRequirementsV1Alpha2   `json:"requirements"`
	Envelopes    []campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2 `json:"envelopes"`
	Leg          campaignmedia.Leg                                  `json:"leg"`
	Payloads     map[campaignmedia.PartitionRole]string             `json:"payloads"`
}

// Target is an already exclusively held attachment. An opener must refuse
// active devices and independently bind its actual descriptor to Facts.
type Target interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
	Close() error
	Facts() mediainventory.TargetFacts
	Revalidate(context.Context) error
}

type Opener interface {
	Open(context.Context, bool, *mediainventory.TargetFacts) (Target, error)
}

type FileIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Size   uint64 `json:"size_bytes"`
}

type Range struct {
	Role   string        `json:"role"`
	Name   string        `json:"name"`
	Offset uint64        `json:"offset_bytes"`
	Size   uint64        `json:"size_bytes"`
	SHA256 bundle.Digest `json:"sha256"`
	File   FileIdentity  `json:"file"`
}

type Preview struct {
	SchemaVersion              string                     `json:"schema_version"`
	Scope                      string                     `json:"scope"`
	AttemptID                  string                     `json:"attempt_id"`
	ConfigDigest               bundle.Digest              `json:"config_digest"`
	PlanDigest                 bundle.Digest              `json:"plan_digest"`
	RecoveryRequirementsDigest bundle.Digest              `json:"recovery_requirements_digest"`
	Leg                        campaignmedia.Leg          `json:"leg"`
	Attachment                 mediainventory.TargetFacts `json:"attachment"`
	Directory                  FileIdentity               `json:"directory"`
	Backups                    []Range                    `json:"backups"`
	Writes                     []Range                    `json:"writes"`
	HardwareQualified          bool                       `json:"hardware_qualified"`
	CampaignClaimsClosed       bool                       `json:"campaign_claims_closed"`
	PreviewDigest              bundle.Digest              `json:"preview_digest"`
}

// Approval is an OS-operator assertion. It is not a signature, authenticated
// reviewer identity, live authority grant, or permission to close any claim.
type Approval struct {
	SchemaVersion             string        `json:"schema_version"`
	Scope                     string        `json:"scope"`
	Reviewer                  string        `json:"reviewer"`
	PreviewDigest             bundle.Digest `json:"preview_digest"`
	LocalOperatorAcknowledged bool          `json:"local_operator_acknowledged"`
	CampaignClaimsClosed      bool          `json:"campaign_claims_closed"`
	ApprovalDigest            bundle.Digest `json:"approval_digest"`
}

type Readback struct {
	SchemaVersion          string                          `json:"schema_version"`
	Scope                  string                          `json:"scope"`
	ConfigDigest           bundle.Digest                   `json:"config_digest"`
	PlanDigest             bundle.Digest                   `json:"plan_digest"`
	Leg                    campaignmedia.Leg               `json:"leg"`
	Attachment             mediainventory.TargetFacts      `json:"attachment"`
	Ranges                 []campaignmedia.ByteRangeDigest `json:"ranges"`
	CompleteRangesVerified bool                            `json:"complete_ranges_verified"`
	HardwareQualified      bool                            `json:"hardware_qualified"`
	CampaignClaimsClosed   bool                            `json:"campaign_claims_closed"`
	ReadbackDigest         bundle.Digest                   `json:"readback_digest"`
}

type Report struct {
	SchemaVersion          string        `json:"schema_version"`
	Scope                  string        `json:"scope"`
	PreviewDigest          bundle.Digest `json:"preview_digest"`
	ApprovalDigest         bundle.Digest `json:"approval_digest"`
	Readback               Readback      `json:"readback"`
	BackupReadbackVerified bool          `json:"backup_readback_verified"`
	HardwareQualified      bool          `json:"hardware_qualified"`
	CampaignClaimsClosed   bool          `json:"campaign_claims_closed"`
	ReportDigest           bundle.Digest `json:"report_digest"`
}

func digest(domain string, v any) bundle.Digest {
	b, _ := json.Marshal(v)
	return bundle.Sum(append(append([]byte(domain), 0), b...))
}

func (c Config) Validate() error { _, err := derive(c); return err }

func (p Preview) Validate() error {
	if p.SchemaVersion != PreviewSchema || p.Scope != Scope || p.HardwareQualified || p.CampaignClaimsClosed || len(p.AttemptID) != 64 || p.Directory.Inode == 0 || p.Directory.Size != 0 {
		return errors.New("invalid candidate staging preview boundary")
	}
	id, err := hex.DecodeString(p.AttemptID)
	if err != nil || hex.EncodeToString(id) != p.AttemptID {
		return errors.New("invalid attempt ID")
	}
	for _, d := range []bundle.Digest{p.ConfigDigest, p.PlanDigest, p.RecoveryRequirementsDigest} {
		if err := d.Validate(); err != nil {
			return err
		}
	}
	if p.Leg != campaignmedia.LegMalakSD && p.Leg != campaignmedia.LegPiLocalNVMe {
		return errors.New("invalid campaign leg")
	}
	if err := validateFacts(p.Attachment); err != nil {
		return err
	}
	seen := map[[2]uint64]bool{{p.Directory.Device, p.Directory.Inode}: true}
	for group, ranges := range [][]Range{p.Backups, p.Writes} {
		if len(ranges) == 0 || len(ranges) > 32 {
			return errors.New("invalid staging range count")
		}
		prefix := "backup"
		if group == 1 {
			prefix = "source"
		}
		for i, r := range ranges {
			if r.Role == "" || len(r.Role) > 128 || r.Name != fmt.Sprintf("%s-%d.img", prefix, i) || r.File.Inode == 0 || r.File.Size != r.Size {
				return errors.New("invalid staging range file")
			}
			if err := checkedRange(r.Offset, r.Size); err != nil {
				return err
			}
			if r.Offset+r.Size > p.Attachment.SizeBytes {
				return errors.New("staging range exceeds target")
			}
			if err := r.SHA256.Validate(); err != nil {
				return err
			}
			key := [2]uint64{r.File.Device, r.File.Inode}
			if seen[key] {
				return errors.New("staging evidence inode reused")
			}
			seen[key] = true
			for _, prev := range ranges[:i] {
				if r.Offset < prev.Offset+prev.Size && prev.Offset < r.Offset+r.Size {
					return errors.New("overlapping staging ranges")
				}
			}
		}
	}
	for _, w := range p.Writes {
		covered := false
		for _, b := range p.Backups {
			if w.Offset >= b.Offset && w.Offset+w.Size <= b.Offset+b.Size {
				covered = true
			}
		}
		if !covered {
			return errors.New("write lacks complete recovery coverage")
		}
	}
	want := p.PreviewDigest
	p.PreviewDigest = ""
	if want != digest(PreviewSchema, p) {
		return errors.New("preview digest mismatch")
	}
	return nil
}

func validateFacts(f mediainventory.TargetFacts) error {
	if f.Kind != mediainventory.TargetBlockDevice || !f.WholeDevice || f.DeviceNumber == 0 || f.DiskSequence == 0 || f.SizeBytes == 0 || f.BootID == "" || f.SysfsPath == "" || f.RequestedPath == "" || f.ResolvedPath == "" {
		return errors.New("target lacks complete inactive block-attachment identity")
	}
	return nil
}

func Approve(p Preview, expectedDigest bundle.Digest, reviewer string) (Approval, error) {
	if err := p.Validate(); err != nil {
		return Approval{}, err
	}
	if expectedDigest != p.PreviewDigest {
		return Approval{}, errors.New("explicit preview digest differs from reviewed preview")
	}
	a := Approval{SchemaVersion: ApprovalSchema, Scope: Scope, Reviewer: reviewer, PreviewDigest: p.PreviewDigest, LocalOperatorAcknowledged: true}
	a.ApprovalDigest = digest(ApprovalSchema, a)
	return a, a.Validate()
}

func (a Approval) Validate() error {
	if a.SchemaVersion != ApprovalSchema || a.Scope != Scope || !a.LocalOperatorAcknowledged || a.CampaignClaimsClosed || len(a.Reviewer) == 0 || len(a.Reviewer) > 128 {
		return errors.New("invalid local operator acknowledgement")
	}
	for _, c := range a.Reviewer {
		if c < 33 || c > 126 {
			return errors.New("reviewer must be printable ASCII without spaces")
		}
	}
	if err := a.PreviewDigest.Validate(); err != nil {
		return err
	}
	want := a.ApprovalDigest
	a.ApprovalDigest = ""
	if want != digest(ApprovalSchema, a) {
		return errors.New("acknowledgement digest mismatch")
	}
	return nil
}

func (r Readback) Validate() error {
	if r.SchemaVersion != ReadbackSchema || r.Scope != Scope || !r.CompleteRangesVerified || r.HardwareQualified || r.CampaignClaimsClosed || len(r.Ranges) == 0 || len(r.Ranges) > 32 {
		return errors.New("invalid mechanical readback boundary")
	}
	if r.Leg != campaignmedia.LegMalakSD && r.Leg != campaignmedia.LegPiLocalNVMe {
		return errors.New("invalid readback leg")
	}
	if err := validateFacts(r.Attachment); err != nil {
		return err
	}
	for _, d := range []bundle.Digest{r.ConfigDigest, r.PlanDigest} {
		if err := d.Validate(); err != nil {
			return err
		}
	}
	for i, span := range r.Ranges {
		if err := checkedRange(span.OffsetBytes, span.SizeBytes); err != nil {
			return err
		}
		if span.OffsetBytes+span.SizeBytes > r.Attachment.SizeBytes {
			return errors.New("readback range exceeds target")
		}
		if err := span.SHA256.Validate(); err != nil {
			return err
		}
		for _, prev := range r.Ranges[:i] {
			if span.OffsetBytes < prev.OffsetBytes+prev.SizeBytes && prev.OffsetBytes < span.OffsetBytes+span.SizeBytes {
				return errors.New("overlapping readback ranges")
			}
		}
	}
	want := r.ReadbackDigest
	r.ReadbackDigest = ""
	if want != digest(ReadbackSchema, r) {
		return errors.New("readback digest mismatch")
	}
	return nil
}

func (r Report) Validate() error {
	if r.SchemaVersion != ReportSchema || r.Scope != Scope || !r.BackupReadbackVerified || r.HardwareQualified || r.CampaignClaimsClosed {
		return errors.New("invalid mechanical staging report")
	}
	if err := r.Readback.Validate(); err != nil {
		return err
	}
	for _, d := range []bundle.Digest{r.PreviewDigest, r.ApprovalDigest} {
		if err := d.Validate(); err != nil {
			return err
		}
	}
	want := r.ReportDigest
	r.ReportDigest = ""
	if want != digest(ReportSchema, r) {
		return errors.New("report digest mismatch")
	}
	return nil
}

func canonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) >= maximumRecordBytes {
		return nil, errors.New("candidate staging record exceeds limit")
	}
	return append(b, '\n'), nil
}
func parse(b []byte, v any) error {
	if len(b) == 0 || len(b) > maximumRecordBytes {
		return errors.New("invalid candidate record size")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	c, err := canonical(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, c) {
		return errors.New("candidate JSON must be canonical with one final newline")
	}
	return nil
}
func (p Preview) CanonicalJSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return canonical(p)
}
func (a Approval) CanonicalJSON() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return canonical(a)
}
func (r Report) CanonicalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return canonical(r)
}
func (r Readback) CanonicalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return canonical(r)
}
func ParsePreview(b []byte) (Preview, error) {
	var v Preview
	if err := parse(b, &v); err != nil {
		return v, err
	}
	return v, v.Validate()
}
func ParseApproval(b []byte) (Approval, error) {
	var v Approval
	if err := parse(b, &v); err != nil {
		return v, err
	}
	return v, v.Validate()
}
func ParseReport(b []byte) (Report, error) {
	var v Report
	if err := parse(b, &v); err != nil {
		return v, err
	}
	return v, v.Validate()
}
func ParseReadback(b []byte) (Readback, error) {
	var v Readback
	if err := parse(b, &v); err != nil {
		return v, err
	}
	return v, v.Validate()
}

func checkedRange(offset, size uint64) error {
	if size == 0 || offset > math.MaxInt64 || size > math.MaxInt64-offset {
		return errors.New("invalid bounded byte range")
	}
	return nil
}
func canonicalPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}
