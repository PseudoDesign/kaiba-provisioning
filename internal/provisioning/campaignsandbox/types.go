// Package campaignsandbox rehearses recovery and staging on newly created
// regular files. It never opens a device for writing and cannot authorize a
// physical campaign. Only the explicitly captured recovery ranges are copied
// from input fixtures; the resulting sparse files are not whole-disk backups.
package campaignsandbox

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
)

const (
	PreviewSchema  = "kaiba.provisioning.synthetic-campaign-sandbox-preview/v1alpha1"
	ApprovalSchema = "kaiba.provisioning.synthetic-campaign-sandbox-approval/v1alpha1"
	ReportSchema   = "kaiba.provisioning.synthetic-campaign-sandbox-report/v1alpha1"
	Scope          = "synthetic-regular-files-captured-recovery-ranges-only"
)

type DiskInput struct {
	Leg  campaignmedia.Leg `json:"leg"`
	Path string            `json:"path"`
}

type PayloadInput struct {
	Leg  campaignmedia.Leg           `json:"leg"`
	Role campaignmedia.PartitionRole `json:"role"`
	Path string                      `json:"path"`
}

// Input accepts public contracts and regular-file fixtures, never block
// devices. Prepare creates independent sparse files under a new directory.
type Input struct {
	Plan         campaignmedia.StagingPlan                          `json:"plan"`
	Envelopes    []campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2 `json:"envelopes"`
	Requirements campaignmedia.RecoveryBackupRequirementsV1Alpha2   `json:"requirements"`
	Disks        []DiskInput                                        `json:"disks"`
	Payloads     []PayloadInput                                     `json:"payloads"`
}

// Attachment binds an opened synthetic file to its current local inode.
// These values are not physical-device identity or authentication.
type Attachment struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Size   uint64 `json:"size"`
}

type Range struct {
	Name       string        `json:"name"`
	Offset     uint64        `json:"offset_bytes"`
	Size       uint64        `json:"size_bytes"`
	SHA256     bundle.Digest `json:"sha256"`
	Attachment Attachment    `json:"attachment"`
}

type Disk struct {
	Leg        campaignmedia.Leg `json:"leg"`
	Name       string            `json:"name"`
	Attachment Attachment        `json:"attachment"`
	Backups    []Range           `json:"backups"`
	Writes     []Range           `json:"writes"`
}

type Preview struct {
	SchemaVersion              string        `json:"schema_version"`
	Scope                      string        `json:"scope"`
	SandboxID                  string        `json:"sandbox_id"`
	Directory                  Attachment    `json:"directory"`
	PlanDigest                 bundle.Digest `json:"plan_digest"`
	RecoveryRequirementsDigest bundle.Digest `json:"recovery_requirements_digest"`
	Disks                      []Disk        `json:"disks"`
	PhysicalStagingReady       bool          `json:"physical_staging_ready"`
	HardwareObserved           bool          `json:"hardware_observed"`
	PreviewDigest              bundle.Digest `json:"preview_digest"`
}

type Approval struct {
	SchemaVersion            string        `json:"schema_version"`
	Scope                    string        `json:"scope"`
	Reviewer                 string        `json:"reviewer"`
	PreviewDigest            bundle.Digest `json:"preview_digest"`
	PhysicalWritesAuthorized bool          `json:"physical_writes_authorized"`
	ApprovalDigest           bundle.Digest `json:"approval_digest"`
}

type Report struct {
	SchemaVersion          string        `json:"schema_version"`
	Scope                  string        `json:"scope"`
	PreviewDigest          bundle.Digest `json:"preview_digest"`
	ApprovalDigest         bundle.Digest `json:"approval_digest"`
	Outcome                string        `json:"outcome"`
	BackupReadbackVerified bool          `json:"backup_readback_verified"`
	FinalReadbackVerified  bool          `json:"final_readback_verified"`
	PhysicalStagingReady   bool          `json:"physical_staging_ready"`
	HardwareObserved       bool          `json:"hardware_observed"`
}

func digest(domain string, value any) bundle.Digest {
	encoded, _ := json.Marshal(value)
	return bundle.Sum(append(append([]byte(domain), 0), encoded...))
}

func (p Preview) Validate() error {
	if p.SchemaVersion != PreviewSchema || p.Scope != Scope || p.PhysicalStagingReady || p.HardwareObserved || len(p.SandboxID) != 64 || len(p.Disks) != 2 {
		return errors.New("invalid synthetic sandbox preview boundary")
	}
	if id, err := hex.DecodeString(p.SandboxID); err != nil || hex.EncodeToString(id) != p.SandboxID {
		return errors.New("invalid sandbox identifier")
	}
	if err := p.PlanDigest.Validate(); err != nil {
		return err
	}
	if err := p.RecoveryRequirementsDigest.Validate(); err != nil {
		return err
	}
	if p.Directory.Inode == 0 || p.Directory.Size != 0 {
		return errors.New("invalid sandbox directory attachment")
	}
	seen := make(map[[2]uint64]bool)
	for i, d := range p.Disks {
		if d.Leg != []campaignmedia.Leg{campaignmedia.LegMalakSD, campaignmedia.LegPiLocalNVMe}[i] || d.Name != fmt.Sprintf("disk-%d.img", i) || d.Attachment.Size == 0 || len(d.Backups) == 0 || len(d.Writes) == 0 {
			return errors.New("invalid synthetic disk declaration")
		}
		attachments := []Attachment{d.Attachment}
		for groupIndex, ranges := range [][]Range{d.Backups, d.Writes} {
			prefix := "backup"
			if groupIndex == 1 {
				prefix = "source"
			}
			for j, span := range ranges {
				if span.Name != fmt.Sprintf("%s-%d-%d.img", prefix, i, j) || span.Attachment.Size != span.Size {
					return errors.New("invalid sandbox range name or attachment")
				}
				if err := checkedRange(span.Offset, span.Size); err != nil {
					return err
				}
				if span.Offset+span.Size > d.Attachment.Size {
					return errors.New("range exceeds disk")
				}
				if err := span.SHA256.Validate(); err != nil {
					return err
				}
				for _, prior := range ranges[:j] {
					if span.Offset < prior.Offset+prior.Size && prior.Offset < span.Offset+span.Size {
						return errors.New("overlapping sandbox ranges")
					}
				}
				attachments = append(attachments, span.Attachment)
			}
		}
		for _, w := range d.Writes {
			covered := false
			for _, b := range d.Backups {
				if w.Offset >= b.Offset && w.Offset+w.Size <= b.Offset+b.Size {
					covered = true
				}
			}
			if !covered {
				return errors.New("sandbox write lacks complete recovery coverage")
			}
		}
		for _, a := range attachments {
			key := [2]uint64{a.Device, a.Inode}
			if a.Inode == 0 || seen[key] {
				return errors.New("sandbox attachment reused across roles")
			}
			seen[key] = true
		}
	}
	want := p.PreviewDigest
	p.PreviewDigest = ""
	if want != digest(PreviewSchema, p) {
		return errors.New("sandbox preview digest mismatch")
	}
	return nil
}

// Approve expresses approval of synthetic file writes only. The digest binds
// the exact plan, recovery requirements, inode attachments and source bytes.
func Approve(p Preview, reviewer string) (Approval, error) {
	if err := p.Validate(); err != nil {
		return Approval{}, err
	}
	if len(reviewer) == 0 || len(reviewer) > 128 {
		return Approval{}, errors.New("reviewer must contain 1 through 128 printable ASCII characters")
	}
	for _, c := range reviewer {
		if c < 33 || c > 126 {
			return Approval{}, errors.New("reviewer must be printable ASCII without spaces")
		}
	}
	a := Approval{SchemaVersion: ApprovalSchema, Scope: Scope, Reviewer: reviewer, PreviewDigest: p.PreviewDigest}
	a.ApprovalDigest = digest(ApprovalSchema, a)
	return a, nil
}

func (a Approval) Validate() error {
	if a.SchemaVersion != ApprovalSchema || a.Scope != Scope || a.PhysicalWritesAuthorized || a.Reviewer == "" || len(a.Reviewer) > 128 {
		return errors.New("invalid synthetic sandbox approval boundary")
	}
	for _, c := range a.Reviewer {
		if c < 33 || c > 126 {
			return errors.New("invalid reviewer")
		}
	}
	if err := a.PreviewDigest.Validate(); err != nil {
		return err
	}
	want := a.ApprovalDigest
	a.ApprovalDigest = ""
	if want != digest(ApprovalSchema, a) {
		return errors.New("sandbox approval digest mismatch")
	}
	return nil
}

func canonical(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	return append(encoded, '\n'), err
}

func parse(encoded []byte, result any) error {
	if len(encoded) > 4*1024*1024 {
		return errors.New("sandbox record exceeds 4 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(encoded))
	d.DisallowUnknownFields()
	if err := d.Decode(result); err != nil {
		return err
	}
	canonicalBytes, err := canonical(result)
	if err != nil {
		return err
	}
	if !bytes.Equal(encoded, canonicalBytes) {
		return errors.New("sandbox JSON must be canonical, including its final newline")
	}
	return nil
}

func (p Preview) CanonicalJSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return canonical(p)
}
func ParsePreview(b []byte) (Preview, error) {
	var p Preview
	if err := parse(b, &p); err != nil {
		return p, err
	}
	return p, p.Validate()
}
func (a Approval) CanonicalJSON() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return canonical(a)
}
func ParseApproval(b []byte) (Approval, error) {
	var a Approval
	if err := parse(b, &a); err != nil {
		return a, err
	}
	return a, a.Validate()
}
func (r Report) CanonicalJSON() ([]byte, error) {
	if r.SchemaVersion != ReportSchema || r.Scope != Scope || r.PhysicalStagingReady || r.HardwareObserved || r.Outcome != "synthetic-staging-complete" || !r.BackupReadbackVerified || !r.FinalReadbackVerified {
		return nil, fmt.Errorf("invalid synthetic completion report")
	}
	if err := r.PreviewDigest.Validate(); err != nil {
		return nil, err
	}
	if err := r.ApprovalDigest.Validate(); err != nil {
		return nil, err
	}
	return canonical(r)
}
func ParseReport(b []byte) (Report, error) {
	var r Report
	if err := parse(b, &r); err != nil {
		return r, err
	}
	_, err := r.CanonicalJSON()
	return r, err
}
