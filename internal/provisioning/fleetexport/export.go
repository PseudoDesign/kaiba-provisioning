// Package fleetexport emits development candidate observations. It has no
// station mutation, identity issuance, enrollment, or admission interface.
package fleetexport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
)

const ContractVersion = "0.1.0-draft.1"
const SourceRepository = "https://github.com/PseudoDesign/kaiba-provisioning"

// Policy is operator-owned, immutable for a source transaction, and reviewed
// separately from its exported records. Evidence references never select trust.
type Policy struct {
	AuthorityID      string      `json:"authority_id"`
	TenantID         string      `json:"tenant_id"`
	SecurityDomainID string      `json:"security_domain_id"`
	SourceCommit     string      `json:"source_commit"`
	ProfileID        string      `json:"profile_id"`
	BundleDigest     string      `json:"bundle_digest"`
	PolicyDigest     string      `json:"policy_digest"`
	ProfileRef       EvidenceRef `json:"profile_ref"`
	PostureRef       EvidenceRef `json:"posture_ref"`
	ReleaseRef       EvidenceRef `json:"release_ref"`
}
type EvidenceRef struct {
	URI    string `json:"uri"`
	Digest string `json:"digest"`
}
type Source struct {
	Repository    string      `json:"repository"`
	Commit        string      `json:"commit"`
	TransactionID string      `json:"transaction_id"`
	State         string      `json:"state"`
	ProfileRef    EvidenceRef `json:"profile_ref"`
	PostureRef    EvidenceRef `json:"posture_ref"`
	ReleaseRef    EvidenceRef `json:"release_ref"`
}
type Readiness struct {
	ProductionReady bool     `json:"production_ready"`
	EnrollmentReady bool     `json:"enrollment_ready"`
	Reasons         []string `json:"reasons"`
}
type Evidence struct {
	ControlRecord EvidenceRef `json:"control_record"`
	AuditReceipt  EvidenceRef `json:"audit_receipt"`
}
type Record struct {
	Contract         string    `json:"contract"`
	ContractVersion  string    `json:"contract_version"`
	RecordID         string    `json:"record_id"`
	Revision         uint64    `json:"revision"`
	IssuedAt         string    `json:"issued_at"`
	AuthorityID      string    `json:"authority_id"`
	TenantID         string    `json:"tenant_id"`
	SecurityDomainID string    `json:"security_domain_id"`
	CorrelationID    string    `json:"correlation_id"`
	Purpose          string    `json:"purpose"`
	AssetRef         string    `json:"asset_ref"`
	Cohort           string    `json:"cohort"`
	Source           Source    `json:"source"`
	Readiness        Readiness `json:"readiness"`
	Evidence         Evidence  `json:"evidence"`
}

// Bundle separates the public contract from access-controlled retained evidence.
// The latter contains audit lookup metadata and MUST NOT be served by fleet APIs.
type Bundle struct {
	Record                   Record
	ControlBytes, AuditBytes []byte
}
type ControlReader interface {
	GetTransaction(context.Context, string) (controlplane.Transaction, error)
}
type AuditReader interface {
	Records(string) []auditlog.Record
}

// Build brackets audit collection with stable control reads. Readers are trusted
// authority adapters, never client-supplied JSON. Unknown outcomes remain visible.
func Build(ctx context.Context, control ControlReader, audit AuditReader, id string, policy Policy) (Bundle, error) {
	if control == nil || audit == nil {
		return Bundle{}, errors.New("authority readers required")
	}
	first, err := control.GetTransaction(ctx, id)
	if err != nil {
		return Bundle{}, err
	}
	if first.ID != id {
		return Bundle{}, errors.New("source transaction identity mismatch")
	}
	before, err := json.Marshal(first)
	if err != nil {
		return Bundle{}, err
	}
	records := audit.Records(id)
	second, err := control.GetTransaction(ctx, id)
	if err != nil {
		return Bundle{}, err
	}
	after, err := json.Marshal(second)
	if err != nil {
		return Bundle{}, err
	}
	if !bytes.Equal(before, after) {
		return Bundle{}, errors.New("source changed during export; retry observation")
	}
	if err := validate(first, policy); err != nil {
		return Bundle{}, err
	}
	selected, err := selectAudit(first, records)
	if err != nil {
		return Bundle{}, err
	}
	auditBytes, err := json.Marshal(selected)
	if err != nil {
		return Bundle{}, err
	}
	reasons := []string{"approved-development-only", "live_authority_verification_required"}
	if first.SecurityApplied != nil {
		if first.Status != controlplane.StatusSecurityApplied || first.SecurityApplied.RollbackStatus != "rollback_unimplemented" || first.SecurityApplied.ReleaseClassification != "development_asset" {
			return Bundle{}, errors.New("unsupported security-applied disposition")
		}
		reasons = append(reasons, "development_asset", "rollback_unimplemented")
	} else if first.Status == controlplane.StatusSecurityApplied {
		return Bundle{}, errors.New("missing terminal evidence")
	} else {
		reasons = append(reasons, "source_state:"+string(first.Status))
	}
	identity := policy.AuthorityID + "\x00" + policy.TenantID + "\x00" + policy.SecurityDomainID + "\x00" + first.ID
	record := Record{
		Contract: "ProvisioningRecord", ContractVersion: ContractVersion,
		RecordID: "provisioning-" + Digest([]byte(identity))[7:], Revision: first.ResourceVersion,
		IssuedAt:    first.UpdatedAt.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.999999Z"),
		AuthorityID: policy.AuthorityID, TenantID: policy.TenantID, SecurityDomainID: policy.SecurityDomainID,
		CorrelationID: first.ID, Purpose: "candidate_evidence", AssetRef: first.AssetID, Cohort: "development",
		Source:    Source{SourceRepository, policy.SourceCommit, first.ID, string(first.Status), policy.ProfileRef, policy.PostureRef, policy.ReleaseRef},
		Readiness: Readiness{Reasons: reasons}, Evidence: Evidence{Reference(before), Reference(auditBytes)},
	}
	return Bundle{record, before, auditBytes}, nil
}
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func Reference(data []byte) EvidenceRef {
	digest := Digest(data)
	return EvidenceRef{"urn:kaiba:evidence:" + digest, digest}
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func validate(tx controlplane.Transaction, p Policy) error {
	if tx.SchemaVersion != controlplane.TransactionSchemaVersion || tx.ResourceVersion < 1 || tx.ResourceVersion > 9007199254740991 || tx.UpdatedAt.IsZero() {
		return errors.New("unsupported source schema or revision")
	}
	for _, id := range []string{tx.ID, tx.AssetID, p.AuthorityID, p.TenantID, p.SecurityDomainID} {
		if !idPattern.MatchString(id) {
			return errors.New("invalid identifier")
		}
	}
	if !commitPattern.MatchString(p.SourceCommit) || p.ProfileID == "" || p.ProfileID != tx.ProfileID || !digestPattern.MatchString(p.BundleDigest) || p.BundleDigest != tx.BundleDigest || !digestPattern.MatchString(p.PolicyDigest) || p.PolicyDigest != tx.PolicyDigest {
		return errors.New("source differs from pinned export policy")
	}
	if len(tx.Status) == 0 || len(tx.Status) > 200 {
		return errors.New("invalid source state")
	}
	for _, ref := range []EvidenceRef{p.ProfileRef, p.PostureRef, p.ReleaseRef} {
		u, err := url.Parse(ref.URI)
		if err != nil || u.Scheme == "" || u.User != nil || !digestPattern.MatchString(ref.Digest) {
			return errors.New("invalid policy evidence reference")
		}
	}
	return nil
}

// Only receipts already referenced by durable control state participate. Later
// audit appends cannot change an existing exported revision.
func selectAudit(tx controlplane.Transaction, records []auditlog.Record) ([]auditlog.Record, error) {
	required := map[string]bool{}
	add := func(id string) {
		if id != "" {
			required[id] = true
		}
	}
	if tx.Approval != nil {
		add(tx.Approval.AuditReceiptID)
	}
	for _, op := range tx.Operations {
		add(op.Approval.AuditReceiptID)
		add(op.IntentAuditReceiptID)
		add(op.EvidenceAuditReceiptID)
		add(op.ReconciliationAuditReceiptID)
	}
	if tx.SecurityApplied != nil {
		add(tx.SecurityApplied.AuditReceiptID)
	}
	if tx.Quarantine != nil {
		add(tx.Quarantine.AuditReceiptID)
	}
	if tx.Abort != nil {
		add(tx.Abort.AuditReceiptID)
	}
	selected := []auditlog.Record{}
	for _, r := range records {
		if err := auditlog.ValidateRetainedRecord(r); err != nil {
			return nil, err
		}
		id := Digest([]byte("kaiba-audit-receipt\x00" + r.EventHash))
		if wanted, exists := required[id]; exists {
			if !wanted || r.Event.TransactionID != tx.ID {
				return nil, errors.New("duplicate or mismatched audit evidence")
			}
			if tx.SecurityApplied != nil && id == tx.SecurityApplied.AuditReceiptID {
				s := tx.SecurityApplied
				if tx.Approval == nil || r.Event.Stage != "security_applied" || r.Event.Result != auditlog.ResultSucceeded || r.Event.OutputDigest != s.EvidenceDigest || r.Event.InputDigest != tx.Approval.PlanDigest || r.Event.FenceEpoch != tx.FenceEpoch {
					return nil, errors.New("terminal audit binding mismatch")
				}
			}
			selected = append(selected, r)
			required[id] = false
		}
	}
	for _, missing := range required {
		if missing {
			return nil, errors.New("required audit evidence missing")
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Sequence < selected[j].Sequence })
	return selected, nil
}

// DecodePolicy rejects ambiguous JSON using the source's strict decoder.
func DecodePolicy(data []byte) (Policy, error) {
	var p Policy
	err := controlplane.DecodeStrict(data, &p)
	return p, err
}

// Write errors include no retained authority evidence.
func (b Bundle) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(b.Record, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode fleet record: %w", err)
	}
	return append(data, '\n'), nil
}
