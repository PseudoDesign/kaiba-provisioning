//go:build linux

package pilotenrollment

import (
	wire "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
	"slices"
	"time"
)

type recoveryRequest struct {
	renewalRequest
	Review Ref `json:"review_ref"`
}
type recoveryAuthorization struct {
	renewalAuthorization
	Approver string `json:"approver_id"`
	Review   Ref    `json:"review_ref"`
	Deadline string `json:"predecessor_access_expires_at"`
}
type recoveryChallenge struct {
	renewalMetadata
	Purpose       string    `json:"purpose"`
	Operation     string    `json:"operation_id"`
	Instance      string    `json:"instance_id"`
	Authorization RecordRef `json:"authorization_ref"`
	Predecessor   RecordRef `json:"predecessor_binding_ref"`
	Certificate   string    `json:"predecessor_certificate_digest"`
	SPKI          string    `json:"spki_digest"`
	Nonce         string    `json:"nonce"`
	Expires       string    `json:"expires_at"`
}
type recoveryApproval struct {
	Request       recoveryRequest       `json:"request"`
	Authorization recoveryAuthorization `json:"authorization"`
	Challenge     recoveryChallenge     `json:"challenge"`
	State         string                `json:"state"`
	Signature     string                `json:"signature,omitempty"`
	Verified      string                `json:"verified_at,omitempty"`
}

// This public packet must be supplied through the reviewed management relay.
// The independently supplied digest pins the complete selection, including its
// authority, review, fresh records, predecessor and challenge. It is not a
// signature by the authority, nor a replacement for server authorization.
type recoveryPacket struct {
	Schema      string           `json:"schema_version"`
	Predecessor renewalBinding   `json:"predecessor"`
	Approval    recoveryApproval `json:"approval"`
}
type recoveryState struct {
	Installation *recoveryInstallState `json:"installation,omitempty"`
	Packet       recoveryPacket        `json:"packet"`
	Digest       string                `json:"reviewed_digest"`
	Prepared     string                `json:"prepared_at"`
	Signature    string                `json:"signature"`
}
type RecoveryStatus struct {
	Operation string `json:"operation_id"`
	Phase     string `json:"phase"`
}

// PrepareRecovery performs no network I/O. Only the saved proof is returned for
// a management-authenticated relay. Persist before output; an exact repeat
// returns the identical proof, even after challenge expiry. Never re-sign it.
func (c *Client) PrepareRecovery(raw []byte, reviewedDigest string) (Proof, error) {
	var packet recoveryPacket
	if len(raw) > 1048576 || decode(raw, &packet) != nil || reviewedDigest != wire.Digest(canon(packet)) {
		return Proof{}, ErrInput
	}
	if e := checkStorage(c.store, c.value.Config, c.runtime); e != nil {
		return Proof{}, e
	}
	if r := c.value.Recovery; r != nil {
		if r.Digest != reviewedDigest || !sameRenewal(r.Packet, packet) {
			return Proof{}, ErrReconcile
		}
		return Proof{r.Signature}, nil
	}
	now := c.runtime.Now()
	if e := validateRecovery(c.value, packet, now); e != nil {
		return Proof{}, e
	}
	signature, e := renewalSign(c.value, packet.Approval.Challenge)
	if e != nil {
		return Proof{}, e
	}
	v := c.value
	v.Recovery = &recoveryState{Packet: packet, Digest: reviewedDigest, Prepared: now.UTC().Format(time.RFC3339Nano), Signature: signature}
	if e = checkStorage(c.store, c.value.Config, c.runtime); e != nil {
		return Proof{}, e
	}
	if e = c.save(v); e != nil {
		return Proof{}, e
	}
	return Proof{signature}, nil
}
func (r recoveryState) validate(s state) error {
	if r.Digest != wire.Digest(canon(r.Packet)) || validateRecovery(s, r.Packet, renewalTime(r.Prepared)) != nil || !renewalVerify(s, r.Packet.Approval.Challenge, r.Signature) {
		return ErrState
	}
	if r.Installation != nil {
		return r.Installation.validate(s)
	}
	return nil
}
func validateRecovery(s state, packet recoveryPacket, at time.Time) error {
	if s.Phase != "verified" || packet.Schema != "kaiba.pilot-recovery-packet/v1alpha1" {
		return ErrState
	}
	p, v := packet.Predecessor, packet.Approval
	a, ch, req := v.Authorization, v.Challenge, v.Request
	if v.State != "awaiting_proof" || v.Signature != "" || v.Verified != "" {
		return ErrInput
	}
	revision := uint64(1)
	version := "0.2.0-draft.1"
	// Retain all renewal records unchanged. A pending renewal cannot be bypassed.
	if s.Renewal != nil {
		r := s.Renewal
		if r.Phase != "active" || r.Active == nil || !sameRenewal(*r.Active, p) {
			return ErrReconcile
		}
		revision = r.Active.CredentialRevision
		version = "0.3.0-draft.1"
		s.Certificate = r.Certificate
		s.Config.Binding = renewalProofBinding(*r.Active)
	} else if len(s.History) != 0 || p.CredentialRevision != 0 || p.CertificateDigest != "" || p.RenewalRef != nil || p.PredecessorRef != nil || p.InstallationRef != nil {
		return ErrBinding
	}
	if revision == 0 || revision >= 9007199254740991 {
		return ErrBinding
	}
	for _, prior := range s.History {
		if prior.Approval.Request.Operation == req.Operation {
			return ErrBinding
		}
	}
	if s.Renewal != nil && s.Renewal.Approval.Request.Operation == req.Operation {
		return ErrBinding
	}
	status, e := s.status()
	if e != nil {
		return e
	}
	leaf, e := certificate(s.Certificate)
	if e != nil {
		return e
	}
	// Validate the retained certificate and key at issuance only for historical
	// binding comparison. No request or TLS verification uses this timestamp.
	if _, e = s.leaf(leaf.NotBefore); e != nil {
		return e
	}
	b := s.Config.Binding
	if !renewalMetadataValid(p.renewalMetadata, "PilotDeviceBinding", version) || renewalTime(p.Issued).After(at) || p.State != "active" || p.Full || p.Logical != status.Logical || p.Instance != status.Enrollment || p.Storage != 1 || p.Target != b.Target || p.Adoption != b.Adoption || p.Policy != b.Policy || p.Admission != b.Decision || p.Audience != b.Audience || p.Profile != b.Profile || p.Activation == nil {
		return ErrBinding
	}
	expected := credential{"management", "pilot_management", 1, status.SPKIDigest, b.Issuer, leaf.SerialNumber.Text(16), leaf.NotBefore.UTC().Format(time.RFC3339Nano), leaf.NotAfter.UTC().Format(time.RFC3339Nano)}
	if p.Credential != expected || !slices.Equal(p.Permissions, []string{"pilot:self:read", "pilot:diagnostic-reference:submit"}) {
		return ErrBinding
	}
	deadline := renewalTime(a.Deadline)
	if deadline.IsZero() || !deadline.After(leaf.NotBefore) || deadline.After(leaf.NotAfter) || at.Before(deadline) {
		return ErrBinding
	}
	if !renewalMetadataValid(a.renewalMetadata, "PilotRecoveryAuthorization", "0.4.0-draft.1") || a.Authority != p.Authority || a.Tenant != p.Tenant || a.Domain != p.Domain || a.Full || a.Mode != "supervised_same_key_expired" || !wire.ID.MatchString(a.Operation) || a.Correlation != a.Operation || !contractID.MatchString(a.Approver) || (!absoluteURI(a.Review.URI) || !validDigest(a.Review.Digest)) || req.Review != a.Review || a.Logical != p.Logical || a.Instance != p.Instance || a.Storage != p.Storage || a.Target != p.Target || a.Audience != p.Audience || a.Profile != p.Profile || !slices.Equal(a.Permissions, p.Permissions) || a.Previous != revision || a.Next != revision+1 || a.Slot != p.Credential.Slot || a.Generation != p.Credential.Generation || a.SPKI != p.Credential.SPKI || a.Issuer != p.Credential.Issuer || a.Predecessor != renewalRef(p, p.renewalMetadata) || a.Certificate != CertificateDigest(s.Certificate) {
		return ErrBinding
	}
	if a.Issued != a.From || !renewalInterval(a.From, a.Expires, at) || renewalTime(a.From).Before(deadline) || renewalTime(a.Expires).Sub(renewalTime(a.From)) > 7*24*time.Hour || req.Operation != a.Operation || req.Predecessor != a.Predecessor || req.Certificate != a.Certificate || req.Expires != a.Expires || req.Records.Adoption.Ref != a.Adoption || req.Records.Policy.Ref != a.Policy || req.Records.Decision.Ref != a.Admission {
		return ErrBinding
	}
	for _, sel := range []renewalSelection{req.Records.Adoption, req.Records.Policy, req.Records.Decision} {
		if !wire.ID.MatchString(sel.Handle) || !validRef(sel.Ref) {
			return ErrBinding
		}
	}
	if !renewalMetadataValid(ch.renewalMetadata, "PilotRecoveryKeyChallenge", "0.4.0-draft.1") || ch.Authority != a.Authority || ch.Tenant != a.Tenant || ch.Domain != a.Domain || ch.Correlation != a.Operation || ch.Purpose != "pilot_expired_recovery_key_possession" || ch.Operation != a.Operation || ch.Instance != a.Instance || ch.Authorization != renewalRef(a, a.renewalMetadata) || ch.Predecessor != a.Predecessor || ch.Certificate != a.Certificate || ch.SPKI != a.SPKI || !renewalChallengeWindow(ch.Nonce, ch.Issued, ch.Expires, at) || renewalTime(ch.Issued).Before(renewalTime(a.From)) || renewalTime(ch.Expires).After(renewalTime(a.Expires)) {
		return ErrBinding
	}
	return nil
}
