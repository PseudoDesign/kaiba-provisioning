package pilotenrollment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	wire "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
	"slices"
	"time"
)

func renewalRef(v any, m renewalMetadata) RecordRef {
	return RecordRef{m.ID, m.Revision, wire.Digest(canon(v))}
}
func renewalTime(s string) time.Time { v, _ := time.Parse(time.RFC3339Nano, s); return v }
func renewalInterval(from, to string, at time.Time) bool {
	a, b := renewalTime(from), renewalTime(to)
	return !a.IsZero() && !b.IsZero() && !at.Before(a) && at.Before(b)
}
func sameRenewal(a, b any) bool { return bytes.Equal(canon(a), canon(b)) }
func renewalMetadataValid(m renewalMetadata, kind, version string) bool {
	return m.Contract == kind && m.Version == version && contractID.MatchString(m.ID) && m.Revision > 0 && m.Revision <= 9007199254740991 && !renewalTime(m.Issued).IsZero() && contractID.MatchString(m.Authority) && contractID.MatchString(m.Tenant) && contractID.MatchString(m.Domain) && contractID.MatchString(m.Correlation)
}
func renewalSign(s state, ch any) (string, error) {
	k, e := privateKey(s.Key)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(canon(ch))
	b, e := ecdsa.SignASN1(rand.Reader, k, h[:])
	return base64.StdEncoding.EncodeToString(b), e
}
func renewalVerify(s state, ch any, signature string) bool {
	k, e := privateKey(s.Key)
	if e != nil {
		return false
	}
	sig, e := base64.StdEncoding.DecodeString(signature)
	if e != nil || len(sig) > 128 || base64.StdEncoding.EncodeToString(sig) != signature {
		return false
	}
	h := sha256.Sum256(canon(ch))
	return ecdsa.VerifyASN1(&k.PublicKey, h[:], sig)
}
func renewalChallengeWindow(nonce, issued, expires string, at time.Time) bool {
	return len(nonce) == 48 && wire.Hex.MatchString(nonce+"0000000000000000") && renewalInterval(issued, expires, at) && renewalTime(expires).Sub(renewalTime(issued)) <= 5*time.Minute
}
func validateRenewalApproval(s state, p renewalBinding, v renewalApproval, at time.Time) error {
	revision := uint64(1)
	version := "0.2.0-draft.1"
	if len(s.History) > 0 {
		prior := s.History[len(s.History)-1]
		if prior.Phase != "active" || prior.Active == nil || !sameRenewal(*prior.Active, p) || renewalTime(prior.Active.Issued).After(at) {
			return ErrBinding
		}
		revision = prior.Active.CredentialRevision
		if revision < 2 || revision >= 9007199254740991 {
			return ErrBinding
		}
		version = "0.3.0-draft.1"
	} else if p.CredentialRevision != 0 || p.CertificateDigest != "" || p.RenewalRef != nil || p.PredecessorRef != nil || p.InstallationRef != nil {
		return ErrBinding
	}
	s = s.renewalBase()

	status, e := s.status()
	if e != nil {
		return e
	}
	leaf, e := s.leaf(at)
	if e != nil {
		return e
	}
	b := s.Config.Binding
	a := v.Authorization
	ch := v.Challenge
	req := v.Request
	if !renewalMetadataValid(p.renewalMetadata, "PilotDeviceBinding", version) || p.State != "active" || p.Full || p.Logical != status.Logical || p.Instance != status.Enrollment || p.Storage != 1 || p.Target != b.Target || p.Adoption != b.Adoption || p.Policy != b.Policy || p.Admission != b.Decision || p.Audience != b.Audience || p.Profile != b.Profile || p.Activation == nil {
		return ErrBinding
	}
	expected := credential{"management", "pilot_management", 1, status.SPKIDigest, b.Issuer, leaf.SerialNumber.Text(16), leaf.NotBefore.UTC().Format(time.RFC3339Nano), leaf.NotAfter.UTC().Format(time.RFC3339Nano)}
	if p.Credential != expected || !slices.Equal(p.Permissions, []string{"pilot:self:read", "pilot:diagnostic-reference:submit"}) {
		return ErrBinding
	}
	if !renewalMetadataValid(a.renewalMetadata, "PilotRenewalAuthorization", "0.3.0-draft.1") || a.Authority != p.Authority || a.Tenant != p.Tenant || a.Domain != p.Domain || a.Full || a.Mode != "same_key_unexpired" || !wire.ID.MatchString(a.Operation) || a.Correlation != a.Operation || a.Logical != p.Logical || a.Instance != p.Instance || a.Storage != p.Storage || a.Target != p.Target || a.Audience != p.Audience || a.Profile != p.Profile || !slices.Equal(a.Permissions, p.Permissions) || a.Previous != revision || a.Next != revision+1 || a.Slot != p.Credential.Slot || a.Generation != p.Credential.Generation || a.SPKI != p.Credential.SPKI || a.Issuer != p.Credential.Issuer || a.Predecessor != renewalRef(p, p.renewalMetadata) || a.Certificate != CertificateDigest(s.Certificate) {
		return ErrBinding
	}
	if a.Issued != a.From || !renewalInterval(a.From, a.Expires, at) || renewalTime(a.Expires).Sub(renewalTime(a.From)) > 7*24*time.Hour || req.Operation != a.Operation || req.Predecessor != a.Predecessor || req.Certificate != a.Certificate || req.Expires != a.Expires || req.Records.Adoption.Ref != a.Adoption || req.Records.Policy.Ref != a.Policy || req.Records.Decision.Ref != a.Admission {
		return ErrBinding
	}
	for _, sel := range []renewalSelection{req.Records.Adoption, req.Records.Policy, req.Records.Decision} {
		if !wire.ID.MatchString(sel.Handle) || !validRef(sel.Ref) {
			return ErrBinding
		}
	}
	if ch.Schema != "kaiba.pilot-renewal-key-proof/v1alpha1" || ch.Purpose != "pilot_renewal_key_possession" || ch.Operation != a.Operation || ch.Enrollment != p.Instance || ch.Authorization != renewalRef(a, a.renewalMetadata) || ch.Certificate != a.Certificate || !renewalChallengeWindow(ch.Nonce, ch.Issued, ch.Expires, at) || renewalTime(ch.Issued).Before(renewalTime(a.From)) || renewalTime(ch.Expires).After(renewalTime(a.Expires)) || renewalTime(ch.Expires).After(leaf.NotAfter) {
		return ErrBinding
	}
	return nil
}
func (r renewalState) validateStaged(s state, b renewalBinding, cert string, at time.Time) error {
	v := s
	v.Certificate = cert
	leaf, e := v.leaf(at)
	if e != nil {
		return e
	}
	a := r.Approval.Authorization
	before := renewalTime(a.From).Truncate(time.Second)
	if before.Before(renewalTime(a.From)) {
		before = before.Add(time.Second)
	}
	after := renewalTime(a.Expires).Truncate(time.Second)
	if !leaf.NotBefore.Equal(before) || !leaf.NotAfter.Equal(after) || leaf.SerialNumber.Text(16) == r.Predecessor.Credential.Serial || CertificateDigest(cert) == a.Certificate {
		return ErrBinding
	}
	if !renewalMetadataValid(b.renewalMetadata, "PilotDeviceBinding", "0.3.0-draft.1") || b.ID == r.Predecessor.ID || b.Revision != 1 || b.Authority != a.Authority || b.Tenant != a.Tenant || b.Domain != a.Domain || b.Correlation != a.Operation || renewalTime(b.Issued).Before(renewalTime(a.Issued)) || renewalTime(b.Issued).After(at) {
		return ErrBinding
	}
	expected := r.Predecessor
	expected.renewalMetadata = b.renewalMetadata
	expected.State = "staged"
	expected.Activation = nil
	expected.InstallationRef = nil
	expected.Credential.Serial = leaf.SerialNumber.Text(16)
	expected.Credential.Before = leaf.NotBefore.UTC().Format(time.RFC3339Nano)
	expected.Credential.After = leaf.NotAfter.UTC().Format(time.RFC3339Nano)
	expected.Adoption = a.Adoption
	expected.Policy = a.Policy
	expected.Admission = a.Admission
	expected.CredentialRevision = a.Next
	expected.CertificateDigest = CertificateDigest(cert)
	ref := renewalRef(a, a.renewalMetadata)
	expected.RenewalRef = &ref
	pre := a.Predecessor
	expected.PredecessorRef = &pre
	if !sameRenewal(expected, b) {
		return ErrBinding
	}
	return nil
}
func (r renewalState) validateChallenge(ch renewalInstallChallenge, at time.Time) error {
	if r.Staged == nil {
		return ErrState
	}
	a := r.Approval.Authorization
	b := r.Staged
	if ch.Purpose != "pilot_renewal_installed_key" || ch.Restart != "client_process" || ch.Operation != a.Operation || ch.Authorization != renewalRef(a, a.renewalMetadata) || ch.Predecessor != a.Predecessor || ch.Staged != renewalRef(*b, b.renewalMetadata) || ch.Certificate != b.CertificateDigest || ch.Tenant != a.Tenant || ch.Domain != a.Domain || !renewalChallengeWindow(ch.Nonce, ch.Issued, ch.Expires, at) || renewalTime(ch.Issued).Before(renewalTime(b.Issued)) || renewalTime(ch.Expires).After(renewalTime(b.Credential.After)) || renewalTime(ch.Expires).After(renewalTime(r.Predecessor.Credential.After)) {
		return ErrBinding
	}
	return nil
}
func (r renewalState) validateReceipt(s state, receipt renewalInstallReceipt, at time.Time) error {
	if r.Challenge == nil || r.Staged == nil {
		return ErrState
	}
	ch := r.Challenge
	proof := struct {
		Challenge *renewalInstallChallenge `json:"challenge"`
		Signature string                   `json:"signature"`
	}{ch, r.Signature}
	expectedRef := Ref{"urn:kaiba:evidence:" + wire.Digest(canon(proof)), wire.Digest(canon(proof))}
	verified := renewalTime(receipt.Verified)
	if !renewalMetadataValid(receipt.renewalMetadata, "PilotRenewalInstallationReceipt", "0.3.0-draft.1") || receipt.Authority != r.Staged.Authority || receipt.Tenant != ch.Tenant || receipt.Domain != ch.Domain || receipt.Correlation != ch.Operation || receipt.Revision != 1 || receipt.Full || receipt.renewalInstallFields != ch.renewalInstallFields || receipt.Proof != expectedRef || verified.After(at) || renewalTime(receipt.renewalMetadata.Issued).Before(verified) || renewalTime(receipt.renewalMetadata.Issued).After(at) || r.validateChallenge(*ch, verified) != nil || !renewalVerify(s, *ch, r.Signature) {
		return ErrBinding
	}
	return nil
}
func (r renewalState) validateActive(b renewalBinding, at time.Time) error {
	if r.Receipt == nil || r.Staged == nil || b.Activation == nil {
		return ErrState
	}
	expected := *r.Staged
	expected.State = "active"
	expected.Revision++
	expected.Issued = b.Issued
	expected.Activation = b.Activation
	ref := renewalRef(*r.Receipt, r.Receipt.renewalMetadata)
	expected.InstallationRef = &ref
	act := b.Activation
	verified := renewalTime(r.Receipt.Verified)
	if !sameRenewal(expected, b) || act.Restart != "client_process" || act.Policy != b.Policy || act.Receipt.Digest != ref.Digest || act.Receipt.URI != "urn:kaiba:evidence:"+ref.Digest || renewalTime(act.At).Before(verified) || renewalTime(act.At).Sub(verified) > 5*time.Minute || renewalTime(b.Issued).Before(renewalTime(act.At)) || renewalTime(b.Issued).Before(renewalTime(r.Receipt.renewalMetadata.Issued)) || !renewalInterval(r.Predecessor.Credential.Before, r.Predecessor.Credential.After, renewalTime(act.At)) || !renewalInterval(b.Credential.Before, b.Credential.After, renewalTime(act.At)) || renewalTime(b.Issued).After(at) {
		return ErrBinding
	}
	return nil
}
func (r renewalState) validate(s state) error {
	if validateRenewalApproval(s, r.Predecessor, r.Approval, renewalTime(r.PreparedAt)) != nil || r.Approval.State != "awaiting_proof" || r.Approval.Signature != "" || r.Approval.Verified != "" || !renewalVerify(s, r.Approval.Challenge, r.Proof) {
		return ErrState
	}
	switch r.Phase {
	case "prepared", "approved":
		if r.Certificate != "" || r.Staged != nil || r.InstalledProcess != "" || r.Challenge != nil || r.Signature != "" || r.Receipt != nil || r.Active != nil {
			return ErrState
		}
		return nil
	case "installed", "proof_submitted", "verified", "active":
	default:
		return ErrState
	}
	if r.Staged == nil || r.InstalledProcess == "" || r.validateStaged(s, *r.Staged, r.Certificate, renewalTime(r.Staged.Issued)) != nil {
		return ErrState
	}
	if r.Phase == "installed" {
		if r.Challenge != nil || r.Signature != "" || r.Receipt != nil || r.Active != nil {
			return ErrState
		}
		return nil
	}
	if r.Challenge == nil || r.validateChallenge(*r.Challenge, renewalTime(r.Challenge.Issued)) != nil || !renewalVerify(s, *r.Challenge, r.Signature) {
		return ErrState
	}
	if r.Phase == "proof_submitted" {
		if r.Receipt != nil || r.Active != nil {
			return ErrState
		}
		return nil
	}
	if r.Receipt == nil || r.validateReceipt(s, *r.Receipt, renewalTime(r.Receipt.renewalMetadata.Issued)) != nil {
		return ErrState
	}
	if r.Phase == "verified" {
		if r.Active != nil {
			return ErrState
		}
		return nil
	}
	if r.Active == nil || r.validateActive(*r.Active, renewalTime(r.Active.Issued)) != nil {
		return ErrState
	}
	return nil
}

// Project the exact predecessor for the current operation without rewriting the
// original enrollment, configuration or proofs in protected storage.
func (s state) renewalBase() state {
	if len(s.History) > 0 {
		last := s.History[len(s.History)-1]
		s.Certificate = last.Certificate
		if last.Active != nil {
			s.Config.Binding = renewalProofBinding(*last.Active)
		}
	}
	return s
}
func renewalProofBinding(b renewalBinding) ProofBinding {
	return ProofBinding{b.Target, b.Adoption, b.Policy, b.Admission, b.Audience, b.Profile, b.Credential.Issuer}
}
