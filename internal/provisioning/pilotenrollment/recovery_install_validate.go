package pilotenrollment

import (
	wire "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
	"time"
)

func (r recoveryInstallState) validateStaged(s state, b renewalBinding, cert string, at time.Time) error {
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
	if !renewalMetadataValid(b.renewalMetadata, "PilotDeviceBinding", "0.4.0-draft.1") || b.ID == r.Predecessor.ID || b.Revision != 1 || b.Authority != a.Authority || b.Tenant != a.Tenant || b.Domain != a.Domain || b.Correlation != a.Operation || renewalTime(b.Issued).Before(renewalTime(a.Issued)) || renewalTime(b.Issued).After(at) {
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
	expected.RenewalRef = nil
	expected.RecoveryRef = &ref
	pre := a.Predecessor
	expected.PredecessorRef = &pre
	if !sameRenewal(expected, b) {
		return ErrBinding
	}
	return nil
}
func (r recoveryInstallState) validateChallenge(ch renewalInstallChallenge, at time.Time) error {
	if r.Staged == nil {
		return ErrState
	}
	a := r.Approval.Authorization
	b := r.Staged
	if ch.Purpose != "pilot_expired_recovery_installed_key" || ch.Restart != "client_process" || ch.Operation != a.Operation || ch.Authorization != renewalRef(a, a.renewalMetadata) || ch.Predecessor != a.Predecessor || ch.Staged != renewalRef(*b, b.renewalMetadata) || ch.Certificate != b.CertificateDigest || ch.Tenant != a.Tenant || ch.Domain != a.Domain || !renewalChallengeWindow(ch.Nonce, ch.Issued, ch.Expires, at) || renewalTime(ch.Issued).Before(renewalTime(b.Issued)) || renewalTime(ch.Expires).After(renewalTime(b.Credential.After)) || renewalTime(ch.Expires).After(renewalTime(a.Expires)) {
		return ErrBinding
	}
	return nil
}
func (r recoveryInstallState) validateReceipt(s state, receipt renewalInstallReceipt, at time.Time) error {
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
	if !renewalMetadataValid(receipt.renewalMetadata, "PilotRecoveryInstallationReceipt", "0.4.0-draft.1") || receipt.Authority != r.Staged.Authority || receipt.Tenant != ch.Tenant || receipt.Domain != ch.Domain || receipt.Correlation != ch.Operation || receipt.Revision != 1 || receipt.Full || receipt.renewalInstallFields != ch.renewalInstallFields || receipt.Proof != expectedRef || verified.After(at) || renewalTime(receipt.renewalMetadata.Issued).Before(verified) || renewalTime(receipt.renewalMetadata.Issued).After(at) || r.validateChallenge(*ch, verified) != nil || !renewalVerify(s, *ch, r.Signature) {
		return ErrBinding
	}
	return nil
}
func (r recoveryInstallState) validateActive(b renewalBinding, at time.Time) error {
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
	if !sameRenewal(expected, b) || act.Restart != "client_process" || act.Policy != b.Policy || act.Receipt.Digest != ref.Digest || act.Receipt.URI != "urn:kaiba:evidence:"+ref.Digest || renewalTime(act.At).Before(verified) || renewalTime(act.At).Sub(verified) > 5*time.Minute || renewalTime(b.Issued).Before(renewalTime(act.At)) || renewalTime(b.Issued).Before(renewalTime(r.Receipt.renewalMetadata.Issued)) || !renewalInterval(b.Credential.Before, b.Credential.After, renewalTime(act.At)) || renewalTime(b.Issued).After(at) {
		return ErrBinding
	}
	return nil
}
func (r recoveryInstallState) validate(s state) error {
	parent := s.Recovery
	if parent == nil || !sameRenewal(r.Approval, parent.Packet.Approval) || !sameRenewal(r.Predecessor, parent.Packet.Predecessor) || r.Proof != parent.Signature || r.PreparedAt != parent.Prepared {
		return ErrState
	}
	switch r.Phase {
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
