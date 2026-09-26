//go:build linux

package pilotenrollment

import (
	"context"
	"errors"
)

func (c *Client) saveRecoveryInstallation(r recoveryInstallState) error {
	if c.value.Recovery == nil {
		return ErrState
	}
	if e := checkStorage(c.store, c.value.Config, c.runtime); e != nil {
		return e
	}
	v := c.value
	parent := *v.Recovery
	parent.Installation = &r
	v.Recovery = &parent
	return c.save(v)
}
func (r recoveryInstallState) path() string {
	return "/api/v1/pilot/enrollments/" + r.Approval.Authorization.Instance + "/recoveries/" + r.Approval.Request.Operation
}
func (s state) recoveryPredecessor() state {
	s = s.renewalBase()
	if s.Renewal != nil && s.Renewal.Phase == "active" {
		s.Certificate = s.Renewal.Certificate
		s.Config.Binding = renewalProofBinding(*s.Renewal.Active)
	}
	return s
}
func (c *Client) recoveryInstallation(raw []byte, r recoveryInstallState) (recoveryInstallation, error) {
	var out recoveryInstallation
	if decode(raw, &out) != nil {
		return out, ErrInput
	}
	approved := out.Approval
	if approved.State != "proof_verified" || approved.Signature != r.Proof || !renewalInterval(r.Approval.Challenge.Issued, r.Approval.Challenge.Expires, renewalTime(approved.Verified)) {
		return out, ErrBinding
	}
	approved.State = "awaiting_proof"
	approved.Signature = ""
	approved.Verified = ""
	var old renewalBinding
	if !sameRenewal(approved, r.Approval) || out.Predecessor.ID != r.Approval.Authorization.Instance || out.Predecessor.Logical != r.Approval.Authorization.Logical || out.Predecessor.State != "active" || out.Predecessor.Certificate != c.value.recoveryPredecessor().Certificate || out.Predecessor.Intent != c.value.recoveryPredecessor().Config.Binding || decode(out.Predecessor.Binding, &old) != nil || !sameRenewal(old, r.Predecessor) {
		return out, ErrBinding
	}
	if e := r.validateStaged(c.value, out.Staged, out.Certificate, c.runtime.Now()); e != nil {
		return out, e
	}
	if r.Staged != nil && (!sameRenewal(*r.Staged, out.Staged) || r.Certificate != out.Certificate) {
		return out, ErrBinding
	}
	return out, nil
}

// InstallRecovery consumes a management-relayed public installation response.
// Certificate trust and the exact saved approval/key proof are checked locally.
// The device never tries to fetch this using its expired certificate.
func (c *Client) InstallRecovery(raw []byte) (Status, error) {
	parent := c.value.Recovery
	if parent == nil {
		return Status{}, ErrState
	}
	r := recoveryInstallState{PreparedAt: parent.Prepared, Approval: parent.Packet.Approval, Predecessor: parent.Packet.Predecessor, Proof: parent.Signature}
	if parent.Installation != nil {
		r = *parent.Installation
	}
	v, e := c.recoveryInstallation(raw, r)
	if e != nil {
		return Status{}, e
	}
	if parent.Installation != nil {
		return c.Status()
	}
	if v.State != "staged" || v.Challenge != nil || v.Signature != "" || v.Receipt != nil || v.Active != nil {
		return Status{}, ErrReconcile
	}
	r.Certificate = v.Certificate
	r.Staged = &v.Staged
	r.InstalledProcess = c.runtime.Process
	r.Phase = "installed"
	if e = c.saveRecoveryInstallation(r); e != nil {
		return Status{}, e
	}
	return c.Status()
}
func (c *Client) ProveRecoveryInstalled(ctx context.Context) (Status, error) {
	if c.value.Recovery == nil || c.value.Recovery.Installation == nil {
		return Status{}, ErrState
	}
	r := *c.value.Recovery.Installation
	if r.Phase == "proof_submitted" {
		return Status{}, ErrReconcile
	}
	if r.Phase == "verified" || r.Phase == "active" {
		return c.Status()
	}
	if r.Phase != "installed" {
		return Status{}, ErrState
	}
	if r.InstalledProcess == c.runtime.Process {
		return Status{}, ErrRestart
	}
	raw, e := c.requestCertificate(ctx, "POST", r.path()+"/install-challenge", []byte("{}"), "", r.Certificate)
	if e != nil {
		return Status{}, e
	}
	v, e := c.recoveryInstallation(raw, r)
	if e != nil {
		return Status{}, e
	}
	if v.State != "staged" || v.Challenge == nil || v.Signature != "" || v.Receipt != nil || v.Active != nil || r.validateChallenge(*v.Challenge, c.runtime.Now()) != nil {
		return Status{}, ErrBinding
	}
	r.Challenge = v.Challenge
	r.Signature, e = renewalSign(c.value, *v.Challenge)
	if e != nil {
		return Status{}, e
	}
	r.Phase = "proof_submitted"
	if e = c.saveRecoveryInstallation(r); e != nil {
		return Status{}, e
	}
	raw, e = c.requestCertificate(ctx, "POST", r.path()+"/installed-proof", canon(Proof{r.Signature}), "", r.Certificate)
	if e != nil {
		return Status{}, errors.Join(ErrReconcile, e)
	}
	return c.acceptRecoveryResult(ctx, raw)
}
func (c *Client) acceptRecoveryResult(ctx context.Context, raw []byte) (Status, error) {
	r := *c.value.Recovery.Installation
	v, e := c.recoveryInstallation(raw, r)
	if e != nil {
		return Status{}, e
	}
	if (v.State != "verified" && v.State != "active") || v.Challenge == nil || r.Challenge == nil || *v.Challenge != *r.Challenge || v.Signature != r.Signature || v.Receipt == nil || r.validateReceipt(c.value, *v.Receipt, c.runtime.Now()) != nil {
		return Status{}, ErrBinding
	}
	r.Receipt = v.Receipt
	r.Phase = "verified"
	if v.State == "active" {
		if v.Active == nil || r.validateActive(*v.Active, c.runtime.Now()) != nil {
			return Status{}, ErrBinding
		}
		// Historical protocol state alone cannot switch local relying credentials.
		selfRaw, err := c.requestCertificate(ctx, "GET", "/api/v1/pilot/self", nil, "", r.Certificate)
		if err != nil {
			return Status{}, errors.Join(ErrReconcile, err)
		}
		var self renewalSelf
		var binding renewalBinding
		if decode(selfRaw, &self) != nil || self.Full || self.Authorized != "pilot" || self.Instance != r.Approval.Authorization.Instance || decode(self.Binding, &binding) != nil || !sameRenewal(binding, *v.Active) {
			return Status{}, ErrBinding
		}
		r.Active = v.Active
		r.Phase = "active"
	} else if v.Active != nil {
		return Status{}, ErrBinding
	}
	if e = c.saveRecoveryInstallation(r); e != nil {
		return Status{}, e
	}
	return c.Status()
}
func (c *Client) ReconcileRecovery(ctx context.Context) (Status, error) {
	if c.value.RecoveryRenewalStart != nil {
		return Status{}, ErrReconcile
	}
	if c.value.Recovery == nil || c.value.Recovery.Installation == nil || c.value.Recovery.Installation.Challenge == nil {
		return Status{}, ErrState
	}
	r := *c.value.Recovery.Installation
	raw, e := c.requestCertificate(ctx, "GET", r.path()+"/installation", nil, "", r.Certificate)
	if e != nil {
		return Status{}, e
	}
	return c.acceptRecoveryResult(ctx, raw)
}

// RetryRecoveryInstalled explicitly reuses only the retained installation proof.
// A fresh authenticated read must confirm the exact pending challenge first.
func (c *Client) RetryRecoveryInstalled(ctx context.Context) (Status, error) {
	if c.value.Recovery == nil || c.value.Recovery.Installation == nil || c.value.Recovery.Installation.Phase != "proof_submitted" {
		return Status{}, ErrState
	}
	r := *c.value.Recovery.Installation
	raw, e := c.requestCertificate(ctx, "GET", r.path()+"/installation", nil, "", r.Certificate)
	if e != nil {
		return Status{}, e
	}
	v, e := c.recoveryInstallation(raw, r)
	if e != nil {
		return Status{}, e
	}
	if v.State == "verified" || v.State == "active" {
		return c.acceptRecoveryResult(ctx, raw)
	}
	if v.State != "staged" || v.Challenge == nil || r.Challenge == nil || *v.Challenge != *r.Challenge || v.Receipt != nil || v.Signature != "" || v.Active != nil || r.validateChallenge(*v.Challenge, c.runtime.Now()) != nil {
		return Status{}, ErrReconcile
	}
	raw, e = c.requestCertificate(ctx, "POST", r.path()+"/installed-proof", canon(Proof{r.Signature}), "", r.Certificate)
	if e != nil {
		return Status{}, errors.Join(ErrReconcile, e)
	}
	return c.acceptRecoveryResult(ctx, raw)
}
