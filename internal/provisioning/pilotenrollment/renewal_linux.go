//go:build linux

package pilotenrollment

import (
	"context"
	"errors"
	"time"
)

func (c *Client) saveRenewal(r renewalState) error {
	if e := checkStorage(c.store, c.value.Config, c.runtime); e != nil {
		return e
	}
	v := c.value
	v.Renewal = &r
	return c.save(v)
}
func (r renewalState) path() string {
	return "/api/v1/pilot/enrollments/" + r.Approval.Authorization.Instance + "/renewals/" + r.Approval.Request.Operation
}

// PrepareRenewal validates reviewed approval against an authenticated current
// binding, persists one signature, then sends it. A lost reply never re-signs.
func (c *Client) PrepareRenewal(ctx context.Context, raw []byte) (Status, error) {
	if c.value.Recovery != nil {
		return Status{}, ErrReconcile
	}
	var approval renewalApproval
	if decode(raw, &approval) != nil || approval.State != "awaiting_proof" || approval.Signature != "" || approval.Verified != "" {
		return Status{}, ErrInput
	}
	next := c.value
	for _, prior := range next.History {
		if prior.Approval.Request.Operation == approval.Request.Operation {
			return Status{}, ErrBinding
		}
	}
	if next.Renewal != nil {
		if sameRenewal(next.Renewal.Approval, approval) {
			if next.Renewal.Phase == "prepared" {
				return Status{}, ErrReconcile
			}
			return c.Status()
		}
		if next.Renewal.Phase != "active" || next.Renewal.Approval.Request.Operation == approval.Request.Operation || len(next.History) >= 127 {
			return Status{}, ErrBinding
		}
		next.History = append(append([]renewalState(nil), next.History...), *next.Renewal)
		next.Renewal = nil
	}
	if c.value.Phase != "verified" {
		return Status{}, ErrState
	}
	raw, e := c.request(ctx, "GET", "/api/v1/pilot/self", nil)
	if e != nil {
		return Status{}, e
	}
	var self renewalSelf
	var predecessor renewalBinding
	if decode(raw, &self) != nil || self.Authorized != "pilot" || self.Full || self.Instance != c.value.Bootstrap.Enrollment || decode(self.Binding, &predecessor) != nil {
		return Status{}, ErrBinding
	}
	now := c.runtime.Now()
	if e = validateRenewalApproval(next, predecessor, approval, now); e != nil {
		return Status{}, e
	}
	proof, e := renewalSign(c.value, approval.Challenge)
	if e != nil {
		return Status{}, e
	}
	r := renewalState{Phase: "prepared", PreparedAt: now.UTC().Format(time.RFC3339Nano), Approval: approval, Predecessor: predecessor, Proof: proof}
	next.Renewal = &r
	if e = checkStorage(c.store, c.value.Config, c.runtime); e != nil {
		return Status{}, e
	}
	if e = c.save(next); e != nil {
		return Status{}, e
	}
	return c.sendRenewalProof(ctx)
}
func (c *Client) sendRenewalProof(ctx context.Context) (Status, error) {
	r := *c.value.Renewal
	raw, e := c.request(ctx, "POST", r.path()+"/proof", canon(Proof{r.Proof}))
	if e != nil {
		return Status{}, errors.Join(ErrReconcile, e)
	}
	var approved renewalApproval
	if decode(raw, &approved) != nil || approved.State != "proof_verified" || approved.Signature != r.Proof || !renewalInterval(r.Approval.Challenge.Issued, r.Approval.Challenge.Expires, renewalTime(approved.Verified)) || renewalTime(approved.Verified).After(c.runtime.Now()) {
		return Status{}, ErrBinding
	}
	normalized := approved
	normalized.State = "awaiting_proof"
	normalized.Signature = ""
	normalized.Verified = ""
	if !sameRenewal(normalized, r.Approval) {
		return Status{}, ErrBinding
	}
	r.Phase = "approved"
	if e = c.saveRenewal(r); e != nil {
		return Status{}, e
	}
	return c.Status()
}
func (c *Client) RetryRenewalProof(ctx context.Context) (Status, error) {
	if c.value.Renewal == nil || c.value.Renewal.Phase != "prepared" {
		return Status{}, ErrState
	}
	return c.sendRenewalProof(ctx)
}
func (c *Client) installation(raw []byte, r renewalState) (renewalInstallation, error) {
	var out renewalInstallation
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
	if !sameRenewal(approved, r.Approval) || out.Predecessor.ID != r.Approval.Authorization.Instance || out.Predecessor.Logical != r.Approval.Authorization.Logical || out.Predecessor.State != "active" || out.Predecessor.Certificate != c.value.renewalBase().Certificate || out.Predecessor.Intent != c.value.renewalBase().Config.Binding || decode(out.Predecessor.Binding, &old) != nil || !sameRenewal(old, r.Predecessor) {
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
func (c *Client) InstallRenewal(ctx context.Context) (Status, error) {
	if c.value.Renewal == nil {
		return Status{}, ErrState
	}
	r := *c.value.Renewal
	if r.Phase != "approved" {
		if r.Staged != nil {
			return c.Status()
		}
		return Status{}, ErrState
	}
	raw, e := c.request(ctx, "GET", r.path()+"/installation", nil)
	if e != nil {
		return Status{}, e
	}
	v, e := c.installation(raw, r)
	if e != nil {
		return Status{}, e
	}
	if v.State != "staged" || v.Challenge != nil || v.Signature != "" || v.Receipt != nil || v.Active != nil {
		return Status{}, ErrReconcile
	}
	r.Certificate = v.Certificate
	r.Staged = &v.Staged
	r.InstalledProcess = c.runtime.Process
	r.Phase = "installed"
	if e = c.saveRenewal(r); e != nil {
		return Status{}, e
	}
	return c.Status()
}
func (c *Client) ProveRenewalInstalled(ctx context.Context) (Status, error) {
	if c.value.Renewal == nil {
		return Status{}, ErrState
	}
	r := *c.value.Renewal
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
	v, e := c.installation(raw, r)
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
	if e = c.saveRenewal(r); e != nil {
		return Status{}, e
	}
	raw, e = c.requestCertificate(ctx, "POST", r.path()+"/installed-proof", canon(Proof{r.Signature}), "", r.Certificate)
	if e != nil {
		return Status{}, errors.Join(ErrReconcile, e)
	}
	return c.acceptRenewalResult(ctx, raw)
}
func (c *Client) acceptRenewalResult(ctx context.Context, raw []byte) (Status, error) {
	r := *c.value.Renewal
	v, e := c.installation(raw, r)
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
	if e = c.saveRenewal(r); e != nil {
		return Status{}, e
	}
	return c.Status()
}
func (c *Client) ReconcileRenewal(ctx context.Context) (Status, error) {
	if c.value.Renewal == nil || c.value.Renewal.Challenge == nil {
		return Status{}, ErrState
	}
	r := *c.value.Renewal
	raw, e := c.requestCertificate(ctx, "GET", r.path()+"/installation", nil, "", r.Certificate)
	if e != nil {
		return Status{}, e
	}
	return c.acceptRenewalResult(ctx, raw)
}

// RetryRenewalInstalled explicitly reuses only the retained installation proof.
// A fresh authenticated read must confirm the exact pending challenge first.
func (c *Client) RetryRenewalInstalled(ctx context.Context) (Status, error) {
	if c.value.Renewal == nil || c.value.Renewal.Phase != "proof_submitted" {
		return Status{}, ErrState
	}
	r := *c.value.Renewal
	raw, e := c.requestCertificate(ctx, "GET", r.path()+"/installation", nil, "", r.Certificate)
	if e != nil {
		return Status{}, e
	}
	v, e := c.installation(raw, r)
	if e != nil {
		return Status{}, e
	}
	if v.State == "verified" || v.State == "active" {
		return c.acceptRenewalResult(ctx, raw)
	}
	if v.State != "staged" || v.Challenge == nil || r.Challenge == nil || *v.Challenge != *r.Challenge || v.Receipt != nil || v.Signature != "" || v.Active != nil || r.validateChallenge(*v.Challenge, c.runtime.Now()) != nil {
		return Status{}, ErrReconcile
	}
	raw, e = c.requestCertificate(ctx, "POST", r.path()+"/installed-proof", canon(Proof{r.Signature}), "", r.Certificate)
	if e != nil {
		return Status{}, errors.Join(ErrReconcile, e)
	}
	return c.acceptRenewalResult(ctx, raw)
}
