//go:build linux

package pilotenrollment

import (
	"context"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
	"syscall"
	"time"
)

// ContinueTrust is a separate local owner action, never a renewal-worker action.
// The caller supplies an independently reviewed canonical packet digest. Original
// configuration, membership, keys and certificate/recovery history stay intact.
func (c *Client) ContinueTrust(ctx context.Context, raw []byte, reviewed string) (TrustContinuationResult, error) {
	var q TrustContinuation
	if decode(raw, &q) != nil || !validDigest(reviewed) || handoff.Digest(canon(q)) != reviewed {
		return TrustContinuationResult{}, ErrInput
	}
	for _, r := range c.value.TrustHistory {
		if r.Request.Operation == q.Operation {
			if r.Digest != reviewed {
				return TrustContinuationResult{}, ErrBinding
			}
			return r.result(), nil
		}
	}
	if c.value.Phase != "verified" || len(c.value.TrustHistory) >= 32 || (c.value.Renewal != nil && c.value.Renewal.Phase != "active") || (c.value.Recovery != nil && (c.value.Recovery.Installation == nil || c.value.Recovery.Installation.Phase != "active")) {
		return TrustContinuationResult{}, ErrReconcile
	}
	status, e := c.Status()
	if e != nil {
		return TrustContinuationResult{}, e
	}
	now := c.runtime.Now()
	if e = validTrustContinuation(q, c.value.effectiveTrust(), status, now); e != nil {
		return TrustContinuationResult{}, e
	}
	clockCertain := c.runtime.ClockCertain
	if clockCertain == nil {
		clockCertain = func() bool {
			var tx syscall.Timex
			clock, e := syscall.Adjtimex(&tx)
			return e == nil && clock != 5 && tx.Status&0x40 == 0
		}
	}
	if !clockCertain() {
		return TrustContinuationResult{}, ErrBinding
	}

	// Revoked/expired membership cannot be recovered by updating trust.
	raw, e = c.CheckAccess(ctx)
	if e != nil {
		return TrustContinuationResult{}, e
	}
	var self renewalSelf
	var binding renewalBinding
	if decode(raw, &self) != nil || decode(self.Binding, &binding) != nil || binding.Credential.SPKI != q.SPKI {
		return TrustContinuationResult{}, ErrBinding
	}
	cert := c.value.renewalBase().Certificate
	if c.value.Renewal != nil && c.value.Renewal.Phase == "active" {
		cert = c.value.Renewal.Certificate
	}
	if r := c.value.Recovery; c.value.RecoveryRenewalStart == nil && r != nil && r.Installation != nil && r.Installation.Phase == "active" {
		cert = r.Installation.Certificate
	}
	if CertificateDigest(cert) != q.Credential {
		return TrustContinuationResult{}, ErrBinding
	}
	if e = checkStorage(c.store, c.value.Config, c.runtime); e != nil {
		return TrustContinuationResult{}, e
	}
	// The authenticated read can span a clock change or the end of the
	// approval/credential interval. Recheck before recording a transition.
	applied := c.runtime.Now()
	if !clockCertain() || applied.Before(now) || validTrustContinuation(q, c.value.effectiveTrust(), status, applied) != nil {
		return TrustContinuationResult{}, ErrBinding
	}
	leaf, e := certificate(cert)
	if e != nil || applied.Before(leaf.NotBefore) || !applied.Before(leaf.NotAfter) {
		return TrustContinuationResult{}, ErrBinding
	}
	r := trustContinuationReceipt{q, reviewed, applied.UTC().Format(time.RFC3339Nano)}
	next := c.value
	next.TrustHistory = append(append([]trustContinuationReceipt(nil), next.TrustHistory...), r)
	if e = c.save(next); e != nil {
		return TrustContinuationResult{}, e
	}
	return r.result(), nil
}
