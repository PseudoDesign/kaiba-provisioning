package pilotenrollment

import (
	"errors"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
	"time"
)

type TrustContinuation struct {
	Schema     string `json:"schema_version"`
	Operation  string `json:"operation_id"`
	Approval   Ref    `json:"owner_approval_ref"`
	Enrollment string `json:"enrollment_id"`
	Logical    string `json:"logical_device_id"`
	SPKI       string `json:"spki_digest"`
	Credential string `json:"predecessor_certificate_digest"`
	OldServer  string `json:"old_server_ca_digest"`
	OldIssuer  string `json:"old_issuer_ca_digest"`
	Server     string `json:"server_ca_pem"`
	Issuer     string `json:"issuer_ca_pem"`
	From       string `json:"valid_from"`
	Expires    string `json:"expires_at"`
}
type trustContinuationReceipt struct {
	Request TrustContinuation `json:"request"`
	Digest  string            `json:"reviewed_digest"`
	Applied string            `json:"applied_at"`
}
type TrustContinuationResult struct {
	Operation     string `json:"operation_id"`
	Digest        string `json:"reviewed_digest"`
	Applied       string `json:"applied_at"`
	IssuerExpires string `json:"issuer_expires_at"`
	ServerExpires string `json:"server_expires_at"`
	Full          bool   `json:"full_qualification"`
}

func trustDigest(pem string) string {
	c, e := certificate(pem)
	if e != nil {
		return ""
	}
	return handoff.Digest(c.Raw)
}
func (s state) effectiveTrust() Config {
	c := s.Config
	for _, r := range s.TrustHistory {
		c.ServerCA = r.Request.Server
		c.IssuerCA = r.Request.Issuer
	}
	return c
}
func validTrustContinuation(q TrustContinuation, c Config, status Status, now time.Time) error {
	fail := errors.New("trust continuation requires exact retained-key owner review")
	from, e1 := time.Parse(time.RFC3339Nano, q.From)
	until, e2 := time.Parse(time.RFC3339Nano, q.Expires)
	if q.Schema != "kaiba.pilot-device-trust-continuation/v1alpha1" || !handoff.ID.MatchString(q.Operation) || q.Enrollment != status.Enrollment || q.Logical != status.Logical || q.SPKI != status.SPKIDigest || !validDigest(q.Credential) || q.Approval.URI == "" || !validDigest(q.Approval.Digest) || q.OldServer != trustDigest(c.ServerCA) || q.OldIssuer != trustDigest(c.IssuerCA) || e1 != nil || e2 != nil || !from.Before(until) || until.Sub(from) > 12*time.Hour || now.Before(from) || !now.Before(until) {
		return fail
	}
	for _, pair := range [][2]string{{c.ServerCA, q.Server}, {c.IssuerCA, q.Issuer}} {
		a, e := certificate(pair[0])
		if e != nil {
			return fail
		}
		b, e := certificate(pair[1])
		if e != nil {
			return fail
		}
		if e = sameKeyCAContinuation(a, b, now); e != nil {
			return e
		}
	}
	return nil
}
func (s state) validateTrustHistory() error {
	if len(s.TrustHistory) == 0 {
		return nil
	}
	if len(s.TrustHistory) > 32 || s.Phase != "verified" {
		return ErrState
	}
	status, e := s.status()
	if e != nil {
		return e
	}
	config := s.Config
	seen := map[string]bool{}
	var prior time.Time
	for _, r := range s.TrustHistory {
		at, e := time.Parse(time.RFC3339Nano, r.Applied)
		if e != nil || at.Before(prior) || r.Digest != handoff.Digest(canon(r.Request)) || seen[r.Request.Operation] || validTrustContinuation(r.Request, config, status, at) != nil {
			return ErrState
		}
		seen[r.Request.Operation] = true
		prior = at
		config.ServerCA = r.Request.Server
		config.IssuerCA = r.Request.Issuer
	}
	return nil
}
func (r trustContinuationReceipt) result() TrustContinuationResult {
	a, _ := certificate(r.Request.Issuer)
	b, _ := certificate(r.Request.Server)
	return TrustContinuationResult{r.Request.Operation, r.Digest, r.Applied, a.NotAfter.UTC().Format(time.RFC3339Nano), b.NotAfter.UTC().Format(time.RFC3339Nano), false}
}
