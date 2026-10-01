//go:build linux

package pilotenrollment

import (
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
	"syscall"
	"time"
)

// TrustCertificateObservation contains metadata from the CA selected by the
// protected client, not from a staged candidate or the original configuration.
type TrustCertificateObservation struct {
	Digest string `json:"certificate_der_sha256"`
	SPKI   string `json:"spki_sha256"`
	Before string `json:"not_before"`
	After  string `json:"not_after"`
}

type TrustObservation struct {
	Schema             string                      `json:"schema_version"`
	Enrollment         string                      `json:"enrollment_id"`
	Logical            string                      `json:"logical_device_id"`
	SPKI               string                      `json:"device_spki_digest"`
	Observed           string                      `json:"observed_at"`
	Server             TrustCertificateObservation `json:"server_ca"`
	Issuer             TrustCertificateObservation `json:"issuer_ca"`
	ContinuationCount  int                         `json:"continuation_count"`
	LatestContinuation string                      `json:"latest_continuation_digest,omitempty"`
	Protected          bool                        `json:"protected_storage_verified"`
	ClockCertain       bool                        `json:"clock_certain"`
	Full               bool                        `json:"full_qualification"`
}

func (r Runtime) certainTime() bool {
	if r.ClockCertain != nil {
		return r.ClockCertain()
	}
	var tx syscall.Timex
	clock, e := syscall.Adjtimex(&tx)
	return e == nil && clock != 5 && tx.Status&0x40 == 0
}

// InspectTrust is a local read under the existing protected-store lock. It
// neither contacts Fleet nor asserts current membership or delegation authority.
// A caller must authenticate and check those independently before using bounds.
func (c *Client) InspectTrust() (TrustObservation, error) {
	var out TrustObservation
	if c.value.Phase != "verified" || !c.runtime.certainTime() {
		return out, ErrState
	}
	start := c.runtime.Now()
	if e := c.value.validateTrustHistory(); e != nil {
		return out, e
	}
	status, e := c.Status()
	if e != nil {
		return out, e
	}
	selected := c.value.effectiveTrust()
	certs := []TrustCertificateObservation{}
	for _, raw := range []string{selected.ServerCA, selected.IssuerCA} {
		cert, e := certificate(raw)
		if e != nil || !cert.IsCA || start.Before(cert.NotBefore) || !start.Before(cert.NotAfter) {
			return TrustObservation{}, ErrBinding
		}
		certs = append(certs, TrustCertificateObservation{
			Digest: handoff.Digest(cert.Raw), SPKI: handoff.Digest(cert.RawSubjectPublicKeyInfo),
			Before: cert.NotBefore.UTC().Format(time.RFC3339Nano), After: cert.NotAfter.UTC().Format(time.RFC3339Nano),
		})
	}
	if e := checkStorage(c.store, c.value.Config, c.runtime); e != nil {
		return out, e
	}
	checked := c.runtime.Now()
	if !c.runtime.certainTime() || checked.Before(start) || checked.Sub(start) > 15*time.Second {
		return out, ErrState
	}
	for _, cert := range certs {
		until, e := time.Parse(time.RFC3339Nano, cert.After)
		if e != nil || !checked.Before(until) {
			return out, ErrBinding
		}
	}
	out = TrustObservation{Schema: "kaiba.pilot-device-trust-observation/v1alpha1",
		Enrollment: status.Enrollment, Logical: status.Logical, SPKI: status.SPKIDigest,
		Observed: checked.UTC().Format(time.RFC3339Nano), Server: certs[0], Issuer: certs[1],
		ContinuationCount: len(c.value.TrustHistory), Protected: true, ClockCertain: true}
	if out.ContinuationCount > 0 {
		out.LatestContinuation = c.value.TrustHistory[out.ContinuationCount-1].Digest
	}
	return out, nil
}
