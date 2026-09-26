// Package pilotenrollment is the separate, protected-storage pilot credential
// client. It has no provisioning transaction, hardware action or admission API.
package pilotenrollment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"regexp"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
)

const Version = "kaiba.pilot-device-client/v1alpha1"
const Profile = "rpi5-existing-luks-pilot-v1"
const maxBytes = handoff.MaxBytes

var ErrInput = errors.New("invalid pilot input")
var ErrState = errors.New("invalid private pilot credential state")
var ErrStorage = errors.New("protected pilot credential filesystem unavailable")
var ErrBinding = errors.New("pilot binding mismatch")
var ErrRestart = errors.New("client process restart required")
var ErrReconcile = errors.New("station reconciliation required; no automatic retry")
var bootPattern = regexp.MustCompile(`^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)

type Ref struct {
	URI    string `json:"uri"`
	Digest string `json:"digest"`
}
type RecordRef struct {
	ID       string `json:"record_id"`
	Revision uint64 `json:"revision"`
	Digest   string `json:"digest"`
}
type Target struct {
	Asset    string `json:"asset_ref"`
	Identity Ref    `json:"identity_ref"`
	Storage  Ref    `json:"storage_ref"`
}
type Config struct {
	Schema          string       `json:"schema_version"`
	FleetURL        string       `json:"fleet_url"`
	ServerCA        string       `json:"server_ca_pem"`
	IssuerCA        string       `json:"issuer_ca_pem"`
	Binding         ProofBinding `json:"binding"`
	ProtectedVolume string       `json:"protected_volume_uuid"`
}
type Status struct {
	Recovery   *RecoveryStatus `json:"recovery,omitempty"`
	Renewal    *RenewalStatus  `json:"renewal,omitempty"`
	Schema     string          `json:"schema_version"`
	Phase      string          `json:"phase"`
	SPKI       string          `json:"spki"`
	SPKIDigest string          `json:"spki_digest"`
	Enrollment string          `json:"enrollment_id,omitempty"`
	Logical    string          `json:"logical_device_id,omitempty"`
	Full       bool            `json:"full_qualification"`
}
type state struct {
	// Number of normal renewals completed before the retained recovery.
	RecoveryRenewalStart *int           `json:"recovery_renewal_start,omitempty"`
	Recovery             *recoveryState `json:"recovery,omitempty"`
	History              []renewalState `json:"renewal_history,omitempty"`
	Renewal              *renewalState  `json:"renewal,omitempty"`
	Schema               string         `json:"schema_version"`
	Config               Config         `json:"config"`
	Key                  []byte         `json:"private_key_pkcs8"`
	Phase                string         `json:"phase"`
	Bootstrap            *Challenge     `json:"bootstrap,omitempty"`
	BootstrapProof       string         `json:"bootstrap_proof,omitempty"`
	Certificate          string         `json:"certificate,omitempty"`
	InstalledProcess     string         `json:"installed_process,omitempty"`
	Pending              *Challenge     `json:"pending_challenge,omitempty"`
	PendingProof         string         `json:"pending_proof,omitempty"`
}

func canonical(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return handoff.Canonical(b)
}
func decode(b []byte, v any) error { return handoff.Decode(b, v) }
func certificate(raw string) (*x509.Certificate, error) {
	b, rest := pem.Decode([]byte(raw))
	if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInput
	}
	return x509.ParseCertificate(b.Bytes)
}
func (c Config) validate() error {
	if c.Schema != Version || !bootPattern.MatchString(c.ProtectedVolume) || c.ProtectedVolume == "00000000-0000-0000-0000-000000000000" {
		return ErrInput
	}
	b := c.Binding
	// The challenge validator supplies the closed proof context checks without
	// generating a key or nonce. Real challenges are checked against the local key.
	ch := Challenge{Schema: ProofVersion, Purpose: "bootstrap", Nonce: "000000000000000000000000000000000000000000000000", Expires: "2000-01-01T00:00:00Z", Enrollment: "validate", Logical: "validate", Instance: "validate", Storage: 1, Slot: "management", Generation: 1, SPKI: "sha256:0000000000000000000000000000000000000000000000000000000000000000", Binding: b, Restart: "client_process"}
	if ch.Validate(time.Time{}, false) != nil {
		return ErrInput
	}
	u, e := url.Parse(c.FleetURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return ErrInput
	}
	for _, raw := range []string{c.ServerCA, c.IssuerCA} {
		ca, e := certificate(raw)
		if e != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
			return ErrInput
		}
	}
	return nil
}
func DecodeConfig(b []byte) (Config, error) {
	var c Config
	if e := decode(b, &c); e != nil {
		return c, e
	}
	return c, c.validate()
}
func privateKey(raw []byte) (*ecdsa.PrivateKey, error) {
	v, e := x509.ParsePKCS8PrivateKey(raw)
	if e != nil {
		return nil, ErrState
	}
	k, ok := v.(*ecdsa.PrivateKey)
	if !ok || k.Curve.Params().Name != "P-256" {
		return nil, ErrState
	}
	return k, nil
}
func (s state) status() (Status, error) {
	k, e := privateKey(s.Key)
	if e != nil {
		return Status{}, e
	}
	spki, e := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if e != nil {
		return Status{}, e
	}
	out := Status{Schema: Version, Phase: s.Phase, SPKI: base64.StdEncoding.EncodeToString(spki), SPKIDigest: handoff.Digest(spki)}
	if s.Bootstrap != nil {
		out.Enrollment = s.Bootstrap.Enrollment
		out.Logical = s.Bootstrap.Logical
	}
	if s.Renewal != nil {
		r := s.Renewal
		out.Renewal = &RenewalStatus{r.Approval.Request.Operation, r.Phase, r.Approval.Authorization.Next, CertificateDigest(r.Certificate)}
	}
	if s.Recovery != nil {
		phase := "proof_prepared"
		if s.Recovery.Installation != nil {
			phase = s.Recovery.Installation.Phase
		}
		out.Recovery = &RecoveryStatus{s.Recovery.Packet.Approval.Request.Operation, phase}
	}
	return out, nil
}
func (s state) checkChallenge(c Challenge, purpose string, now time.Time, checkTime bool) error {
	status, e := s.status()
	if e != nil {
		return e
	}
	if c.Validate(now, checkTime) != nil || c.Binding != s.Config.Binding || c.SPKI != status.SPKIDigest || c.Purpose != purpose {
		return ErrBinding
	}
	if purpose == "installed_key" {
		if s.Bootstrap == nil || c.Enrollment != s.Bootstrap.Enrollment || c.Logical != s.Bootstrap.Logical || c.Certificate != CertificateDigest(s.Certificate) {
			return ErrBinding
		}
	}
	return nil
}
func (s state) leaf(now time.Time) (*x509.Certificate, error) {
	if s.Bootstrap == nil {
		return nil, ErrState
	}
	status, e := s.status()
	if e != nil {
		return nil, e
	}
	ca, e := certificate(s.Config.IssuerCA)
	if e != nil {
		return nil, e
	}
	return ValidateCertificate(s.Certificate, status.SPKI, status.Logical, status.Enrollment, ca, now)
}
func (s state) validate() error {
	if s.Schema != Version || s.Config.validate() != nil {
		return ErrState
	}
	if _, e := privateKey(s.Key); e != nil {
		return e
	}
	if len(s.History) > 127 || (len(s.History) > 0 && s.Renewal == nil) {
		return ErrState
	}
	if s.RecoveryRenewalStart != nil {
		n := *s.RecoveryRenewalStart
		if n < 0 || n > len(s.History) || s.Renewal == nil || s.Recovery == nil || s.Recovery.Installation == nil || s.Recovery.Installation.Phase != "active" {
			return ErrState
		}
		prefix := s
		prefix.History = s.History[:n]
		prefix.Renewal = nil
		prefix.RecoveryRenewalStart = nil
		if n > 0 {
			prefix.Renewal = &s.History[n-1]
			prefix.History = s.History[:n-1]
		}
		if s.Recovery.validate(prefix) != nil {
			return ErrState
		}
	}
	seen := map[string]bool{}
	if s.Recovery != nil {
		seen[s.Recovery.Packet.Approval.Request.Operation] = true
	}
	for i, r := range s.History {
		prefix := s
		prefix.History = s.History[:i]
		prefix.Renewal = nil
		if s.RecoveryRenewalStart != nil && i < *s.RecoveryRenewalStart {
			prefix.Recovery = nil
			prefix.RecoveryRenewalStart = nil
		}
		if s.Phase != "verified" || r.Phase != "active" || seen[r.Approval.Request.Operation] || r.validate(prefix) != nil {
			return ErrState
		}
		seen[r.Approval.Request.Operation] = true
	}
	if s.Renewal != nil {
		if s.Phase != "verified" || seen[s.Renewal.Approval.Request.Operation] || s.Renewal.validate(s) != nil {
			return ErrState
		}
	}
	if s.RecoveryRenewalStart == nil && s.Recovery != nil && s.Recovery.validate(s) != nil {
		return ErrState
	}
	if s.Phase == "initialized" {
		if s.Bootstrap != nil || s.BootstrapProof != "" || s.Certificate != "" || s.InstalledProcess != "" || s.Pending != nil || s.PendingProof != "" {
			return ErrState
		}
		return nil
	}
	if s.Bootstrap == nil || s.checkChallenge(*s.Bootstrap, "bootstrap", time.Time{}, false) != nil || !s.verifySaved(*s.Bootstrap, s.BootstrapProof) {
		return ErrState
	}
	if s.Phase == "bootstrap_proved" {
		if s.Certificate != "" || s.InstalledProcess != "" || s.Pending != nil || s.PendingProof != "" {
			return ErrState
		}
		return nil
	}
	leaf, e := certificate(s.Certificate)
	if e != nil {
		return ErrState
	}
	if _, e = s.leaf(leaf.NotBefore); e != nil || s.InstalledProcess == "" {
		return ErrState
	}
	switch s.Phase {
	case "installed":
		if s.Pending != nil || s.PendingProof != "" {
			return ErrState
		}
	case "proof_submitted", "verified":
		if s.Pending == nil || s.checkChallenge(*s.Pending, "installed_key", time.Time{}, false) != nil || !s.verifySaved(*s.Pending, s.PendingProof) {
			return ErrState
		}
	default:
		return ErrState
	}
	return nil
}
func (s state) verifySaved(c Challenge, signature string) bool {
	k, e := privateKey(s.Key)
	if e != nil {
		return false
	}
	sig, e := base64.StdEncoding.DecodeString(signature)
	sum := sha256.Sum256(canon(c))
	return e == nil && ecdsa.VerifyASN1(&k.PublicKey, sum[:], sig)
}
