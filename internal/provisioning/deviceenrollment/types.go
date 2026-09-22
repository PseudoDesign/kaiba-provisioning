// Package deviceenrollment implements a development-only device credential
// client. It never grants fleet eligibility or performs hardware operations.
package deviceenrollment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
)

const Version = "kaiba.device-enrollment-client/v1alpha1"
const Audience = "kaiba-fleet-rehearsal"
const CertificateProfile = "rehearsal-management-v1"
const maxBytes = 1 << 20

var (
	ErrInput      = errors.New("invalid enrollment input")
	ErrState      = errors.New("invalid or incomplete private credential state")
	ErrBinding    = errors.New("enrollment binding mismatch")
	ErrRestart    = errors.New("required restart has not occurred")
	ErrReconcile  = errors.New("station reconciliation required; do not repeat the request automatically")
	ErrTransport  = errors.New("fleet request unavailable; no automatic retry")
	ErrResponse   = errors.New("invalid fleet response")
	ErrStorage    = errors.New("protected credential filesystem unavailable or mismatched")
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	noncePattern  = regexp.MustCompile(`^[0-9a-f]{48}$`)
	bootPattern   = regexp.MustCompile(`^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)
)

type RecordRef struct {
	ID       string `json:"record_id"`
	Revision uint64 `json:"revision"`
	Digest   string `json:"digest"`
}
type Config struct {
	Schema          string    `json:"schema_version"`
	Mode            string    `json:"mode"`
	FleetURL        string    `json:"fleet_url"`
	ServerCA        string    `json:"server_ca_pem"`
	IssuerCA        string    `json:"issuer_ca_pem"`
	IssuerID        string    `json:"issuer_id"`
	Provisioning    RecordRef `json:"provisioning_ref"`
	Restart         string    `json:"restart_requirement"`
	Authority       string    `json:"authority_id"`
	Transaction     string    `json:"transaction_id"`
	Target          string    `json:"target"`
	ProtectedVolume string    `json:"protected_volume_uuid,omitempty"`
}
type Challenge struct {
	Purpose      string    `json:"purpose"`
	Nonce        string    `json:"nonce"`
	Expires      string    `json:"expires_at"`
	Audience     string    `json:"audience"`
	Enrollment   string    `json:"enrollment_id"`
	Logical      string    `json:"logical_device_id"`
	Instance     string    `json:"instance_id"`
	Storage      uint64    `json:"storage_generation"`
	Slot         string    `json:"slot"`
	Generation   uint64    `json:"key_generation"`
	SPKI         string    `json:"spki_digest"`
	Profile      string    `json:"certificate_profile"`
	Provisioning RecordRef `json:"provisioning_ref"`
}
type Proof struct {
	Signature string `json:"signature"`
}

// Status deliberately excludes private key bytes, signatures and certificate
// bodies. Verified installed-key proof is not evidence of fleet activation.
type Status struct {
	Schema               string `json:"schema_version"`
	Phase                string `json:"phase"`
	SPKI                 string `json:"spki"`
	SPKIDigest           string `json:"spki_digest"`
	Enrollment           string `json:"enrollment_id,omitempty"`
	Logical              string `json:"logical_device_id,omitempty"`
	RestartRequirement   string `json:"restart_requirement"`
	BootChangeObserved   bool   `json:"boot_change_observed"`
	ProductionEnrollment bool   `json:"production_enrollment"`
	HardwareQualified    bool   `json:"hardware_qualified"`
}

type state struct {
	Schema           string     `json:"schema_version"`
	Config           Config     `json:"config"`
	Key              []byte     `json:"private_key_pkcs8"`
	Phase            string     `json:"phase"`
	Bootstrap        *Challenge `json:"bootstrap,omitempty"`
	BootstrapProof   string     `json:"bootstrap_proof,omitempty"`
	Certificate      string     `json:"certificate,omitempty"`
	InstalledBoot    string     `json:"installed_boot_id,omitempty"`
	InstalledProcess string     `json:"installed_process,omitempty"`
	Pending          *Challenge `json:"pending_challenge,omitempty"`
	PendingProof     string     `json:"pending_proof,omitempty"`
	VerifiedBoot     string     `json:"verified_boot_id,omitempty"`
	ProofBoot        string     `json:"proof_boot_id,omitempty"`
}

func canonical(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, ErrInput
	}
	return handoff.Canonical(b)
}
func decode(b []byte, v any) error {
	if len(b) > maxBytes {
		return ErrInput
	}
	normalized, e := handoff.Canonical(b)
	if e != nil {
		return ErrInput
	}
	if e = handoff.Decode(normalized, v); e != nil {
		return ErrInput
	}
	return nil
}
func digest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func certificate(raw string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInput
	}
	c, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return nil, ErrInput
	}
	return c, nil
}
func (c Config) validate() error {
	if c.Schema != Version || c.Mode != "development" || !idPattern.MatchString(c.IssuerID) || !idPattern.MatchString(c.Authority) || !idPattern.MatchString(c.Transaction) || !idPattern.MatchString(c.Target) || (c.Restart != "boot" && c.Restart != "process") || !idPattern.MatchString(c.Provisioning.ID) || c.Provisioning.Revision == 0 || c.Provisioning.Revision > 9007199254740991 || !digestPattern.MatchString(c.Provisioning.Digest) {
		return ErrInput
	}
	if (c.Restart == "boot" && c.ProtectedVolume == "") || (c.ProtectedVolume != "" && (!bootPattern.MatchString(c.ProtectedVolume) || c.ProtectedVolume == "00000000-0000-0000-0000-000000000000")) {
		return ErrInput
	}
	u, e := url.Parse(c.FleetURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
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
func privateKey(b []byte) (*ecdsa.PrivateKey, error) {
	v, e := x509.ParsePKCS8PrivateKey(b)
	if e != nil {
		return nil, ErrState
	}
	k, ok := v.(*ecdsa.PrivateKey)
	if !ok || k.Curve != elliptic.P256() {
		return nil, ErrState
	}
	return k, nil
}
func public(k *ecdsa.PrivateKey) ([]byte, error) { return x509.MarshalPKIXPublicKey(&k.PublicKey) }
func (s state) status() (Status, error) {
	k, e := privateKey(s.Key)
	if e != nil {
		return Status{}, e
	}
	b, e := public(k)
	if e != nil {
		return Status{}, ErrState
	}
	out := Status{Schema: Version, Phase: s.Phase, SPKI: base64.StdEncoding.EncodeToString(b), SPKIDigest: digest(b), RestartRequirement: s.Config.Restart, BootChangeObserved: s.VerifiedBoot != "" && s.VerifiedBoot != s.InstalledBoot}
	if s.Bootstrap != nil {
		out.Enrollment = s.Bootstrap.Enrollment
		out.Logical = s.Bootstrap.Logical
	}
	return out, nil
}
func (c Challenge) valid(s state, purpose string, now time.Time, checkTime bool) error {
	k, e := privateKey(s.Key)
	if e != nil {
		return e
	}
	pub, e := public(k)
	if e != nil {
		return ErrState
	}
	if c.Purpose != purpose || !noncePattern.MatchString(c.Nonce) || c.Audience != Audience || !idPattern.MatchString(c.Enrollment) || !idPattern.MatchString(c.Logical) || c.Instance != c.Enrollment || c.Storage == 0 || c.Storage > 9007199254740991 || c.Slot != "management" || c.Generation != 1 || c.SPKI != digest(pub) || c.Profile != CertificateProfile || c.Provisioning != s.Config.Provisioning {
		return ErrBinding
	}
	deadline, e := time.Parse(time.RFC3339Nano, c.Expires)
	if e != nil {
		return ErrInput
	}
	if checkTime && (!now.Before(deadline) || deadline.After(now.Add(5*time.Minute))) {
		return ErrBinding
	}
	if s.Bootstrap != nil {
		a, b := c, *s.Bootstrap
		a.Purpose = b.Purpose
		a.Nonce = b.Nonce
		a.Expires = b.Expires
		if a != b {
			return ErrBinding
		}
	}
	return nil
}
func (s state) leaf(now time.Time, checkTime bool) (*x509.Certificate, error) {
	c, e := certificate(s.Certificate)
	if e != nil {
		return nil, ErrState
	}
	issuer, e := certificate(s.Config.IssuerCA)
	if e != nil {
		return nil, ErrState
	}
	k, e := privateKey(s.Key)
	if e != nil {
		return nil, e
	}
	pub, _ := public(k)
	if s.Bootstrap == nil || c.IsCA || !bytes.Equal(c.RawSubjectPublicKeyInfo, pub) || c.CheckSignatureFrom(issuer) != nil || len(c.URIs) != 1 || c.URIs[0].String() != "spiffe://kaiba.test/device/"+s.Bootstrap.Logical+"/instance/"+s.Bootstrap.Enrollment || len(c.DNSNames) != 0 || len(c.IPAddresses) != 0 || len(c.EmailAddresses) != 0 || len(c.UnhandledCriticalExtensions) != 0 || c.KeyUsage != x509.KeyUsageDigitalSignature || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(c.UnknownExtKeyUsage) != 0 {
		return nil, ErrBinding
	}
	if checkTime {
		pool := x509.NewCertPool()
		pool.AddCert(issuer)
		if _, e = c.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
			return nil, ErrBinding
		}
	}
	return c, nil
}
func (s state) validate() error {
	if s.Schema != Version || s.Config.validate() != nil {
		return ErrState
	}
	k, e := privateKey(s.Key)
	if e != nil {
		return e
	}
	if s.Phase == "initialized" {
		if s.Bootstrap != nil || s.BootstrapProof != "" || s.Certificate != "" || s.InstalledBoot != "" || s.InstalledProcess != "" || s.Pending != nil || s.PendingProof != "" || s.VerifiedBoot != "" || s.ProofBoot != "" {
			return ErrState
		}
		return nil
	}
	if s.Bootstrap == nil || s.Bootstrap.valid(s, "bootstrap", time.Time{}, false) != nil {
		return ErrState
	}
	b, _ := canonical(s.Bootstrap)
	sum := sha256.Sum256(b)
	sig, e := base64.StdEncoding.DecodeString(s.BootstrapProof)
	if e != nil || !ecdsa.VerifyASN1(&k.PublicKey, sum[:], sig) {
		return ErrState
	}
	if s.Phase == "bootstrap_proved" {
		if s.Certificate != "" || s.InstalledBoot != "" || s.InstalledProcess != "" || s.Pending != nil || s.PendingProof != "" || s.VerifiedBoot != "" || s.ProofBoot != "" {
			return ErrState
		}
		return nil
	}
	if _, e = s.leaf(time.Time{}, false); e != nil || !bootPattern.MatchString(s.InstalledBoot) || s.InstalledProcess == "" {
		return ErrState
	}
	switch s.Phase {
	case "installed":
		if s.Pending != nil || s.PendingProof != "" || s.VerifiedBoot != "" || s.ProofBoot != "" {
			return ErrState
		}
	case "proof_submitted", "verified":
		if s.Pending == nil || s.Pending.valid(s, "installed_key", time.Time{}, false) != nil || !bootPattern.MatchString(s.ProofBoot) || (s.Config.Restart == "boot" && s.ProofBoot == s.InstalledBoot) {
			return ErrState
		}
		b, _ = canonical(s.Pending)
		sum = sha256.Sum256(b)
		sig, e = base64.StdEncoding.DecodeString(s.PendingProof)
		if e != nil || !ecdsa.VerifyASN1(&k.PublicKey, sum[:], sig) {
			return ErrState
		}
		if s.Phase == "verified" && s.VerifiedBoot != s.ProofBoot {
			return ErrState
		}
		if s.Phase == "proof_submitted" && s.VerifiedBoot != "" {
			return ErrState
		}
	default:
		return ErrState
	}
	return nil
}
func cleanOrigin(s string) string { return strings.TrimSuffix(s, "/") }
