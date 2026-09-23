package pilotenrollment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"regexp"
	"time"

	wire "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
)

const ProofVersion = "kaiba.pilot-key-proof/v1alpha1"

// ProofBinding is the immutable enrollment intent. A bootstrap proof predates
// issuance; installed-key proof adds the exact issued certificate digest.
type ProofBinding struct {
	Target   Target    `json:"target"`
	Adoption RecordRef `json:"adoption_ref"`
	Policy   RecordRef `json:"policy_ref"`
	Decision RecordRef `json:"admission_ref"`
	Audience string    `json:"audience"`
	Profile  string    `json:"certificate_profile"`
	Issuer   string    `json:"issuer_id"`
}
type Challenge struct {
	Schema      string       `json:"schema_version"`
	Purpose     string       `json:"purpose"`
	Nonce       string       `json:"nonce"`
	Expires     string       `json:"expires_at"`
	Enrollment  string       `json:"enrollment_id"`
	Logical     string       `json:"logical_device_id"`
	Instance    string       `json:"instance_id"`
	Storage     uint64       `json:"storage_generation"`
	Slot        string       `json:"slot"`
	Generation  uint64       `json:"key_generation"`
	SPKI        string       `json:"spki_digest"`
	Binding     ProofBinding `json:"binding"`
	Certificate string       `json:"certificate_digest"`
	Restart     string       `json:"restart_kind"`
}
type Proof struct {
	Signature string `json:"signature"`
}

func canon(v any) []byte { b, _ := json.Marshal(v); c, _ := wire.Canonical(b); return c }
func randomID() (string, error) {
	b := make([]byte, 24)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func public(raw string) (*ecdsa.PublicKey, []byte, error) {
	b, e := base64.StdEncoding.DecodeString(raw)
	if e != nil || base64.StdEncoding.EncodeToString(b) != raw {
		return nil, nil, errors.New("invalid_key")
	}
	v, e := x509.ParsePKIXPublicKey(b)
	if e != nil {
		return nil, nil, errors.New("invalid_key")
	}
	k, ok := v.(*ecdsa.PublicKey)
	if !ok || k.Curve != elliptic.P256() {
		return nil, nil, errors.New("invalid_key")
	}
	return k, b, nil
}
func NewChallenge(binding ProofBinding, spki, enrollment, logical, purpose, certificate string, now time.Time) (Challenge, error) {
	_, b, e := public(spki)
	if e != nil {
		return Challenge{}, e
	}
	nonce, e := randomID()
	if e != nil {
		return Challenge{}, e
	}
	c := Challenge{ProofVersion, purpose, nonce, now.Add(5 * time.Minute).UTC().Format(time.RFC3339Nano), enrollment, logical, enrollment, 1, "management", 1, wire.Digest(b), binding, certificate, "client_process"}
	if e = c.Validate(now, true); e != nil {
		return Challenge{}, e
	}
	return c, nil
}

var contractID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$`)

func absoluteURI(s string) bool { u, e := url.Parse(s); return e == nil && u.IsAbs() && len(s) <= 2048 }
func validRef(r RecordRef) bool {
	return contractID.MatchString(r.ID) && r.Revision > 0 && r.Revision <= 9007199254740991 && validDigest(r.Digest)
}
func validDigest(s string) bool {
	return len(s) == 71 && s[:7] == "sha256:" && wire.Hex.MatchString(s[7:])
}
func (c Challenge) Validate(now time.Time, checkTime bool) error {
	b := c.Binding
	if c.Schema != ProofVersion || (c.Purpose != "bootstrap" && c.Purpose != "installed_key") || len(c.Nonce) != 48 || !wire.Hex.MatchString(c.Nonce+"0000000000000000") || !wire.ID.MatchString(c.Enrollment) || !wire.ID.MatchString(c.Logical) || c.Instance != c.Enrollment || c.Storage != 1 || c.Slot != "management" || c.Generation != 1 || !validDigest(c.SPKI) || b.Profile != Profile || !contractID.MatchString(b.Audience) || b.Audience == "kaiba-fleet-rehearsal" || !contractID.MatchString(b.Issuer) || !validRef(b.Adoption) || !validRef(b.Policy) || !validRef(b.Decision) || !contractID.MatchString(b.Target.Asset) || !absoluteURI(b.Target.Identity.URI) || !absoluteURI(b.Target.Storage.URI) || !validDigest(b.Target.Identity.Digest) || !validDigest(b.Target.Storage.Digest) || c.Restart != "client_process" {
		return errors.New("invalid_challenge")
	}
	if (c.Purpose == "bootstrap" && c.Certificate != "") || (c.Purpose == "installed_key" && !validDigest(c.Certificate)) {
		return errors.New("invalid_challenge")
	}
	expiry, e := time.Parse(time.RFC3339Nano, c.Expires)
	if e != nil || (checkTime && (!now.Before(expiry) || expiry.After(now.Add(5*time.Minute)))) {
		return errors.New("challenge_expired")
	}
	return nil
}
func VerifyProof(c Challenge, p Proof, spki string, now time.Time) error {
	if e := c.Validate(now, true); e != nil {
		return e
	}
	k, b, e := public(spki)
	if e != nil || wire.Digest(b) != c.SPKI {
		return errors.New("invalid_key")
	}
	sig, e := base64.StdEncoding.DecodeString(p.Signature)
	sum := sha256.Sum256(canon(c))
	if e != nil || !ecdsa.VerifyASN1(k, sum[:], sig) {
		return errors.New("invalid_proof")
	}
	return nil
}
func DeviceURI(logical, instance string) string {
	return "spiffe://kaiba.pilot/device/" + logical + "/instance/" + instance
}
func ValidateCertificate(raw, spki, logical, instance string, issuer *x509.Certificate, now time.Time) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid_certificate")
	}
	c, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return nil, errors.New("invalid_certificate")
	}
	_, key, e := public(spki)
	if e != nil || c.IsCA || !bytes.Equal(c.RawSubjectPublicKeyInfo, key) || len(c.URIs) != 1 || c.URIs[0].String() != DeviceURI(logical, instance) || len(c.DNSNames) != 0 || len(c.IPAddresses) != 0 || len(c.EmailAddresses) != 0 || c.KeyUsage != x509.KeyUsageDigitalSignature || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(c.UnknownExtKeyUsage) != 0 || len(c.UnhandledCriticalExtensions) != 0 {
		return nil, errors.New("certificate_binding_mismatch")
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	if _, e = c.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return nil, errors.New("invalid_certificate")
	}
	return c, nil
}
func CertificateDigest(raw string) string {
	b, _ := pem.Decode([]byte(raw))
	if b == nil {
		return ""
	}
	return wire.Digest(b.Bytes)
}
func validPrincipal(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Scheme == "spiffe" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}
