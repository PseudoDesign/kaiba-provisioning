// Package appliancewire defines the additive production appliance protocol.
// Signed records authorize bounded transitions, never shell commands or admission.
package appliancewire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

const Version = "0.7.0-draft.1"

var ErrInvalid = errors.New("invalid appliance record")
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func ID(v string) bool       { return idPattern.MatchString(v) }
func IsDigest(v string) bool { return digestPattern.MatchString(v) }
func Encode(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Canonical(b)
}

type Header struct {
	Contract string `json:"contract"`
	Version  string `json:"contract_version"`
}

func NewHeader(kind string) Header      { return Header{kind, Version} }
func (h Header) Valid(kind string) bool { return h == NewHeader(kind) }

// Identity excludes a replaceable certificate: every protected HTTP request must
// additionally compare the presented certificate with current Fleet inventory.
type Identity struct {
	Authority  string `json:"authority_id"`
	Tenant     string `json:"tenant_id"`
	Device     string `json:"logical_device_id"`
	Instance   string `json:"instance_id"`
	Profile    string `json:"profile_id"`
	Storage    uint64 `json:"storage_generation"`
	Slot       string `json:"credential_slot"`
	Generation uint64 `json:"key_generation"`
	SPKI       string `json:"spki_digest"`
}

func (i Identity) Validate() error {
	for _, v := range []string{i.Authority, i.Tenant, i.Device, i.Instance, i.Profile, i.Slot} {
		if !ID(v) {
			return ErrInvalid
		}
	}
	if i.Storage == 0 || i.Generation == 0 || i.Storage > 9007199254740991 || i.Generation > 9007199254740991 || !IsDigest(i.SPKI) {
		return ErrInvalid
	}
	return nil
}
func PublicKey(raw string) (*ecdsa.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(b) > 1024 || base64.StdEncoding.EncodeToString(b) != raw {
		return nil, ErrInvalid
	}
	v, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, ErrInvalid
	}
	k, ok := v.(*ecdsa.PublicKey)
	if !ok || k.Curve != elliptic.P256() || !k.Curve.IsOnCurve(k.X, k.Y) {
		return nil, ErrInvalid
	}
	return k, nil
}
func SPKIDigest(k *ecdsa.PublicKey) string {
	b, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return ""
	}
	return Digest(b)
}

// Signed uses purpose separation and authenticates the key identifier as well
// as the JCS payload. Trust keys are installation inputs, not payload inputs.
type Signed struct {
	KeyID     string          `json:"key_id"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

func message(kind, keyID string, b []byte) []byte {
	return append([]byte("kaiba.appliance/"+Version+"/"+kind+"/"+keyID+"\x00"), b...)
}
func Sign(kind, keyID string, v any, k *ecdsa.PrivateKey) (Signed, error) {
	if !ID(kind) || !ID(keyID) || k == nil || k.Curve != elliptic.P256() {
		return Signed{}, ErrInvalid
	}
	b, err := Encode(v)
	if err != nil || len(b) > MaxBytes {
		return Signed{}, ErrInvalid
	}
	h := sha256.Sum256(message(kind, keyID, b))
	sig, err := ecdsa.SignASN1(rand.Reader, k, h[:])
	if err != nil {
		return Signed{}, err
	}
	return Signed{keyID, b, base64.StdEncoding.EncodeToString(sig)}, nil
}
func Verify(kind string, s Signed, keys map[string]*ecdsa.PublicKey, out any) error {
	k := keys[s.KeyID]
	if !ID(kind) || !ID(s.KeyID) || k == nil || k.Curve != elliptic.P256() || k.X == nil || k.Y == nil || !k.Curve.IsOnCurve(k.X, k.Y) || len(s.Payload) > MaxBytes {
		return ErrInvalid
	}
	b, err := Canonical(s.Payload)
	if err != nil {
		return ErrInvalid
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || len(sig) > 128 || base64.StdEncoding.EncodeToString(sig) != s.Signature {
		return ErrInvalid
	}
	h := sha256.Sum256(message(kind, s.KeyID, b))
	if !ecdsa.VerifyASN1(k, h[:], sig) {
		return ErrInvalid
	}
	return Decode(b, out)
}
func interval(start, end string, now time.Time, max time.Duration, live bool) error {
	a, e := time.Parse(time.RFC3339, start)
	if e != nil || a.UTC().Format(time.RFC3339) != start {
		return ErrInvalid
	}
	b, e := time.Parse(time.RFC3339, end)
	if e != nil || b.UTC().Format(time.RFC3339) != end || !b.After(a) || b.Sub(a) > max {
		return ErrInvalid
	}
	if live && (now.Before(a) || !now.Before(b)) {
		return ErrInvalid
	}
	return nil
}

type Artifact struct {
	Role   string `json:"role"`
	Digest string `json:"digest"`
	Bytes  uint64 `json:"size_bytes"`
}
type SlotImage struct {
	Slot      string     `json:"slot"`
	RootHash  string     `json:"verity_root_hash"`
	Artifacts []Artifact `json:"artifacts"`
}
type Release struct {
	Header
	ID              string      `json:"release_id"`
	Profile         string      `json:"profile_id"`
	Layout          string      `json:"layout_digest"`
	Source          string      `json:"source_revision"`
	StateFormat     uint64      `json:"state_format"`
	ReadableFormats []uint64    `json:"readable_state_formats"`
	Catalog         string      `json:"catalog_digest"`
	Images          []SlotImage `json:"images"`
}

func (r Release) Validate() error {
	if !r.Header.Valid("ApplianceRelease") || !ID(r.ID) || !ID(r.Profile) || !IsDigest(r.Layout) || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(r.Source) || (r.StateFormat == 0 || r.StateFormat > 9007199254740991) || !IsDigest(r.Catalog) || len(r.Images) != 2 {
		return ErrInvalid
	}
	formats := map[uint64]bool{}
	for _, f := range r.ReadableFormats {
		if f == 0 || f > 9007199254740991 || formats[f] {
			return ErrInvalid
		}
		formats[f] = true
	}
	if !formats[r.StateFormat] {
		return ErrInvalid
	}
	for n, img := range r.Images {
		if img.Slot != []string{"A", "B"}[n] || !IsDigest(img.RootHash) || len(img.Artifacts) != 4 {
			return ErrInvalid
		}
		for j, a := range img.Artifacts {
			if a.Role != []string{"boot", "root", "hash", "metadata"}[j] || !IsDigest(a.Digest) || a.Bytes == 0 || a.Bytes > 9007199254740991 {
				return ErrInvalid
			}
		}
	}
	return nil
}
func (r Release) Image(slot string) (SlotImage, error) {
	for _, i := range r.Images {
		if i.Slot == slot {
			return i, nil
		}
	}
	return SlotImage{}, ErrInvalid
}

type Offer struct {
	Header
	Sequence      uint64   `json:"sequence"`
	Attempt       string   `json:"attempt_id"`
	Identity      Identity `json:"identity"`
	Current       string   `json:"current_release"`
	Target        string   `json:"target_release"`
	Slot          string   `json:"inactive_slot"`
	ReleaseDigest string   `json:"release_index_digest"`
	Layout        string   `json:"layout_digest"`
	Scope         string   `json:"scope"`
	Campaign      string   `json:"qualification_grant,omitempty"`
	Issued        string   `json:"issued_at"`
	Expires       string   `json:"expires_at"`
}

func (o Offer) Validate(now time.Time, live bool) error {
	if o.Sequence == 0 || o.Sequence > 9007199254740991 || !o.Header.Valid("ApplianceUpdateOffer") || o.Identity.Validate() != nil || !ID(o.Attempt) || !ID(o.Current) || !ID(o.Target) || o.Current == o.Target || (o.Slot != "A" && o.Slot != "B") || !IsDigest(o.ReleaseDigest) || !IsDigest(o.Layout) {
		return ErrInvalid
	}
	if (o.Scope == "production" && o.Campaign != "") || (o.Scope == "qualification" && !IsDigest(o.Campaign)) || (o.Scope != "production" && o.Scope != "qualification") {
		return ErrInvalid
	}
	return interval(o.Issued, o.Expires, now, 24*time.Hour, live)
}

type Lease struct {
	Header
	ID          string   `json:"lease_id"`
	Attempt     string   `json:"attempt_id"`
	OfferDigest string   `json:"offer_digest"`
	Phase       string   `json:"phase"`
	Identity    Identity `json:"identity"`
	Certificate string   `json:"certificate_digest"`
	Issued      string   `json:"issued_at"`
	Expires     string   `json:"expires_at"`
}

func (l Lease) Validate(now time.Time, live bool) error {
	if !l.Header.Valid("ApplianceUpdateLease") || !ID(l.ID) || !ID(l.Attempt) || !IsDigest(l.OfferDigest) || l.Identity.Validate() != nil || !IsDigest(l.Certificate) || (l.Phase != "install" && l.Phase != "activate") {
		return ErrInvalid
	}
	return interval(l.Issued, l.Expires, now, 5*time.Minute, live)
}

type Challenge struct {
	Header
	ID           string   `json:"operation_id"`
	Identity     Identity `json:"identity"`
	Purpose      string   `json:"purpose"`
	PublicKey    string   `json:"public_key_spki"`
	Provisioning string   `json:"provisioning_digest"`
	Predecessor  string   `json:"predecessor_certificate_digest,omitempty"`
	Nonce        string   `json:"nonce"`
	Issued       string   `json:"issued_at"`
	Expires      string   `json:"expires_at"`
}

func (c Challenge) Validate(now time.Time, live bool) error {
	k, e := PublicKey(c.PublicKey)
	if !c.Header.Valid("ProductionCredentialChallenge") || !ID(c.ID) || c.Identity.Validate() != nil || e != nil || SPKIDigest(k) != c.Identity.SPKI || !IsDigest(c.Provisioning) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(c.Nonce) {
		return ErrInvalid
	}
	if c.Purpose != "enroll" && c.Purpose != "renew" && c.Purpose != "recover" && c.Purpose != "installed" {
		return ErrInvalid
	}
	if (c.Purpose == "enroll" && c.Predecessor != "") || (c.Purpose != "enroll" && !IsDigest(c.Predecessor)) {
		return ErrInvalid
	}
	return interval(c.Issued, c.Expires, now, 2*time.Minute, live)
}

type SandboxLifecycle struct {
	Header
	Catalog     string `json:"catalog_digest"`
	Instance    string `json:"instance_id"`
	Release     string `json:"release_id"`
	StateFormat uint64 `json:"state_format"`
	Ready       bool   `json:"ready"`
	Quiesced    bool   `json:"quiesced"`
	Operation   string `json:"operation_id"`
}

func (s SandboxLifecycle) Validate() error {
	if !s.Header.Valid("SandboxLifecycle") || !IsDigest(s.Catalog) || !ID(s.Instance) || !ID(s.Release) || (s.StateFormat == 0 || s.StateFormat > 9007199254740991) || !ID(s.Operation) {
		return ErrInvalid
	}
	return nil
}

type Receipt struct {
	Header
	Identity    Identity   `json:"identity"`
	Attempt     string     `json:"attempt_id"`
	OfferDigest string     `json:"offer_digest"`
	Current     string     `json:"current_release"`
	Target      string     `json:"target_release"`
	Slot        string     `json:"slot"`
	Phase       string     `json:"phase"`
	Sequence    uint64     `json:"sequence"`
	Journal     string     `json:"journal_digest"`
	Readback    []Artifact `json:"readback"`
	BootID      string     `json:"boot_id,omitempty"`
	Outcome     string     `json:"outcome"`
}

func (r Receipt) Validate() error {
	if !r.Header.Valid("ApplianceUpdateReceipt") || r.Identity.Validate() != nil || !ID(r.Attempt) || !IsDigest(r.OfferDigest) || !ID(r.Current) || !ID(r.Target) || (r.Slot != "A" && r.Slot != "B") || !ID(r.Phase) || r.Sequence == 0 || !IsDigest(r.Journal) {
		return ErrInvalid
	}
	if r.Sequence > 9007199254740991 || r.Current == r.Target || (r.BootID != "" && !ID(r.BootID)) {
		return ErrInvalid
	}
	phases := map[string]string{"writing": "reconciliation", "staged": "pending", "trial_arming": "reconciliation", "trial": "pending", "committing": "reconciliation", "committed": "pending", "confirmed": "confirmed", "fallback": "fallback", "fallback_pending": "pending", "reconciliation": "reconciliation"}
	if phases[r.Phase] != r.Outcome {
		return ErrInvalid
	}
	if len(r.Readback) != 0 && len(r.Readback) != 4 {
		return ErrInvalid
	}
	for n, a := range r.Readback {
		if a.Role != []string{"boot", "root", "hash", "metadata"}[n] || !IsDigest(a.Digest) || a.Bytes == 0 || a.Bytes > 9007199254740991 {
			return ErrInvalid
		}
	}
	if r.Outcome == "confirmed" && (r.BootID == "" || len(r.Readback) != 4) {
		return ErrInvalid
	}
	if r.Outcome != "pending" && r.Outcome != "confirmed" && r.Outcome != "fallback" && r.Outcome != "reconciliation" {
		return ErrInvalid
	}
	return nil
}

// QualificationGrant is an operator-approved bounded transition before fleet
// admission. Its digest binds the physical board and terminal provisioning record.
type QualificationGrant struct {
	Header
	ID            string   `json:"grant_id"`
	Identity      Identity `json:"identity"`
	Board         string   `json:"board_digest"`
	Provisioning  string   `json:"provisioning_digest"`
	Current       string   `json:"current_release"`
	Target        string   `json:"target_release"`
	ReleaseDigest string   `json:"release_index_digest"`
	Layout        string   `json:"layout_digest"`
	Issued        string   `json:"issued_at"`
	Expires       string   `json:"expires_at"`
}

func (g QualificationGrant) Validate(now time.Time, live bool) error {
	if !g.Header.Valid("ApplianceQualificationGrant") || !ID(g.ID) || g.Identity.Validate() != nil || !IsDigest(g.Board) || !IsDigest(g.Provisioning) || !ID(g.Current) || !ID(g.Target) || g.Current == g.Target || !IsDigest(g.ReleaseDigest) || !IsDigest(g.Layout) {
		return ErrInvalid
	}
	return interval(g.Issued, g.Expires, now, 24*time.Hour, live)
}

// Diagnostics contains fixed event codes, never free-form command output,
// application logs, certificate material, paths, environment, or unlock data.
type Diagnostic struct {
	Code    string `json:"code"`
	At      string `json:"at"`
	Attempt string `json:"attempt_id,omitempty"`
}
type Diagnostics struct {
	Header
	Identity Identity     `json:"identity"`
	Sequence uint64       `json:"sequence"`
	Entries  []Diagnostic `json:"entries"`
}

func (d Diagnostics) Validate() error {
	if !d.Header.Valid("ApplianceDiagnostics") || d.Identity.Validate() != nil || d.Sequence == 0 || d.Sequence > 9007199254740991 || len(d.Entries) > 128 {
		return ErrInvalid
	}
	for _, entry := range d.Entries {
		switch entry.Code {
		case "poll-failed", "credential-denied", "update-deferred", "update-overdue", "update-staged", "trial-started", "update-confirmed", "update-fallback", "reconciliation-required":
		default:
			return ErrInvalid
		}
		t, e := time.Parse(time.RFC3339, entry.At)
		if e != nil || t.UTC().Format(time.RFC3339) != entry.At || (entry.Attempt != "" && !ID(entry.Attempt)) {
			return ErrInvalid
		}
	}
	return nil
}
