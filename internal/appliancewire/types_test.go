package appliancewire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testIdentity() Identity {
	return Identity{"authority", "tenant", "device", "instance", "shipping-rpi5", 1, "management", 1, "sha256:" + strings.Repeat("a", 64)}
}
func TestSignaturePurposeKeyAndPayload(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := map[string]*ecdsa.PublicKey{"offer": &k.PublicKey, "other": &k.PublicKey}
	o := Offer{Sequence: 1, Header: NewHeader("ApplianceUpdateOffer"), Attempt: "attempt", Identity: testIdentity(), Current: "release-1", Target: "release-2", Slot: "B", ReleaseDigest: "sha256:" + strings.Repeat("b", 64), Layout: "sha256:" + strings.Repeat("c", 64), Scope: "production", Issued: "2026-10-03T00:00:00Z", Expires: "2026-10-04T00:00:00Z"}
	s, e := Sign("offer", "offer", o, k)
	if e != nil {
		t.Fatal(e)
	}
	var got Offer
	if Verify("offer", s, keys, &got) != nil || got.Identity != o.Identity {
		t.Fatal("valid offer rejected")
	}
	if Verify("lease", s, keys, &got) == nil {
		t.Fatal("cross-purpose signature accepted")
	}
	s.KeyID = "other"
	if Verify("offer", s, keys, &got) == nil {
		t.Fatal("key identifier substitution accepted")
	}
	s.KeyID = "offer"
	s.Payload = json.RawMessage(strings.Replace(string(s.Payload), "release-2", "release-3", 1))
	if Verify("offer", s, keys, &got) == nil {
		t.Fatal("altered offer accepted")
	}
	for _, raw := range []string{`{"contract":"x","contract":"y"}`, `{"contract_version":"0.7.0-draft.1","unknown":1}`} {
		if Decode([]byte(raw), &got) == nil {
			t.Fatal("ambiguous/unknown input accepted")
		}
	}
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, e = Sign("offer", "offer", o, k384); e == nil {
		t.Fatal("unsupported curve")
	}
}
func TestLeaseExpiryAndPhase(t *testing.T) {
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	l := Lease{Header: NewHeader("ApplianceUpdateLease"), ID: "lease", Attempt: "attempt", OfferDigest: "sha256:" + strings.Repeat("b", 64), Phase: "install", Identity: testIdentity(), Certificate: "sha256:" + strings.Repeat("c", 64), Issued: now.Format(time.RFC3339), Expires: now.Add(5 * time.Minute).Format(time.RFC3339)}
	if l.Validate(now, true) != nil {
		t.Fatal("valid lease")
	}
	if l.Validate(now.Add(5*time.Minute), true) == nil {
		t.Fatal("expiry boundary accepted")
	}
	l.Expires = now.Add(6 * time.Minute).Format(time.RFC3339)
	if l.Validate(now, true) == nil {
		t.Fatal("oversized lease")
	}
	l.Expires = now.Add(time.Minute).Format(time.RFC3339)
	l.Phase = "exec"
	if l.Validate(now, true) == nil {
		t.Fatal("command phase accepted")
	}
}
func TestChallengeSPKIAndRecoveryBinding(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := marshalPublic(&k.PublicKey)
	id := testIdentity()
	id.SPKI = SPKIDigest(&k.PublicKey)
	c := Challenge{Header: NewHeader("ProductionCredentialChallenge"), ID: "operation", Identity: id, Purpose: "recover", PublicKey: pub, Provisioning: "sha256:" + strings.Repeat("a", 64), Predecessor: "sha256:" + strings.Repeat("b", 64), Nonce: strings.Repeat("c", 64), Issued: "2026-10-03T00:00:00Z", Expires: "2026-10-03T00:02:00Z"}
	if c.Validate(time.Date(2026, 10, 3, 0, 1, 0, 0, time.UTC), true) != nil {
		t.Fatal("valid recovery challenge")
	}
	c.Identity.SPKI = "sha256:" + strings.Repeat("d", 64)
	if c.Validate(time.Time{}, false) == nil {
		t.Fatal("key substitution")
	}
	c.Identity = id
	c.Predecessor = ""
	if c.Validate(time.Time{}, false) == nil {
		t.Fatal("recovery without predecessor")
	}
}
