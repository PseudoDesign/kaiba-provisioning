//go:build linux

package pilotenrollment

import (
	"context"
	wire "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func recoveryFixture(t *testing.T, c *Client) recoveryPacket {
	t.Helper()
	p, renewal := renewalFixture(t, c)
	leaf, _ := certificate(c.value.Certificate)
	now := leaf.NotAfter.Add(time.Minute)
	c.runtime.Now = func() time.Time { return now }
	stamp := func(v time.Time) string { return v.UTC().Format(time.RFC3339Nano) }
	a := recoveryAuthorization{renewalAuthorization: renewal.Authorization, Approver: "operator", Review: Ref{"urn:fixture:review", wire.Digest([]byte("review"))}, Deadline: stamp(leaf.NotAfter)}
	a.Contract, a.Version, a.Mode = "PilotRecoveryAuthorization", "0.4.0-draft.1", "supervised_same_key_expired"
	a.Issued, a.From, a.Expires = stamp(now.Add(-time.Second)), stamp(now.Add(-time.Second)), stamp(now.Add(24*time.Hour))
	req := recoveryRequest{renewal.Request, a.Review}
	req.Expires = a.Expires
	ch := recoveryChallenge{renewalMetadata: renewalMetadata{"PilotRecoveryKeyChallenge", "0.4.0-draft.1", "challenge", 1, a.Issued, a.Authority, a.Tenant, a.Domain, a.Operation}, Purpose: "pilot_expired_recovery_key_possession", Operation: a.Operation, Instance: a.Instance, Authorization: renewalRef(a, a.renewalMetadata), Predecessor: a.Predecessor, Certificate: a.Certificate, SPKI: a.SPKI, Nonce: strings.Repeat("a", 48), Expires: stamp(now.Add(time.Minute))}
	return recoveryPacket{"kaiba.pilot-recovery-packet/v1alpha1", p, recoveryApproval{Request: req, Authorization: a, Challenge: ch, State: "awaiting_proof"}}
}
func TestRecoveryProofPersistedWithoutNetwork(t *testing.T) {
	requests := 0
	c, _, dir, _, _ := readTestClientIssuer(t, func(w http.ResponseWriter, r *http.Request) { requests++; t.Error("unexpected network request") })
	packet := recoveryFixture(t, c)
	raw := canon(packet)
	digest := wire.Digest(raw)
	originalCert := c.value.Certificate
	originalKey := append([]byte(nil), c.value.Key...)
	proof, e := c.PrepareRecovery(raw, digest)
	if e != nil || !renewalVerify(c.value, packet.Approval.Challenge, proof.Signature) {
		t.Fatalf("proof: %v", e)
	}
	if c.value.Certificate != originalCert || string(c.value.Key) != string(originalKey) || c.value.Renewal != nil {
		t.Fatal("credential changed")
	}
	runtime := c.runtime
	c.Close()
	runtime.Now = func() time.Time { return renewalTime(packet.Approval.Challenge.Expires).Add(time.Hour) }
	reopened, e := Open(dir, runtime)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	before, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	again, e := reopened.PrepareRecovery(raw, digest)
	if e != nil || again != proof {
		t.Fatalf("saved proof: %v", e)
	}
	status, _ := reopened.Status()
	if status.Recovery == nil || status.Recovery.Phase != "proof_prepared" || status.Full {
		t.Fatal("misleading status")
	}
	changed := packet
	changed.Approval.Challenge.Nonce = strings.Repeat("b", 48)
	if _, e = reopened.PrepareRecovery(canon(changed), wire.Digest(canon(changed))); e == nil {
		t.Fatal("changed challenge allowed")
	}
	changed = packet
	changed.Approval.Request.Operation = "replacement"
	if _, e = reopened.PrepareRecovery(canon(changed), wire.Digest(canon(changed))); e == nil {
		t.Fatal("new operation allowed")
	}
	if _, e = reopened.PrepareRenewal(context.Background(), nil); e == nil {
		t.Fatal("renewal bypass")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if string(before) != string(after) || requests != 0 {
		t.Fatal("repeat mutated state or contacted authority")
	}
}
func TestRecoveryRejectsUnboundInputs(t *testing.T) {
	c, _, dir, _, _ := readTestClientIssuer(t, func(w http.ResponseWriter, r *http.Request) { t.Fatal("network") })
	packet := recoveryFixture(t, c)
	cases := map[string]func(*recoveryPacket){
		"purpose":       func(p *recoveryPacket) { p.Approval.Challenge.Purpose = "pilot_renewal_key_possession" },
		"authority":     func(p *recoveryPacket) { p.Approval.Authorization.Authority = "other" },
		"tenant":        func(p *recoveryPacket) { p.Approval.Challenge.Tenant = "other" },
		"review":        func(p *recoveryPacket) { p.Approval.Request.Review.URI = "urn:changed" },
		"review digest": func(p *recoveryPacket) { p.Approval.Authorization.Review.Digest = "bad" },
		"approver":      func(p *recoveryPacket) { p.Approval.Authorization.Approver = "" },
		"key":           func(p *recoveryPacket) { p.Approval.Authorization.SPKI = wire.Digest([]byte("other")) },
		"certificate":   func(p *recoveryPacket) { p.Approval.Authorization.Certificate = wire.Digest([]byte("other")) },
		"predecessor":   func(p *recoveryPacket) { p.Predecessor.Logical = "other" },
		"quarantined":   func(p *recoveryPacket) { p.Predecessor.State = "quarantined" },
		"storage":       func(p *recoveryPacket) { p.Approval.Authorization.Storage++ },
		"permissions":   func(p *recoveryPacket) { p.Approval.Authorization.Permissions = []string{"admin"} },
		"revision":      func(p *recoveryPacket) { p.Approval.Authorization.Next++ },
		"full":          func(p *recoveryPacket) { p.Approval.Authorization.Full = true },
		"not expired": func(p *recoveryPacket) {
			p.Approval.Authorization.Deadline = c.runtime.Now().Add(time.Hour).Format(time.RFC3339Nano)
		},
		"expired challenge": func(p *recoveryPacket) { p.Approval.Challenge.Expires = c.runtime.Now().Format(time.RFC3339Nano) },
		"long challenge": func(p *recoveryPacket) {
			p.Approval.Challenge.Expires = c.runtime.Now().Add(6 * time.Minute).Format(time.RFC3339Nano)
		},
		"nonce":        func(p *recoveryPacket) { p.Approval.Challenge.Nonce = "00" },
		"auth ref":     func(p *recoveryPacket) { p.Approval.Challenge.Authorization.Revision++ },
		"fresh record": func(p *recoveryPacket) { p.Approval.Request.Records.Policy.Ref.Revision++ },
	}
	before, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var p recoveryPacket
			decode(canon(packet), &p)
			mutate(&p)
			raw := canon(p)
			if _, e := c.PrepareRecovery(raw, wire.Digest(raw)); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, e := c.PrepareRecovery(canon(packet), wire.Digest([]byte("wrong packet"))); e == nil {
		t.Fatal("digest bypass")
	}
	if _, e := c.PrepareRecovery([]byte(strings.Repeat(" ", 1048577)), ""); e == nil {
		t.Fatal("oversized input")
	}
	if _, e := c.PrepareRecovery(append(canon(packet), []byte(` {}`)...), wire.Digest(canon(packet))); e == nil {
		t.Fatal("trailing input")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if string(before) != string(after) {
		t.Fatal("rejection wrote state")
	}
	c.value.Renewal = &renewalState{Phase: "prepared"}
	if _, e := c.PrepareRecovery(canon(packet), wire.Digest(canon(packet))); e == nil {
		t.Fatal("pending renewal bypass")
	}
	c.value.Renewal = nil
}

func TestRecoveryStorageAndSavedProofChecks(t *testing.T) {
	c, _, _, _, _ := readTestClientIssuer(t, func(w http.ResponseWriter, r *http.Request) { t.Error("network") })
	packet := recoveryFixture(t, c)
	raw := canon(packet)
	digest := wire.Digest(raw)
	guard := c.runtime.CheckStorage
	c.runtime.CheckStorage = func(*os.File, string) error { return ErrState }
	if _, e := c.PrepareRecovery(raw, digest); e == nil {
		t.Fatal("storage failure ignored")
	}
	if c.value.Recovery != nil {
		t.Fatal("saved on unprotected storage")
	}
	c.runtime.CheckStorage = guard
	if _, e := c.PrepareRecovery(raw, digest); e != nil {
		t.Fatal(e)
	}
	r := *c.value.Recovery
	c.value.Recovery.Signature = "AA=="
	if c.value.validate() == nil {
		t.Fatal("saved invalid signature accepted")
	}
	c.value.Recovery = &r
	c.value.Recovery.Digest = wire.Digest([]byte("other"))
	if c.value.validate() == nil {
		t.Fatal("saved digest mismatch accepted")
	}
	c.value.Recovery.Digest = digest
	c.value.Recovery.Prepared = packet.Approval.Challenge.Expires
	if c.value.validate() == nil {
		t.Fatal("out-of-window signing time accepted")
	}
}
