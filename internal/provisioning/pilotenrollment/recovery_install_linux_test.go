//go:build linux

package pilotenrollment

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	wire "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
	"io"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestRecoveryInstallationRestartAndLostReply(t *testing.T) {
	var installation recoveryInstallation
	var c *Client
	posts := 0
	allowSelf := false
	handler := func(w http.ResponseWriter, r *http.Request) {
		write := func(v any) { w.Header().Set("Content-Type", "application/json"); w.Write(canon(v)) }
		switch r.URL.Path {
		case "/api/v1/pilot/enrollments/instance/recoveries/renewal-2/install-challenge":
			write(installation)
		case "/api/v1/pilot/enrollments/instance/recoveries/renewal-2/installed-proof":
			posts++
			raw, _ := io.ReadAll(r.Body)
			var proof Proof
			decode(raw, &proof)
			if !renewalVerify(c.value, *installation.Challenge, proof.Signature) {
				t.Error("wrong signature")
			}
			installation.Signature = proof.Signature
			installation.State = "verified"
			evidence := struct {
				Challenge *renewalInstallChallenge `json:"challenge"`
				Signature string                   `json:"signature"`
			}{installation.Challenge, proof.Signature}
			now := time.Now().UTC().Format(time.RFC3339Nano)
			installation.Receipt = &renewalInstallReceipt{renewalMetadata: renewalMetadata{"PilotRecoveryInstallationReceipt", "0.4.0-draft.1", "receipt", 1, now, installation.Staged.Authority, installation.Staged.Tenant, installation.Staged.Domain, installation.Approval.Request.Operation}, renewalInstallFields: installation.Challenge.renewalInstallFields, Proof: Ref{"urn:kaiba:evidence:" + wire.Digest(canon(evidence)), wire.Digest(canon(evidence))}, Verified: now}
			w.WriteHeader(503) // server saved the result, caller lost its reply
		case "/api/v1/pilot/enrollments/instance/recoveries/renewal-2/installation":
			write(installation)
		case "/api/v1/pilot/self":
			if !allowSelf {
				w.WriteHeader(403)
				return
			}
			if wire.Digest(r.TLS.PeerCertificates[0].Raw) != CertificateDigest(installation.Certificate) {
				t.Error("wrong relying credential")
			}
			write(renewalSelf{"pilot", "instance", canon(*installation.Active), false})
		default:
			t.Errorf("unexpected route %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}
	client, _, dir, ca, key := readTestClientIssuer(t, handler)
	c = client
	packet := recoveryFixture(t, c)
	c.runtime.Now = time.Now
	now := time.Now().Add(-time.Second)
	stamp := func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
	a := &packet.Approval.Authorization
	a.Deadline = stamp(now.Add(-time.Second))
	a.Issued = stamp(now)
	a.From = a.Issued
	a.Expires = stamp(now.Add(20 * time.Minute))
	packet.Approval.Request.Expires = a.Expires
	ch := &packet.Approval.Challenge
	ch.Issued = a.Issued
	ch.Expires = stamp(now.Add(time.Minute))
	ch.Authorization = renewalRef(*a, a.renewalMetadata)
	raw := canon(packet)
	proof, e := c.PrepareRecovery(raw, wire.Digest(raw))
	if e != nil {
		t.Fatal(e)
	}
	oldCert := c.value.Certificate
	oldKey := append([]byte(nil), c.value.Key...)
	oldLeaf, _ := certificate(oldCert)
	tmpl := *oldLeaf
	tmpl.SerialNumber = big.NewInt(999)
	tmpl.NotBefore = renewalTime(a.From).Truncate(time.Second).Add(time.Second)
	tmpl.NotAfter = renewalTime(a.Expires).Truncate(time.Second)
	der, e := x509.CreateCertificate(rand.Reader, &tmpl, ca, oldLeaf.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	b := packet.Predecessor
	b.renewalMetadata = renewalMetadata{"PilotDeviceBinding", "0.4.0-draft.1", "successor", 1, stamp(time.Now()), a.Authority, a.Tenant, a.Domain, a.Operation}
	b.State = "staged"
	b.Activation = nil
	b.InstallationRef = nil
	b.RenewalRef = nil
	ref := renewalRef(*a, a.renewalMetadata)
	b.RecoveryRef = &ref
	pre := a.Predecessor
	b.PredecessorRef = &pre
	b.CredentialRevision = a.Next
	b.CertificateDigest = CertificateDigest(cert)
	b.Credential.Serial = "3e7"
	b.Credential.Before = stamp(tmpl.NotBefore)
	b.Credential.After = stamp(tmpl.NotAfter)
	approved := packet.Approval
	approved.State = "proof_verified"
	approved.Signature = proof.Signature
	approved.Verified = stamp(time.Now())
	installation = recoveryInstallation{State: "staged", Approval: approved, Predecessor: response{ID: "instance", Logical: "logical", State: "active", Certificate: oldCert, Intent: c.value.Config.Binding, Binding: canon(packet.Predecessor)}, Certificate: cert, Staged: b}
	wrong := installation
	wrong.Staged.State = "active"
	if _, e = c.InstallRecovery(canon(wrong)); e == nil {
		t.Fatal("wrong staged state accepted")
	}
	guard := c.runtime.CheckStorage
	c.runtime.CheckStorage = func(*os.File, string) error { return ErrStorage }
	if _, e = c.InstallRecovery(canon(installation)); !errors.Is(e, ErrStorage) || c.value.Recovery.Installation != nil {
		t.Fatal("storage guard ignored")
	}
	c.runtime.CheckStorage = guard
	if _, e = c.InstallRecovery(canon(installation)); e != nil {
		t.Fatal(e)
	}
	if _, e = c.ProveRecoveryInstalled(context.Background()); !errors.Is(e, ErrRestart) {
		t.Fatal("same-process proof permitted")
	}
	rt := c.runtime
	rt.Process = "new-process"
	c.Close()
	c, e = Open(dir, rt)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	fields := renewalInstallFields{"pilot_expired_recovery_installed_key", a.Operation, ref, pre, renewalRef(b, b.renewalMetadata), b.CertificateDigest, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", stamp(time.Now()), stamp(time.Now().Add(time.Minute)), "client_process"}
	installation.Challenge = &renewalInstallChallenge{fields, a.Tenant, a.Domain}
	if _, e = c.ProveRecoveryInstalled(context.Background()); !errors.Is(e, ErrReconcile) {
		t.Fatalf("lost reply: %v", e)
	}
	saved := c.value.Recovery.Installation.Signature
	if _, e = c.ProveRecoveryInstalled(context.Background()); !errors.Is(e, ErrReconcile) {
		t.Fatal("automatic retry allowed")
	}
	if _, e = c.RetryRecoveryInstalled(context.Background()); e != nil {
		t.Fatal(e)
	}
	if posts != 1 || c.value.Recovery.Installation.Signature != saved {
		t.Fatal("proof resigned or resubmitted after saved receipt")
	}
	active := b
	active.State = "active"
	active.Revision++
	active.Issued = stamp(time.Now())
	receiptRef := renewalRef(*installation.Receipt, installation.Receipt.renewalMetadata)
	active.InstallationRef = &receiptRef
	active.Activation = &renewalActivation{active.Issued, Ref{"urn:kaiba:evidence:" + receiptRef.Digest, receiptRef.Digest}, b.Policy, "client_process"}
	installation.Active = &active
	installation.State = "active"
	if _, e = c.ReconcileRecovery(context.Background()); e == nil || c.value.Recovery.Installation.Phase != "verified" {
		t.Fatal("switched before fresh self read")
	}
	allowSelf = true
	if _, e = c.ReconcileRecovery(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e = c.CheckAccess(context.Background()); e != nil {
		t.Fatal(e)
	}
	if c.value.Certificate != oldCert || string(c.value.Key) != string(oldKey) {
		t.Fatal("original identity history changed")
	}
	var tampered state
	decode(canon(c.value), &tampered)
	tampered.Recovery.Installation.Receipt.Contract = "PilotRenewalInstallationReceipt"
	if tampered.validate() == nil {
		t.Fatal("wrong receipt contract accepted")
	}
	t.Run("renewal retains recovery anchor", func(t *testing.T) {
		base := c.value
		zero := 0
		base.RecoveryRenewalStart = &zero
		projected := *c
		projected.value = base.renewalBase()
		_, next := renewalFixture(t, &projected)
		a := &next.Authorization
		a.Operation, a.Correlation = "renewal-after-recovery", "renewal-after-recovery"
		a.Issued, a.From = stamp(time.Now()), stamp(time.Now())
		a.Issued = a.From
		a.Previous, a.Next = 2, 3
		a.Predecessor = renewalRef(active, active.renewalMetadata)
		next.Request.Operation, next.Request.Predecessor = a.Operation, a.Predecessor
		next.Challenge.Operation = a.Operation
		next.Challenge.Issued = a.From
		next.Challenge.Authorization = renewalRef(*a, a.renewalMetadata)
		proof, err := renewalSign(base, next.Challenge)
		if err != nil {
			t.Fatal(err)
		}
		base.Renewal = &renewalState{Phase: "prepared", PreparedAt: stamp(time.Now()), Approval: next, Predecessor: active, Proof: proof}
		if err := base.validate(); err != nil {
			t.Fatal("valid anchored renewal", err)
		}
		for _, mutate := range []func(*state){
			func(s *state) { s.RecoveryRenewalStart = nil },
			func(s *state) { one := 1; s.RecoveryRenewalStart = &one },
			func(s *state) { s.Recovery = nil },
			func(s *state) { s.Recovery.Installation.Phase = "verified" },
			func(s *state) { s.Renewal.Predecessor.RecoveryRef = nil },
		} {
			var bad state
			decode(canon(base), &bad)
			mutate(&bad)
			if bad.validate() == nil {
				t.Fatal("broken recovery history accepted")
			}
		}
	})
	allowSelf = false
	if _, e = c.ReconcileRecovery(context.Background()); e == nil {
		t.Fatal("revocation ignored")
	}
}
