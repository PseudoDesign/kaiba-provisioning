//go:build linux

package pilotenrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	wire "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func renewalFixture(t *testing.T, c *Client) (renewalBinding, renewalApproval) {
	t.Helper()
	s := c.value
	st, _ := s.status()
	leaf, _ := s.leaf(time.Now())
	b := s.Config.Binding
	stamp := func(v time.Time) string { return v.UTC().Format(time.RFC3339Nano) }
	now := time.Now().Add(-time.Second)
	meta := renewalMetadata{"PilotDeviceBinding", "0.2.0-draft.1", "predecessor", 2, stamp(now), "inventory", "tenant", "pilot", "instance"}
	p := renewalBinding{renewalMetadata: meta, Logical: st.Logical, Instance: st.Enrollment, Storage: 1, Bootstrap: Ref{"urn:fixture:bootstrap", wire.Digest([]byte("fixture"))}, Credential: credential{"management", "pilot_management", 1, st.SPKIDigest, b.Issuer, leaf.SerialNumber.Text(16), stamp(leaf.NotBefore), stamp(leaf.NotAfter)}, State: "active", Target: b.Target, Adoption: b.Adoption, Policy: b.Policy, Admission: b.Decision, Audience: b.Audience, Profile: b.Profile, Permissions: []string{"pilot:self:read", "pilot:diagnostic-reference:submit"}, Activation: &renewalActivation{}}
	a := renewalAuthorization{renewalMetadata: renewalMetadata{"PilotRenewalAuthorization", "0.3.0-draft.1", "authorization", 1, stamp(now), p.Authority, p.Tenant, p.Domain, "renewal-2"}, Mode: "same_key_unexpired", Operation: "renewal-2", Logical: p.Logical, Instance: p.Instance, Storage: 1, Target: p.Target, Adoption: p.Adoption, Policy: p.Policy, Admission: p.Admission, Audience: p.Audience, Profile: p.Profile, Permissions: p.Permissions, Predecessor: renewalRef(p, p.renewalMetadata), Certificate: CertificateDigest(s.Certificate), Previous: 1, Next: 2, Slot: "management", Generation: 1, SPKI: st.SPKIDigest, Issuer: b.Issuer, From: stamp(now), Expires: stamp(now.Add(20 * time.Minute))}
	req := renewalRequest{a.Operation, renewalRecords{renewalSelection{"adoption", a.Adoption}, renewalSelection{"policy", a.Policy}, renewalSelection{"decision", a.Admission}}, a.Expires, a.Predecessor, a.Certificate}
	ch := renewalKeyChallenge{"kaiba.pilot-renewal-key-proof/v1alpha1", "pilot_renewal_key_possession", a.Operation, p.Instance, renewalRef(a, a.renewalMetadata), a.Certificate, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", stamp(now), stamp(now.Add(5 * time.Minute))}
	return p, renewalApproval{Request: req, Authorization: a, Challenge: ch, State: "awaiting_proof"}
}
func TestRenewalDurableRecoveryAndCredentialSelection(t *testing.T) {
	var c *Client
	var old renewalBinding
	var approved renewalApproval
	var installation renewalInstallation
	keyPosts, installPosts := 0, 0
	dropKey, dropInstall, denySelf := true, true, false
	handler := func(w http.ResponseWriter, r *http.Request) {
		path := strings.ReplaceAll(r.URL.Path, "renewal-3", "renewal-2")
		write := func(v any) { w.Header().Set("Content-Type", "application/json"); w.Write(canon(v)) }
		switch path {
		case "/api/v1/pilot/self":
			if denySelf {
				w.WriteHeader(503)
				return
			}
			b := old
			if installation.State == "active" {
				if wire.Digest(r.TLS.PeerCertificates[0].Raw) != CertificateDigest(installation.Certificate) {
					w.WriteHeader(403)
					return
				}
				b = *installation.Active
			}
			write(renewalSelf{"pilot", old.Instance, canon(b), false})
		case "/api/v1/pilot/enrollments/instance/renewals/renewal-2/proof":
			keyPosts++
			raw, _ := io.ReadAll(r.Body)
			var proof Proof
			decode(raw, &proof)
			if approved.Signature != "" && approved.Signature != proof.Signature {
				t.Error("key proof re-signed")
			}
			approved = c.value.Renewal.Approval
			approved.State = "proof_verified"
			approved.Signature = proof.Signature
			approved.Verified = time.Now().UTC().Format(time.RFC3339Nano)
			if dropKey {
				dropKey = false
				conn, _, _ := w.(http.Hijacker).Hijack()
				conn.Close()
				return
			}
			write(approved)
		case "/api/v1/pilot/enrollments/instance/renewals/renewal-2/installation":
			write(installation)
		case "/api/v1/pilot/enrollments/instance/renewals/renewal-2/install-challenge":
			write(installation)
		case "/api/v1/pilot/enrollments/instance/renewals/renewal-2/installed-proof":
			installPosts++
			raw, _ := io.ReadAll(r.Body)
			var proof Proof
			decode(raw, &proof)
			if installation.Signature != "" && installation.Signature != proof.Signature {
				t.Error("installation proof re-signed")
			}
			installation.Signature = proof.Signature
			installation.State = "verified"
			ch := installation.Challenge
			ev := struct {
				Challenge *renewalInstallChallenge `json:"challenge"`
				Signature string                   `json:"signature"`
			}{ch, proof.Signature}
			now := time.Now().UTC().Format(time.RFC3339Nano)
			installation.Receipt = &renewalInstallReceipt{renewalMetadata: renewalMetadata{"PilotRenewalInstallationReceipt", "0.3.0-draft.1", "receipt", 1, now, old.Authority, old.Tenant, old.Domain, "renewal-2"}, renewalInstallFields: ch.renewalInstallFields, Proof: Ref{"urn:kaiba:evidence:" + wire.Digest(canon(ev)), wire.Digest(canon(ev))}, Verified: now}
			if dropInstall {
				dropInstall = false
				conn, _, _ := w.(http.Hijacker).Hijack()
				conn.Close()
				return
			}
			write(installation)
		default:
			t.Errorf("unexpected route %s", path)
			w.WriteHeader(404)
		}
	}
	var d string
	var issuer *x509.Certificate
	client, _, dir, ca, issuerKey := readTestClientIssuer(t, handler)
	c = client
	d = dir
	issuer = ca
	old, approved = renewalFixture(t, c)
	input := canon(approved)
	original := c.value.Certificate
	key := append([]byte(nil), c.value.Key...)
	if _, e := c.PrepareRenewal(context.Background(), input); !errors.Is(e, ErrReconcile) {
		t.Fatalf("expected lost reply: %v", e)
	}
	if keyPosts != 1 || c.value.Renewal.Phase != "prepared" {
		t.Fatal("missing durable intent")
	}
	signature := c.value.Renewal.Proof
	if _, e := c.PrepareRenewal(context.Background(), input); !errors.Is(e, ErrReconcile) || keyPosts != 1 {
		t.Fatal("automatic retry")
	}
	restart := func(name string) {
		r := c.runtime
		c.Close()
		r.Process = name
		var e error
		c, e = Open(d, r)
		if e != nil {
			t.Fatal(e)
		}
	}
	restart("renewal-install")
	defer func() { c.Close() }()
	if _, e := c.RetryRenewalProof(context.Background()); e != nil || c.value.Renewal.Proof != signature {
		t.Fatalf("proof reconciliation: %v", e)
	}
	a := c.value.Renewal.Approval.Authorization
	before := renewalTime(a.From).Truncate(time.Second).Add(time.Second)
	after := renewalTime(a.Expires).Truncate(time.Second)
	uri, _ := url.Parse(DeviceURI(old.Logical, old.Instance))
	private, _ := privateKey(c.value.Key)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(99), NotBefore: before, NotAfter: after, URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, issuer, &private.PublicKey, issuerKey)
	if e != nil {
		t.Fatal(e)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	b := old
	b.renewalMetadata = renewalMetadata{"PilotDeviceBinding", "0.3.0-draft.1", "successor", 1, time.Now().UTC().Format(time.RFC3339Nano), old.Authority, old.Tenant, old.Domain, a.Operation}
	b.State = "staged"
	b.Activation = nil
	b.Credential.Serial = "63"
	b.Credential.Before = before.UTC().Format(time.RFC3339Nano)
	b.Credential.After = after.UTC().Format(time.RFC3339Nano)
	b.CredentialRevision = 2
	b.CertificateDigest = CertificateDigest(cert)
	authRef := renewalRef(a, a.renewalMetadata)
	b.RenewalRef = &authRef
	b.PredecessorRef = &a.Predecessor
	installation = renewalInstallation{State: "staged", Approval: approved, Predecessor: response{ID: old.Instance, Logical: old.Logical, State: "active", Intent: c.value.Config.Binding, Certificate: original, Binding: canon(old)}, Certificate: cert, Staged: b}
	// Loss of the storage guard must not write the pending certificate.
	guard := c.runtime.CheckStorage
	c.runtime.CheckStorage = func(*os.File, string) error { return ErrStorage }
	if _, e = c.InstallRenewal(context.Background()); !errors.Is(e, ErrStorage) {
		t.Fatalf("storage guard: %v", e)
	}
	c.runtime.CheckStorage = guard
	if _, e = c.InstallRenewal(context.Background()); e != nil {
		t.Fatal(e)
	}
	if c.value.Certificate != original || !sameRenewal(c.value.Key, key) {
		t.Fatal("predecessor/key overwritten")
	}
	if _, e = c.ProveRenewalInstalled(context.Background()); e != ErrRestart {
		t.Fatalf("same-process proof allowed: %v", e)
	}
	now := time.Now()
	installation.Challenge = &renewalInstallChallenge{renewalInstallFields{"pilot_renewal_installed_key", a.Operation, authRef, a.Predecessor, renewalRef(b, b.renewalMetadata), b.CertificateDigest, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now.UTC().Format(time.RFC3339Nano), now.Add(4 * time.Minute).UTC().Format(time.RFC3339Nano), "client_process"}, old.Tenant, old.Domain}
	restart("renewal-proof")
	if _, e = c.ProveRenewalInstalled(context.Background()); !errors.Is(e, ErrReconcile) {
		t.Fatalf("lost install proof: %v", e)
	}
	if _, e = c.ProveRenewalInstalled(context.Background()); e != ErrReconcile || installPosts != 1 {
		t.Fatal("proof automatically repeated")
	}
	restart("renewal-recovery")
	if _, e = c.RetryRenewalInstalled(context.Background()); e != nil || installPosts != 1 {
		t.Fatalf("proof read reconciliation: %v", e)
	}
	active := b
	active.State = "active"
	active.Revision++
	active.Issued = time.Now().UTC().Format(time.RFC3339Nano)
	receiptRef := renewalRef(*installation.Receipt, installation.Receipt.renewalMetadata)
	active.InstallationRef = &receiptRef
	active.Activation = &renewalActivation{active.Issued, Ref{"urn:kaiba:evidence:" + receiptRef.Digest, receiptRef.Digest}, active.Policy, "client_process"}
	installation.Active = &active
	installation.State = "active"
	denySelf = true
	if _, e = c.ReconcileRenewal(context.Background()); e == nil || c.value.Renewal.Phase != "verified" {
		t.Fatal("historical result activated local credential without current self")
	}
	denySelf = false
	restart("renewal-local-cutover")
	if _, e = c.ReconcileRenewal(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e = c.CheckAccess(context.Background()); e != nil {
		t.Fatal(e)
	}
	saved, _ := os.ReadFile(filepath.Join(d, "state.json"))
	var stored state
	if json.Unmarshal(saved, &stored) != nil || stored.Renewal.Phase != "active" || stored.Certificate != original || !sameRenewal(stored.Key, key) {
		t.Fatal("protected history lost")
	}
	// Start a second renewal without rewriting the first operation or original
	// enrollment. Every attempt below opens the same protected state directory.
	archived := *c.value.Renewal
	var next renewalApproval
	if json.Unmarshal(canon(archived.Approval), &next) != nil {
		t.Fatal("fixture")
	}
	next.Request.Operation = "renewal-3"
	next.Authorization.Operation = "renewal-3"
	next.Authorization.ID = "authorization-3"
	next.Authorization.Correlation = "renewal-3"
	next.Authorization.Previous = 2
	next.Authorization.Next = 3
	next.Authorization.Predecessor = renewalRef(*archived.Active, archived.Active.renewalMetadata)
	next.Authorization.Certificate = CertificateDigest(archived.Certificate)
	next.Request.Predecessor = next.Authorization.Predecessor
	next.Request.Certificate = next.Authorization.Certificate
	next.Challenge.Operation = "renewal-3"
	next.Challenge.Authorization = renewalRef(next.Authorization, next.Authorization.renewalMetadata)
	next.Challenge.Certificate = next.Authorization.Certificate
	approved = next
	beforeState := canon(c.value)
	denySelf = true
	if _, e := c.PrepareRenewal(context.Background(), canon(next)); e == nil || !bytes.Equal(beforeState, canon(c.value)) {
		t.Fatal("outage archived current credential")
	}
	denySelf = false
	guard = c.runtime.CheckStorage
	c.runtime.CheckStorage = func(*os.File, string) error { return ErrStorage }
	if _, e := c.PrepareRenewal(context.Background(), canon(next)); !errors.Is(e, ErrStorage) || !bytes.Equal(beforeState, canon(c.value)) {
		t.Fatal("failed save changed current history")
	}
	c.runtime.CheckStorage = guard
	dropKey = true
	if _, e := c.PrepareRenewal(context.Background(), canon(next)); !errors.Is(e, ErrReconcile) {
		t.Fatalf("next lost reply: %v", e)
	}
	if len(c.value.History) != 1 || !sameRenewal(c.value.History[0], archived) || c.value.Renewal.Phase != "prepared" {
		t.Fatal("archive and preparation not retained together")
	}
	sig := c.value.Renewal.Proof
	restart("second-renewal-recovery")
	if _, e := c.CheckAccess(context.Background()); e != nil {
		t.Fatalf("pending operation discarded active predecessor: %v", e)
	}
	if _, e := c.PrepareRenewal(context.Background(), input); !errors.Is(e, ErrBinding) {
		t.Fatal("archived operation replay accepted")
	}
	if _, e := c.RetryRenewalProof(context.Background()); e != nil || c.value.Renewal.Proof != sig {
		t.Fatalf("second exact retry: %v", e)
	}
	if keyPosts != 4 || c.value.Certificate != original || !sameRenewal(c.value.Key, key) {
		t.Fatal("proof re-signed or original state changed")
	}
	for name, mutate := range map[string]func(*state){
		"missing history":     func(v *state) { v.History = nil },
		"duplicate history":   func(v *state) { v.History = append(v.History, v.History[0]) },
		"incomplete history":  func(v *state) { v.History[0].Phase = "verified" },
		"changed certificate": func(v *state) { v.History[0].Certificate = original },
		"changed receipt":     func(v *state) { v.History[0].Receipt.Proof.Digest = "sha256:" + strings.Repeat("0", 64) },
		"revision jump":       func(v *state) { v.Renewal.Approval.Authorization.Next++ },
		"reused operation":    func(v *state) { v.Renewal.Approval.Request.Operation = v.History[0].Approval.Request.Operation },
		"missing current":     func(v *state) { v.Renewal = nil },
	} {
		t.Run(name, func(t *testing.T) {
			var changed state
			json.Unmarshal(canon(c.value), &changed)
			mutate(&changed)
			if changed.validate() == nil {
				t.Fatal("invalid renewal chain accepted")
			}
		})
	}

	// Expired history must remain readable for supervised diagnosis, while
	// current network requests still reject expired credentials.
	rt := c.runtime
	rt.Now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	c.Close()
	c, e = Open(d, rt)
	if e != nil {
		t.Fatalf("expired history could not be reopened: %v", e)
	}
	if _, e = c.CheckAccess(context.Background()); e == nil {
		t.Fatal("expired credential granted access")
	}

}
func TestRenewalApprovalRejectsChangedBindings(t *testing.T) {
	c, _, _ := readTestClient(t, func(http.ResponseWriter, *http.Request) { t.Error("unexpected request") })
	p, a := renewalFixture(t, c)
	if e := validateRenewalApproval(c.value, p, a, time.Now()); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*renewalApproval){
		func(v *renewalApproval) {
			v.Authorization.SPKI = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
		func(v *renewalApproval) { v.Authorization.Next = 3 }, func(v *renewalApproval) { v.Authorization.Target.Asset = "other" },
		func(v *renewalApproval) { v.Challenge.Purpose = "installed_key" }, func(v *renewalApproval) { v.Challenge.Authorization.Revision++ },
		func(v *renewalApproval) { v.Request.Expires = "2099-01-01T00:00:00Z" }, func(v *renewalApproval) { v.Authorization.Permissions = []string{"admin"} },
	} {
		v := a
		mutate(&v)
		if validateRenewalApproval(c.value, p, v, time.Now()) == nil {
			t.Fatal("substituted renewal accepted")
		}
	}
}
