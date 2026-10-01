//go:build linux

package pilotenrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
	"math/big"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestTrustContinuationRetainsIdentityHistoryAndRequiresReview(t *testing.T) {
	var binding renewalBinding
	denied := false
	c, server, dir, ca, key := readTestClientIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		if denied {
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(canon(renewalSelf{"pilot", "instance", canon(binding), false}))
	})
	binding, _ = renewalFixture(t, c)
	// Use a real leaf below the CA. The shared legacy fixture presents its
	// self-signed CA as a server leaf, which cannot chain to a different root DER.
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(50), Subject: pkix.Name{CommonName: "fixture server"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, IPAddresses: ca.IPAddresses, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server.TLS.Certificates[0].Certificate = [][]byte{serverDER}

	next := *ca
	next.SerialNumber = big.NewInt(31)
	next.NotAfter = time.Now().Add(45 * 24 * time.Hour)
	// Preserve the original signed extensions byte-for-byte, including ordering.
	next.ExtraExtensions = ca.Extensions
	der, e := x509.CreateCertificate(rand.Reader, &next, &next, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	st, _ := c.Status()
	now := time.Now()
	q := TrustContinuation{Schema: "kaiba.pilot-device-trust-continuation/v1alpha1", Operation: "trust-1", Approval: Ref{"urn:owner:review", handoff.Digest([]byte("review"))}, Enrollment: st.Enrollment, Logical: st.Logical, SPKI: st.SPKIDigest, Credential: CertificateDigest(c.value.Certificate), OldServer: trustDigest(c.value.Config.ServerCA), OldIssuer: trustDigest(c.value.Config.IssuerCA), Server: cert, Issuer: cert, From: now.Add(-time.Minute).UTC().Format(time.RFC3339Nano), Expires: now.Add(time.Hour).UTC().Format(time.RFC3339Nano)}
	raw := canon(q)
	digest := handoff.Digest(raw)
	original := canon(c.value)
	oldKey := append([]byte(nil), c.value.Key...)
	config := c.value.Config
	c.runtime.ClockCertain = func() bool { return false }
	if _, e = c.ContinueTrust(context.Background(), raw, digest); e == nil {
		t.Fatal("uncertain clock accepted")
	}
	c.runtime.ClockCertain = func() bool { return true }
	if _, e = c.ContinueTrust(context.Background(), raw, handoff.Digest([]byte("other"))); e == nil {
		t.Fatal("unreviewed packet accepted")
	}
	denied = true
	if _, e = c.ContinueTrust(context.Background(), raw, digest); e == nil {
		t.Fatal("revoked membership accepted")
	}
	denied = false
	if !bytes.Equal(original, canon(c.value)) {
		t.Fatal("failed attempt changed state")
	}
	result, e := c.ContinueTrust(context.Background(), raw, digest)
	if e != nil {
		t.Fatal(e)
	}
	if c.value.Config != config || !bytes.Equal(c.value.Key, oldKey) || len(c.value.TrustHistory) != 1 || c.value.effectiveTrust().IssuerCA != cert {
		t.Fatal("original state changed or trust unavailable")
	}
	after := c.value
	after.TrustHistory = nil
	if !bytes.Equal(canon(after), original) {
		t.Fatal("membership/history rewritten")
	}
	if _, e = c.CheckAccess(context.Background()); e != nil {
		t.Fatal(e)
	}
	runtime := c.runtime
	c.Close()
	c, e = Open(dir, runtime)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	repeat, e := c.ContinueTrust(context.Background(), raw, digest)
	if e != nil || !reflect.DeepEqual(repeat, result) {
		t.Fatal("idempotent restart", e)
	}
	changed := q
	changed.Credential = handoff.Digest([]byte("other"))
	if _, e = c.ContinueTrust(context.Background(), canon(changed), handoff.Digest(canon(changed))); e == nil {
		t.Fatal("operation substitution accepted")
	}
	damaged := c.value
	damaged.TrustHistory = append([]trustContinuationReceipt(nil), damaged.TrustHistory...)
	damaged.TrustHistory[0].Request.OldIssuer = handoff.Digest([]byte("other"))
	if damaged.validate() == nil {
		t.Fatal("history corruption accepted")
	}
}
