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
	"sync/atomic"
	"testing"
	"time"
)

func TestTrustContinuationRetainsIdentityHistoryAndRequiresReview(t *testing.T) {
	var binding renewalBinding
	denied := false
	var afterRead atomic.Bool
	c, server, dir, ca, key := readTestClientIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		if denied {
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		afterRead.Store(true)
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
	observed, e := c.InspectTrust()
	if e != nil || observed.Server.Digest != q.OldServer || observed.Issuer.Digest != q.OldIssuer || observed.ContinuationCount != 0 || observed.LatestContinuation != "" {
		t.Fatal("original effective trust unavailable", e)
	}
	if _, e = c.ContinueTrust(context.Background(), raw, handoff.Digest([]byte("other"))); e == nil {
		t.Fatal("unreviewed packet accepted")
	}
	denied = true
	if _, e = c.ContinueTrust(context.Background(), raw, digest); e == nil {
		t.Fatal("revoked membership accepted")
	}
	denied = false
	for _, tc := range []struct {
		name      string
		uncertain bool
		offset    time.Duration
	}{
		{"clock lost during read", true, 0},
		{"clock moved backward during read", false, -time.Second},
		{"packet expired during read", false, 2 * time.Hour},
		{"credential expired during read", false, 31 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			afterRead.Store(false)
			c.runtime.ClockCertain = func() bool { return !(tc.uncertain && afterRead.Load()) }
			c.runtime.Now = func() time.Time {
				if afterRead.Load() {
					return now.Add(tc.offset)
				}
				return now
			}
			if _, e := c.ContinueTrust(context.Background(), raw, digest); e == nil {
				t.Fatal("transition accepted after its preconditions changed")
			}
			if !bytes.Equal(original, canon(c.value)) {
				t.Fatal("failed transition changed state")
			}
		})
	}
	c.runtime.ClockCertain = func() bool { return true }
	c.runtime.Now = time.Now
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
	observed, e = c.InspectTrust()
	if e != nil || observed.Server.Digest != handoff.Digest(der) || observed.Issuer.Digest != handoff.Digest(der) || observed.ContinuationCount != 1 || observed.LatestContinuation != digest || observed.Full || !observed.Protected || !observed.ClockCertain {
		t.Fatal("observer did not select installed continuation", e)
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
	restartedObservation, e := c.InspectTrust()
	if e != nil || restartedObservation.Server != observed.Server || restartedObservation.Issuer != observed.Issuer || restartedObservation.LatestContinuation != digest {
		t.Fatal("observer lost selected trust after restart", e)
	}
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
