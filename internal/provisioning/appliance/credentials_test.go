package appliance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	w "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/appliancewire"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type credentialFixture struct {
	now       time.Time
	ca        *x509.Certificate
	caKey     *ecdsa.PrivateKey
	id        w.Identity
	public    string
	provision string
	ch        w.Challenge
	result    *w.CredentialResult
	issued    int
	failAck   bool
	revoked   bool
	alter     bool
	current   string
}

func (f *credentialFixture) Challenge(i w.Identity, p string) (w.Challenge, error) {
	if i != f.id || f.revoked {
		return w.Challenge{}, ErrDenied
	}
	pre := ""
	if f.current != "" {
		cert, _ := w.ParseCertificate(f.current)
		pre = w.Digest(cert.Raw)
	}
	f.ch = w.Challenge{Header: w.NewHeader("ProductionCredentialChallenge"), ID: "operation-" + f.now.Format("20060102T150405"), Identity: i, Purpose: p, PublicKey: f.public, Provisioning: f.provision, Predecessor: pre, Nonce: "0123456789012345678901234567890123456789012345678901234567890123", Issued: f.now.UTC().Format(time.RFC3339), Expires: f.now.Add(time.Minute).UTC().Format(time.RFC3339)}
	return f.ch, nil
}
func (f *credentialFixture) Prove(i w.Identity, p w.Signed) (w.CredentialResult, error) {
	if i != f.id || f.revoked {
		return w.CredentialResult{}, ErrDenied
	}
	var ch w.Challenge
	k, _ := w.PublicKey(f.public)
	if w.Verify("credential-proof", p, map[string]*ecdsa.PublicKey{"device": k}, &ch) != nil {
		return w.CredentialResult{}, ErrDenied
	}
	a, _ := w.Encode(ch)
	b, _ := w.Encode(f.ch)
	if string(a) != string(b) {
		return w.CredentialResult{}, ErrDenied
	}
	if f.result != nil && f.result.Operation == ch.ID {
		return *f.result, nil
	}
	if ch.Validate(f.now, true) != nil {
		return w.CredentialResult{}, ErrDenied
	}
	f.issued++
	uri, _ := w.CertificateURI(i)
	c := &x509.Certificate{SerialNumber: big.NewInt(int64(10 + f.issued)), NotBefore: f.now.Add(-time.Second), NotAfter: f.now.Add(30*24*time.Hour - time.Second), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
	der, e := x509.CreateCertificate(rand.Reader, c, f.ca, k, f.caKey)
	if e != nil {
		return w.CredentialResult{}, e
	}
	r := w.CredentialResult{Header: w.NewHeader("ProductionCredentialResult"), Operation: ch.ID, Identity: i, ChallengeDigest: w.Digest(a), Certificate: base64.StdEncoding.EncodeToString(der)}
	f.result = &r
	if f.alter {
		r.Identity.Storage++
	}
	return r, nil
}
func (f *credentialFixture) Installed(i w.Identity, p w.Signed) error {
	if i != f.id || f.revoked {
		return ErrDenied
	}
	var result w.CredentialResult
	k, _ := w.PublicKey(f.public)
	if w.Verify("credential-installed", p, map[string]*ecdsa.PublicKey{"device": k}, &result) != nil {
		return ErrDenied
	}
	a, _ := w.Encode(result)
	b, _ := w.Encode(f.result)
	if string(a) != string(b) {
		return ErrDenied
	}
	f.current = result.Certificate
	if f.failAck {
		f.failAck = false
		return ErrDeferred
	}
	return nil
}
func credentialsFixture(t *testing.T) (*Credentials, *credentialFixture, *x509.CertPool, string) {
	t.Helper()
	clock := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: clock.Add(-time.Hour), NotAfter: clock.AddDate(2, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ = x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	f := &credentialFixture{now: clock, ca: ca, caKey: k, provision: w.Digest([]byte("provisioning"))}
	id := w.Identity{Authority: "fixture", Tenant: "tenant", Device: "pi", Instance: "unit", Profile: "shipping-rpi5", Storage: 1, Slot: "management", Generation: 1}
	dir := filepath.Join(t.TempDir(), "credentials")
	os.Mkdir(dir, 0700)
	c, e := CreateCredentials(dir, "volume", id, f.provision, roots, func() time.Time { return f.now }, func(*os.File, string) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	f.id = c.Identity()
	f.public, _ = c.PublicKey()
	return c, f, roots, dir
}
func TestCredentialsLostAcknowledgementRebootRenewAndExpiredRecovery(t *testing.T) {
	c, f, roots, dir := credentialsFixture(t)
	f.failAck = true
	if e := c.Maintain(f); e != ErrDeferred {
		t.Fatal(e)
	}
	if _, e := c.TLSCertificate(); e != nil {
		t.Fatal(e)
	}
	c.Close()
	var e error
	c, e = OpenCredentials(dir, "volume", f.id, f.provision, roots, func() time.Time { return f.now }, func(*os.File, string) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if e = c.Maintain(f); e != nil || f.issued != 1 {
		t.Fatal("lost acknowledgement duplicated issuance", e)
	}
	spki := c.Identity().SPKI
	f.now = f.now.Add(21 * 24 * time.Hour)
	if e = c.Maintain(f); e != nil || f.issued != 2 {
		t.Fatal("renewal", e)
	}
	cert, _ := w.ParseCertificate(f.current)
	f.now = cert.NotAfter.Add(time.Second)
	if _, e = c.TLSCertificate(); e == nil {
		t.Fatal("expired credential sent")
	}
	if e = c.Maintain(f); e != nil || f.issued != 3 || spki != c.Identity().SPKI {
		t.Fatal("same key recovery", e)
	}
	cert, _ = w.ParseCertificate(f.current)
	f.now = cert.NotAfter.Add(time.Second)
	f.revoked = true
	if e = c.Maintain(f); e == nil {
		t.Fatal("revoked recovery")
	}
}
func TestCredentialBindingMutationAndMissingKeyNeverRekeys(t *testing.T) {
	c, f, roots, dir := credentialsFixture(t)
	f.alter = true
	if e := c.Maintain(f); e == nil {
		t.Fatal("wrong identity installed")
	}
	c.Close()
	if e := os.Remove(filepath.Join(dir, "state.json")); e != nil {
		t.Fatal(e)
	}
	if recovered, e := OpenCredentials(dir, "volume", f.id, f.provision, roots, func() time.Time { return f.now }, func(*os.File, string) error { return nil }); e == nil {
		recovered.Close()
		t.Fatal("missing key recreated")
	}
}
func TestCredentialsReconcileExpiredInstalledResult(t *testing.T) {
	c, f, _, _ := credentialsFixture(t)
	defer c.Close()
	f.failAck = true
	if e := c.Maintain(f); e != ErrDeferred {
		t.Fatal(e)
	}
	f.now = f.now.Add(31 * 24 * time.Hour)
	if e := c.Maintain(f); e != nil {
		t.Fatal("expired pending acknowledgement", e)
	}
	if e := c.Maintain(f); e != nil || f.issued != 2 {
		t.Fatal("recovery after pending acknowledgement", e)
	}
}
