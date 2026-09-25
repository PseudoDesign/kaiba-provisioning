//go:build linux

package pilotenrollment

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic pilot CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	raw, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	c, e := x509.ParseCertificate(raw)
	if e != nil {
		t.Fatal(e)
	}
	return c, k, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
}
func setup(t *testing.T) (string, Config, Runtime, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	ca, key, pem := testCA(t)
	d := t.TempDir()
	os.Chmod(d, 0700)
	ref := RecordRef{"fixture-record", 1, "sha256:1111111111111111111111111111111111111111111111111111111111111111"}
	evidence := Ref{"urn:fixture:evidence", ref.Digest}
	c := Config{Version, "https://127.0.0.1", pem, pem, ProofBinding{Target{"fixture", evidence, evidence}, ref, ref, ref, "fixture-pilot", Profile, "fixture-issuer"}, "11111111-1111-4111-8111-111111111111"}
	r := Runtime{Now: time.Now, Process: "first-process", CheckStorage: func(*os.File, string) error { return nil }}
	return d, c, r, ca, key
}
func install(t *testing.T, c *Client, issuer *x509.Certificate, key *ecdsa.PrivateKey) Challenge {
	t.Helper()
	status, e := c.Status()
	if e != nil {
		t.Fatal(e)
	}
	ch, e := NewChallenge(c.value.Config.Binding, status.SPKI, "instance", "logical", "bootstrap", "", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Bootstrap(canon(ch)); e != nil {
		t.Fatal(e)
	}
	spki, _ := base64.StdEncoding.DecodeString(status.SPKI)
	pub, e := x509.ParsePKIXPublicKey(spki)
	if e != nil {
		t.Fatal(e)
	}
	uri, _ := url.Parse(DeviceURI("logical", "instance"))
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * time.Minute), URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Install(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); e != nil {
		t.Fatal(e)
	}
	return ch
}
func TestGuardBeforeKeyCreation(t *testing.T) {
	d, c, r, _, _ := setup(t)
	r.CheckStorage = nil
	if _, e := Initialize(d, c, r); e != ErrStorage {
		t.Fatalf("expected actual storage rejection: %v", e)
	}
	if _, e := os.Stat(filepath.Join(d, "state.json")); !os.IsNotExist(e) {
		t.Fatal("key created on plaintext filesystem")
	}
	c.ProtectedVolume = ""
	r.CheckStorage = func(*os.File, string) error { return nil }
	if _, e := Initialize(d, c, r); e == nil {
		t.Fatal("missing storage binding accepted")
	}
}
func TestPrivateStoreAndRestart(t *testing.T) {
	d, config, r, issuer, key := setup(t)
	first, e := Initialize(d, config, r)
	if e != nil {
		t.Fatal(e)
	}
	again, e := Initialize(d, config, r)
	if e != nil || first.SPKI != again.SPKI {
		t.Fatal("key regenerated")
	}
	c, e := Open(d, r)
	if e != nil {
		t.Fatal(e)
	}
	install(t, c, issuer, key)
	if _, e = c.ProveInstalled(context.Background()); e != ErrRestart {
		t.Fatalf("same-process proof allowed: %v", e)
	}
	c.Close()
	r.Process = "second-process"
	c, e = Open(d, r)
	if e != nil {
		t.Fatal(e)
	}
	status, _ := c.Status()
	if status.SPKI != first.SPKI || status.Phase != "installed" {
		t.Fatal("restart lost credential")
	}
	c.Close()
	os.Chmod(filepath.Join(d, "state.json"), 0644)
	if c, e = Open(d, r); e == nil {
		c.Close()
		t.Fatal("insecure state file accepted")
	}
}
func TestBootstrapSubstitutionAndRehearsal(t *testing.T) {
	d, c, r, _, _ := setup(t)
	status, e := Initialize(d, c, r)
	if e != nil {
		t.Fatal(e)
	}
	client, e := Open(d, r)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	ch, e := NewChallenge(c.Binding, status.SPKI, "instance", "logical", "bootstrap", "", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	bad := ch
	bad.Binding.Target.Asset = "other"
	if _, e = client.Bootstrap(canon(bad)); e == nil {
		t.Fatal("target swap accepted")
	}
	bad = ch
	bad.Binding.Audience = "kaiba-fleet-rehearsal"
	if _, e = client.Bootstrap(canon(bad)); e == nil {
		t.Fatal("rehearsal accepted")
	}
	proof, e := client.Bootstrap(canon(ch))
	if e != nil {
		t.Fatal(e)
	}
	retry, e := client.Bootstrap(canon(ch))
	if e != nil || proof != retry {
		t.Fatal("bootstrap retry re-signed")
	}
	bad = ch
	bad.Nonce = "222222222222222222222222222222222222222222222222"
	if _, e = client.Bootstrap(canon(bad)); e == nil {
		t.Fatal("existing bootstrap replaced")
	}
}

// A closed TLS peer after committed verification must leave a saved proof and
// require reconciliation. The caller cannot accidentally create a second proof.
func TestLostInstalledProofReply(t *testing.T) {
	d, config, r, issuer, key := setup(t)
	var handler http.HandlerFunc
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { handler(w, req) }))
	// The synthetic CA doubles as this local test server's leaf, with loopback SAN.
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	pair, e := tlsPair(config.ServerCA, keyDER)
	if e != nil {
		t.Fatal(e)
	}
	server.TLS = pair
	server.StartTLS()
	defer server.Close()
	config.FleetURL = server.URL
	if _, e = Initialize(d, config, r); e != nil {
		t.Fatal(e)
	}
	c, e := Open(d, r)
	if e != nil {
		t.Fatal(e)
	}
	install(t, c, issuer, key)
	c.Close()
	r.Process = "second"
	c, e = Open(d, r)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	status, _ := c.Status()
	ch, e := NewChallenge(config.Binding, status.SPKI, "instance", "logical", "installed_key", CertificateDigest(c.value.Certificate), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	en := response{ID: "instance", Logical: "logical", State: "staged", Intent: config.Binding, Certificate: c.value.Certificate, Challenge: &ch}
	calls := 0
	handler = func(w http.ResponseWriter, req *http.Request) {
		calls++
		if req.URL.Path == "/api/v1/pilot/enrollments/instance/pending-challenge" {
			w.Write(canon(en))
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		conn.Close()
	}
	if _, e = c.ProveInstalled(context.Background()); !errors.Is(e, ErrReconcile) {
		t.Fatalf("wanted reconciliation: %v", e)
	}
	saved := c.value.PendingProof
	if saved == "" || c.value.Phase != "proof_submitted" {
		t.Fatal("proof not durable")
	}
	if _, e = c.ProveInstalled(context.Background()); !errors.Is(e, ErrReconcile) || calls != 2 {
		t.Fatal("automatic resubmit")
	}
	leaf, _ := c.value.leaf(time.Now())
	en.State = "verified"
	en.Challenge = nil
	en.Receipt = &receipt{ch, credential{"management", "pilot_management", 1, ch.SPKI, config.Binding.Issuer, leaf.SerialNumber.Text(16), leaf.NotBefore.UTC().Format(time.RFC3339Nano), leaf.NotAfter.UTC().Format(time.RFC3339Nano)}, saved, time.Now().UTC().Format(time.RFC3339Nano), "client_process"}
	if _, e = c.Reconcile(canon(en)); e != nil {
		t.Fatal(e)
	}
	if c.value.PendingProof != saved || calls != 2 {
		t.Fatal("reconciliation changed proof or performed network call")
	}
}

func tlsPair(cert string, key []byte) (*tls.Config, error) {
	pair, e := tls.X509KeyPair([]byte(cert), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}, e
}
