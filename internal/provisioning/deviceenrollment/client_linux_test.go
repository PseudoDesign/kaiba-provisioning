//go:build linux

package deviceenrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const firstBoot = "11111111-1111-1111-1111-111111111111"
const secondBoot = "22222222-2222-2222-2222-222222222222"

type fixture struct {
	t            *testing.T
	now          time.Time
	config       Config
	dir          string
	runtime      Runtime
	issuer       *x509.Certificate
	issuerKey    *ecdsa.PrivateKey
	caPEM        string
	client       *Client
	challenge    Challenge
	cert         string
	server       *httptest.Server
	calls        atomic.Int64
	proofs       atomic.Int64
	mode         string
	lastResponse []byte
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func makeCert(t *testing.T, template, parent *x509.Certificate, pub any, key *ecdsa.PrivateKey) (*x509.Certificate, string) {
	t.Helper()
	der, e := x509.CreateCertificate(rand.Reader, template, parent, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	c, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return c, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, now: time.Now().UTC().Truncate(time.Second), dir: t.TempDir()}
	if e := os.Chmod(f.dir, 0700); e != nil {
		t.Fatal(e)
	}
	f.issuerKey = newKey(t)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "disposable client test CA"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	f.issuer, f.caPEM = makeCert(t, ca, ca, &f.issuerKey.PublicKey, f.issuerKey)
	serverKey := newKey(t)
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverCert, _ := makeCert(t, serverTemplate, f.issuer, &serverKey.PublicKey, f.issuerKey)
	roots := x509.NewCertPool()
	roots.AddCert(f.issuer)
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.handle))
	f.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{serverCert.Raw}, PrivateKey: serverKey}}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	f.config = Config{Schema: Version, Mode: "development", FleetURL: f.server.URL, ServerCA: f.caPEM, IssuerCA: f.caPEM, IssuerID: "disposable-ca", Provisioning: RecordRef{"record-1", 1, "sha256:" + strings.Repeat("a", 64)}, Restart: "boot", Authority: "synthetic", Transaction: "candidate-1", Target: "target-1"}
	f.config.ProtectedVolume = "12345678-1234-1234-1234-123456789abc"
	f.runtime = Runtime{Now: func() time.Time { return f.now }, BootID: func() (string, error) { return firstBoot, nil }, Process: "process-1", CheckStorage: func(*os.File, string) error { return nil }}
	st, e := Initialize(f.dir, f.config, f.runtime)
	if e != nil {
		t.Fatal("initialize", e)
	}
	f.challenge = Challenge{Purpose: "bootstrap", Nonce: strings.Repeat("a", 48), Expires: f.now.Add(4 * time.Minute).Format(time.RFC3339Nano), Audience: Audience, Enrollment: "enrollment-1", Logical: "device-1", Instance: "enrollment-1", Storage: 1, Slot: "management", Generation: 1, SPKI: st.SPKIDigest, Profile: CertificateProfile, Provisioning: f.config.Provisioning}
	f.open()
	t.Cleanup(func() {
		if f.client != nil {
			f.client.Close()
		}
	})
	return f
}
func (f *fixture) open() {
	f.t.Helper()
	c, e := Open(f.dir, f.runtime)
	if e != nil {
		f.t.Fatal("open", e)
	}
	f.client = c
}
func (f *fixture) reopen() { f.client.Close(); f.client = nil; f.open() }
func (f *fixture) bootstrap() {
	f.t.Helper()
	b, _ := canonical(f.challenge)
	p, e := f.client.Bootstrap(b)
	if e != nil {
		f.t.Fatal(e)
	}
	k, _ := privateKey(f.client.value.Key)
	sum := sha256.Sum256(b)
	sig, _ := base64.StdEncoding.DecodeString(p.Signature)
	if !ecdsa.VerifyASN1(&k.PublicKey, sum[:], sig) {
		f.t.Fatal("invalid proof")
	}
}
func (f *fixture) issue(change func(*x509.Certificate)) string {
	f.t.Helper()
	k, _ := privateKey(f.client.value.Key)
	uri, _ := url.Parse("spiffe://kaiba.test/device/device-1/instance/enrollment-1")
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: f.now.Add(-time.Minute), NotAfter: f.now.Add(30 * time.Minute), URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if change != nil {
		change(tmpl)
	}
	_, encoded := makeCert(f.t, tmpl, f.issuer, &k.PublicKey, f.issuerKey)
	return encoded
}
func (f *fixture) install() {
	f.t.Helper()
	f.bootstrap()
	f.cert = f.issue(nil)
	if _, e := f.client.Install([]byte(f.cert)); e != nil {
		f.t.Fatal(e)
	}
}
func (f *fixture) restart() {
	f.runtime.BootID = func() (string, error) { return secondBoot, nil }
	f.runtime.Process = "process-2"
	f.reopen()
}
func (f *fixture) response(ch Challenge, status string) enrollmentResponse {
	st, _ := f.client.Status()
	en := enrollmentResponse{ID: f.challenge.Enrollment, State: status, Challenge: ch, Certificate: f.cert, Policy: "rehearsal-v1", Logical: f.challenge.Logical, Storage: 1, Binding: json.RawMessage(`{}`)}
	en.Request.Authority = f.config.Authority
	en.Request.Transaction = f.config.Transaction
	en.Request.Record = f.config.Provisioning
	en.Request.SPKI = st.SPKI
	en.Request.Target = f.config.Target
	return en
}
func (f *fixture) handle(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	if f.mode == "redirect" {
		http.Redirect(w, r, f.server.URL+"/redirect-target", 302)
		return
	}
	if f.mode == "oversized" {
		_, _ = io.WriteString(w, strings.Repeat("x", maxBytes+1))
		return
	}
	if r.URL.Path == "/api/v1/access" {
		if f.mode == "allow" {
			_, _ = io.WriteString(w, `{"authorized":"rehearsal","instance_id":"enrollment-1"}`)
		} else {
			w.WriteHeader(403)
		}
		return
	}
	ch := f.challenge
	ch.Purpose = "installed_key"
	ch.Nonce = strings.Repeat("b", 48)
	en := f.response(ch, "staged")
	if strings.HasSuffix(r.URL.Path, "/pending-challenge") {
		if f.mode == "bad-audience" {
			en.Challenge.Audience = "other"
		}
		if f.mode == "bad-record" {
			en.Request.Record.Revision++
		}
		if f.mode == "bad-instance" {
			en.Challenge.Instance = "another"
		}
		if f.mode == "bad-cert" {
			en.Certificate = "different"
		}
		_ = json.NewEncoder(w).Encode(en)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/pending-proof") {
		f.proofs.Add(1)
		if f.mode == "proof-not-committed" {
			f.lastResponse, _ = canonical(en)
			w.WriteHeader(503)
			return
		}
		var p Proof
		if json.NewDecoder(r.Body).Decode(&p) != nil {
			w.WriteHeader(400)
			return
		}
		k, _ := privateKey(f.client.value.Key)
		b, _ := canonical(ch)
		sum := sha256.Sum256(b)
		sig, _ := base64.StdEncoding.DecodeString(p.Signature)
		if !ecdsa.VerifyASN1(&k.PublicKey, sum[:], sig) {
			w.WriteHeader(403)
			return
		}
		en.State = "verified"
		en.Challenge = Challenge{}
		leaf, _ := certificate(f.cert)
		v := credential{"management", "outbound_management", 1, ch.SPKI, "disposable-ca", leaf.SerialNumber.Text(16), leaf.NotBefore.Format(time.RFC3339Nano), leaf.NotAfter.Format(time.RFC3339Nano)}
		at := f.now
		switch f.mode {
		case "wrong-verified-key":
			v.SPKI = "sha256:" + strings.Repeat("f", 64)
		case "wrong-verified-serial":
			v.Serial = "different"
		case "wrong-verified-issuer":
			v.Issuer = "other-ca"
		case "wrong-verified-role":
			v.Role = "administrator"
		case "late-verification":
			at = at.Add(6 * time.Minute)
		}
		en.Verifier, _ = canonical(map[string]any{"challenge": ch, "credential": v, "verified_at": at.Format(time.RFC3339Nano), "policy": "rehearsal-v1"})
		f.lastResponse, _ = canonical(en)
		if f.mode == "lost-proof-response" {
			conn, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				conn.Close()
			}
			return
		}
		_, _ = w.Write(f.lastResponse)
		return
	}
	w.WriteHeader(404)
}
func TestLifecycleAndPrivatePersistence(t *testing.T) {
	f := newFixture(t)
	first, _ := f.client.Status()
	f.client.Close()
	f.client = nil
	second, e := Initialize(f.dir, f.config, f.runtime)
	if e != nil || second.SPKI != first.SPKI {
		t.Fatal("init replaced key", e)
	}
	f.open()
	f.install()
	if _, e = f.client.ProveInstalled(context.Background()); !errors.Is(e, ErrRestart) || f.calls.Load() != 0 {
		t.Fatal("same boot accepted", e)
	}
	f.restart()
	st, e := f.client.ProveInstalled(context.Background())
	if e != nil || st.Phase != "verified" || !st.BootChangeObserved || st.HardwareQualified || st.ProductionEnrollment {
		t.Fatal(st, e)
	}
	f.reopen()
	again, e := f.client.ProveInstalled(context.Background())
	if e != nil || again != st || f.proofs.Load() != 1 {
		t.Fatal("proof repeated", again, e)
	}
	f.mode = "allow"
	access, e := f.client.CheckAccess(context.Background())
	if e != nil || !access.Allowed || access.ProductionEnrollment {
		t.Fatal(access, e)
	}
	f.mode = "deny"
	access, e = f.client.CheckAccess(context.Background())
	if e != nil || access.Allowed {
		t.Fatal(access, e)
	}
	raw, _ := json.Marshal(st)
	key, _ := privateKey(f.client.value.Key)
	if bytes.Contains(raw, f.client.value.Key) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(f.client.value.Key))) || bytes.Contains(raw, key.D.Bytes()) {
		t.Fatal("private key in status")
	}
	info, _ := os.Stat(filepath.Join(f.dir, "state.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("state permissions")
	}
}
func TestBootstrapRejectsSubstitutionAndCachesExactProof(t *testing.T) {
	f := newFixture(t)
	cases := map[string]func(*Challenge){"audience": func(c *Challenge) { c.Audience = "wrong" }, "purpose": func(c *Challenge) { c.Purpose = "installed_key" }, "key": func(c *Challenge) { c.SPKI = "sha256:" + strings.Repeat("b", 64) }, "record": func(c *Challenge) { c.Provisioning.Revision++ }, "expired": func(c *Challenge) { c.Expires = f.now.Format(time.RFC3339Nano) }, "long-lived": func(c *Challenge) { c.Expires = f.now.Add(time.Hour).Format(time.RFC3339Nano) }, "instance": func(c *Challenge) { c.Instance = "different" }, "profile": func(c *Challenge) { c.Profile = "production" }, "slot": func(c *Challenge) { c.Slot = "ca" }, "generation": func(c *Challenge) { c.Generation = 2 }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			ch := f.challenge
			change(&ch)
			b, _ := canonical(ch)
			if _, e := f.client.Bootstrap(b); e == nil {
				t.Fatal("accepted substitution")
			}
		})
	}
	b, _ := canonical(f.challenge)
	one, e := f.client.Bootstrap(b)
	if e != nil {
		t.Fatal(e)
	}
	f.reopen()
	two, e := f.client.Bootstrap(b)
	if e != nil || one != two {
		t.Fatal("proof changed", e)
	}
	f.now = f.now.Add(10 * time.Minute)
	two, e = f.client.Bootstrap(b)
	if e != nil || one != two {
		t.Fatal("historical proof was not retained", e)
	}
	changed := f.challenge
	changed.Logical = "different"
	b, _ = canonical(changed)
	if _, e = f.client.Bootstrap(b); e == nil {
		t.Fatal("binding replaced")
	}
}
func TestCertificateInstallationRejectsWrongIdentityAndProfile(t *testing.T) {
	for name, change := range map[string]func(*x509.Certificate){"expired": func(c *x509.Certificate) { c.NotAfter = c.NotBefore }, "server": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }, "ca": func(c *x509.Certificate) { c.IsCA = true; c.BasicConstraintsValid = true }, "uri": func(c *x509.Certificate) { c.URIs[0], _ = url.Parse("spiffe://kaiba.test/device/other") }, "extra-san": func(c *x509.Certificate) { c.DNSNames = []string{"extra"} }, "key-usage": func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageKeyEncipherment }} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.bootstrap()
			if _, e := f.client.Install([]byte(f.issue(change))); e == nil {
				t.Fatal("bad certificate installed")
			}
			st, _ := f.client.Status()
			if st.Phase != "bootstrap_proved" {
				t.Fatal("state advanced")
			}
		})
	}
	f := newFixture(t)
	f.install()
	before, _ := os.ReadFile(filepath.Join(f.dir, "state.json"))
	if _, e := f.client.Install([]byte(f.cert)); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(filepath.Join(f.dir, "state.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("installation replay altered state")
	}
}
func TestUncertainProofRequiresStationReconciliation(t *testing.T) {
	f := newFixture(t)
	f.install()
	f.restart()
	f.mode = "lost-proof-response"
	if _, e := f.client.ProveInstalled(context.Background()); !errors.Is(e, ErrReconcile) {
		t.Fatal(e)
	}
	f.reopen()
	calls := f.calls.Load()
	if _, e := f.client.ProveInstalled(context.Background()); !errors.Is(e, ErrReconcile) || calls != f.calls.Load() {
		t.Fatal("uncertain proof replayed", e)
	}
	wrong := append([]byte(nil), f.lastResponse...)
	wrong = bytes.Replace(wrong, []byte(`"state":"verified"`), []byte(`"state":"staged"`), 1)
	if _, e := f.client.Reconcile(wrong); e == nil {
		t.Fatal("unverified state accepted")
	}
	st, e := f.client.Reconcile(f.lastResponse)
	if e != nil || st.Phase != "verified" || f.proofs.Load() != 1 {
		t.Fatal(st, e)
	}
}
func TestTransportAndResponseFailuresNeverSubmitProof(t *testing.T) {
	for _, mode := range []string{"redirect", "oversized", "bad-audience", "bad-record", "bad-instance", "bad-cert"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.install()
			f.restart()
			f.mode = mode
			if _, e := f.client.ProveInstalled(context.Background()); e == nil {
				t.Fatal("bad response accepted")
			}
			if f.proofs.Load() != 0 || f.calls.Load() != 1 {
				t.Fatal("proof/redirect followed")
			}
		})
	}
	t.Run("wrong-root", func(t *testing.T) {
		f := newFixture(t)
		other := newFixture(t)
		f.install()
		f.restart()
		f.client.value.Config.ServerCA = other.caPEM
		if _, e := f.client.ProveInstalled(context.Background()); e == nil || f.calls.Load() != 0 {
			t.Fatal("untrusted server reached handler")
		}
	})
}

func TestExplicitRetryRequiresSameLiveStagedChallenge(t *testing.T) {
	f := newFixture(t)
	f.install()
	f.restart()
	f.mode = "proof-not-committed"
	if _, e := f.client.ProveInstalled(context.Background()); !errors.Is(e, ErrReconcile) {
		t.Fatal(e)
	}
	f.reopen()
	proof := f.client.value.PendingProof
	staged := append([]byte(nil), f.lastResponse...)
	calls := f.calls.Load()
	for _, raw := range [][]byte{
		bytes.Replace(staged, []byte(`"state":"staged"`), []byte(`"state":"quarantined"`), 1),
		bytes.Replace(staged, []byte(strings.Repeat("b", 48)), []byte(strings.Repeat("c", 48)), 1),
		bytes.Replace(staged, []byte(`"id":"enrollment-1"`), []byte(`"id":"other"`), 1),
	} {
		if _, e := f.client.RetryInstalled(context.Background(), raw); e == nil || f.calls.Load() != calls {
			t.Fatal("retry accepted changed station observation", e)
		}
	}
	f.now = f.now.Add(10 * time.Minute)
	if _, e := f.client.RetryInstalled(context.Background(), staged); e == nil || f.calls.Load() != calls {
		t.Fatal("retry accepted expired challenge", e)
	}
	f.now = f.now.Add(-10 * time.Minute)
	f.mode = ""
	st, e := f.client.RetryInstalled(context.Background(), staged)
	if e != nil || st.Phase != "verified" || f.calls.Load() != calls+1 || f.client.value.PendingProof != proof {
		t.Fatal("retry must send only the original proof", st, e)
	}
}

func TestWrongVerificationReceiptRequiresReconciliation(t *testing.T) {
	for _, mode := range []string{"wrong-verified-key", "wrong-verified-serial", "wrong-verified-issuer", "wrong-verified-role", "late-verification"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.install()
			f.restart()
			f.mode = mode
			if _, e := f.client.ProveInstalled(context.Background()); e == nil {
				t.Fatal("mismatched verification receipt accepted")
			}
			f.reopen()
			if _, e := f.client.ProveInstalled(context.Background()); !errors.Is(e, ErrReconcile) || f.proofs.Load() != 1 {
				t.Fatal("proof repeated after mismatched result", e)
			}
		})
	}
}
func TestProcessRestartDoesNotClaimBootChange(t *testing.T) {
	f := newFixture(t)
	f.client.Close()
	f.client = nil
	if e := os.Remove(filepath.Join(f.dir, "state.json")); e != nil {
		t.Fatal(e)
	}
	f.config.Restart = "process"
	st, e := Initialize(f.dir, f.config, f.runtime)
	if e != nil {
		t.Fatal(e)
	}
	f.challenge.SPKI = st.SPKIDigest
	f.open()
	f.install()
	if _, e = f.client.ProveInstalled(context.Background()); !errors.Is(e, ErrRestart) {
		t.Fatal(e)
	}
	f.runtime.Process = "process-2"
	f.reopen()
	st, e = f.client.ProveInstalled(context.Background())
	if e != nil || st.BootChangeObserved || st.HardwareQualified || st.ProductionEnrollment {
		t.Fatal(st, e)
	}
}
func TestPrivateStoreRejectsUnsafeOrIncompleteState(t *testing.T) {
	for _, name := range []string{"mode", "symlink", "hardlink", "fifo", "pending", "corrupt", "lock"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			statePath := filepath.Join(f.dir, "state.json")
			if name == "lock" {
				if _, e := Open(f.dir, f.runtime); e == nil {
					t.Fatal("concurrent writer")
				}
				return
			}
			f.client.Close()
			f.client = nil
			switch name {
			case "mode":
				_ = os.Chmod(statePath, 0644)
			case "symlink":
				saved := filepath.Join(t.TempDir(), "saved")
				if e := os.Rename(statePath, saved); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(saved, statePath); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				_ = os.Link(statePath, filepath.Join(t.TempDir(), "duplicate"))
			case "fifo":
				if e := os.Remove(statePath); e != nil {
					t.Fatal(e)
				}
				if e := syscall.Mkfifo(statePath, 0600); e != nil {
					t.Fatal(e)
				}
			case "pending":
				_ = os.WriteFile(filepath.Join(f.dir, ".pending-preserved"), []byte("partial"), 0600)
			case "corrupt":
				_ = os.WriteFile(statePath, []byte(`{"schema_version":null}`), 0600)
			}
			if _, e := Open(f.dir, f.runtime); e == nil {
				t.Fatal("unsafe store opened")
			}
			if _, e := Initialize(f.dir, f.config, f.runtime); e == nil {
				t.Fatal("unsafe store reinitialized")
			}
		})
	}
}
func TestConfigRejectsProductionAmbiguityAndUnsafeOrigins(t *testing.T) {
	f := newFixture(t)
	for _, origin := range []string{"http://127.0.0.1", "https://user:pass@example.org", "https://example.org/path", "https://example.org?", "https://example.org?query=1", "https://example.org/#fragment"} {
		c := f.config
		c.FleetURL = origin
		if c.validate() == nil {
			t.Fatal(origin)
		}
	}
	c := f.config
	c.Mode = "production"
	if c.validate() == nil {
		t.Fatal("production enabled")
	}
	raw, _ := json.Marshal(f.config)
	for _, b := range [][]byte{bytes.Replace(raw, []byte(`"mode":"development"`), []byte(`"mode":"development","mode":"development"`), 1), append(append([]byte(nil), raw...), []byte(`{}`)...), bytes.Replace(raw, []byte(`"revision":1`), []byte(`"revision":null`), 1)} {
		if _, e := DecodeConfig(b); e == nil {
			t.Fatal("ambiguous config")
		}
	}
}
