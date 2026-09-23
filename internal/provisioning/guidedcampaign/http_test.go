package guidedcampaign

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
)

func testPKI(t *testing.T) (tls.Certificate, *x509.CertPool, string, func(string) mtls.ClientFiles) {
	t.Helper()
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "disposable campaign test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ = x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	caPath := filepath.Join(dir, "ca.pem")
	os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	serial := int64(1)
	mint := func(uri string) (tls.Certificate, string, string) {
		serial++
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		if uri != "" {
			u, _ := url.Parse(uri)
			cert.URIs = []*url.URL{u}
		}
		b, e := x509.CreateCertificate(rand.Reader, cert, ca, &k.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		pk, _ := x509.MarshalPKCS8PrivateKey(k)
		cp := filepath.Join(dir, cert.SerialNumber.String()+".crt")
		kp := filepath.Join(dir, cert.SerialNumber.String()+".key")
		os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}), 0600)
		os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600)
		pair, e := tls.LoadX509KeyPair(cp, kp)
		if e != nil {
			t.Fatal(e)
		}
		return pair, cp, kp
	}
	server, _, _ := mint("")
	return server, pool, caPath, func(station string) mtls.ClientFiles {
		_, cert, key := mint("spiffe://kaiba.network/station/" + station + "/lane/lane-1")
		return mtls.ClientFiles{Certificate: cert, PrivateKey: key, ServerCA: caPath}
	}
}
func TestAuthenticatedRelayPreservesScopedActionsAndDurableState(t *testing.T) {
	p := fixturePlan()
	e := openTest(t, privateDir(t), p, runnerFunc(func(_ context.Context, _ Program, x Execution) (Result, error) { return success(x), nil }))
	defer e.Close()
	cert, pool, _, files := testPKI(t)
	server := httptest.NewUnstartedServer(Handler(e))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	good := files("station-1")
	client, err := NewClient(server.URL, p.ID, p.Digest(), p.Station, p.Lane, good)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	s, err := client.Current(context.Background())
	if err != nil || s.Status != "ready" {
		t.Fatal(s, err)
	}
	a := Action{"start", s.Revision, "begin", ""}
	if _, err = client.Apply(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	awaitStatus(t, e, "awaiting_input")
	if _, err = client.Apply(context.Background(), a); err != nil {
		t.Fatal("idempotent read lost", err)
	}
	r, err := client.Report(context.Background())
	if err != nil || len(r.Attempts) != 1 || r.State.Production {
		t.Fatal(r, err)
	}
	wrong, err := NewClient(server.URL, p.ID, p.Digest(), "station-2", p.Lane, files("station-2"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrong.Current(context.Background()); !errors.Is(err, ErrDenied) {
		t.Fatal("wrong station authorized", err)
	}
	if _, err = NewClient(server.URL, p.ID, p.Digest(), "station-2", p.Lane, good); !errors.Is(err, mtls.ErrClientIdentityMismatch) {
		t.Fatal(err)
	}
	other, err := NewClient(server.URL, "other-campaign", p.Digest(), p.Station, p.Lane, good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.Current(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	wrongPlan, err := NewClient(server.URL, p.ID, "sha256:"+strings.Repeat("f", 64), p.Station, p.Lane, good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrongPlan.Current(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err = http.Get(server.URL + "/api/v1/campaign/state"); err == nil {
		t.Fatal("unauthenticated connection succeeded")
	}
	for _, origin := range []string{"http://localhost", "https://user@localhost", "https://localhost/path", "https://localhost?", "https://localhost/#fragment"} {
		if _, err = NewClient(origin, p.ID, p.Digest(), p.Station, p.Lane, good); err == nil {
			t.Fatal(origin)
		}
	}
}
func TestRelayRejectsRedirectMalformedOversizeAndTransportOutage(t *testing.T) {
	p := fixturePlan()
	cert, pool, _, files := testPKI(t)
	mode := "malformed"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch mode {
		case "redirect":
			http.Redirect(w, r, "https://127.0.0.1:1/private", 302)
		case "denied":
			w.WriteHeader(403)
		case "oversize":
			w.Write([]byte(strings.Repeat(" ", MaxBytes+1)))
		default:
			w.Write([]byte(`{"private_key":"must not reach the browser"}`))
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	c, err := NewClient(server.URL, p.ID, p.Digest(), p.Station, p.Lane, files(p.Station))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"malformed", "oversize", "redirect", "denied"} {
		mode = kind
		if _, err = c.Current(context.Background()); err == nil {
			t.Fatal(kind)
		}
	}
	server.Close()
	if _, err = c.Current(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
