package appliance

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestNetworkFixedOriginTLSAndRedirectDenial(t *testing.T) {
	c, f, _, _ := credentialsFixture(t)
	defer c.Close()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
			t.Error("TLS version")
		}
		out.Header().Set("Content-Type", "application/json")
		http.Redirect(out, r, "https://other.example/", http.StatusFound)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	for _, origin := range []string{"http://authority.example", "https://authority.example/path", "https://user@authority.example", "https://authority.example?token=x", "https://authority.example#x"} {
		if n, e := NewNetwork(origin, roots, c); e == nil {
			n.Close()
			t.Fatal("unbound origin", origin)
		}
	}
	n, e := NewNetwork(server.URL, roots, c)
	if e != nil {
		t.Fatal(e)
	}
	defer n.Close()
	tr := n.client.Transport.(*http.Transport)
	if tr.Proxy != nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("ambient proxy or weak TLS")
	}
	if _, e = n.Challenge(f.id, "enroll"); e == nil {
		t.Fatal("redirect followed")
	}
	if _, e = n.Artifact("../../etc/shadow"); e == nil {
		t.Fatal("arbitrary artifact path")
	}
}
func TestDiagnosticsBoundedDurableAndRedacted(t *testing.T) {
	c, f, _, dir := credentialsFixture(t)
	defer c.Close()
	path := dir + "-logs"
	os.Mkdir(path, 0700)
	log, e := OpenDiagnosticLog(path, c.Identity(), "volume", func(*os.File, string) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	for range 130 {
		if e = log.Append("update-deferred", "attempt", f.now); e != nil {
			t.Fatal(e)
		}
	}
	snapshot := log.Snapshot()
	if len(snapshot.Entries) != 128 || snapshot.Sequence != 130 || snapshot.Validate() != nil {
		t.Fatal("log bound")
	}
	if e = log.Append("PRIVATE KEY", "attempt", f.now); e == nil {
		t.Fatal("free form log")
	}
	log.Close()
	log, e = OpenDiagnosticLog(path, c.Identity(), "volume", func(*os.File, string) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	if log.Snapshot().Sequence != 130 {
		t.Fatal("sequence reset after reboot")
	}
	if e = log.Append("update-overdue", "attempt", f.now); e != nil || log.Snapshot().Sequence != 131 {
		t.Fatal("log restart", e)
	}
}
