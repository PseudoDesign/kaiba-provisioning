package handoff

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestScopedReadsRetainExactBytes(t *testing.T) {
	u, _ := url.Parse("spiffe://kaiba.test/service/fleet")
	policy := Policy{[]Grant{{u.String(), []string{"tx"}}}}
	data := []byte(`{"id":"tx","resource_version":1}`)
	h := Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(405) }), policy, t.TempDir(), func(context.Context, string) ([]byte, error) { return data, nil })
	for _, tc := range []struct {
		path, principal string
		code            int
	}{{"/api/v1/handoff/tx/current", u.String(), 200}, {"/api/v1/handoff/tx/evidence/" + Digest(data)[7:], u.String(), 200}, {"/api/v1/handoff/other/current", u.String(), 403}, {"/api/v1/handoff/tx/current", "spiffe://kaiba.test/wrong", 403}, {"/api/v1/commands", u.String(), 405}} {
		r := httptest.NewRequest("GET", tc.path, nil)
		uri, _ := url.Parse(tc.principal)
		r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{uri}}}}}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatalf("%s: %d", tc.path, w.Code)
		}
		if w.Code == 200 && strings.TrimSpace(w.Body.String()) != string(data) {
			t.Fatal("evidence was transformed")
		}
	}
}
