//go:build linux

package pilotenrollment

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server, string) {
	t.Helper()
	d, config, r, issuer, key := setup(t)
	server := httptest.NewUnstartedServer(handler)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	cfg, err := tlsPair(config.ServerCA, der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = roots
	server.TLS = cfg
	server.StartTLS()
	t.Cleanup(server.Close)
	config.FleetURL = server.URL
	if _, err = Initialize(d, config, r); err != nil {
		t.Fatal(err)
	}
	c, err := Open(d, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	install(t, c, issuer, key)
	// Synthetic fixture: hardware/live installed-key proof is covered separately.
	v := c.value
	v.Phase = "verified"
	status, _ := c.Status()
	ch, err := NewChallenge(config.Binding, status.SPKI, "instance", "logical", "installed_key", CertificateDigest(v.Certificate), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := sign(v, ch)
	if err != nil {
		t.Fatal(err)
	}
	v.Pending = &ch
	v.PendingProof = proof.Signature
	if err = c.save(v); err != nil {
		t.Fatal(err)
	}
	return c, server, d
}
func requestFailure(t *testing.T, err error, kind string, status int) {
	t.Helper()
	var r *RequestError
	if !errors.As(err, &r) || r.Kind != kind || r.HTTPStatus != status || !errors.Is(err, ErrReconcile) {
		t.Fatalf("unexpected failure: %v", err)
	}
	if strings.Contains(err.Error(), "sensitive") {
		t.Fatal("remote error leaked")
	}
}
func TestReadStatusClassification(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 409, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			c, _, _ := readTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(status)
				fmt.Fprint(w, "sensitive server body")
			})
			_, err := c.CheckAccess(context.Background())
			requestFailure(t, err, "http_status", status)
			if calls != 1 {
				t.Fatal("automatic retry")
			}
		})
	}
}
func TestTransportAndResponseFailures(t *testing.T) {
	t.Run("canceled", func(t *testing.T) {
		c, _, _ := readTestClient(t, func(http.ResponseWriter, *http.Request) { t.Error("canceled request sent") })
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := c.CheckAccess(ctx)
		requestFailure(t, err, "canceled", 0)
	})
	for _, body := range []string{`not json`, `{"authorized":"pilot","instance_id":"other","binding":{},"full_qualification":false}`} {
		t.Run("invalid-response", func(t *testing.T) {
			c, _, _ := readTestClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			_, err := c.CheckAccess(context.Background())
			requestFailure(t, err, "invalid_response", 200)
		})
	}

	t.Run("timeout", func(t *testing.T) {
		c, _, _ := readTestClient(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		_, err := c.CheckAccess(ctx)
		requestFailure(t, err, "timeout", 0)
	})
	t.Run("connection", func(t *testing.T) {
		c, s, _ := readTestClient(t, func(http.ResponseWriter, *http.Request) {})
		s.Close()
		_, err := c.CheckAccess(context.Background())
		requestFailure(t, err, "transport", 0)
	})
	t.Run("redirect", func(t *testing.T) {
		c, _, _ := readTestClient(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://sensitive.invalid/", 302) })
		_, err := c.CheckAccess(context.Background())
		requestFailure(t, err, "redirect", 0)
	})
	t.Run("trust", func(t *testing.T) {
		c, _, _ := readTestClient(t, func(http.ResponseWriter, *http.Request) {})
		_, _, other := testCA(t)
		c.value.Config.ServerCA = other
		_, err := c.CheckAccess(context.Background())
		requestFailure(t, err, "tls_verification", 0)
	})
	t.Run("oversized", func(t *testing.T) {
		c, _, _ := readTestClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat("x", maxBytes+1)) })
		_, err := c.CheckAccess(context.Background())
		requestFailure(t, err, "invalid_response", 200)
	})
}
func TestDiagnosticReferenceRetryAndReceipt(t *testing.T) {
	var firstBody, firstKey string
	calls := 0
	c, _, d := readTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		b, _ := io.ReadAll(r.Body)
		if len(r.TLS.VerifiedChains) == 0 || r.Method != "POST" || r.URL.Path != "/api/v1/pilot/diagnostic-references" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("wrong authenticated request")
		}
		if calls == 1 {
			firstBody = string(b)
			firstKey = r.Header.Get("Idempotency-Key")
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		if string(b) != firstBody || r.Header.Get("Idempotency-Key") != firstKey {
			t.Error("retry changed input")
		}
		json.NewEncoder(w).Encode(DiagnosticReceipt{"instance", fmt.Sprintf("sha256:%x", sha256.Sum256(b))})
	})
	input := canon(DiagnosticSubmission{Ref{"urn:synthetic:diagnostic", "sha256:" + strings.Repeat("1", 64)}})
	before, _ := os.ReadFile(filepath.Join(d, "state.json"))
	_, err := c.SubmitDiagnostic(context.Background(), input, "diagnostic-1")
	requestFailure(t, err, "transport", 0)
	if calls != 1 {
		t.Fatal("automatically retried write")
	}
	if _, err = c.SubmitDiagnostic(context.Background(), input, "diagnostic-1"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(d, "state.json"))
	if string(before) != string(after) {
		t.Fatal("credential state changed")
	}
}
func TestDiagnosticRejectsInputAndReceipt(t *testing.T) {
	calls := 0
	c, _, _ := readTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprint(w, `{"instance_id":"other","receipt_digest":"sha256:wrong"}`)
	})
	valid := canon(DiagnosticSubmission{Ref{"urn:synthetic:diagnostic", "sha256:" + strings.Repeat("1", 64)}})
	for _, tc := range []struct {
		b []byte
		k string
	}{{valid, ""}, {valid, "bad\nkey"}, {[]byte(`{"reference":{"uri":"relative","digest":"bad"}}`), "key"}, {append(valid, make([]byte, 4097)...), "key"}, {[]byte(`{"reference":{},"device_id":"other"}`), "key"}} {
		if _, err := c.SubmitDiagnostic(context.Background(), tc.b, tc.k); err != ErrInput {
			t.Fatalf("accepted bad input: %v", err)
		}
	}
	if calls != 0 {
		t.Fatal("invalid input sent")
	}
	_, err := c.SubmitDiagnostic(context.Background(), valid, "key")
	requestFailure(t, err, "invalid_response", 200)
}
