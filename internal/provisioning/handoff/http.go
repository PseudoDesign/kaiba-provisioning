package handoff

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var ID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Grant struct {
	Principal    string   `json:"principal"`
	Transactions []string `json:"transactions"`
}
type Policy struct {
	Grants []Grant `json:"grants"`
}

func (p Policy) Authorize(r *http.Request, id string) bool {
	principal, e := Principal(r)
	if e != nil || !ID.MatchString(id) {
		return false
	}
	for _, g := range p.Grants {
		if g.Principal == principal {
			for _, tx := range g.Transactions {
				if tx == id {
					return true
				}
			}
		}
	}
	return false
}
func Principal(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", errors.New("unverified principal")
	}
	c := r.TLS.VerifiedChains[0][0]
	if len(c.URIs) != 1 {
		return "", errors.New("ambiguous principal")
	}
	return c.URIs[0].String(), nil
}
func LoadPolicy(path string) (Policy, error) {
	var p Policy
	b, e := os.ReadFile(path)
	if e == nil {
		e = Decode(b, &p)
	}
	if e != nil {
		return p, e
	}
	if len(p.Grants) == 0 {
		return p, errors.New("empty grants")
	}
	for _, g := range p.Grants {
		u, e := url.Parse(g.Principal)
		if e != nil || u.Scheme != "spiffe" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(g.Transactions) == 0 {
			return p, errors.New("invalid grant")
		}
		for _, tx := range g.Transactions {
			if !ID.MatchString(tx) {
				return p, errors.New("invalid transaction grant")
			}
		}
	}
	return p, nil
}

// Retain publishes exact bytes durably, never replacing an existing blob.
func Retain(path string, b []byte) error {
	if len(b) > MaxBytes {
		return errors.New("evidence too large")
	}
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".handoff-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Link(f.Name(), path); e != nil {
		old, er := os.ReadFile(path)
		if er != nil || string(old) != string(b) {
			return errors.New("immutable evidence conflict")
		}
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

// Wrap adds only scoped read routes. Service identities remain rejected by the
// existing command/append handlers, which still require station/approver identities.
func Wrap(next http.Handler, p Policy, dir string, current func(context.Context, string) ([]byte, error)) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", next)
	mux.HandleFunc("GET /api/v1/handoff/{id}/current", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !p.Authorize(r, id) {
			Fail(w, 403, "scope_mismatch")
			return
		}
		b, e := current(r.Context(), id)
		if e != nil {
			Fail(w, 409, "source_unavailable")
			return
		}
		if e = Retain(filepath.Join(dir, id, Digest(b)[7:]+".json"), b); e != nil {
			Fail(w, 500, "retention_failed")
			return
		}
		Write(w, 200, b)
	})
	mux.HandleFunc("GET /api/v1/handoff/{id}/evidence/{hash}", func(w http.ResponseWriter, r *http.Request) {
		id, h := r.PathValue("id"), r.PathValue("hash")
		if !p.Authorize(r, id) || !Hex.MatchString(h) {
			Fail(w, 403, "scope_mismatch")
			return
		}
		b, e := os.ReadFile(filepath.Join(dir, id, h+".json"))
		if e != nil || Digest(b) != "sha256:"+h {
			Fail(w, 404, "not_found")
			return
		}
		Write(w, 200, b)
	})
	return mux
}
func Write(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
func Fail(w http.ResponseWriter, status int, code string) {
	b, _ := json.Marshal(map[string]string{"error": code})
	Write(w, status, b)
}

type Client struct {
	Base string
	HTTP *http.Client
}

func NewClient(base, cert, key, ca string) (*Client, error) {
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("HTTPS origin required")
	}
	c, e := tls.LoadX509KeyPair(cert, key)
	if e != nil {
		return nil, e
	}
	roots := x509.NewCertPool()
	b, e := os.ReadFile(ca)
	if e != nil || !roots.AppendCertsFromPEM(b) {
		return nil, errors.New("explicit CA required")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{c}, RootCAs: roots}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	return &Client{strings.TrimSuffix(base, "/"), &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect denied") }}}, nil
}
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	b, e := c.GetRaw(ctx, path)
	if e != nil {
		return nil, e
	}
	if _, e = Canonical(b); e != nil {
		return nil, e
	}
	return b, nil
}
func (c *Client) GetRaw(ctx context.Context, path string) ([]byte, error) {
	r, e := http.NewRequestWithContext(ctx, "GET", c.Base+path, nil)
	if e != nil {
		return nil, e
	}
	res, e := c.HTTP.Do(r)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("authority HTTP %d", res.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, MaxBytes+1))
	if e != nil || len(b) > MaxBytes {
		return nil, errors.New("invalid response bounds")
	}
	return b, nil
}
