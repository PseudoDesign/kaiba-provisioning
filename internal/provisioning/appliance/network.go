package appliance

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	w "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/appliancewire"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Assignment struct {
	Offer    w.Signed   `json:"offer"`
	Release  w.Signed   `json:"release"`
	Receipt  *w.Receipt `json:"receipt,omitempty"`
	Reported string     `json:"reported_at,omitempty"`
}
type Network struct {
	qualification bool
	origin        string
	client        *http.Client
	public        *http.Client
	credentials   *Credentials
}

// NewNetwork fixes one authority origin, system roots, TLS 1.3 and timeouts.
// Redirects and environment proxies are disabled; response URLs never become
// callback, issuance, management or artifact destinations.
func NewNetwork(origin string, serverRoots *x509.CertPool, c *Credentials) (*Network, error) {
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || serverRoots == nil || c == nil {
		return nil, ErrDenied
	}
	build := func(auth bool) *http.Client {
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: serverRoots}
		if auth {
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				cert, e := c.TLSCertificate()
				return &cert, e
			}
		}
		tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: cfg, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 16384, MaxConnsPerHost: 2, IdleConnTimeout: time.Minute, ForceAttemptHTTP2: true}
		return &http.Client{Transport: tr, Timeout: time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrDenied }}
	}
	return &Network{origin: origin, client: build(true), public: build(false), credentials: c}, nil
}

// NewQualificationNetwork uses the same intended production credential and
// fixed origin; Fleet requires a separate expiring exact-transition grant.
func NewQualificationNetwork(origin string, roots *x509.CertPool, c *Credentials) (*Network, error) {
	n, e := NewNetwork(origin, roots, c)
	if e == nil {
		n.qualification = true
	}
	return n, e
}
func (n *Network) updatePath(action string) string {
	if n.qualification {
		return "/appliance/v1/qualification/" + action
	}
	return "/appliance/v1/update/" + action
}
func (n *Network) Close() { n.client.CloseIdleConnections(); n.public.CloseIdleConnections() }
func (n *Network) post(path string, q any, out any, public bool) error {
	body, e := w.Encode(q)
	if e != nil {
		return ErrDenied
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "POST", n.origin+path, bytes.NewReader(body))
	if e != nil {
		return ErrDenied
	}
	req.Header.Set("Content-Type", "application/json")
	client := n.client
	if public {
		client = n.public
	}
	resp, e := client.Do(req)
	if e != nil {
		return ErrDeferred
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, w.MaxBytes+1))
	if e != nil || len(b) > w.MaxBytes {
		return ErrDenied
	}
	if resp.StatusCode == 409 {
		return ErrReconcile
	}
	if resp.StatusCode != 200 {
		return ErrDenied
	}
	if resp.Header.Get("Content-Type") != "application/json" || w.Decode(b, out) != nil {
		return ErrDenied
	}
	return nil
}
func (n *Network) Challenge(i w.Identity, p string) (w.Challenge, error) {
	q := struct {
		Identity w.Identity `json:"identity"`
		Purpose  string     `json:"purpose"`
	}{i, p}
	var out w.Challenge
	e := n.post("/appliance/v1/credential/challenge", q, &out, p != "renew")
	return out, e
}
func (n *Network) Prove(i w.Identity, p w.Signed) (w.CredentialResult, error) {
	q := struct {
		Identity w.Identity `json:"identity"`
		Proof    w.Signed   `json:"proof"`
	}{i, p}
	var out w.CredentialResult
	e := n.post("/appliance/v1/credential/prove", q, &out, true)
	return out, e
}
func (n *Network) Installed(i w.Identity, p w.Signed) error {
	q := struct {
		Identity w.Identity `json:"identity"`
		Proof    w.Signed   `json:"proof"`
	}{i, p}
	var out struct {
		Installed bool `json:"installed"`
	}
	if e := n.post("/appliance/v1/credential/installed", q, &out, true); e != nil {
		return e
	}
	if !out.Installed {
		return ErrDenied
	}
	return nil
}
func (n *Network) Poll(i w.Identity) (*Assignment, error) {
	q := struct {
		Identity w.Identity `json:"identity"`
	}{i}
	var a *Assignment
	e := n.post(n.updatePath("poll"), q, &a, false)
	return a, e
}
func (n *Network) Lease(i w.Identity, phase string) (w.Signed, error) {
	q := struct {
		Identity w.Identity `json:"identity"`
		Phase    string     `json:"phase"`
	}{i, phase}
	var out w.Signed
	e := n.post(n.updatePath("lease"), q, &out, false)
	return out, e
}
func (n *Network) Report(r w.Receipt) error {
	q := struct {
		Identity w.Identity `json:"identity"`
		Receipt  w.Receipt  `json:"receipt"`
	}{r.Identity, r}
	var out struct {
		Recorded bool `json:"recorded"`
	}
	if e := n.post(n.updatePath("report"), q, &out, false); e != nil {
		return e
	}
	if !out.Recorded {
		return ErrDenied
	}
	return nil
}

// Artifact uses only the content-addressed path on the fixed authority origin.
// The caller checks length and digest against an independently signed release.
func (n *Network) Artifact(digest string) (io.ReadCloser, error) {
	if !w.IsDigest(digest) {
		return nil, ErrDenied
	}
	req, e := http.NewRequest("GET", n.origin+"/appliance/v1/artifacts/"+strings.TrimPrefix(digest, "sha256:"), nil)
	if e != nil {
		return nil, e
	}
	resp, e := n.client.Do(req)
	if e != nil {
		return nil, ErrDeferred
	}
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/octet-stream" {
		resp.Body.Close()
		return nil, ErrDenied
	}
	return resp.Body, nil
}
