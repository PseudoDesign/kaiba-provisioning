//go:build linux

package pilotenrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Runtime struct {
	Now          func() time.Time
	Process      string
	CheckStorage func(*os.File, string) error
}

func SystemRuntime() Runtime {
	return Runtime{Now: time.Now, Process: strconv.Itoa(os.Getpid()) + ":" + strconv.FormatInt(time.Now().UnixNano(), 10)}
}

type Client struct {
	store   *store
	value   state
	runtime Runtime
}

func Initialize(path string, c Config, r Runtime) (Status, error) {
	if c.validate() != nil || r.Now == nil || r.Process == "" {
		return Status{}, ErrInput
	}
	s, e := openStore(path)
	if e != nil {
		return Status{}, e
	}
	defer s.close()
	if e = checkStorage(s, c, r); e != nil {
		return Status{}, e
	}
	old, e := s.load()
	if e == nil {
		if old.Config != c {
			return Status{}, ErrBinding
		}
		return old.status()
	}
	if !errors.Is(e, os.ErrNotExist) {
		return Status{}, ErrState
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return Status{}, e
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return Status{}, e
	}
	defer clear(der)
	v := state{Schema: Version, Config: c, Key: der, Phase: "initialized"}
	if e = s.save(v); e != nil {
		return Status{}, e
	}
	return v.status()
}
func Open(path string, r Runtime) (*Client, error) {
	if r.Now == nil || r.Process == "" {
		return nil, ErrInput
	}
	s, e := openStore(path)
	if e != nil {
		return nil, e
	}
	v, e := s.load()
	if e == nil {
		e = checkStorage(s, v.Config, r)
	}
	if e != nil {
		clear(v.Key)
		s.close()
		return nil, e
	}
	return &Client{s, v, r}, nil
}
func (c *Client) Close()                  { clear(c.value.Key); c.store.close() }
func (c *Client) Status() (Status, error) { return c.value.status() }
func (c *Client) save(v state) error {
	if e := c.store.save(v); e != nil {
		return e
	}
	c.value = v
	return nil
}
func sign(s state, ch Challenge) (Proof, error) {
	key, e := privateKey(s.Key)
	if e != nil {
		return Proof{}, e
	}
	sum := sha256.Sum256(canon(ch))
	sig, e := ecdsa.SignASN1(rand.Reader, key, sum[:])
	return Proof{base64.StdEncoding.EncodeToString(sig)}, e
}
func (c *Client) Bootstrap(raw []byte) (Proof, error) {
	var ch Challenge
	if decode(raw, &ch) != nil {
		return Proof{}, ErrInput
	}
	if c.value.checkChallenge(ch, "bootstrap", c.runtime.Now(), c.value.Bootstrap == nil) != nil {
		return Proof{}, ErrBinding
	}
	if c.value.Bootstrap != nil {
		if *c.value.Bootstrap != ch {
			return Proof{}, ErrBinding
		}
		return Proof{c.value.BootstrapProof}, nil
	}
	if c.value.Phase != "initialized" {
		return Proof{}, ErrState
	}
	p, e := sign(c.value, ch)
	if e != nil {
		return Proof{}, e
	}
	v := c.value
	v.Bootstrap = &ch
	v.BootstrapProof = p.Signature
	v.Phase = "bootstrap_proved"
	if e = c.save(v); e != nil {
		return Proof{}, e
	}
	return p, nil
}
func (c *Client) Install(raw []byte) (Status, error) {
	if len(raw) > maxBytes {
		return Status{}, ErrInput
	}
	if c.value.Certificate != "" {
		if c.value.Certificate != string(raw) {
			return Status{}, ErrBinding
		}
		return c.Status()
	}
	if c.value.Phase != "bootstrap_proved" {
		return Status{}, ErrState
	}
	v := c.value
	v.Certificate = string(raw)
	if _, e := v.leaf(c.runtime.Now()); e != nil {
		return Status{}, e
	}
	v.InstalledProcess = c.runtime.Process
	v.Phase = "installed"
	if e := c.save(v); e != nil {
		return Status{}, e
	}
	return c.Status()
}
func (c *Client) request(ctx context.Context, method, path string, b []byte) ([]byte, error) {
	leaf, e := c.value.leaf(c.runtime.Now())
	if e != nil {
		return nil, e
	}
	key, e := privateKey(c.value.Key)
	if e != nil {
		return nil, e
	}
	ca, e := certificate(c.value.Config.ServerCA)
	if e != nil {
		return nil, e
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}}}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	defer tr.CloseIdleConnections()
	h := &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect denied") }}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.value.Config.FleetURL, "/")+path, bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	res, e := h.Do(req)
	if e != nil {
		return nil, ErrReconcile
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if e != nil || len(raw) > maxBytes || res.StatusCode != 200 {
		return nil, ErrReconcile
	}
	return raw, nil
}

// Only this response subset is interpreted, but the envelope remains closed.
type response struct {
	ID          string          `json:"id"`
	Logical     string          `json:"logical_device_id"`
	State       string          `json:"state"`
	Request     json.RawMessage `json:"request"`
	Intent      ProofBinding    `json:"intent"`
	Challenge   *Challenge      `json:"challenge,omitempty"`
	Bootstrap   json.RawMessage `json:"bootstrap_receipt,omitempty"`
	Certificate string          `json:"certificate,omitempty"`
	Binding     json.RawMessage `json:"binding,omitempty"`
	Receipt     *receipt        `json:"verifier_receipt,omitempty"`
}
type credential struct {
	Slot       string `json:"slot"`
	Role       string `json:"role"`
	Generation uint64 `json:"key_generation"`
	SPKI       string `json:"spki_digest"`
	Issuer     string `json:"issuer_id"`
	Serial     string `json:"certificate_serial"`
	Before     string `json:"not_before"`
	After      string `json:"not_after"`
}
type receipt struct {
	Challenge  Challenge  `json:"challenge"`
	Credential credential `json:"credential"`
	Signature  string     `json:"signature"`
	At         string     `json:"verified_at"`
	Restart    string     `json:"restart_kind"`
}

func (c *Client) response(raw []byte) (response, error) {
	var r response
	if decode(raw, &r) != nil {
		return r, ErrInput
	}
	b := c.value.Bootstrap
	if b == nil || r.ID != b.Enrollment || r.Logical != b.Logical || r.Intent != c.value.Config.Binding || r.Certificate != c.value.Certificate {
		return r, ErrBinding
	}
	return r, nil
}
func (c *Client) ProveInstalled(ctx context.Context) (Status, error) {
	if c.value.Phase == "verified" {
		return c.Status()
	}
	if c.value.Phase == "proof_submitted" {
		return Status{}, ErrReconcile
	}
	if c.value.Phase != "installed" {
		return Status{}, ErrState
	}
	if c.runtime.Process == c.value.InstalledProcess {
		return Status{}, ErrRestart
	}
	path := "/api/v1/pilot/enrollments/" + c.value.Bootstrap.Enrollment
	raw, e := c.request(ctx, "POST", path+"/pending-challenge", []byte("{}"))
	if e != nil {
		return Status{}, e
	}
	r, e := c.response(raw)
	if e != nil || r.State != "staged" || r.Challenge == nil {
		return Status{}, ErrBinding
	}
	if e = c.value.checkChallenge(*r.Challenge, "installed_key", c.runtime.Now(), true); e != nil {
		return Status{}, e
	}
	proof, e := sign(c.value, *r.Challenge)
	if e != nil {
		return Status{}, e
	}
	v := c.value
	v.Pending = r.Challenge
	v.PendingProof = proof.Signature
	v.Phase = "proof_submitted"
	if e = c.save(v); e != nil {
		return Status{}, e
	}
	raw, e = c.request(ctx, "POST", path+"/pending-proof", canon(proof))
	if e != nil {
		return Status{}, ErrReconcile
	}
	return c.Reconcile(raw)
}
func (c *Client) Reconcile(raw []byte) (Status, error) {
	if c.value.Phase != "proof_submitted" || c.value.Pending == nil {
		return Status{}, ErrState
	}
	r, e := c.response(raw)
	if e != nil {
		return Status{}, e
	}
	receipt := r.Receipt
	if (r.State != "verified" && r.State != "active") || receipt == nil || receipt.Challenge != *c.value.Pending || receipt.Signature != c.value.PendingProof || receipt.Restart != "client_process" {
		return Status{}, ErrBinding
	}
	leaf, e := c.value.leaf(c.runtime.Now())
	if e != nil {
		return Status{}, e
	}
	cred := receipt.Credential
	before, e1 := time.Parse(time.RFC3339Nano, cred.Before)
	after, e2 := time.Parse(time.RFC3339Nano, cred.After)
	at, e3 := time.Parse(time.RFC3339Nano, receipt.At)
	if e1 != nil || e2 != nil || e3 != nil || cred.Slot != "management" || cred.Role != "pilot_management" || cred.Generation != 1 || cred.SPKI != c.value.Pending.SPKI || cred.Issuer != c.value.Config.Binding.Issuer || cred.Serial != leaf.SerialNumber.Text(16) || !before.Equal(leaf.NotBefore) || !after.Equal(leaf.NotAfter) || at.After(c.runtime.Now().Add(30*time.Second)) {
		return Status{}, ErrBinding
	}
	status, _ := c.Status()
	if VerifyProof(receipt.Challenge, Proof{receipt.Signature}, status.SPKI, at) != nil {
		return Status{}, ErrBinding
	}
	v := c.value
	v.Phase = "verified"
	if e = c.save(v); e != nil {
		return Status{}, e
	}
	return c.Status()
}
func (c *Client) CheckAccess(ctx context.Context) (json.RawMessage, error) {
	raw, e := c.request(ctx, "GET", "/api/v1/pilot/self", nil)
	if e != nil {
		return nil, e
	}
	var v struct {
		Authorized string          `json:"authorized"`
		Instance   string          `json:"instance_id"`
		Binding    json.RawMessage `json:"binding"`
		Full       bool            `json:"full_qualification"`
	}
	if decode(raw, &v) != nil || v.Authorized != "pilot" || v.Instance != c.value.Bootstrap.Enrollment || v.Full {
		return nil, ErrBinding
	}
	return raw, nil
}

// RetryInstalled uses only the saved proof after an authenticated station read.
// It never creates another key, challenge or signature after an ambiguous reply.
func (c *Client) RetryInstalled(ctx context.Context, raw []byte) (Status, error) {
	if c.value.Phase != "proof_submitted" || c.value.Pending == nil {
		return Status{}, ErrState
	}
	r, e := c.response(raw)
	if e != nil {
		return Status{}, e
	}
	if r.State == "verified" || r.State == "active" {
		return c.Reconcile(raw)
	}
	if r.State != "staged" || r.Challenge == nil || *r.Challenge != *c.value.Pending || r.Receipt != nil {
		return Status{}, ErrReconcile
	}
	if e = c.value.checkChallenge(*r.Challenge, "installed_key", c.runtime.Now(), true); e != nil {
		return Status{}, e
	}
	reply, e := c.request(ctx, "POST", "/api/v1/pilot/enrollments/"+r.ID+"/pending-proof", canon(Proof{c.value.PendingProof}))
	if e != nil {
		return Status{}, ErrReconcile
	}
	return c.Reconcile(reply)
}
