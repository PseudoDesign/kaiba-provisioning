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

// Runtime is supplied by the executable. Tests use deterministic clocks and boot
// IDs; the CLI reads the real kernel boot ID and starts a new process identity.
type Runtime struct {
	Now     func() time.Time
	BootID  func() (string, error)
	Process string
}

func SystemRuntime() Runtime {
	return Runtime{Now: time.Now, BootID: func() (string, error) {
		b, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
		id := strings.TrimSpace(string(b))
		if e != nil || !bootPattern.MatchString(id) {
			return "", ErrState
		}
		return id, nil
	}, Process: strconv.Itoa(os.Getpid()) + ":" + strconv.FormatInt(time.Now().UnixNano(), 10)}
}

type Client struct {
	store   *store
	value   state
	runtime Runtime
}

func Open(path string, r Runtime) (*Client, error) {
	if r.Now == nil || r.BootID == nil || r.Process == "" {
		return nil, ErrInput
	}
	s, e := openStore(path)
	if e != nil {
		return nil, ErrState
	}
	v, e := s.load()
	if e != nil {
		s.close()
		return nil, ErrState
	}
	return &Client{s, v, r}, nil
}
func Initialize(path string, c Config, r Runtime) (Status, error) {
	if c.validate() != nil || r.Now == nil || r.BootID == nil || r.Process == "" {
		return Status{}, ErrInput
	}
	s, e := openStore(path)
	if e != nil {
		return Status{}, ErrState
	}
	defer s.close()
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
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return Status{}, ErrState
	}
	der, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		return Status{}, ErrState
	}
	defer clear(der)
	v := state{Schema: Version, Config: c, Key: der, Phase: "initialized"}
	if e = s.save(v); e != nil {
		return Status{}, e
	}
	return v.status()
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
func sign(v state, ch Challenge) (string, error) {
	k, e := privateKey(v.Key)
	if e != nil {
		return "", e
	}
	b, e := canonical(ch)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256(b)
	sig, e := ecdsa.SignASN1(rand.Reader, k, sum[:])
	if e != nil {
		return "", ErrState
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Bootstrap accepts a challenge relayed over the station's authenticated target
// connection. The caller does not get a generic signing or private-key API.
func (c *Client) Bootstrap(raw []byte) (Proof, error) {
	var ch Challenge
	if e := decode(raw, &ch); e != nil {
		return Proof{}, e
	}
	if e := ch.valid(c.value, "bootstrap", c.runtime.Now(), c.value.Bootstrap == nil); e != nil {
		return Proof{}, e
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
	proof, e := sign(c.value, ch)
	if e != nil {
		return Proof{}, e
	}
	v := c.value
	v.Bootstrap = &ch
	v.BootstrapProof = proof
	v.Phase = "bootstrap_proved"
	if e = c.save(v); e != nil {
		return Proof{}, e
	}
	return Proof{proof}, nil
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
	if _, e := v.leaf(c.runtime.Now(), true); e != nil {
		return Status{}, e
	}
	boot, e := c.runtime.BootID()
	if e != nil || !bootPattern.MatchString(boot) {
		return Status{}, ErrState
	}
	v.InstalledBoot = boot
	v.InstalledProcess = c.runtime.Process
	v.Phase = "installed"
	if e = c.save(v); e != nil {
		return Status{}, e
	}
	return c.Status()
}

type enrollmentResponse struct {
	ID      string `json:"id"`
	Request struct {
		Authority   string    `json:"authority"`
		Transaction string    `json:"transaction_id"`
		Record      RecordRef `json:"record"`
		SPKI        string    `json:"spki"`
		Target      string    `json:"target"`
		Replaces    string    `json:"replaces,omitempty"`
	} `json:"request"`
	State       string          `json:"state"`
	Challenge   Challenge       `json:"challenge"`
	Certificate string          `json:"certificate,omitempty"`
	Binding     json.RawMessage `json:"binding,omitempty"`
	Verifier    json.RawMessage `json:"verifier_receipt,omitempty"`
	Policy      string          `json:"policy"`
	Logical     string          `json:"logical_device_id"`
	Storage     uint64          `json:"storage_generation"`
}

// This is the credential tuple verified by the rehearsal service. The client
// does not treat a DeviceBinding document as authorization for fleet access.
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

func (c *Client) validCredential(v credential) bool {
	leaf, e := c.value.leaf(time.Time{}, false)
	if e != nil {
		return false
	}
	before, beforeErr := time.Parse(time.RFC3339Nano, v.Before)
	after, afterErr := time.Parse(time.RFC3339Nano, v.After)
	return v.Slot == "management" && v.Role == "outbound_management" && v.Generation == 1 &&
		v.SPKI == c.value.Bootstrap.SPKI && v.Issuer == c.value.Config.IssuerID &&
		v.Serial == leaf.SerialNumber.Text(16) && beforeErr == nil && afterErr == nil &&
		before.Equal(leaf.NotBefore) && after.Equal(leaf.NotAfter)
}

func (c *Client) response(b []byte) (enrollmentResponse, error) {
	var en enrollmentResponse
	if decode(b, &en) != nil {
		return en, ErrResponse
	}
	bound := c.value.Bootstrap
	status, e := c.Status()
	if e != nil || bound == nil {
		return en, ErrState
	}
	if en.ID != bound.Enrollment || en.Logical != bound.Logical || en.Storage != bound.Storage || en.Request.Record != bound.Provisioning || en.Request.SPKI != status.SPKI || en.Certificate != c.value.Certificate || en.Policy != "rehearsal-v1" || en.Request.Authority != c.value.Config.Authority || en.Request.Transaction != c.value.Config.Transaction || en.Request.Target != c.value.Config.Target || en.Request.Replaces != "" {
		return en, ErrBinding
	}
	return en, nil
}
func (c *Client) transport() (*http.Client, error) {
	leaf, e := c.value.leaf(c.runtime.Now(), true)
	if e != nil {
		return nil, e
	}
	k, e := privateKey(c.value.Key)
	if e != nil {
		return nil, e
	}
	root, e := certificate(c.value.Config.ServerCA)
	if e != nil {
		return nil, ErrInput
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: k, Leaf: leaf}}}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, DisableKeepAlives: true}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrTransport }}, nil
}
func (c *Client) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	h, e := c.transport()
	if e != nil {
		return nil, 0, e
	}
	defer h.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, method, cleanOrigin(c.value.Config.FleetURL)+path, bytes.NewReader(body))
	if e != nil {
		return nil, 0, ErrInput
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := h.Do(req)
	if e != nil {
		return nil, 0, ErrTransport
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, res.StatusCode, ErrTransport
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if e != nil || len(b) > maxBytes {
		return nil, res.StatusCode, ErrResponse
	}
	return b, res.StatusCode, nil
}

// ProveInstalled submits at most one challenge request and one proof request.
// The signed proof is durable before transmission. An ambiguous proof response
// requires authenticated station reconciliation, not a new challenge or retry.
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
	boot, e := c.runtime.BootID()
	if e != nil || !bootPattern.MatchString(boot) {
		return Status{}, ErrState
	}
	if (c.value.Config.Restart == "boot" && boot == c.value.InstalledBoot) || (c.value.Config.Restart == "process" && c.runtime.Process == c.value.InstalledProcess) {
		return Status{}, ErrRestart
	}
	path := "/api/v1/enrollments/" + c.value.Bootstrap.Enrollment
	raw, _, e := c.request(ctx, http.MethodPost, path+"/pending-challenge", []byte("{}"))
	if e != nil {
		return Status{}, e
	}
	en, e := c.response(raw)
	if e != nil {
		return Status{}, e
	}
	if en.State != "staged" {
		return Status{}, ErrResponse
	}
	if e = en.Challenge.valid(c.value, "installed_key", c.runtime.Now(), true); e != nil {
		return Status{}, e
	}
	proof, e := sign(c.value, en.Challenge)
	if e != nil {
		return Status{}, e
	}
	v := c.value
	v.Pending = &en.Challenge
	v.PendingProof = proof
	v.ProofBoot = boot
	v.Phase = "proof_submitted"
	if e = c.save(v); e != nil {
		return Status{}, e
	}
	body, _ := canonical(Proof{proof})
	raw, _, e = c.request(ctx, http.MethodPost, path+"/pending-proof", body)
	if e != nil {
		return Status{}, ErrReconcile
	}
	return c.complete(raw, boot)
}
func (c *Client) complete(raw []byte, boot string) (Status, error) {
	en, e := c.response(raw)
	if e != nil {
		return Status{}, e
	}
	if en.State != "verified" && en.State != "active" {
		return Status{}, ErrReconcile
	}
	var receipt struct {
		Challenge  Challenge  `json:"challenge"`
		Credential credential `json:"credential"`
		VerifiedAt string     `json:"verified_at"`
		Policy     string     `json:"policy"`
	}
	if decode(en.Verifier, &receipt) != nil || c.value.Pending == nil || receipt.Challenge != *c.value.Pending || receipt.Policy != en.Policy || !c.validCredential(receipt.Credential) {
		return Status{}, ErrBinding
	}
	at, e := time.Parse(time.RFC3339Nano, receipt.VerifiedAt)
	deadline, _ := time.Parse(time.RFC3339Nano, receipt.Challenge.Expires)
	if e != nil || at.Before(deadline.Add(-5*time.Minute)) || !at.Before(deadline) || at.After(c.runtime.Now().Add(30*time.Second)) {
		return Status{}, ErrResponse
	}
	if !bootPattern.MatchString(boot) || (c.value.Config.Restart == "boot" && boot == c.value.InstalledBoot) {
		return Status{}, ErrRestart
	}
	v := c.value
	v.Phase = "verified"
	v.VerifiedBoot = boot
	if e = c.save(v); e != nil {
		return Status{}, e
	}
	return c.Status()
}

// Reconcile consumes a response obtained by the authenticated station from the
// fleet status endpoint. It cannot cause network requests or reissue a proof.
func (c *Client) Reconcile(raw []byte) (Status, error) {
	if c.value.Phase != "proof_submitted" {
		return Status{}, ErrState
	}
	return c.complete(raw, c.value.ProofBoot)
}

// RetryInstalled is an explicit retry after the authenticated station confirms
// that the same unexpired challenge is still staged. It sends only the saved
// signature; it cannot acquire a new challenge or sign again. A raced or lost
// response still requires reconciliation.
func (c *Client) RetryInstalled(ctx context.Context, raw []byte) (Status, error) {
	if c.value.Phase != "proof_submitted" || c.value.Pending == nil {
		return Status{}, ErrState
	}
	en, e := c.response(raw)
	if e != nil {
		return Status{}, e
	}
	if en.State != "staged" || en.Challenge != *c.value.Pending || len(en.Verifier) != 0 {
		return Status{}, ErrReconcile
	}
	if e = en.Challenge.valid(c.value, "installed_key", c.runtime.Now(), true); e != nil {
		return Status{}, e
	}
	body, _ := canonical(Proof{c.value.PendingProof})
	result, _, e := c.request(ctx, http.MethodPost, "/api/v1/enrollments/"+en.ID+"/pending-proof", body)
	if e != nil {
		return Status{}, ErrReconcile
	}
	return c.complete(result, c.value.ProofBoot)
}

type AccessResult struct {
	Allowed              bool `json:"allowed"`
	ProductionEnrollment bool `json:"production_enrollment"`
	HardwareQualified    bool `json:"hardware_qualified"`
}

func (c *Client) CheckAccess(ctx context.Context) (AccessResult, error) {
	if c.value.Certificate == "" {
		return AccessResult{}, ErrState
	}
	raw, status, e := c.request(ctx, http.MethodGet, "/api/v1/access", nil)
	if status == http.StatusForbidden {
		return AccessResult{}, nil
	}
	if e != nil {
		return AccessResult{}, e
	}
	var value struct {
		Authorized string `json:"authorized"`
		Instance   string `json:"instance_id"`
	}
	if decode(raw, &value) != nil || value.Authorized != "rehearsal" || value.Instance != c.value.Bootstrap.Instance {
		return AccessResult{}, ErrBinding
	}
	return AccessResult{Allowed: true}, nil
}
