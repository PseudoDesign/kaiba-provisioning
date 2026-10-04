package appliance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"os"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/appliancestate"
	w "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/appliancewire"
)

// CredentialAPI must use a pinned server-authenticated origin. Renewal also
// presents the current mTLS certificate; expired recovery never does.
type CredentialAPI interface {
	Challenge(w.Identity, string) (w.Challenge, error)
	Prove(w.Identity, w.Signed) (w.CredentialResult, error)
	Installed(w.Identity, w.Signed) error
}
type credentialState struct {
	Version      string              `json:"version"`
	Identity     w.Identity          `json:"identity"`
	Provisioning string              `json:"provisioning_digest"`
	Key          string              `json:"private_key_pkcs8"`
	Certificate  string              `json:"certificate_der,omitempty"`
	Challenge    *w.Challenge        `json:"challenge,omitempty"`
	Result       *w.CredentialResult `json:"installation_pending,omitempty"`
}
type Credentials struct {
	store    *appliancestate.Store
	state    credentialState
	key      *ecdsa.PrivateKey
	roots    *x509.CertPool
	now      func() time.Time
	check    func(*os.File, string) error
	volume   string
	poisoned bool
}

func newCredentials(path, volume string, roots *x509.CertPool, now func() time.Time, check func(*os.File, string) error) (*Credentials, error) {
	if volume == "" || roots == nil || now == nil {
		return nil, ErrDenied
	}
	s, e := appliancestate.Open(path)
	if e != nil {
		return nil, e
	}
	if check == nil {
		check = VerifyProtectedDirectory
	}
	if check(s.Directory(), volume) != nil {
		s.Close()
		return nil, ErrDenied
	}
	return &Credentials{store: s, roots: roots, now: now, check: check, volume: volume}, nil
}

// CreateCredentials is a one-time fixture operation before Fleet registration.
// Missing state during normal boot is never interpreted as permission to rekey.
func CreateCredentials(path, volume string, i w.Identity, provisioning string, roots *x509.CertPool, now func() time.Time, check func(*os.File, string) error) (*Credentials, error) {
	c, e := newCredentials(path, volume, roots, now, check)
	if e != nil {
		return nil, e
	}
	var old credentialState
	e = c.store.Load(&old)
	if !os.IsNotExist(e) || i.SPKI != "" || !w.IsDigest(provisioning) {
		c.Close()
		return nil, ErrDenied
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		c.Close()
		return nil, e
	}
	i.SPKI = w.SPKIDigest(&key.PublicKey)
	if i.Validate() != nil {
		c.Close()
		return nil, ErrDenied
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		c.Close()
		return nil, e
	}
	c.key = key
	c.state = credentialState{Version: "kaiba.production-credentials/v1", Identity: i, Provisioning: provisioning, Key: base64.StdEncoding.EncodeToString(der)}
	clear(der)
	if e = c.save(); e != nil {
		c.Close()
		return nil, e
	}
	return c, nil
}
func OpenCredentials(path, volume string, i w.Identity, provisioning string, roots *x509.CertPool, now func() time.Time, check func(*os.File, string) error) (*Credentials, error) {
	c, e := newCredentials(path, volume, roots, now, check)
	if e != nil {
		return nil, e
	}
	if c.store.Load(&c.state) != nil || c.state.Version != "kaiba.production-credentials/v1" || c.state.Identity != i || i.Validate() != nil || c.state.Provisioning != provisioning {
		c.Close()
		return nil, ErrReconcile
	}
	b, e := base64.StdEncoding.DecodeString(c.state.Key)
	if e != nil || len(b) > 2048 {
		c.Close()
		return nil, ErrReconcile
	}
	raw, e := x509.ParsePKCS8PrivateKey(b)
	clear(b)
	k, ok := raw.(*ecdsa.PrivateKey)
	if e != nil || !ok || k.Curve != elliptic.P256() || w.SPKIDigest(&k.PublicKey) != i.SPKI {
		c.Close()
		return nil, ErrReconcile
	}
	c.key = k
	if c.state.Challenge != nil && (c.state.Challenge.Validate(time.Time{}, false) != nil || c.state.Challenge.Identity != i || c.state.Challenge.Provisioning != provisioning) {
		c.Close()
		return nil, ErrReconcile
	}
	if c.state.Certificate != "" {
		cert, e := w.ParseCertificate(c.state.Certificate)
		if e != nil || w.ValidateCertificate(cert, roots, i, cert.NotBefore.Add(time.Second)) != nil {
			c.Close()
			return nil, ErrReconcile
		}
	}
	if c.state.Result != nil && c.validateResult(*c.state.Result) != nil {
		c.Close()
		return nil, ErrReconcile
	}
	return c, nil
}
func (c *Credentials) Close() { c.store.Close() }
func (c *Credentials) save() error {
	if c.poisoned || c.check(c.store.Directory(), c.volume) != nil {
		return ErrReconcile
	}
	if c.store.Save(c.state) != nil {
		c.poisoned = true
		return ErrReconcile
	}
	return nil
}
func (c *Credentials) Identity() w.Identity       { return c.state.Identity }
func (c *Credentials) PublicKey() (string, error) { return w.MarshalPublic(&c.key.PublicKey) }
func (c *Credentials) CertificateDigest() (string, error) {
	cert, e := w.ParseCertificate(c.state.Certificate)
	if e != nil {
		return "", ErrDenied
	}
	return w.Digest(cert.Raw), nil
}
func (c *Credentials) TLSCertificate() (tls.Certificate, error) {
	if c.poisoned || c.check(c.store.Directory(), c.volume) != nil {
		return tls.Certificate{}, ErrDenied
	}
	cert, e := w.ParseCertificate(c.state.Certificate)
	if e != nil || w.ValidateCertificate(cert, c.roots, c.state.Identity, c.now()) != nil {
		return tls.Certificate{}, ErrDenied
	}
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: c.key, Leaf: cert}, nil
}
func (c *Credentials) validateResult(r w.CredentialResult) error {
	if c.state.Challenge == nil || r.Validate() != nil || r.Identity != c.state.Identity || r.Operation != c.state.Challenge.ID {
		return ErrDenied
	}
	raw, _ := w.Encode(*c.state.Challenge)
	if r.ChallengeDigest != w.Digest(raw) {
		return ErrDenied
	}
	cert, e := w.ParseCertificate(r.Certificate)
	if e != nil {
		return ErrDenied
	}
	return w.ValidateCertificate(cert, c.roots, c.state.Identity, cert.NotBefore.Add(time.Second))
}

// Maintain completes saved issuance/installation before requesting another
// challenge. Certificates and keys survive a reboot on the protected volume.
func (c *Credentials) Maintain(api CredentialAPI) error {
	if api == nil || c.poisoned || c.check(c.store.Directory(), c.volume) != nil {
		return ErrDenied
	}
	if c.state.Result != nil {
		return c.install(api)
	}
	purpose := "enroll"
	predecessor := ""
	if c.state.Certificate != "" {
		cert, e := w.ParseCertificate(c.state.Certificate)
		if e != nil {
			return ErrReconcile
		}
		predecessor = w.Digest(cert.Raw)
		if !c.now().Before(cert.NotAfter) {
			purpose = "recover"
		} else if cert.NotAfter.Sub(c.now()) <= 10*24*time.Hour {
			purpose = "renew"
		} else {
			return nil
		}
	}
	if c.state.Challenge == nil {
		ch, e := api.Challenge(c.state.Identity, purpose)
		if e != nil {
			return e
		}
		key, _ := c.PublicKey()
		if ch.Validate(c.now(), true) != nil || ch.Identity != c.state.Identity || ch.PublicKey != key || ch.Purpose != purpose || ch.Predecessor != predecessor || ch.Provisioning != c.state.Provisioning {
			return ErrDenied
		}
		c.state.Challenge = &ch
		if e = c.save(); e != nil {
			return e
		}
	}
	proof, e := w.Sign("credential-proof", "device", *c.state.Challenge, c.key)
	if e != nil {
		return e
	}
	result, e := api.Prove(c.state.Identity, proof)
	if e != nil {
		// Retain a dispatched transaction. Only a new, live server challenge can
		// replace an expired challenge the server has never dispatched.
		if c.state.Challenge.Validate(c.now(), true) != nil {
			ch, ce := api.Challenge(c.state.Identity, purpose)
			key, _ := c.PublicKey()
			if ce == nil && ch.Validate(c.now(), true) == nil && ch.Identity == c.state.Identity && ch.PublicKey == key && ch.Purpose == purpose && ch.Predecessor == predecessor && ch.Provisioning == c.state.Provisioning {
				c.state.Challenge = &ch
				if ce = c.save(); ce != nil {
					return ce
				}
			}
		}
		return e
	}
	if c.validateResult(result) != nil {
		return ErrDenied
	}
	cert, _ := w.ParseCertificate(result.Certificate)
	if w.ValidateCertificate(cert, c.roots, c.state.Identity, cert.NotBefore.Add(time.Second)) != nil {
		return ErrDenied
	}
	c.state.Result = &result
	if e = c.save(); e != nil {
		return e
	}
	return c.install(api)
}
func (c *Credentials) install(api CredentialAPI) error {
	r := *c.state.Result
	if c.validateResult(r) != nil {
		return ErrReconcile
	}
	cert, _ := w.ParseCertificate(r.Certificate)
	if w.ValidateCertificate(cert, c.roots, c.state.Identity, cert.NotBefore.Add(time.Second)) != nil {
		return ErrDenied
	}
	c.state.Certificate = r.Certificate
	if e := c.save(); e != nil {
		return e
	}
	proof, e := w.Sign("credential-installed", "device", r, c.key)
	if e != nil {
		return e
	}
	if e = api.Installed(c.state.Identity, proof); e != nil {
		return e
	}
	c.state.Result = nil
	c.state.Challenge = nil
	return c.save()
}
