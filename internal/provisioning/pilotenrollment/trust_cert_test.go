package pilotenrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestSameKeyCAContinuation(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	base := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 0, MaxPathLenZero: true}
	cert := func(v x509.Certificate, k *ecdsa.PrivateKey) *x509.Certificate {
		b, e := x509.CreateCertificate(rand.Reader, &v, &v, &k.PublicKey, k)
		if e != nil {
			t.Fatal(e)
		}
		c, e := x509.ParseCertificate(b)
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	old := cert(base, key)
	next := base
	next.SerialNumber = big.NewInt(2)
	next.NotAfter = now.Add(45 * 24 * time.Hour)
	if e := sameKeyCAContinuation(old, cert(next, key), now); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(*x509.Certificate){"subject": func(c *x509.Certificate) { c.Subject.CommonName = "other" }, "path": func(c *x509.Certificate) { c.MaxPathLen = 1; c.MaxPathLenZero = false }, "backdate": func(c *x509.Certificate) { c.NotBefore = now.Add(-2 * time.Hour) }, "usage": func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageDigitalSignature }, "unbounded": func(c *x509.Certificate) { c.NotAfter = now.Add(91 * 24 * time.Hour) }, "same-serial": func(c *x509.Certificate) { c.SerialNumber = big.NewInt(1) }, "dns-constraint": func(c *x509.Certificate) { c.PermittedDNSDomains = []string{"example.test"} }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			bad := next
			change(&bad)
			if sameKeyCAContinuation(old, cert(bad, key), now) == nil {
				t.Fatal("changed trust accepted")
			}
		})
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if sameKeyCAContinuation(old, cert(next, other), now) == nil {
		t.Fatal("replacement key accepted")
	}
	if sameKeyCAContinuation(old, cert(next, key), now.Add(25*time.Hour)) == nil {
		t.Fatal("expired old trust accepted")
	}
}
