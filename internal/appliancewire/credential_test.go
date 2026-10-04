package appliancewire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func TestCertificateExactRoleIdentityAndWindow(t *testing.T) {
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true}
	b, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ = x509.ParseCertificate(b)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	id := testIdentity()
	id.SPKI = SPKIDigest(&key.PublicKey)
	for _, mutation := range []string{"valid", "identity", "role", "name", "lifetime", "key-usage", "uri", "hidden-name", "subject"} {
		t.Run(mutation, func(t *testing.T) {
			uri, _ := CertificateURI(id)
			c := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Second), NotAfter: now.Add(30*24*time.Hour - time.Second), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
			expected := id
			switch mutation {
			case "identity":
				expected.Storage++
			case "role":
				c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
			case "name":
				c.DNSNames = []string{"unexpected.example"}
			case "lifetime":
				c.NotAfter = c.NotAfter.Add(time.Hour)
			case "key-usage":
				c.KeyUsage |= x509.KeyUsageKeyEncipherment
			case "subject":
				c.Subject.CommonName = "another-role"
			case "hidden-name":
				hidden, _ := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(uri.String())}, {Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: []byte{}}})
				c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: hidden}}
			case "uri":
				c.URIs = append(c.URIs, uri)
			}
			b, e := x509.CreateCertificate(rand.Reader, c, ca, &key.PublicKey, caKey)
			if e != nil {
				t.Fatal(e)
			}
			c, _ = x509.ParseCertificate(b)
			e = ValidateCertificate(c, roots, expected, now)
			if (e == nil) != (mutation == "valid") {
				t.Fatal("certificate policy", e)
			}
			if mutation == "valid" && ValidateCertificate(c, roots, id, c.NotAfter) == nil {
				t.Fatal("exact expiry accepted")
			}
		})
	}
}
func TestPathIDsAndDiagnostics(t *testing.T) {
	for _, id := range []string{"../attempt", "attempt/other", ".", ""} {
		if ID(id) {
			t.Fatal("unsafe ID", id)
		}
	}
	d := Diagnostics{Header: NewHeader("ApplianceDiagnostics"), Identity: testIdentity(), Sequence: 1, Entries: []Diagnostic{{Code: "update-deferred", At: "2026-10-03T00:00:00Z", Attempt: "attempt"}}}
	if d.Validate() != nil {
		t.Fatal("valid diagnostics")
	}
	d.Entries[0].Code = "cat /etc/shadow"
	if d.Validate() == nil {
		t.Fatal("free-form diagnostics accepted")
	}
}
