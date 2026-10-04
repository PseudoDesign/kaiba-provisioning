package appliancewire

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"net/url"
	"time"
)

// CredentialURI encodes every immutable binding. It grants only the appliance
// API role; authorization still requires the exact current inventory certificate.
func CredentialURI(i Identity) string {
	return fmt.Sprintf("kaiba-appliance://%s/%s/%s/%s/%s/%d/%s/%d/%s", i.Authority, i.Tenant, i.Device, i.Instance, i.Profile, i.Storage, i.Slot, i.Generation, i.SPKI)
}
func ParseCertificate(raw string) (*x509.Certificate, error) {
	b, e := base64.StdEncoding.DecodeString(raw)
	if e != nil || len(b) > 16384 || base64.StdEncoding.EncodeToString(b) != raw {
		return nil, ErrInvalid
	}
	return x509.ParseCertificate(b)
}
func ValidateCertificate(c *x509.Certificate, roots *x509.CertPool, i Identity, now time.Time) error {
	if c == nil || roots == nil || now.Before(c.NotBefore) || !now.Before(c.NotAfter) || i.Validate() != nil || c.IsCA || c.Subject.String() != "" || !singleURI(c, i) || c.KeyUsage != x509.KeyUsageDigitalSignature || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(c.UnknownExtKeyUsage) != 0 || len(c.URIs) != 1 || c.URIs[0].String() != CredentialURI(i) || len(c.DNSNames) != 0 || len(c.IPAddresses) != 0 || len(c.EmailAddresses) != 0 || c.NotAfter.Sub(c.NotBefore) > 30*time.Hour*24 || c.NotAfter.Sub(c.NotBefore) < time.Hour {
		return ErrInvalid
	}
	k, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || SPKIDigest(k) != i.SPKI {
		return ErrInvalid
	}
	raw, e := MarshalPublic(k)
	if e != nil {
		return ErrInvalid
	}
	if _, e := PublicKey(raw); e != nil {
		return ErrInvalid
	}
	_, e = c.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if e != nil {
		return ErrInvalid
	}
	return nil
}
func CertificateURI(i Identity) (*url.URL, error) {
	if i.Validate() != nil {
		return nil, ErrInvalid
	}
	return url.Parse(CredentialURI(i))
}

type CredentialResult struct {
	Header
	Operation       string   `json:"operation_id"`
	Identity        Identity `json:"identity"`
	ChallengeDigest string   `json:"challenge_digest"`
	Certificate     string   `json:"certificate_der"`
}

func (r CredentialResult) Validate() error {
	if !r.Header.Valid("ProductionCredentialResult") || !ID(r.Operation) || r.Identity.Validate() != nil || !IsDigest(r.ChallengeDigest) {
		return ErrInvalid
	}
	_, e := ParseCertificate(r.Certificate)
	return e
}

func singleURI(c *x509.Certificate, i Identity) bool {
	count := 0
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		count++
		var sequence asn1.RawValue
		rest, e := asn1.Unmarshal(ext.Value, &sequence)
		if e != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
			return false
		}
		var name asn1.RawValue
		rest, e = asn1.Unmarshal(sequence.Bytes, &name)
		if e != nil || len(rest) != 0 || name.Class != asn1.ClassContextSpecific || name.Tag != 6 || name.IsCompound || string(name.Bytes) != CredentialURI(i) {
			return false
		}
	}
	return count == 1
}
