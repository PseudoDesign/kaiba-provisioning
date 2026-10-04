package appliancewire

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
)

func marshalPublic(k *ecdsa.PublicKey) (string, error) {
	b, e := x509.MarshalPKIXPublicKey(k)
	return base64.StdEncoding.EncodeToString(b), e
}
func MarshalPublic(k *ecdsa.PublicKey) (string, error) { return marshalPublic(k) }
