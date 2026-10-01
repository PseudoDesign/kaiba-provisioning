package pilotenrollment

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"time"
)

// sameKeyCAContinuation permits only a new serial/signature and a bounded
// extension of NotAfter. Every other signed field, including all constraints,
// the subject and the public key, must remain byte-for-byte identical.
func sameKeyCAContinuation(old, next *x509.Certificate, now time.Time) error {
	fail := errors.New("CA continuation requires unchanged key and constraints")
	if old == nil || next == nil || !old.IsCA || !next.IsCA || !old.BasicConstraintsValid || !next.BasicConstraintsValid || old.CheckSignatureFrom(old) != nil || next.CheckSignatureFrom(old) != nil || !bytes.Equal(old.RawIssuer, old.RawSubject) || !bytes.Equal(next.RawIssuer, next.RawSubject) || now.Before(old.NotBefore) || !now.Before(old.NotAfter) || !old.NotBefore.Equal(next.NotBefore) || !next.NotAfter.After(old.NotAfter) || next.NotAfter.After(now.Add(90*24*time.Hour)) || len(old.UnhandledCriticalExtensions) != 0 || len(next.UnhandledCriticalExtensions) != 0 {
		return fail
	}
	fields := func(raw []byte) ([][]byte, error) {
		var seq asn1.RawValue
		rest, e := asn1.Unmarshal(raw, &seq)
		if e != nil || len(rest) != 0 || seq.Class != 0 || seq.Tag != 16 || !seq.IsCompound {
			return nil, fail
		}
		var out [][]byte
		data := seq.Bytes
		for len(data) > 0 {
			var v asn1.RawValue
			data, e = asn1.Unmarshal(data, &v)
			if e != nil {
				return nil, fail
			}
			out = append(out, v.FullBytes)
		}
		// Require explicit v3. Its TBS order is version, serial, algorithm, issuer,
		// validity, subject, SPKI, then optional unique IDs and extensions.
		if len(out) < 8 || !bytes.Equal(out[0], []byte{0xa0, 3, 2, 1, 2}) {
			return nil, fail
		}
		return out, nil
	}
	a, e := fields(old.RawTBSCertificate)
	if e != nil {
		return e
	}
	b, e := fields(next.RawTBSCertificate)
	if e != nil || len(a) != len(b) {
		return fail
	}
	for i := range a {
		if i != 1 && i != 4 && !bytes.Equal(a[i], b[i]) {
			return fail
		}
	}
	if old.SerialNumber.Cmp(next.SerialNumber) == 0 {
		return fail
	}
	return nil
}
