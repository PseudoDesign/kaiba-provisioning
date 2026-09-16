package mtls

import (
	"crypto/x509"
	"errors"
	"net/url"
	"testing"
)

func TestCertificateIdentityParserRequiresOneCanonicalStationURI(t *testing.T) {
	for _, test := range []struct {
		name  string
		uris  []string
		valid bool
	}{
		{"station", []string{"spiffe://kaiba.network/station/station-1/lane/lane-1"}, true},
		{"absent", nil, false},
		{"ambiguous", []string{"spiffe://kaiba.network/station/station-1/lane/lane-1", "spiffe://kaiba.network/station/station-2/lane/lane-1"}, false},
		{"approver", []string{"spiffe://kaiba.network/approver/verifier"}, false},
		{"other trust domain", []string{"spiffe://other.example/station/station-1/lane/lane-1"}, false},
		{"query", []string{"spiffe://kaiba.network/station/station-1/lane/lane-1?ignored=true"}, false},
		{"escaped", []string{"spiffe://kaiba.network/station/%73tation-1/lane/lane-1"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate := &x509.Certificate{}
			for _, value := range test.uris {
				uri, err := url.Parse(value)
				if err != nil {
					t.Fatal(err)
				}
				certificate.URIs = append(certificate.URIs, uri)
			}
			identity, err := ParseStationLaneCertificate(certificate)
			if test.valid {
				if err != nil || identity != (StationLaneIdentity{StationID: "station-1", LaneID: "lane-1"}) {
					t.Fatalf("identity=%#v err=%v", identity, err)
				}
			} else if !errors.Is(err, ErrClientIdentity) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	if _, err := ParseStationLaneCertificate(nil); !errors.Is(err, ErrClientIdentity) {
		t.Fatalf("nil certificate error=%v", err)
	}
}
