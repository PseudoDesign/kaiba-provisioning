package authorityhttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
)

func TestStationIdentityUsesTheLoadedCredential(t *testing.T) {
	certificate, key := writeClientCredential(t, "spiffe://kaiba.network/station/station-1/lane/lane-1")
	reader, err := NewControlReader("https://control.example", mtls.ClientFiles{Certificate: certificate, PrivateKey: key, ServerCA: certificate})
	if err != nil {
		t.Fatal(err)
	}
	other, _ := writeClientCredential(t, "spiffe://kaiba.network/station/station-2/lane/lane-2")
	replacement, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certificate, replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := reader.StationIdentity()
	if err != nil || identity != (mtls.StationLaneIdentity{StationID: "station-1", LaneID: "lane-1"}) {
		t.Fatalf("loaded identity=%#v err=%v", identity, err)
	}
}

func TestControlReaderClassifiesRejectedAndInvalidResponses(t *testing.T) {
	certificate, key := writeClientCredential(t)
	for _, test := range []struct {
		name        string
		status      int
		contentType string
		body        string
		wantInvalid bool
	}{
		{"denied", 403, "application/json", `{"private":"do not propagate"}`, false},
		{"unauthenticated", 401, "application/json", `{}`, false},
		{"missing", 404, "application/json", `{}`, false},
		{"server unavailable", 503, "application/json", `{}`, false},
		{"invalid content type", 200, "text/html", `<html>error</html>`, true},
		{"broken JSON", 200, "application/json", `{`, true},
		{"wrong identity", 200, "application/json", `{"schema_version":"provisioning.kaiba.network/control-transaction/v1alpha4","id":"another-transaction"}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, ca := startMTLSServer(t, func(writer http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodGet {
					t.Error("reader made a non-GET request")
				}
				writer.Header().Set("Content-Type", test.contentType)
				writer.WriteHeader(test.status)
				fmt.Fprint(writer, test.body)
			})
			reader, err := NewControlReader(server.URL, mtls.ClientFiles{Certificate: certificate, PrivateKey: key, ServerCA: ca})
			if err != nil {
				t.Fatal(err)
			}
			_, err = reader.GetTransaction(context.Background(), "transaction-1")
			if test.wantInvalid {
				var invalid *InvalidResponseError
				if !errors.As(err, &invalid) {
					t.Fatalf("expected invalid response, got %v", err)
				}
			} else {
				var status *HTTPStatusError
				if !errors.As(err, &status) || status.StatusCode != test.status {
					t.Fatalf("expected status %d, got %v", test.status, err)
				}
				if status.Error() != fmt.Sprintf("unexpected HTTP status %d %s", test.status, http.StatusText(test.status)) {
					t.Fatal("authority body reached status error")
				}
			}
		})
	}
}
