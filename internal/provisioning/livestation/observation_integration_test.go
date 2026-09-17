package livestation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/authorityhttp"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
)

func TestObservationAgainstRealMutualTLSControlService(t *testing.T) {
	for _, scenario := range []string{"created", "claimed", "uncertain", "confirmed_applied", "confirmed_not_applied", "quarantined", "security_applied", "released", "transferred_then_released"} {
		t.Run(scenario, func(t *testing.T) {
			f := newObservationFixture(t)
			setup := scenario
			if scenario == "released" || scenario == "transferred_then_released" {
				setup = "aborted"
			}
			if scenario == "transferred_then_released" {
				setup = "claimed"
			}
			f.prepare(setup)
			if scenario == "transferred_then_released" {
				f.accept(f.service.TransferClaim(context.Background(), controlplane.TransferClaimRequest{
					SchemaVersion: controlplane.TransferClaimRequestSchemaVersion, IdempotencyKey: "handoff", TransactionID: f.transaction.ID,
					ExpectedResourceVersion: f.transaction.ResourceVersion, ClaimID: f.transaction.ActiveClaim.ID, FenceEpoch: f.transaction.FenceEpoch,
					NewStationID: "station-2", NewLaneID: "lane-2", Mode: controlplane.ClaimModeMutation, AllowedStages: f.operations, LeaseDurationSeconds: 300,
				}))
				f.accept(f.service.AbortTransaction(context.Background(), controlplane.AbortRequest{
					SchemaVersion: controlplane.AbortRequestSchemaVersion, IdempotencyKey: "abort-handoff", MutationContext: f.mutation(),
					ReusableBaselineDigest: observationDigest("a"), AuditReceiptID: observationDigest("b"),
				}))
			}
			if scenario == "released" || scenario == "transferred_then_released" {
				f.accept(f.service.ReleaseClaim(context.Background(), controlplane.ReleaseClaimRequest{
					SchemaVersion: controlplane.ReleaseClaimRequestSchemaVersion, IdempotencyKey: "release", TransactionID: f.transaction.ID,
					ExpectedResourceVersion: f.transaction.ResourceVersion, ClaimID: f.transaction.ActiveClaim.ID, FenceEpoch: f.transaction.FenceEpoch,
				}))
			}
			var reads atomic.Int32
			realHandler := controlplane.Handler(f.service, mtls.MutualTLSIdentityPolicy())
			server, files := observationTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reads.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/transactions/transaction-1" {
					t.Errorf("unexpected authority request: %s %s", r.Method, r.URL.Path)
				}
				realHandler.ServeHTTP(w, r)
			}))
			reader, err := authorityhttp.NewControlReader(server.URL, files)
			if err != nil {
				t.Fatal(err)
			}
			observer, err := NewObserver(observerConfig(t), reader)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := f.store.Load()
			state := readObservation(t, observer)
			after, _ := f.store.Load()
			if !bytes.Equal(before, after) || reads.Load() != 1 {
				t.Fatal("observation modified control state or made excess authority calls")
			}
			if scenario == "created" || scenario == "transferred_then_released" {
				if state.ReadStatus != "denied" || state.Snapshot != nil {
					t.Fatalf("inaccessible transaction leaked: %#v", state)
				}
				return
			}
			if state.ReadStatus != "current" || state.Snapshot == nil || state.Snapshot.Status != f.transaction.Status {
				t.Fatalf("state = %#v", state)
			}
			if scenario == "released" && (state.Snapshot.ActiveClaim != nil || len(state.Snapshot.ClaimHistory) != 1) {
				t.Fatal("historical owner did not recover released transaction")
			}
			// A different station/lane configuration cannot accept another owner's
			// response even if a caller wires the wrong credential to the reader.
			config := observerConfig(t)
			config.LaneID = "lane-other"
			mismatched, err := NewObserver(config, reader)
			if err != nil {
				t.Fatal(err)
			}
			if state := readObservation(t, mismatched); state.ReadStatus != "invalid_response" || state.Snapshot != nil {
				t.Fatal("mismatched owner response accepted")
			}
		})
	}
}

func TestObservationRealAuthorityDenialAndMalformedResponsesClearPreviousSnapshot(t *testing.T) {
	f := newObservationFixture(t)
	f.claim()
	var corrupt atomic.Bool
	realHandler := controlplane.Handler(f.service, mtls.MutualTLSIdentityPolicy())
	server, files := observationTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if corrupt.Load() {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"schema_version":"` + controlplane.TransactionSchemaVersion + `","id":"transaction-1","resource_version":"invalid"}`))
			return
		}
		realHandler.ServeHTTP(w, r)
	}))
	reader, err := authorityhttp.NewControlReader(server.URL, files)
	if err != nil {
		t.Fatal(err)
	}
	observer, err := NewObserver(observerConfig(t), reader)
	if err != nil {
		t.Fatal(err)
	}
	if readObservation(t, observer).Snapshot == nil {
		t.Fatal("initial read failed")
	}
	corrupt.Store(true)
	if state := readObservation(t, observer); state.ReadStatus != "invalid_response" || state.Snapshot != nil || state.LastSuccessfulRead != nil {
		t.Fatal("malformed response retained evidence")
	}
	corrupt.Store(false)
	if readObservation(t, observer).Snapshot == nil {
		t.Fatal("valid response did not restore view")
	}
	f.accept(f.service.TransferClaim(context.Background(), controlplane.TransferClaimRequest{
		SchemaVersion: controlplane.TransferClaimRequestSchemaVersion, IdempotencyKey: "handoff", TransactionID: f.transaction.ID,
		ExpectedResourceVersion: f.transaction.ResourceVersion, ClaimID: f.transaction.ActiveClaim.ID, FenceEpoch: f.transaction.FenceEpoch,
		NewStationID: "station-2", NewLaneID: "lane-2", Mode: controlplane.ClaimModeMutation, AllowedStages: f.operations, LeaseDurationSeconds: 300,
	}))
	before, _ := f.store.Load()
	if state := readObservation(t, observer); state.ReadStatus != "denied" || state.Snapshot != nil || state.LastSuccessfulRead != nil {
		t.Fatal("revoked owner retained evidence")
	}
	after, _ := f.store.Load()
	if !bytes.Equal(before, after) {
		t.Fatal("denied read changed authority state")
	}
}

// Disposable test PKI uses real verified TLS chains and the normal identity
// policy; no request.TLS or identity headers are injected by the tests.
func observationTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, mtls.ClientFiles) {
	t.Helper()
	directory := t.TempDir()
	now := time.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "observation-test-ca"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	issue := func(name string, serial int64, server bool) (string, string) {
		t.Helper()
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if server {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			uri, _ := url.Parse("spiffe://kaiba.network/station/station-1/lane/lane-1")
			leaf.URIs = []*url.URL{uri}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(leafKey)
		if err != nil {
			t.Fatal(err)
		}
		certPath, keyPath := filepath.Join(directory, name+".pem"), filepath.Join(directory, name+"-key.pem")
		if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
			t.Fatal(err)
		}
		return certPath, keyPath
	}
	serverCert, serverKey := issue("server", 2, true)
	clientCert, clientKey := issue("station", 3, false)
	serverTLS, err := mtls.LoadServerConfig(mtls.Files{Certificate: serverCert, PrivateKey: serverKey, ClientCA: caPath})
	if err != nil {
		t.Fatal(err)
	}
	if serverTLS.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("test TLS does not verify clients")
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = serverTLS
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, mtls.ClientFiles{Certificate: clientCert, PrivateKey: clientKey, ServerCA: caPath}
}
