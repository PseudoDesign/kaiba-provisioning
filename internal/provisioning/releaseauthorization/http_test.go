package releaseauthorization

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNonProductionHandlerCompletesBoundAuthorizationFlow(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	handler := NonProductionHandler(fixture.authority)
	challengeResponse := serveTLS13Request(handler, http.MethodPost, ChallengeEndpoint, nil, "")
	if challengeResponse.Code != http.StatusCreated {
		t.Fatalf("challenge status = %d; body=%s", challengeResponse.Code, challengeResponse.Body.String())
	}
	assertSecurityHeaders(t, challengeResponse)
	challenge, err := ParseChallenge(challengeResponse.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	requestDocument := fixture.request(t, challenge)
	requestJSON, err := requestDocument.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	authorizationResponse := serveTLS13Request(
		handler, http.MethodPost, AuthorizationEndpoint, requestJSON, "application/json",
	)
	if authorizationResponse.Code != http.StatusOK {
		t.Fatalf("authorization status = %d; body=%s", authorizationResponse.Code, authorizationResponse.Body.String())
	}
	authorization, err := ParseAuthorization(authorizationResponse.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthorization(authorization, requestDocument, fixture.authority.PublicKey(), 0); err != nil {
		t.Fatal(err)
	}
	proof, err := NewOneBootProof(authorization, testPrivateKey(3))
	if err != nil {
		t.Fatal(err)
	}
	proofJSON, err := proof.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	proofResponse := serveTLS13Request(handler, http.MethodPost, OneBootProofEndpoint, proofJSON, "application/json")
	if proofResponse.Code != http.StatusNoContent || proofResponse.Body.Len() != 0 {
		t.Fatalf("proof status = %d; body=%s", proofResponse.Code, proofResponse.Body.String())
	}
	proofReplay := serveTLS13Request(handler, http.MethodPost, OneBootProofEndpoint, proofJSON, "application/json")
	if proofReplay.Code != http.StatusConflict || !strings.Contains(proofReplay.Body.String(), `"code":"one_boot_proof_replayed"`) {
		t.Fatalf("proof replay status = %d; body=%s", proofReplay.Code, proofReplay.Body.String())
	}

	replay := serveTLS13Request(handler, http.MethodPost, AuthorizationEndpoint, requestJSON, "application/json")
	if replay.Code != http.StatusConflict || !strings.Contains(replay.Body.String(), `"code":"challenge_replayed"`) {
		t.Fatalf("replay status = %d; body=%s", replay.Code, replay.Body.String())
	}
}

func TestNonProductionHandlerRequiresTLS13AndFixedPOSTSurface(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	handler := NonProductionHandler(fixture.authority)
	tests := []struct {
		name       string
		method     string
		path       string
		tlsState   *tls.ConnectionState
		wantStatus int
	}{
		{"no TLS", http.MethodPost, ChallengeEndpoint, nil, http.StatusUpgradeRequired},
		{"TLS 1.2", http.MethodPost, ChallengeEndpoint, testTLSState(tls.VersionTLS12), http.StatusUpgradeRequired},
		{"incomplete TLS", http.MethodPost, ChallengeEndpoint, &tls.ConnectionState{Version: tls.VersionTLS13}, http.StatusUpgradeRequired},
		{"GET challenge", http.MethodGet, ChallengeEndpoint, testTLSState(tls.VersionTLS13), http.StatusMethodNotAllowed},
		{"GET authorize", http.MethodGet, AuthorizationEndpoint, testTLSState(tls.VersionTLS13), http.StatusMethodNotAllowed},
		{"registration absent", http.MethodPost, "/non-production/v1alpha1/bootstrap-registrations", testTLSState(tls.VersionTLS13), http.StatusNotFound},
		{"health absent", http.MethodGet, "/healthz", testTLSState(tls.VersionTLS13), http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "https://authority.invalid"+test.path, nil)
			request.TLS = test.tlsState
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
		})
	}
}

func TestNonProductionHandlerRejectsContentTypeAndBodyViolations(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	handler := NonProductionHandler(fixture.authority)
	tests := []struct {
		name        string
		path        string
		body        []byte
		contentType string
		wantStatus  int
	}{
		{"challenge body", ChallengeEndpoint, []byte(`{}`), "application/json", http.StatusBadRequest},
		{"challenge bad content type", ChallengeEndpoint, nil, "text/plain", http.StatusBadRequest},
		{"authorization missing content type", AuthorizationEndpoint, []byte(`{}`), "", http.StatusBadRequest},
		{"authorization wrong content type", AuthorizationEndpoint, []byte(`{}`), "text/plain", http.StatusBadRequest},
		{"authorization empty", AuthorizationEndpoint, nil, "application/json", http.StatusBadRequest},
		{"authorization too large", AuthorizationEndpoint, bytes.Repeat([]byte("x"), MaxDocumentBytes+1), "application/json", http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := serveTLS13Request(handler, http.MethodPost, test.path, test.body, test.contentType)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			assertSecurityHeaders(t, response)
		})
	}
}

func TestNonProductionClientUsesTLSAndPinnedAuthorityKey(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	server, tlsConfig := startTLS13Server(t, NonProductionHandler(fixture.authority))
	defer server.Close()
	client, err := NewNonProductionClient(NonProductionClientConfig{
		BaseURL: server.URL, AuthorityKeyID: "test-authority-1",
		AuthorityPublicKey: fixture.authority.PublicKey(), TLSConfig: tlsConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	receipt, err := client.IssueChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewAuthorizationRequest(
		receipt.Challenge, fixture.binding, clonePrivateKey(fixture.bootstrapPrivate), fixture.oneBootPublic,
		fixture.authority.PublicKey(), receipt.Elapsed(),
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := client.Authorize(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := NewOneBootProof(authorization, testPrivateKey(3))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ProveOneBoot(context.Background(), proof); err != nil {
		t.Fatal(err)
	}
	if err := client.ProveOneBoot(context.Background(), proof); !errors.Is(err, ErrOneBootReplay) {
		t.Fatalf("remote proof replay error = %v", err)
	}
	if _, err := client.Authorize(context.Background(), request); !errors.Is(err, ErrReplay) {
		t.Fatalf("remote replay error = %v", err)
	} else {
		var remote *RemoteError
		if !errors.As(err, &remote) || remote.StatusCode != http.StatusConflict || remote.Code != "challenge_replayed" {
			t.Fatalf("typed remote replay error = %#v", remote)
		}
	}

	wrongKeyClient, err := NewNonProductionClient(NonProductionClientConfig{
		BaseURL: server.URL, AuthorityKeyID: "test-authority-1",
		AuthorityPublicKey: testPrivateKey(12).Public().(ed25519.PublicKey), TLSConfig: tlsConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer wrongKeyClient.CloseIdleConnections()
	if _, err := wrongKeyClient.IssueChallenge(context.Background()); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong authority pin error = %v", err)
	}
}

func TestUnixAdminRegistrationIsIsolatedAndEnablesBootstrapRace(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	registration, err := NewBootstrapRegistration(fixture.binding.LogicalIdentity, fixture.bootstrapPublic)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := registration.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	handler := NonProductionAdminHandler(fixture.authority)
	unmarked := httptest.NewRequest(http.MethodPost, "http://unix"+BootstrapRegistrationEndpoint, bytes.NewReader(encoded))
	unmarked.Header.Set("Content-Type", "application/json")
	unmarkedResponse := httptest.NewRecorder()
	handler.ServeHTTP(unmarkedResponse, unmarked)
	if unmarkedResponse.Code != http.StatusForbidden {
		t.Fatalf("non-Unix admin status = %d", unmarkedResponse.Code)
	}

	socketPath := filepath.Join(shortSocketDirectory(t), "authority.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ConnContext: NonProductionAdminConnContext}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()
	defer func() {
		_ = server.Close()
		<-serveResult
	}()
	client, err := NewNonProductionAdminClient(socketPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if err := client.RegisterBootstrap(context.Background(), registration); err != nil {
		t.Fatal(err)
	}

	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.authority.Authorize(fixture.request(t, challenge)); err != nil {
		t.Fatalf("authorization after Unix registration: %v", err)
	}
}

func shortSocketDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "kaiba-auth-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func TestNonProductionClientCanClassifyOnlyBootstrapRegistrationRaceForRetry(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	server, tlsConfig := startTLS13Server(t, NonProductionHandler(fixture.authority))
	defer server.Close()
	client, err := NewNonProductionClient(NonProductionClientConfig{
		BaseURL: server.URL, AuthorityKeyID: "test-authority-1",
		AuthorityPublicKey: fixture.authority.PublicKey(), TLSConfig: tlsConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	receipt, err := client.IssueChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewAuthorizationRequest(
		receipt.Challenge, fixture.binding, clonePrivateKey(fixture.bootstrapPrivate), fixture.oneBootPublic,
		fixture.authority.PublicKey(), receipt.Elapsed(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Authorize(context.Background(), request); !errors.Is(err, ErrUntrustedBootstrap) {
		t.Fatalf("unregistered bootstrap error = %v", err)
	}
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Authorize(context.Background(), request); err != nil {
		t.Fatalf("retry after out-of-band registration: %v", err)
	}
}

func TestNonProductionClientRejectsRedirectWrongContentTypeAndOversize(t *testing.T) {
	tests := []struct {
		name    string
		handler http.Handler
	}{
		{
			name: "redirect",
			handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				http.Redirect(writer, request, "/elsewhere", http.StatusTemporaryRedirect)
			}),
		},
		{
			name: "wrong content type",
			handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "text/plain")
				writer.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(writer, "not json")
			}),
		},
		{
			name: "oversize",
			handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(http.StatusCreated)
				_, _ = writer.Write(bytes.Repeat([]byte("x"), MaxDocumentBytes+1))
			}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, tlsConfig := startTLS13Server(t, test.handler)
			defer server.Close()
			client, err := NewNonProductionClient(NonProductionClientConfig{
				BaseURL: server.URL, AuthorityKeyID: "test-authority-1",
				AuthorityPublicKey: testPrivateKey(1).Public().(ed25519.PublicKey), TLSConfig: tlsConfig,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			if _, err := client.IssueChallenge(context.Background()); err == nil {
				t.Fatal("invalid HTTP response was accepted")
			}
		})
	}
}

func TestNonProductionClientConfigurationFailsClosed(t *testing.T) {
	roots := x509.NewCertPool()
	valid := NonProductionClientConfig{
		BaseURL: "https://127.0.0.1:8443", AuthorityKeyID: "test-authority-1",
		AuthorityPublicKey: testPrivateKey(1).Public().(ed25519.PublicKey),
		TLSConfig:          &tls.Config{RootCAs: roots},
	}
	tests := []struct {
		name   string
		mutate func(*NonProductionClientConfig)
	}{
		{"plain HTTP", func(value *NonProductionClientConfig) { value.BaseURL = "http://127.0.0.1:8443" }},
		{"URL credentials", func(value *NonProductionClientConfig) { value.BaseURL = "https://user@127.0.0.1:8443" }},
		{"URL path", func(value *NonProductionClientConfig) { value.BaseURL = "https://127.0.0.1:8443/prefix" }},
		{"missing TLS config", func(value *NonProductionClientConfig) { value.TLSConfig = nil }},
		{"ambient roots", func(value *NonProductionClientConfig) { value.TLSConfig = &tls.Config{} }},
		{"insecure TLS", func(value *NonProductionClientConfig) { value.TLSConfig.InsecureSkipVerify = true }},
		{"wrong authority key length", func(value *NonProductionClientConfig) { value.AuthorityPublicKey = []byte("short") }},
		{"invalid key id", func(value *NonProductionClientConfig) { value.AuthorityKeyID = "Test Authority" }},
		{"excess timeout", func(value *NonProductionClientConfig) { value.Timeout = 31 * time.Second }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			config.TLSConfig = valid.TLSConfig.Clone()
			test.mutate(&config)
			if _, err := NewNonProductionClient(config); !errors.Is(err, ErrInvalid) {
				t.Fatalf("NewNonProductionClient() error = %v", err)
			}
		})
	}
}

func serveTLS13Request(handler http.Handler, method, path string, body []byte, contentType string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://authority.invalid"+path, bytes.NewReader(body))
	request.TLS = testTLSState(tls.VersionTLS13)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func testTLSState(version uint16) *tls.ConnectionState {
	return &tls.ConnectionState{Version: version, HandshakeComplete: true}
}

func assertSecurityHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers = %#v", response.Header())
	}
}

func startTLS13Server(t *testing.T, handler http.Handler) (*httptest.Server, *tls.Config) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return server, &tls.Config{RootCAs: roots}
}
