package releaseauthorization

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultClientTimeout = 10 * time.Second

type NonProductionClientConfig struct {
	BaseURL            string
	AuthorityKeyID     string
	AuthorityPublicKey ed25519.PublicKey
	TLSConfig          *tls.Config
	Timeout            time.Duration
}

// ChallengeReceipt pairs the signed document with a local monotonic timestamp
// captured after receipt. Elapsed should be passed to NewAuthorizationRequest.
type ChallengeReceipt struct {
	Challenge Challenge
	received  time.Time
}

func (receipt ChallengeReceipt) Elapsed() time.Duration {
	if receipt.received.IsZero() {
		return -1
	}
	return time.Since(receipt.received)
}

// NonProductionClient talks only to the bounded TLS test-authority endpoints.
// It disables ambient proxies and redirects and authenticates returned protocol
// documents with one pinned Ed25519 authority key.
type NonProductionClient struct {
	baseURL        *url.URL
	authorityKeyID string
	authorityKey   ed25519.PublicKey
	httpClient     *http.Client
}

func NewNonProductionClient(config NonProductionClientConfig) (*NonProductionClient, error) {
	baseURL, err := url.Parse(config.BaseURL)
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil ||
		baseURL.RawQuery != "" || baseURL.Fragment != "" || (baseURL.Path != "" && baseURL.Path != "/") {
		return nil, invalid("client base URL must be an origin-only https URL without credentials")
	}
	if !identifierPattern.MatchString(config.AuthorityKeyID) {
		return nil, invalid("client authority_key_id is invalid")
	}
	if len(config.AuthorityPublicKey) != ed25519.PublicKeySize {
		return nil, invalid("client authority public key has the wrong length")
	}
	if config.TLSConfig == nil || config.TLSConfig.RootCAs == nil || config.TLSConfig.InsecureSkipVerify {
		return nil, invalid("client requires an explicit TLS root pool with certificate verification enabled")
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = DefaultClientTimeout
	}
	if timeout <= 0 || timeout > 30*time.Second {
		return nil, invalid("client timeout must be between 1ns and 30s")
	}
	tlsConfig := config.TLSConfig.Clone()
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.MaxVersion = tls.VersionTLS13
	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true,
		DisableCompression: true, MaxIdleConns: 2, MaxIdleConnsPerHost: 2,
		IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: timeout,
	}
	baseURL.Path = ""
	return &NonProductionClient{
		baseURL: baseURL, authorityKeyID: config.AuthorityKeyID,
		authorityKey: append(ed25519.PublicKey(nil), config.AuthorityPublicKey...),
		httpClient: &http.Client{
			Transport: transport, Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("non-production authorization redirects are forbidden")
			},
		},
	}, nil
}

func (client *NonProductionClient) IssueChallenge(ctx context.Context) (ChallengeReceipt, error) {
	if client == nil || client.httpClient == nil {
		return ChallengeReceipt{}, invalid("client is required")
	}
	if ctx == nil {
		return ChallengeReceipt{}, invalid("context is required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint(ChallengeEndpoint), http.NoBody)
	if err != nil {
		return ChallengeReceipt{}, err
	}
	request.Header.Set("Accept", "application/json")
	started := time.Now()
	response, err := client.httpClient.Do(request)
	if err != nil {
		return ChallengeReceipt{}, fmt.Errorf("request non-production boot challenge: %w", err)
	}
	data, err := readBoundedResponse(response, http.StatusCreated)
	if err != nil {
		return ChallengeReceipt{}, err
	}
	challenge, err := ParseChallenge(data)
	if err != nil {
		return ChallengeReceipt{}, err
	}
	if challenge.AuthorityKeyID != client.authorityKeyID {
		return ChallengeReceipt{}, ErrBindingMismatch
	}
	if err := VerifyChallenge(challenge, client.authorityKey, time.Since(started)); err != nil {
		return ChallengeReceipt{}, err
	}
	return ChallengeReceipt{Challenge: challenge, received: time.Now()}, nil
}

func (client *NonProductionClient) Authorize(ctx context.Context, requestDocument AuthorizationRequest) (Authorization, error) {
	if client == nil || client.httpClient == nil {
		return Authorization{}, invalid("client is required")
	}
	if ctx == nil {
		return Authorization{}, invalid("context is required")
	}
	if requestDocument.Challenge.AuthorityKeyID != client.authorityKeyID {
		return Authorization{}, ErrBindingMismatch
	}
	encoded, err := requestDocument.CanonicalJSON()
	if err != nil {
		return Authorization{}, err
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, client.endpoint(AuthorizationEndpoint), bytes.NewReader(encoded),
	)
	if err != nil {
		return Authorization{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	started := time.Now()
	response, err := client.httpClient.Do(request)
	if err != nil {
		return Authorization{}, fmt.Errorf("request non-production boot authorization: %w", err)
	}
	data, err := readBoundedResponse(response, http.StatusOK)
	if err != nil {
		return Authorization{}, err
	}
	authorization, err := ParseAuthorization(data)
	if err != nil {
		return Authorization{}, err
	}
	if err := VerifyAuthorization(authorization, requestDocument, client.authorityKey, time.Since(started)); err != nil {
		return Authorization{}, err
	}
	return authorization, nil
}

func (client *NonProductionClient) ProveOneBoot(ctx context.Context, proof OneBootProof) error {
	if client == nil || client.httpClient == nil {
		return invalid("client is required")
	}
	if ctx == nil {
		return invalid("context is required")
	}
	if proof.Authorization.AuthorityKeyID != client.authorityKeyID {
		return ErrBindingMismatch
	}
	encoded, err := proof.CanonicalJSON()
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, client.endpoint(OneBootProofEndpoint), bytes.NewReader(encoded),
	)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("submit non-production one-boot proof: %w", err)
	}
	if response.StatusCode != http.StatusNoContent {
		_, err := readBoundedResponse(response, http.StatusNoContent)
		return err
	}
	defer response.Body.Close()
	if response.TLS == nil || !response.TLS.HandshakeComplete || response.TLS.Version != tls.VersionTLS13 {
		return errors.New("non-production one-boot proof response did not use TLS 1.3")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxDocumentBytes+1))
	if err != nil {
		return fmt.Errorf("read non-production one-boot proof response: %w", err)
	}
	if len(data) != 0 {
		return invalid("one-boot proof success response must be empty")
	}
	return nil
}

func (client *NonProductionClient) CloseIdleConnections() {
	if client != nil && client.httpClient != nil {
		client.httpClient.CloseIdleConnections()
	}
}

func (client *NonProductionClient) endpoint(path string) string {
	return strings.TrimSuffix(client.baseURL.String(), "/") + path
}

func readBoundedResponse(response *http.Response, expectedStatus int) ([]byte, error) {
	if response == nil {
		return nil, errors.New("non-production authorization server returned no response")
	}
	defer response.Body.Close()
	if response.TLS == nil || !response.TLS.HandshakeComplete || response.TLS.Version != tls.VersionTLS13 {
		return nil, errors.New("non-production authorization response did not use TLS 1.3")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("non-production authorization response Content-Type is not application/json")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxDocumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read non-production authorization response: %w", err)
	}
	if len(data) == 0 || len(data) > MaxDocumentBytes {
		return nil, invalid("authorization response size is outside the allowed range")
	}
	if response.StatusCode != expectedStatus {
		remote, err := parseErrorResponse(data, response.StatusCode)
		if err != nil {
			return nil, fmt.Errorf("non-production authorization server returned unparseable HTTP %d response: %w", response.StatusCode, err)
		}
		return nil, remote
	}
	return data, nil
}
