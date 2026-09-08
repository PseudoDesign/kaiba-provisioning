package releaseauthorization

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// NonProductionAuthorityConfig configures the ephemeral authority used only by
// the stable-verifier hardware spike. SigningKey and registered bootstrap keys
// must be supplied at runtime and must never be embedded in an image.
type NonProductionAuthorityConfig struct {
	AuthorityKeyID      string
	SigningKey          ed25519.PrivateKey
	ChallengeMaxAge     time.Duration
	AuthorizationMaxAge time.Duration
	// MaxOutstandingChallenges is retained as the spike's public flag name,
	// but bounds all retained challenge/authorization identities and all
	// pending bootstrap registrations. Issued challenges are stateless.
	MaxOutstandingChallenges int
	BindingPolicy            BindingPolicy
	Clock                    func() time.Time
	Entropy                  io.Reader
}

// BindingPolicy is the mandatory fresh server-policy boundary. An authority
// cannot be constructed without one. Implementations must make their decision
// solely from the complete, already validated binding supplied here.
type BindingPolicy interface {
	AuthorizeBootBinding(BootBinding) error
}

// BindingPolicyFunc adapts a function to BindingPolicy.
type BindingPolicyFunc func(BootBinding) error

func (function BindingPolicyFunc) AuthorizeBootBinding(binding BootBinding) error {
	if function == nil {
		return invalid("boot binding policy function is nil")
	}
	return function(binding)
}

type exactBindingPolicy struct {
	allowed map[BootBinding]struct{}
}

// NewExactBindingPolicy constructs an immutable allowlist policy. It is useful
// for a test-authority process preloaded with the release binding selected by
// the hardware-test runner.
func NewExactBindingPolicy(bindings ...BootBinding) (BindingPolicy, error) {
	if len(bindings) == 0 || len(bindings) > 64 {
		return nil, invalid("exact binding policy must contain between one and 64 bindings")
	}
	allowed := make(map[BootBinding]struct{}, len(bindings))
	for _, binding := range bindings {
		if err := binding.Validate(); err != nil {
			return nil, err
		}
		if _, duplicate := allowed[binding]; duplicate {
			return nil, invalid("exact binding policy contains a duplicate binding")
		}
		allowed[binding] = struct{}{}
	}
	return exactBindingPolicy{allowed: allowed}, nil
}

func (policy exactBindingPolicy) AuthorizeBootBinding(binding BootBinding) error {
	if _, authorized := policy.allowed[binding]; !authorized {
		return ErrUnauthorizedBinding
	}
	return nil
}

type retainedRecord struct {
	challengeDigest       string
	authorization         *Authorization
	authorizationIssuedAt time.Time
	retainUntil           time.Time
	proofAccepted         bool
	pending               bool
}

// NonProductionAuthority is an in-memory, process-local test authority. It is
// safe for concurrent use but deliberately provides no persistence, enrollment
// semantics, or production identity claim.
type NonProductionAuthority struct {
	mu                         sync.Mutex
	closed                     bool
	authorityKeyID             string
	privateKey                 ed25519.PrivateKey
	publicKey                  ed25519.PublicKey
	challengeMaxAgeSeconds     uint32
	authorizationMaxAgeSeconds uint32
	maxRetainedState           int
	bindingPolicy              BindingPolicy
	clock                      func() time.Time
	entropy                    io.Reader
	retained                   map[string]retainedRecord
	bootstrapKeys              map[string]map[string]struct{}
}

func NewNonProductionAuthority(config NonProductionAuthorityConfig) (*NonProductionAuthority, error) {
	if !identifierPattern.MatchString(config.AuthorityKeyID) {
		return nil, invalid("authority_key_id is invalid")
	}
	publicKey, err := publicFromPrivate(config.SigningKey)
	if err != nil {
		return nil, err
	}
	challengeAge, err := durationSeconds(config.ChallengeMaxAge, "challenge max age")
	if err != nil {
		return nil, err
	}
	authorizationAge, err := durationSeconds(config.AuthorizationMaxAge, "authorization max age")
	if err != nil {
		return nil, err
	}
	maximum := config.MaxOutstandingChallenges
	if maximum == 0 {
		maximum = DefaultOutstandingChallenges
	}
	if maximum < 1 || maximum > 65536 {
		return nil, invalid("max outstanding challenges must be between 1 and 65536")
	}
	if config.BindingPolicy == nil {
		return nil, invalid("a non-production boot binding policy is required")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	entropy := config.Entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	privateCopy := append(ed25519.PrivateKey(nil), config.SigningKey...)
	publicCopy := append(ed25519.PublicKey(nil), publicKey...)
	return &NonProductionAuthority{
		authorityKeyID: config.AuthorityKeyID,
		privateKey:     privateCopy, publicKey: publicCopy,
		challengeMaxAgeSeconds:     challengeAge,
		authorizationMaxAgeSeconds: authorizationAge,
		maxRetainedState:           maximum,
		bindingPolicy:              config.BindingPolicy,
		clock:                      clock, entropy: entropy,
		retained:      make(map[string]retainedRecord),
		bootstrapKeys: make(map[string]map[string]struct{}),
	}, nil
}

// PublicKey returns a defensive copy of the authority verification key.
func (authority *NonProductionAuthority) PublicKey() ed25519.PublicKey {
	if authority == nil {
		return nil
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.closed {
		return nil
	}
	return append(ed25519.PublicKey(nil), authority.publicKey...)
}

// Close clears the in-memory authority key and all ephemeral protocol state.
// The caller must first stop all HTTP servers and concurrent authority calls.
func (authority *NonProductionAuthority) Close() {
	if authority == nil {
		return
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	clearPrivateKey(authority.privateKey)
	for index := range authority.publicKey {
		authority.publicKey[index] = 0
	}
	authority.closed = true
	authority.retained = nil
	authority.bootstrapKeys = nil
	authority.bindingPolicy = nil
}

// RegisterBootstrapKey adds an exact public key to the test runner's
// out-of-band allowlist for a logical identity. Release, epoch, and verifier
// approval remain the separate mandatory BindingPolicy's responsibility.
func (authority *NonProductionAuthority) RegisterBootstrapKey(logicalIdentity string, publicKey ed25519.PublicKey) error {
	if authority == nil {
		return invalid("authority is required")
	}
	if !identifierPattern.MatchString(logicalIdentity) {
		return invalid("logical identity is invalid")
	}
	encoded, err := EncodePublicKey(publicKey)
	if err != nil {
		return err
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.closed {
		return invalid("authority is closed")
	}
	now, err := authority.now()
	if err != nil {
		return err
	}
	authority.pruneExpired(now)
	keys := authority.bootstrapKeys[logicalIdentity]
	if _, duplicate := keys[encoded]; !duplicate && authority.retainedStateCount() >= authority.maxRetainedState {
		return ErrCapacity
	}
	if keys == nil {
		keys = make(map[string]struct{})
		authority.bootstrapKeys[logicalIdentity] = keys
	}
	keys[encoded] = struct{}{}
	return nil
}

// UnregisterBootstrapKey removes a test-only registration. Already issued
// authorizations remain signed records; unused requests using this key fail.
func (authority *NonProductionAuthority) UnregisterBootstrapKey(logicalIdentity string, publicKey ed25519.PublicKey) bool {
	if authority == nil || !identifierPattern.MatchString(logicalIdentity) {
		return false
	}
	encoded, err := EncodePublicKey(publicKey)
	if err != nil {
		return false
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.closed {
		return false
	}
	if now, clockErr := authority.now(); clockErr == nil {
		authority.pruneExpired(now)
	}
	keys := authority.bootstrapKeys[logicalIdentity]
	if _, exists := keys[encoded]; !exists {
		return false
	}
	delete(keys, encoded)
	if len(keys) == 0 {
		delete(authority.bootstrapKeys, logicalIdentity)
	}
	return true
}

// IssueChallenge creates a stateless signed challenge. Only an authenticated
// authorization attempt allocates replay state, so unauthenticated callers
// cannot exhaust the authority's fixed state budget through this endpoint.
func (authority *NonProductionAuthority) IssueChallenge() (Challenge, error) {
	if authority == nil {
		return Challenge{}, invalid("authority is required")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.closed {
		return Challenge{}, invalid("authority is closed")
	}
	now, err := authority.now()
	if err != nil {
		return Challenge{}, err
	}
	authority.pruneExpired(now)
	for attempts := 0; attempts < 8; attempts++ {
		challengeIDBytes, err := readEntropy(authority.entropy, 32)
		if err != nil {
			return Challenge{}, fmt.Errorf("generate non-production challenge ID: %w", err)
		}
		nonceBytes, err := readEntropy(authority.entropy, 32)
		if err != nil {
			return Challenge{}, fmt.Errorf("generate non-production challenge nonce: %w", err)
		}
		challenge := Challenge{
			SchemaVersion:       ChallengeSchemaVersion,
			ChallengeID:         "challenge:" + hex.EncodeToString(challengeIDBytes),
			Nonce:               "hex:" + hex.EncodeToString(nonceBytes),
			IssuedAtUnixSeconds: now.Unix(),
			MaxAgeSeconds:       authority.challengeMaxAgeSeconds,
			AuthorityKeyID:      authority.authorityKeyID,
			SignatureAlgorithm:  SignatureAlgorithmEd25519,
		}
		if _, collision := authority.retained[challenge.ChallengeID]; collision {
			continue
		}
		canonical, err := challenge.unsignedCanonicalJSON()
		if err != nil {
			return Challenge{}, err
		}
		challenge.Signature, err = signEncoded(challengeSignatureDomain, canonical, authority.privateKey)
		if err != nil {
			return Challenge{}, err
		}
		return challenge, nil
	}
	return Challenge{}, errors.New("could not generate a unique non-production challenge")
}

// Authorize validates every signed request field and consumes the challenge
// exactly once. Concurrent valid requests for the same challenge cannot both
// succeed.
func (authority *NonProductionAuthority) Authorize(request AuthorizationRequest) (Authorization, error) {
	if authority == nil {
		return Authorization{}, invalid("authority is required")
	}
	if err := request.Validate(); err != nil {
		return Authorization{}, err
	}
	if err := VerifyChallenge(request.Challenge, authority.publicKey, 0); err != nil {
		return Authorization{}, err
	}
	if request.Challenge.AuthorityKeyID != authority.authorityKeyID {
		return Authorization{}, ErrBindingMismatch
	}
	if err := VerifyBootstrapProof(request); err != nil {
		return Authorization{}, err
	}
	if _, err := authority.consumeAuthenticatedChallenge(request); err != nil {
		return Authorization{}, err
	}
	defer authority.finishPendingAuthorization(request.Challenge.ChallengeID)
	if err := authority.bindingPolicy.AuthorizeBootBinding(request.Binding); err != nil {
		return Authorization{}, fmt.Errorf("%w: %v", ErrUnauthorizedBinding, err)
	}
	challengeDigest, err := request.Challenge.Digest()
	if err != nil {
		return Authorization{}, err
	}
	return authority.signAuthorizedRequest(request, challengeDigest)
}

// ProveOneBoot validates proof of possession for an issued authorization and
// accepts that proof exactly once while the authorization remains fresh.
func (authority *NonProductionAuthority) ProveOneBoot(proof OneBootProof) error {
	if authority == nil {
		return invalid("authority is required")
	}
	if err := VerifyOneBootProof(proof); err != nil {
		return err
	}
	if err := VerifyAuthorizationSignature(proof.Authorization, authority.authorityKeyID, authority.publicKey); err != nil {
		return err
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.closed {
		return invalid("authority is closed")
	}
	now, err := authority.now()
	if err != nil {
		return err
	}
	if err := validateServerAge(
		now,
		time.Unix(proof.Authorization.IssuedAtUnixSeconds, 0).UTC(),
		proof.Authorization.MaxAgeSeconds,
	); err != nil {
		return err
	}
	authority.pruneExpired(now)
	record, exists := authority.retained[proof.Authorization.ChallengeID]
	if exists && record.proofAccepted {
		return ErrOneBootReplay
	}
	if !exists || record.authorization == nil {
		return ErrUnknownAuthorization
	}
	if *record.authorization != proof.Authorization {
		return ErrBindingMismatch
	}
	if err := validateServerAge(now, record.authorizationIssuedAt, record.authorization.MaxAgeSeconds); err != nil {
		return err
	}
	record.authorization = nil
	record.authorizationIssuedAt = time.Time{}
	record.proofAccepted = true
	authority.retained[proof.Authorization.ChallengeID] = record
	return nil
}

// consumeAuthenticatedChallenge performs the stateful half of Authorize. The
// challenge is consumed only after both the signed challenge and registered
// bootstrap proof have authenticated the caller, but before server policy is
// evaluated. A denied authenticated attempt therefore cannot retry the nonce.
func (authority *NonProductionAuthority) consumeAuthenticatedChallenge(request AuthorizationRequest) (time.Time, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.closed {
		return time.Time{}, invalid("authority is closed")
	}
	now, err := authority.now()
	if err != nil {
		return time.Time{}, err
	}
	authority.pruneExpired(now)
	issuedAt := time.Unix(request.Challenge.IssuedAtUnixSeconds, 0).UTC()
	if err := validateServerAge(now, issuedAt, request.Challenge.MaxAgeSeconds); err != nil {
		return time.Time{}, err
	}
	challengeDigest, err := request.Challenge.Digest()
	if err != nil {
		return time.Time{}, err
	}
	record, exists := authority.retained[request.Challenge.ChallengeID]
	if exists {
		if record.challengeDigest != challengeDigest {
			return time.Time{}, ErrBindingMismatch
		}
		return time.Time{}, ErrReplay
	}
	registered := authority.bootstrapKeys[request.Binding.LogicalIdentity]
	if _, trusted := registered[request.BootstrapPublicKey]; !trusted {
		return time.Time{}, ErrUntrustedBootstrap
	}
	delete(registered, request.BootstrapPublicKey)
	if len(registered) == 0 {
		delete(authority.bootstrapKeys, request.Binding.LogicalIdentity)
	}
	authority.retained[request.Challenge.ChallengeID] = retainedRecord{
		challengeDigest: challengeDigest,
		retainUntil:     issuedAt.Add(time.Duration(request.Challenge.MaxAgeSeconds) * time.Second),
		pending:         true,
	}
	return now, nil
}

func (authority *NonProductionAuthority) signAuthorizedRequest(
	request AuthorizationRequest,
	challengeDigest string,
) (Authorization, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.closed {
		return Authorization{}, invalid("authority is closed")
	}
	now, err := authority.now()
	if err != nil {
		return Authorization{}, err
	}
	issuedAt := time.Unix(request.Challenge.IssuedAtUnixSeconds, 0).UTC()
	if err := validateServerAge(now, issuedAt, request.Challenge.MaxAgeSeconds); err != nil {
		return Authorization{}, err
	}
	record, exists := authority.retained[request.Challenge.ChallengeID]
	if !exists || !record.pending || record.challengeDigest != challengeDigest {
		return Authorization{}, ErrBindingMismatch
	}
	authorization := Authorization{
		SchemaVersion:       AuthorizationSchemaVersion,
		ChallengeID:         request.Challenge.ChallengeID,
		ChallengeNonce:      request.Challenge.Nonce,
		ChallengeDigest:     challengeDigest,
		Binding:             request.Binding,
		BootstrapPublicKey:  request.BootstrapPublicKey,
		OneBootPublicKey:    request.OneBootPublicKey,
		Decision:            DecisionAuthorized,
		IssuedAtUnixSeconds: now.Unix(),
		MaxAgeSeconds:       authority.authorizationMaxAgeSeconds,
		AuthorityKeyID:      authority.authorityKeyID,
		SignatureAlgorithm:  SignatureAlgorithmEd25519,
	}
	canonical, err := authorization.unsignedCanonicalJSON()
	if err != nil {
		return Authorization{}, err
	}
	authorization.Signature, err = signEncoded(authorizationSignatureDomain, canonical, authority.privateKey)
	if err != nil {
		return Authorization{}, err
	}
	record.authorization = &authorization
	record.authorizationIssuedAt = now
	record.pending = false
	authorizationExpiry := now.Add(time.Duration(authorization.MaxAgeSeconds) * time.Second)
	if record.retainUntil.Before(authorizationExpiry) {
		record.retainUntil = authorizationExpiry
	}
	authority.retained[authorization.ChallengeID] = record
	return authorization, nil
}

func (authority *NonProductionAuthority) finishPendingAuthorization(challengeID string) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.closed {
		return
	}
	record, exists := authority.retained[challengeID]
	if !exists || !record.pending {
		return
	}
	record.pending = false
	authority.retained[challengeID] = record
}

func (authority *NonProductionAuthority) now() (time.Time, error) {
	now := authority.clock()
	if now.IsZero() || now.Unix() < 0 || now.Unix() > 253402300799 {
		return time.Time{}, invalid("authority clock returned an unsupported time")
	}
	return now, nil
}

func (authority *NonProductionAuthority) pruneExpired(now time.Time) {
	for id, record := range authority.retained {
		if record.pending || !now.After(record.retainUntil) {
			continue
		}
		delete(authority.retained, id)
	}
}

func (authority *NonProductionAuthority) bootstrapKeyCount() int {
	count := 0
	for _, keys := range authority.bootstrapKeys {
		count += len(keys)
	}
	return count
}

func (authority *NonProductionAuthority) retainedStateCount() int {
	return len(authority.retained) + authority.bootstrapKeyCount()
}

func validateServerAge(now, issuedAt time.Time, maxAgeSeconds uint32) error {
	if now.Before(issuedAt) {
		return invalid("authority clock moved backwards after challenge issuance")
	}
	if now.Sub(issuedAt) > time.Duration(maxAgeSeconds)*time.Second {
		return ErrExpired
	}
	return nil
}

func readEntropy(reader io.Reader, count int) ([]byte, error) {
	result := make([]byte, count)
	if _, err := io.ReadFull(reader, result); err != nil {
		return nil, err
	}
	return result, nil
}
