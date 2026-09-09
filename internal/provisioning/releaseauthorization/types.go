// Package releaseauthorization implements the deliberately non-production
// authorization protocol used by the Raspberry Pi 5 stable-verifier spike.
//
// It is not an enrollment or device-identity system. Bootstrap keys are
// registered out of band by the test runner and all authority state is lost
// when the process exits.
package releaseauthorization

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	ChallengeSchemaVersion             = "kaiba.provisioning.rpi5-non-production-boot-challenge/v1alpha1"
	RequestSchemaVersion               = "kaiba.provisioning.rpi5-non-production-boot-authorization-request/v1alpha1"
	AuthorizationSchemaVersion         = "kaiba.provisioning.rpi5-non-production-boot-authorization/v1alpha1"
	BootstrapRegistrationSchemaVersion = "kaiba.provisioning.rpi5-non-production-bootstrap-registration/v1alpha1"
	OneBootProofSchemaVersion          = "kaiba.provisioning.rpi5-non-production-one-boot-proof/v1alpha1"

	SignatureAlgorithmEd25519 = "ed25519"
	DecisionAuthorized        = "authorized"

	MaxDocumentBytes             = 64 * 1024
	MaxProtocolAgeSeconds        = uint32(300)
	DefaultOutstandingChallenges = 1024

	challengeSignatureDomain     = "kaiba.provisioning.rpi5-non-production-boot-challenge-signature.v1alpha1"
	challengeDigestDomain        = "kaiba.provisioning.rpi5-non-production-boot-challenge-document.v1alpha1"
	requestProofDomain           = "kaiba.provisioning.rpi5-non-production-bootstrap-proof.v1alpha1"
	authorizationSignatureDomain = "kaiba.provisioning.rpi5-non-production-boot-authorization-signature.v1alpha1"
	authorizationDigestDomain    = "kaiba.provisioning.rpi5-non-production-boot-authorization-document.v1alpha1"
	oneBootProofDomain           = "kaiba.provisioning.rpi5-non-production-one-boot-proof.v1alpha1"
)

var (
	ErrInvalid              = errors.New("invalid non-production boot authorization document")
	ErrSignature            = errors.New("non-production boot authorization signature verification failed")
	ErrExpired              = errors.New("non-production boot authorization document expired")
	ErrReplay               = errors.New("non-production boot challenge was already consumed")
	ErrUnknownChallenge     = errors.New("non-production boot challenge is unknown")
	ErrUnknownAuthorization = errors.New("non-production boot authorization is unknown")
	ErrUnauthorizedBinding  = errors.New("non-production boot binding is not registered")
	ErrUntrustedBootstrap   = errors.New("non-production bootstrap key is not registered")
	ErrBindingMismatch      = errors.New("non-production boot authorization binding mismatch")
	ErrCapacity             = errors.New("non-production boot challenge capacity reached")
	ErrOneBootReplay        = errors.New("non-production one-boot proof was already accepted")
)

var (
	identifierPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._:+-]{0,127}$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	challengeIDPattern = regexp.MustCompile(`^challenge:[0-9a-f]{64}$`)
	noncePattern       = regexp.MustCompile(`^hex:[0-9a-f]{64}$`)
	publicKeyPattern   = regexp.MustCompile(`^ed25519:[0-9a-f]{64}$`)
	signaturePattern   = regexp.MustCompile(`^ed25519:[0-9a-f]{128}$`)
)

// Challenge is an authority-signed, short-lived challenge. MaxAgeSeconds is
// intentionally a relative lifetime so the verifier can enforce it with a
// monotonic elapsed-time measurement instead of trusting the Pi wall clock.
type Challenge struct {
	SchemaVersion       string `json:"schema_version"`
	ChallengeID         string `json:"challenge_id"`
	Nonce               string `json:"nonce"`
	IssuedAtUnixSeconds int64  `json:"issued_at_unix_seconds"`
	MaxAgeSeconds       uint32 `json:"max_age_seconds"`
	AuthorityKeyID      string `json:"authority_key_id"`
	SignatureAlgorithm  string `json:"signature_algorithm"`
	Signature           string `json:"signature"`
}

// BootBinding contains every boot decision input which the authorization
// request and response must bind exactly. StorageGeneration is fixed to zero
// for this unfused, explicitly non-production spike.
type BootBinding struct {
	LogicalIdentity   string `json:"logical_identity"`
	Audience          string `json:"audience"`
	StorageGeneration uint64 `json:"storage_generation"`
	VerifierVersion   uint64 `json:"verifier_version"`
	PolicyDigest      string `json:"policy_digest"`
	ManifestDigest    string `json:"manifest_digest"`
	SecurityEpoch     uint64 `json:"security_epoch"`
}

// AuthorizationRequest proves possession of an out-of-band registered
// bootstrap key and binds a distinct one-boot public key to one signed
// challenge and one complete BootBinding.
type AuthorizationRequest struct {
	SchemaVersion      string      `json:"schema_version"`
	Challenge          Challenge   `json:"challenge"`
	Binding            BootBinding `json:"binding"`
	BootstrapPublicKey string      `json:"bootstrap_public_key"`
	OneBootPublicKey   string      `json:"one_boot_public_key"`
	ProofAlgorithm     string      `json:"proof_algorithm"`
	BootstrapProof     string      `json:"bootstrap_proof"`
}

// Authorization is the authority-signed decision consumed immediately before
// handoff. It repeats every request binding rather than relying on an implicit
// server-side association.
type Authorization struct {
	SchemaVersion       string      `json:"schema_version"`
	ChallengeID         string      `json:"challenge_id"`
	ChallengeNonce      string      `json:"challenge_nonce"`
	ChallengeDigest     string      `json:"challenge_digest"`
	Binding             BootBinding `json:"binding"`
	BootstrapPublicKey  string      `json:"bootstrap_public_key"`
	OneBootPublicKey    string      `json:"one_boot_public_key"`
	Decision            string      `json:"decision"`
	IssuedAtUnixSeconds int64       `json:"issued_at_unix_seconds"`
	MaxAgeSeconds       uint32      `json:"max_age_seconds"`
	AuthorityKeyID      string      `json:"authority_key_id"`
	SignatureAlgorithm  string      `json:"signature_algorithm"`
	Signature           string      `json:"signature"`
}

// BootstrapRegistration is accepted only over the filesystem-protected Unix
// admin socket. It is never accepted by the target-facing TLS handler.
type BootstrapRegistration struct {
	SchemaVersion      string `json:"schema_version"`
	LogicalIdentity    string `json:"logical_identity"`
	BootstrapPublicKey string `json:"bootstrap_public_key"`
}

// OneBootProof demonstrates that the released stage received the private key
// whose public half was bound into the complete issued Authorization.
type OneBootProof struct {
	SchemaVersion       string        `json:"schema_version"`
	Authorization       Authorization `json:"authorization"`
	AuthorizationDigest string        `json:"authorization_digest"`
	ProofAlgorithm      string        `json:"proof_algorithm"`
	Proof               string        `json:"proof"`
}

func NewBootstrapRegistration(logicalIdentity string, publicKey ed25519.PublicKey) (BootstrapRegistration, error) {
	encoded, err := EncodePublicKey(publicKey)
	if err != nil {
		return BootstrapRegistration{}, err
	}
	registration := BootstrapRegistration{
		SchemaVersion:      BootstrapRegistrationSchemaVersion,
		LogicalIdentity:    logicalIdentity,
		BootstrapPublicKey: encoded,
	}
	if err := registration.Validate(); err != nil {
		return BootstrapRegistration{}, err
	}
	return registration, nil
}

type unsignedChallenge struct {
	SchemaVersion       string `json:"schema_version"`
	ChallengeID         string `json:"challenge_id"`
	Nonce               string `json:"nonce"`
	IssuedAtUnixSeconds int64  `json:"issued_at_unix_seconds"`
	MaxAgeSeconds       uint32 `json:"max_age_seconds"`
	AuthorityKeyID      string `json:"authority_key_id"`
}

type unsignedRequest struct {
	SchemaVersion      string      `json:"schema_version"`
	Challenge          Challenge   `json:"challenge"`
	Binding            BootBinding `json:"binding"`
	BootstrapPublicKey string      `json:"bootstrap_public_key"`
	OneBootPublicKey   string      `json:"one_boot_public_key"`
}

type unsignedAuthorization struct {
	SchemaVersion       string      `json:"schema_version"`
	ChallengeID         string      `json:"challenge_id"`
	ChallengeNonce      string      `json:"challenge_nonce"`
	ChallengeDigest     string      `json:"challenge_digest"`
	Binding             BootBinding `json:"binding"`
	BootstrapPublicKey  string      `json:"bootstrap_public_key"`
	OneBootPublicKey    string      `json:"one_boot_public_key"`
	Decision            string      `json:"decision"`
	IssuedAtUnixSeconds int64       `json:"issued_at_unix_seconds"`
	MaxAgeSeconds       uint32      `json:"max_age_seconds"`
	AuthorityKeyID      string      `json:"authority_key_id"`
}

func (binding BootBinding) Validate() error {
	if !identifierPattern.MatchString(binding.LogicalIdentity) {
		return invalid("binding.logical_identity is invalid")
	}
	if !identifierPattern.MatchString(binding.Audience) {
		return invalid("binding.audience is invalid")
	}
	if binding.StorageGeneration != 0 {
		return invalid("binding.storage_generation must be zero for the non-production spike")
	}
	if binding.VerifierVersion == 0 {
		return invalid("binding.verifier_version must be non-zero")
	}
	if !digestPattern.MatchString(binding.PolicyDigest) {
		return invalid("binding.policy_digest must be a lowercase sha256 digest")
	}
	if !digestPattern.MatchString(binding.ManifestDigest) {
		return invalid("binding.manifest_digest must be a lowercase sha256 digest")
	}
	if binding.SecurityEpoch == 0 {
		return invalid("binding.security_epoch must be non-zero")
	}
	return nil
}

func (challenge Challenge) Validate() error {
	if challenge.SchemaVersion != ChallengeSchemaVersion {
		return invalid("unsupported challenge schema_version")
	}
	if !challengeIDPattern.MatchString(challenge.ChallengeID) {
		return invalid("challenge_id is invalid")
	}
	if !noncePattern.MatchString(challenge.Nonce) {
		return invalid("nonce is invalid")
	}
	if err := validateIssuedAt(challenge.IssuedAtUnixSeconds); err != nil {
		return err
	}
	if err := validateMaxAge(challenge.MaxAgeSeconds); err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	if !identifierPattern.MatchString(challenge.AuthorityKeyID) {
		return invalid("authority_key_id is invalid")
	}
	if challenge.SignatureAlgorithm != SignatureAlgorithmEd25519 {
		return invalid("challenge signature_algorithm must be ed25519")
	}
	if _, err := decodeSignature(challenge.Signature); err != nil {
		return invalid("challenge signature is invalid")
	}
	return nil
}

func (request AuthorizationRequest) Validate() error {
	if request.SchemaVersion != RequestSchemaVersion {
		return invalid("unsupported authorization request schema_version")
	}
	if err := request.Challenge.Validate(); err != nil {
		return err
	}
	if err := request.Binding.Validate(); err != nil {
		return err
	}
	bootstrap, err := DecodePublicKey(request.BootstrapPublicKey)
	if err != nil {
		return invalid("bootstrap_public_key is invalid")
	}
	oneBoot, err := DecodePublicKey(request.OneBootPublicKey)
	if err != nil {
		return invalid("one_boot_public_key is invalid")
	}
	if bytes.Equal(bootstrap, oneBoot) {
		return invalid("bootstrap_public_key and one_boot_public_key must be distinct")
	}
	if request.ProofAlgorithm != SignatureAlgorithmEd25519 {
		return invalid("proof_algorithm must be ed25519")
	}
	if _, err := decodeSignature(request.BootstrapProof); err != nil {
		return invalid("bootstrap_proof is invalid")
	}
	return nil
}

func (authorization Authorization) Validate() error {
	if authorization.SchemaVersion != AuthorizationSchemaVersion {
		return invalid("unsupported authorization schema_version")
	}
	if !challengeIDPattern.MatchString(authorization.ChallengeID) {
		return invalid("challenge_id is invalid")
	}
	if !noncePattern.MatchString(authorization.ChallengeNonce) {
		return invalid("challenge_nonce is invalid")
	}
	if !digestPattern.MatchString(authorization.ChallengeDigest) {
		return invalid("challenge_digest must be a lowercase sha256 digest")
	}
	if err := authorization.Binding.Validate(); err != nil {
		return err
	}
	bootstrap, err := DecodePublicKey(authorization.BootstrapPublicKey)
	if err != nil {
		return invalid("bootstrap_public_key is invalid")
	}
	oneBoot, err := DecodePublicKey(authorization.OneBootPublicKey)
	if err != nil {
		return invalid("one_boot_public_key is invalid")
	}
	if bytes.Equal(bootstrap, oneBoot) {
		return invalid("bootstrap_public_key and one_boot_public_key must be distinct")
	}
	if authorization.Decision != DecisionAuthorized {
		return invalid("decision must be authorized")
	}
	if err := validateIssuedAt(authorization.IssuedAtUnixSeconds); err != nil {
		return err
	}
	if err := validateMaxAge(authorization.MaxAgeSeconds); err != nil {
		return fmt.Errorf("authorization: %w", err)
	}
	if !identifierPattern.MatchString(authorization.AuthorityKeyID) {
		return invalid("authority_key_id is invalid")
	}
	if authorization.SignatureAlgorithm != SignatureAlgorithmEd25519 {
		return invalid("authorization signature_algorithm must be ed25519")
	}
	if _, err := decodeSignature(authorization.Signature); err != nil {
		return invalid("authorization signature is invalid")
	}
	return nil
}

func (registration BootstrapRegistration) Validate() error {
	if registration.SchemaVersion != BootstrapRegistrationSchemaVersion {
		return invalid("unsupported bootstrap registration schema_version")
	}
	if !identifierPattern.MatchString(registration.LogicalIdentity) {
		return invalid("bootstrap registration logical_identity is invalid")
	}
	if _, err := DecodePublicKey(registration.BootstrapPublicKey); err != nil {
		return invalid("bootstrap registration public key is invalid")
	}
	return nil
}

func (proof OneBootProof) Validate() error {
	if proof.SchemaVersion != OneBootProofSchemaVersion {
		return invalid("unsupported one-boot proof schema_version")
	}
	if err := proof.Authorization.Validate(); err != nil {
		return err
	}
	if !digestPattern.MatchString(proof.AuthorizationDigest) {
		return invalid("one-boot proof authorization_digest is invalid")
	}
	if proof.ProofAlgorithm != SignatureAlgorithmEd25519 {
		return invalid("one-boot proof algorithm must be ed25519")
	}
	if _, err := decodeSignature(proof.Proof); err != nil {
		return invalid("one-boot proof signature is invalid")
	}
	return nil
}

// CanonicalJSON returns the fixed-order JSON representation carried on the
// wire and covered, except for the signature field itself, by the signature.
func (challenge Challenge) CanonicalJSON() ([]byte, error) {
	if err := challenge.Validate(); err != nil {
		return nil, err
	}
	return marshalBounded(challenge)
}

// Digest identifies the complete signed challenge document.
func (challenge Challenge) Digest() (string, error) {
	canonical, err := challenge.CanonicalJSON()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(challengeDigestDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(canonical)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func (request AuthorizationRequest) CanonicalJSON() ([]byte, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	if err := VerifyBootstrapProof(request); err != nil {
		return nil, err
	}
	return marshalBounded(request)
}

func (authorization Authorization) CanonicalJSON() ([]byte, error) {
	if err := authorization.Validate(); err != nil {
		return nil, err
	}
	return marshalBounded(authorization)
}

func (registration BootstrapRegistration) CanonicalJSON() ([]byte, error) {
	if err := registration.Validate(); err != nil {
		return nil, err
	}
	return marshalBounded(registration)
}

func (proof OneBootProof) CanonicalJSON() ([]byte, error) {
	if err := VerifyOneBootProof(proof); err != nil {
		return nil, err
	}
	return marshalBounded(proof)
}

// Digest identifies the complete signed authorization, including its
// authority signature.
func (authorization Authorization) Digest() (string, error) {
	canonical, err := authorization.CanonicalJSON()
	if err != nil {
		return "", err
	}
	return domainDigest(authorizationDigestDomain, canonical), nil
}

// NewOneBootProof signs a domain-separated digest of the complete issued
// authorization. The supplied private key must match the authorization's
// bound one_boot_public_key. The caller's private-key slice is consumed and
// zeroed before return, including on failure.
func NewOneBootProof(authorization Authorization, oneBootPrivateKey ed25519.PrivateKey) (OneBootProof, error) {
	defer clearPrivateKey(oneBootPrivateKey)
	if err := authorization.Validate(); err != nil {
		return OneBootProof{}, err
	}
	publicKey, err := publicFromPrivate(oneBootPrivateKey)
	if err != nil {
		return OneBootProof{}, err
	}
	encodedPublicKey, _ := EncodePublicKey(publicKey)
	if encodedPublicKey != authorization.OneBootPublicKey {
		return OneBootProof{}, ErrBindingMismatch
	}
	digest, err := authorization.Digest()
	if err != nil {
		return OneBootProof{}, err
	}
	proof := OneBootProof{
		SchemaVersion: OneBootProofSchemaVersion, Authorization: authorization,
		AuthorizationDigest: digest, ProofAlgorithm: SignatureAlgorithmEd25519,
	}
	proof.Proof, err = signEncoded(oneBootProofDomain, []byte(digest), oneBootPrivateKey)
	if err != nil {
		return OneBootProof{}, err
	}
	return proof, nil
}

// VerifyOneBootProof verifies the complete authorization digest and proof of
// possession. Authority trust and one-time state are checked by ProveOneBoot.
func VerifyOneBootProof(proof OneBootProof) error {
	if err := proof.Validate(); err != nil {
		return err
	}
	digest, err := proof.Authorization.Digest()
	if err != nil {
		return err
	}
	if digest != proof.AuthorizationDigest {
		return ErrBindingMismatch
	}
	publicKey, _ := DecodePublicKey(proof.Authorization.OneBootPublicKey)
	return verifyEncoded(oneBootProofDomain, []byte(digest), publicKey, proof.Proof)
}

// NewAuthorizationRequest verifies the signed challenge with a relative,
// monotonic-compatible elapsed duration, then constructs a bootstrap-signed
// request. The one-boot key must be different from the bootstrap key. The
// supplied bootstrap private-key slice is consumed and zeroed before return,
// including on failure; callers must pass a disposable buffer.
func NewAuthorizationRequest(
	challenge Challenge,
	binding BootBinding,
	bootstrapPrivateKey ed25519.PrivateKey,
	oneBootPublicKey ed25519.PublicKey,
	authorityPublicKey ed25519.PublicKey,
	challengeElapsed time.Duration,
) (AuthorizationRequest, error) {
	defer clearPrivateKey(bootstrapPrivateKey)
	if err := VerifyChallenge(challenge, authorityPublicKey, challengeElapsed); err != nil {
		return AuthorizationRequest{}, err
	}
	if err := binding.Validate(); err != nil {
		return AuthorizationRequest{}, err
	}
	bootstrapPublicKey, err := publicFromPrivate(bootstrapPrivateKey)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	bootstrapEncoded, _ := EncodePublicKey(bootstrapPublicKey)
	oneBootEncoded, err := EncodePublicKey(oneBootPublicKey)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	request := AuthorizationRequest{
		SchemaVersion:      RequestSchemaVersion,
		Challenge:          challenge,
		Binding:            binding,
		BootstrapPublicKey: bootstrapEncoded,
		OneBootPublicKey:   oneBootEncoded,
		ProofAlgorithm:     SignatureAlgorithmEd25519,
	}
	if bytes.Equal(bootstrapPublicKey, oneBootPublicKey) {
		return AuthorizationRequest{}, invalid("bootstrap and one-boot keys must be distinct")
	}
	canonical, err := request.unsignedCanonicalJSON()
	if err != nil {
		return AuthorizationRequest{}, err
	}
	request.BootstrapProof, err = signEncoded(requestProofDomain, canonical, bootstrapPrivateKey)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	if err := request.Validate(); err != nil {
		return AuthorizationRequest{}, err
	}
	return request, nil
}

func clearPrivateKey(privateKey ed25519.PrivateKey) {
	for index := range privateKey {
		privateKey[index] = 0
	}
}

// VerifyChallenge validates the authority signature and enforces the signed
// maximum age using an elapsed duration supplied by the caller's monotonic
// clock. It intentionally does not compare the Pi's wall clock with IssuedAt.
func VerifyChallenge(challenge Challenge, authorityPublicKey ed25519.PublicKey, elapsed time.Duration) error {
	if err := challenge.Validate(); err != nil {
		return err
	}
	canonical, err := challenge.unsignedCanonicalJSON()
	if err != nil {
		return err
	}
	if err := verifyEncoded(challengeSignatureDomain, canonical, authorityPublicKey, challenge.Signature); err != nil {
		return err
	}
	return validateElapsed(elapsed, challenge.MaxAgeSeconds)
}

// VerifyBootstrapProof verifies request self-consistency. Authority trust is
// established separately by registering this exact key for LogicalIdentity.
func VerifyBootstrapProof(request AuthorizationRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	publicKey, _ := DecodePublicKey(request.BootstrapPublicKey)
	canonical, err := request.unsignedCanonicalJSON()
	if err != nil {
		return err
	}
	return verifyEncoded(requestProofDomain, canonical, publicKey, request.BootstrapProof)
}

// VerifyAuthorization verifies the authority signature, exact request
// bindings, and the signed maximum age using an elapsed duration measured from
// when the request was sent. It does not require a trusted target wall clock.
func VerifyAuthorization(
	authorization Authorization,
	request AuthorizationRequest,
	authorityPublicKey ed25519.PublicKey,
	elapsedSinceRequest time.Duration,
) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := VerifyBootstrapProof(request); err != nil {
		return err
	}
	if err := VerifyChallenge(request.Challenge, authorityPublicKey, 0); err != nil {
		return err
	}
	if err := authorization.Validate(); err != nil {
		return err
	}
	if err := matchAuthorization(authorization, request); err != nil {
		return err
	}
	if err := validateElapsed(elapsedSinceRequest, authorization.MaxAgeSeconds); err != nil {
		return err
	}
	return VerifyAuthorizationSignature(authorization, request.Challenge.AuthorityKeyID, authorityPublicKey)
}

// VerifyAuthorizationSignature authenticates a standalone authorization with
// one explicitly selected authority key. It deliberately does not make a
// freshness claim: callers without a retained monotonic issuance observation
// must rely on the authority's server-side age check at one-boot proof time.
func VerifyAuthorizationSignature(
	authorization Authorization,
	expectedAuthorityKeyID string,
	authorityPublicKey ed25519.PublicKey,
) error {
	if err := authorization.Validate(); err != nil {
		return err
	}
	if !identifierPattern.MatchString(expectedAuthorityKeyID) || authorization.AuthorityKeyID != expectedAuthorityKeyID {
		return ErrBindingMismatch
	}
	canonical, err := authorization.unsignedCanonicalJSON()
	if err != nil {
		return err
	}
	return verifyEncoded(authorizationSignatureDomain, canonical, authorityPublicKey, authorization.Signature)
}

func (challenge Challenge) unsignedCanonicalJSON() ([]byte, error) {
	value := unsignedChallenge{
		SchemaVersion: challenge.SchemaVersion, ChallengeID: challenge.ChallengeID,
		Nonce: challenge.Nonce, IssuedAtUnixSeconds: challenge.IssuedAtUnixSeconds,
		MaxAgeSeconds: challenge.MaxAgeSeconds, AuthorityKeyID: challenge.AuthorityKeyID,
	}
	return marshalBounded(value)
}

func (request AuthorizationRequest) unsignedCanonicalJSON() ([]byte, error) {
	value := unsignedRequest{
		SchemaVersion: request.SchemaVersion, Challenge: request.Challenge,
		Binding: request.Binding, BootstrapPublicKey: request.BootstrapPublicKey,
		OneBootPublicKey: request.OneBootPublicKey,
	}
	return marshalBounded(value)
}

func (authorization Authorization) unsignedCanonicalJSON() ([]byte, error) {
	value := unsignedAuthorization{
		SchemaVersion: authorization.SchemaVersion, ChallengeID: authorization.ChallengeID,
		ChallengeNonce: authorization.ChallengeNonce, ChallengeDigest: authorization.ChallengeDigest,
		Binding: authorization.Binding, BootstrapPublicKey: authorization.BootstrapPublicKey,
		OneBootPublicKey: authorization.OneBootPublicKey, Decision: authorization.Decision,
		IssuedAtUnixSeconds: authorization.IssuedAtUnixSeconds, MaxAgeSeconds: authorization.MaxAgeSeconds,
		AuthorityKeyID: authorization.AuthorityKeyID,
	}
	return marshalBounded(value)
}

func matchAuthorization(authorization Authorization, request AuthorizationRequest) error {
	digest, err := request.Challenge.Digest()
	if err != nil {
		return err
	}
	if authorization.ChallengeID != request.Challenge.ChallengeID ||
		authorization.ChallengeNonce != request.Challenge.Nonce ||
		authorization.ChallengeDigest != digest ||
		authorization.Binding != request.Binding ||
		authorization.BootstrapPublicKey != request.BootstrapPublicKey ||
		authorization.OneBootPublicKey != request.OneBootPublicKey ||
		authorization.AuthorityKeyID != request.Challenge.AuthorityKeyID {
		return ErrBindingMismatch
	}
	return nil
}

func EncodePublicKey(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", invalid("Ed25519 public key has the wrong length")
	}
	return "ed25519:" + hex.EncodeToString(publicKey), nil
}

func DecodePublicKey(encoded string) (ed25519.PublicKey, error) {
	if !publicKeyPattern.MatchString(encoded) {
		return nil, invalid("Ed25519 public key encoding is invalid")
	}
	decoded, err := hex.DecodeString(encoded[len("ed25519:"):])
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, invalid("Ed25519 public key encoding is invalid")
	}
	return ed25519.PublicKey(decoded), nil
}

func marshalBounded(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode canonical non-production authorization document: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > MaxDocumentBytes {
		return nil, invalid(fmt.Sprintf("canonical document must be between 1 and %d bytes", MaxDocumentBytes))
	}
	return encoded, nil
}

func domainDigest(domain string, canonical []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(canonical)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func signEncoded(domain string, canonical []byte, privateKey ed25519.PrivateKey) (string, error) {
	if _, err := publicFromPrivate(privateKey); err != nil {
		return "", err
	}
	signature := ed25519.Sign(privateKey, signingMessage(domain, canonical))
	return "ed25519:" + hex.EncodeToString(signature), nil
}

func verifyEncoded(domain string, canonical []byte, publicKey ed25519.PublicKey, encodedSignature string) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return invalid("authority Ed25519 public key has the wrong length")
	}
	signature, err := decodeSignature(encodedSignature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, signingMessage(domain, canonical), signature) {
		return ErrSignature
	}
	return nil
}

func signingMessage(domain string, canonical []byte) []byte {
	message := make([]byte, 0, len(domain)+1+len(canonical))
	message = append(message, domain...)
	message = append(message, 0)
	return append(message, canonical...)
}

func decodeSignature(encoded string) ([]byte, error) {
	if !signaturePattern.MatchString(encoded) {
		return nil, invalid("Ed25519 signature encoding is invalid")
	}
	decoded, err := hex.DecodeString(encoded[len("ed25519:"):])
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, invalid("Ed25519 signature encoding is invalid")
	}
	return decoded, nil
}

func publicFromPrivate(privateKey ed25519.PrivateKey) (ed25519.PublicKey, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, invalid("Ed25519 private key has the wrong length")
	}
	expected := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(expected, privateKey) != 1 {
		return nil, invalid("Ed25519 private key is internally inconsistent")
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, invalid("Ed25519 private key does not expose a valid public key")
	}
	return publicKey, nil
}

func validateElapsed(elapsed time.Duration, maxAgeSeconds uint32) error {
	if elapsed < 0 {
		return invalid("elapsed duration must not be negative")
	}
	if elapsed > time.Duration(maxAgeSeconds)*time.Second {
		return ErrExpired
	}
	return nil
}

func validateIssuedAt(value int64) error {
	if value < 0 || value > 253402300799 {
		return invalid("issued_at_unix_seconds is outside the supported range")
	}
	return nil
}

func validateMaxAge(value uint32) error {
	if value == 0 || value > MaxProtocolAgeSeconds {
		return invalid(fmt.Sprintf("max_age_seconds must be between 1 and %d", MaxProtocolAgeSeconds))
	}
	return nil
}

func durationSeconds(value time.Duration, name string) (uint32, error) {
	if value <= 0 || value%time.Second != 0 || value > time.Duration(MaxProtocolAgeSeconds)*time.Second {
		return 0, invalid(fmt.Sprintf("%s must be a whole number of seconds between 1s and %ds", name, MaxProtocolAgeSeconds))
	}
	return uint32(value / time.Second), nil
}

func invalid(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalid, message)
}
