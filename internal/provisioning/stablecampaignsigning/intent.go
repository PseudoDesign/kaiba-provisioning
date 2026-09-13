// Package stablecampaignsigning defines the narrow, public authorization
// contract used to sign exactly one stable-campaign Raspberry Pi 5 boot image.
//
// It deliberately contains no private-key, PIN, token, PKCS#11 module, or
// runtime-selected signer configuration. Signing authority remains behind the
// existing approval-gated signing service.
package stablecampaignsigning

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

const (
	IntentSchemaV1Alpha1 = "kaiba.provisioning.rpi5-stable-campaign-provisioner-signing-intent/v1alpha1"
	AuthorizationScope   = "stable_campaign_provisioner_boot"
	MaxIntentBytes       = 64 * 1024

	intentDigestDomain     = "kaiba.provisioning.rpi5-stable-campaign-provisioner-signing-intent.v1alpha1"
	maximumSourceDateEpoch = 253402300799
)

var sourceRevisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// IntentParameters are the caller-supplied public identities from which NewIntent
// constructs the one-input stable signing intent. Versioned constants and the
// signing role are fixed by this package rather than supplied by a caller.
type IntentParameters struct {
	SourceRevision            string
	SourceDateEpoch           uint64
	UnsignedManifestDigest    bundle.Digest
	UnsignedArtifactSetDigest bundle.Digest
	ExpectedCustomerKeyHash   bundle.Digest
	PublicKeyFileDigest       bundle.Digest
	PublicKeyFingerprint      bundle.Digest
	SignerPolicyDigest        bundle.Digest
	SigningInput              bundle.Artifact
}

// Intent binds the exact stable unsigned-artifact manifest, its artifact-set
// identity, the reviewed public key, and the only byte string authorized for a
// private-key operation. It is intentionally distinct from the generic
// five-input release intent.
type Intent struct {
	SchemaVersion             string          `json:"schema_version"`
	AuthorizationScope        string          `json:"authorization_scope"`
	SourceRevision            string          `json:"source_revision"`
	SourceDateEpoch           uint64          `json:"source_date_epoch"`
	UnsignedManifestDigest    bundle.Digest   `json:"unsigned_manifest_digest"`
	UnsignedArtifactSetDigest bundle.Digest   `json:"unsigned_artifact_set_digest"`
	ExpectedCustomerKeyHash   bundle.Digest   `json:"expected_customer_key_hash"`
	PublicKeyFileDigest       bundle.Digest   `json:"public_key_file_digest"`
	PublicKeyFingerprint      bundle.Digest   `json:"public_key_fingerprint"`
	SignerPolicyDigest        bundle.Digest   `json:"signer_policy_digest"`
	SigningInput              bundle.Artifact `json:"signing_input"`
}

// NewIntent fixes the schema, authorization scope, and exact boot-image role.
func NewIntent(parameters IntentParameters) (Intent, error) {
	intent := Intent{
		SchemaVersion:             IntentSchemaV1Alpha1,
		AuthorizationScope:        AuthorizationScope,
		SourceRevision:            parameters.SourceRevision,
		SourceDateEpoch:           parameters.SourceDateEpoch,
		UnsignedManifestDigest:    parameters.UnsignedManifestDigest,
		UnsignedArtifactSetDigest: parameters.UnsignedArtifactSetDigest,
		ExpectedCustomerKeyHash:   parameters.ExpectedCustomerKeyHash,
		PublicKeyFileDigest:       parameters.PublicKeyFileDigest,
		PublicKeyFingerprint:      parameters.PublicKeyFingerprint,
		SignerPolicyDigest:        parameters.SignerPolicyDigest,
		SigningInput:              parameters.SigningInput,
	}
	if err := intent.Validate(); err != nil {
		return Intent{}, err
	}
	return intent, nil
}

// ParseIntent strictly decodes and validates one bounded stable signing
// intent. Unknown fields, duplicate keys, JSON nulls, trailing values, and
// non-canonical bytes are rejected.
func ParseIntent(data []byte) (Intent, error) {
	if len(data) == 0 || len(data) > MaxIntentBytes {
		return Intent{}, fmt.Errorf("stable signing intent size must be between 1 and %d bytes", MaxIntentBytes)
	}
	var intent Intent
	if err := strictDecode(data, &intent); err != nil {
		return Intent{}, fmt.Errorf("decode stable signing intent: %w", err)
	}
	if err := intent.Validate(); err != nil {
		return Intent{}, err
	}
	canonical, err := intent.CanonicalJSON()
	if err != nil {
		return Intent{}, err
	}
	if !bytes.Equal(data, canonical) {
		return Intent{}, errors.New("stable signing intent must use its exact canonical JSON representation")
	}
	return intent, nil
}

// Validate enforces the closed one-artifact authorization vocabulary.
func (intent Intent) Validate() error {
	if intent.SchemaVersion != IntentSchemaV1Alpha1 {
		return fmt.Errorf("unsupported stable signing intent schema_version %q", intent.SchemaVersion)
	}
	if intent.AuthorizationScope != AuthorizationScope {
		return fmt.Errorf("authorization_scope must be %q", AuthorizationScope)
	}
	if !sourceRevisionPattern.MatchString(intent.SourceRevision) {
		return errors.New("source_revision must contain exactly 40 or 64 lower-case hexadecimal characters")
	}
	if intent.SourceDateEpoch == 0 || intent.SourceDateEpoch > maximumSourceDateEpoch {
		return fmt.Errorf("source_date_epoch must be between 1 and %d", maximumSourceDateEpoch)
	}
	for name, digest := range map[string]bundle.Digest{
		"unsigned_manifest_digest":     intent.UnsignedManifestDigest,
		"unsigned_artifact_set_digest": intent.UnsignedArtifactSetDigest,
		"expected_customer_key_hash":   intent.ExpectedCustomerKeyHash,
		"public_key_file_digest":       intent.PublicKeyFileDigest,
		"public_key_fingerprint":       intent.PublicKeyFingerprint,
		"signer_policy_digest":         intent.SignerPolicyDigest,
	} {
		if err := digest.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if intent.SigningInput.Role != bundle.RoleBootImage {
		return fmt.Errorf("signing_input.role must be %q", bundle.RoleBootImage)
	}
	if err := intent.SigningInput.Digest.Validate(); err != nil {
		return fmt.Errorf("signing_input.digest: %w", err)
	}
	if intent.SigningInput.SizeBytes == 0 || intent.SigningInput.SizeBytes > uint64(signing.MaxArtifactBytes) {
		return fmt.Errorf("signing_input.size_bytes must be between 1 and %d", signing.MaxArtifactBytes)
	}
	return nil
}

// CanonicalJSON returns the unique fixed-order representation covered by
// Digest. Transport newlines are not included.
func (intent Intent) CanonicalJSON() ([]byte, error) {
	if err := intent.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(intent)
	if err != nil {
		return nil, fmt.Errorf("encode canonical stable signing intent: %w", err)
	}
	if len(encoded) > MaxIntentBytes {
		return nil, fmt.Errorf("canonical stable signing intent exceeds %d bytes", MaxIntentBytes)
	}
	return encoded, nil
}

// Digest returns the domain-separated identity of the canonical intent.
func (intent Intent) Digest() (bundle.Digest, error) {
	canonical, err := intent.CanonicalJSON()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(intentDigestDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(canonical)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}
