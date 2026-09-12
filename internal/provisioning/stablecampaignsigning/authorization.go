package stablecampaignsigning

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signingapproval"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
)

const (
	ApprovalSchemaV1Alpha1  = "kaiba.provisioning.rpi5-stable-campaign-provisioner-signing-approval/v1alpha1"
	DecisionApproved        = "approved"
	MaxApprovalBytes        = 64 * 1024
	MaximumApprovalLifetime = 24 * time.Hour

	approvalDigestDomain = "kaiba.provisioning.rpi5-stable-campaign-provisioner-signing-approval.v1alpha1"
)

var (
	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	timePattern       = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

// Approval is the canonical public statement attributed to a reviewer. The
// reviewer identity is procedural, as in the generic release-signing flow;
// signing-host root remains the authority that installs the resulting exact
// registry. ApprovalID is derived rather than selected by an operator.
type Approval struct {
	SchemaVersion       string          `json:"schema_version"`
	ApprovalID          string          `json:"approval_id"`
	ApprovalDigest      bundle.Digest   `json:"approval_digest"`
	Decision            string          `json:"decision"`
	ReviewerID          string          `json:"reviewer_id"`
	ApprovedAt          string          `json:"approved_at"`
	ExpiresAt           string          `json:"expires_at"`
	SourceRevision      string          `json:"source_revision"`
	SigningIntentDigest bundle.Digest   `json:"signing_intent_digest"`
	SigningInput        bundle.Artifact `json:"signing_input"`
}

// Authorization is the complete public output consumed by the existing
// signing gate. Registry must contain exactly the one deterministic grant
// reconstructed from Approval and Intent.
type Authorization struct {
	Approval Approval
	Registry signinggate.Registry
}

type approvalDigestMaterial struct {
	SchemaVersion       string          `json:"schema_version"`
	Decision            string          `json:"decision"`
	ReviewerID          string          `json:"reviewer_id"`
	ApprovedAt          string          `json:"approved_at"`
	ExpiresAt           string          `json:"expires_at"`
	SourceRevision      string          `json:"source_revision"`
	SigningIntentDigest bundle.Digest   `json:"signing_intent_digest"`
	SigningInput        bundle.Artifact `json:"signing_input"`
}

// NewAuthorization derives the approval identity and exact one-grant
// v1alpha2 registry. Times must already use canonical UTC RFC3339 seconds.
func NewAuthorization(intent Intent, reviewerID, approvedAt, expiresAt string) (Authorization, error) {
	if err := intent.Validate(); err != nil {
		return Authorization{}, fmt.Errorf("stable signing intent: %w", err)
	}
	intentDigest, err := intent.Digest()
	if err != nil {
		return Authorization{}, err
	}
	approval := Approval{
		SchemaVersion:       ApprovalSchemaV1Alpha1,
		Decision:            DecisionApproved,
		ReviewerID:          reviewerID,
		ApprovedAt:          approvedAt,
		ExpiresAt:           expiresAt,
		SourceRevision:      intent.SourceRevision,
		SigningIntentDigest: intentDigest,
		SigningInput:        intent.SigningInput,
	}
	digest, err := approval.calculateDigest()
	if err != nil {
		return Authorization{}, err
	}
	approval.ApprovalDigest = digest
	approval.ApprovalID = approvalID(digest)
	if err := approval.Validate(); err != nil {
		return Authorization{}, err
	}
	registry, err := registryFor(approval)
	if err != nil {
		return Authorization{}, err
	}
	authorization := Authorization{Approval: approval, Registry: registry}
	if err := authorization.Validate(intent); err != nil {
		return Authorization{}, err
	}
	return authorization, nil
}

// Validate reconstructs every field from intent and requires canonical
// byte-level equality with the exact one-grant registry. Extra grants,
// hand-authored IDs, and generic five-role registries fail closed.
func (authorization Authorization) Validate(intent Intent) error {
	if err := intent.Validate(); err != nil {
		return fmt.Errorf("stable signing intent: %w", err)
	}
	if err := authorization.Approval.Validate(); err != nil {
		return fmt.Errorf("approval: %w", err)
	}
	intentDigest, err := intent.Digest()
	if err != nil {
		return err
	}
	approval := authorization.Approval
	if approval.SourceRevision != intent.SourceRevision || approval.SigningIntentDigest != intentDigest {
		return errors.New("approval does not identify the supplied stable signing intent")
	}
	if approval.SigningInput != intent.SigningInput {
		return errors.New("approval signing input does not exactly match the stable signing intent")
	}
	approvedAt, _ := parseCanonicalTime(approval.ApprovedAt, "approved_at")
	if approvedAt.Unix() < int64(intent.SourceDateEpoch) {
		return errors.New("approved_at precedes the stable signing intent source_date_epoch")
	}
	if err := authorization.Registry.Validate(); err != nil {
		return fmt.Errorf("grant registry: %w", err)
	}
	expected, err := registryFor(approval)
	if err != nil {
		return err
	}
	actualJSON, err := signingapproval.CanonicalRegistryJSON(authorization.Registry)
	if err != nil {
		return err
	}
	expectedJSON, err := signingapproval.CanonicalRegistryJSON(expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(actualJSON, expectedJSON) {
		return errors.New("grant registry is not the exact deterministic one-grant registry for the approval")
	}
	return nil
}

// Validate checks the closed vocabulary, canonical times, and exact
// digest-derived identity without consulting a wall clock.
func (approval Approval) Validate() error {
	if err := approval.validateMaterial(); err != nil {
		return err
	}
	digest, err := approval.calculateDigest()
	if err != nil {
		return err
	}
	if approval.ApprovalDigest != digest {
		return errors.New("approval_digest does not match the canonical approval material")
	}
	if approval.ApprovalID != approvalID(digest) {
		return errors.New("approval_id is not derived from approval_digest")
	}
	return nil
}

// RequireCurrentlyActive checks the ceremony times against the supplied host
// clock. It is used while authoring; offline evidence validation deliberately
// remains possible after expiry.
func (approval Approval) RequireCurrentlyActive(now time.Time) error {
	if err := approval.Validate(); err != nil {
		return err
	}
	approvedAt, _ := parseCanonicalTime(approval.ApprovedAt, "approved_at")
	expiresAt, _ := parseCanonicalTime(approval.ExpiresAt, "expires_at")
	now = now.UTC()
	if now.Before(approvedAt) {
		return errors.New("approved_at is in the future according to the authoring host clock")
	}
	if !now.Before(expiresAt) {
		return errors.New("the approval is already expired according to the authoring host clock")
	}
	return nil
}

// CanonicalJSON returns the unique fixed-order representation covered by the
// approval's digest-derived identity.
func (approval Approval) CanonicalJSON() ([]byte, error) {
	if err := approval.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(approval)
	if err != nil {
		return nil, fmt.Errorf("encode canonical stable signing approval: %w", err)
	}
	if len(encoded) > MaxApprovalBytes {
		return nil, fmt.Errorf("canonical stable signing approval exceeds %d bytes", MaxApprovalBytes)
	}
	return encoded, nil
}

// ParseApproval strictly decodes an approval and requires the exact canonical
// representation, optionally followed by one transport LF.
func ParseApproval(data []byte) (Approval, error) {
	payload, err := canonicalPayload(data, MaxApprovalBytes, "stable signing approval")
	if err != nil {
		return Approval{}, err
	}
	var approval Approval
	if err := strictDecode(payload, &approval); err != nil {
		return Approval{}, fmt.Errorf("decode stable signing approval: %w", err)
	}
	canonical, err := approval.CanonicalJSON()
	if err != nil {
		return Approval{}, err
	}
	if !bytes.Equal(payload, canonical) {
		return Approval{}, errors.New("stable signing approval must use its exact canonical JSON representation")
	}
	return approval, nil
}

func (approval Approval) validateMaterial() error {
	if approval.SchemaVersion != ApprovalSchemaV1Alpha1 {
		return fmt.Errorf("unsupported stable signing approval schema_version %q", approval.SchemaVersion)
	}
	if approval.Decision != DecisionApproved {
		return fmt.Errorf("decision must be %q", DecisionApproved)
	}
	if !identifierPattern.MatchString(approval.ReviewerID) {
		return errors.New("reviewer_id must be a canonical lower-case identifier")
	}
	approvedAt, err := parseCanonicalTime(approval.ApprovedAt, "approved_at")
	if err != nil {
		return err
	}
	expiresAt, err := parseCanonicalTime(approval.ExpiresAt, "expires_at")
	if err != nil {
		return err
	}
	if !expiresAt.After(approvedAt) || expiresAt.After(approvedAt.Add(MaximumApprovalLifetime)) {
		return errors.New("expires_at must be after approved_at and no more than 24 hours later")
	}
	if !sourceRevisionPattern.MatchString(approval.SourceRevision) {
		return errors.New("source_revision must contain exactly 40 or 64 lower-case hexadecimal characters")
	}
	if err := approval.SigningIntentDigest.Validate(); err != nil {
		return fmt.Errorf("signing_intent_digest: %w", err)
	}
	if approval.SigningInput.Role != bundle.RoleBootImage {
		return fmt.Errorf("signing_input.role must be %q", bundle.RoleBootImage)
	}
	if err := approval.SigningInput.Digest.Validate(); err != nil {
		return fmt.Errorf("signing_input.digest: %w", err)
	}
	if approval.SigningInput.SizeBytes == 0 || approval.SigningInput.SizeBytes > uint64(signing.MaxArtifactBytes) {
		return fmt.Errorf("signing_input.size_bytes must be between 1 and %d", signing.MaxArtifactBytes)
	}
	return nil
}

func (approval Approval) calculateDigest() (bundle.Digest, error) {
	if err := approval.validateMaterial(); err != nil {
		return "", err
	}
	material := approvalDigestMaterial{
		SchemaVersion: approval.SchemaVersion, Decision: approval.Decision,
		ReviewerID: approval.ReviewerID, ApprovedAt: approval.ApprovedAt, ExpiresAt: approval.ExpiresAt,
		SourceRevision: approval.SourceRevision, SigningIntentDigest: approval.SigningIntentDigest,
		SigningInput: approval.SigningInput,
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", fmt.Errorf("encode stable signing approval digest material: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(approvalDigestDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

func registryFor(approval Approval) (signinggate.Registry, error) {
	if err := approval.Validate(); err != nil {
		return signinggate.Registry{}, fmt.Errorf("approval: %w", err)
	}
	digestHex := strings.TrimPrefix(string(approval.ApprovalDigest), "sha256:")
	role := string(bundle.RoleBootImage)
	grant := signinggate.Grant{
		SchemaVersion: signinggate.GrantSchemaV1Alpha2,
		GrantID:       "grant:" + digestHex + ":" + role,
		ExpiresAt:     approval.ExpiresAt,
		Request: signing.Request{
			SchemaVersion:  signing.RequestSchemaV1Alpha2,
			RequestID:      "request:" + digestHex + ":" + role,
			Algorithm:      signing.AlgorithmRSA2048SHA256,
			Role:           approval.SigningInput.Role,
			ArtifactDigest: approval.SigningInput.Digest,
			Approval: signing.ApprovalBinding{
				ApprovalID:          approval.ApprovalID,
				ApprovalDigest:      approval.ApprovalDigest,
				ReleaseIntentDigest: approval.SigningIntentDigest,
				Role:                approval.SigningInput.Role,
				ArtifactDigest:      approval.SigningInput.Digest,
			},
		},
	}
	registry, err := signinggate.NewRegistry([]signinggate.Grant{grant})
	if err != nil {
		return signinggate.Registry{}, fmt.Errorf("construct one-grant registry: %w", err)
	}
	return registry, nil
}

func approvalID(digest bundle.Digest) string {
	return "approval:" + strings.TrimPrefix(string(digest), "sha256:")
}

func parseCanonicalTime(value, field string) (time.Time, error) {
	if !timePattern.MatchString(value) {
		return time.Time{}, fmt.Errorf("%s must use canonical UTC RFC3339 seconds", field)
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf("%s must use canonical UTC RFC3339 seconds", field)
	}
	return parsed, nil
}
