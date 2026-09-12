package stablecampaign

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/verifierevents"
)

const (
	MediaReadbackSchemaV1Alpha1    = "kaiba.provisioning.rpi5-stable-verifier-media-readback/v1alpha1"
	ReleasedOSEventSchemaV1Alpha1  = "kaiba.provisioning.rpi5-stable-verifier-released-os-event/v1alpha1"
	AuthorityAuditSchemaV1Alpha1   = "kaiba.provisioning.rpi5-stable-verifier-authority-audit/v1alpha1"
	PowerObservationSchemaV1Alpha1 = "kaiba.provisioning.rpi5-stable-verifier-power-observation/v1alpha1"

	// These source labels describe the claimed record origin only. None is an
	// authenticated provenance assertion in the current contract.
	MediaReadbackSource    = "claimed-readback-collector"
	ReleasedOSEventSource  = "claimed-released-os-uart"
	AuthorityAuditSource   = "claimed-non-production-authority-audit"
	PowerObservationSource = "claimed-manual-operator-observation"

	AuthorityEventAuthorizationIssued = "authorization-issued"
	AuthorityEventOffline             = "authority-offline"
	// AuthorityEventAuthorizationRejected is intentionally generic. The
	// verifier's authorization-verification-failed code does not distinguish a
	// stale replay from any other authorization verification failure. Exact
	// replay closure requires a separately verified public transcript.
	AuthorityEventAuthorizationRejected = "authorization-rejected"

	ReleasedOSEventReady            = "released-os-ready"
	ReleasedOSEventRootDataRejected = "dm-verity-root-data-rejected"
	ReleasedOSEventRootHashRejected = "dm-verity-root-hash-rejected"

	PowerObservationEventColdBoot = "cold-power-cycle-observed"
	PowerObservationModeManual    = "manual-operator-confirmation"

	MaximumSemanticRecordBytes = 64 * 1024

	mediaReadbackDigestDomain    = "kaiba.provisioning.rpi5-stable-verifier-media-readback.v1alpha1"
	releasedOSEventDigestDomain  = "kaiba.provisioning.rpi5-stable-verifier-released-os-event.v1alpha1"
	authorityAuditDigestDomain   = "kaiba.provisioning.rpi5-stable-verifier-authority-audit.v1alpha1"
	powerObservationDigestDomain = "kaiba.provisioning.rpi5-stable-verifier-power-observation.v1alpha1"
)

var (
	evidenceRunIDPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9.:-]{0,255}$`)
	evidencePublicKeyPattern = regexp.MustCompile(`^ed25519:[0-9a-f]{64}$`)
	fixedMediaPartitionRoles = []MediaPartitionRole{
		MediaPartitionBootFilesystem,
		MediaPartitionReleaseFilesystem,
		MediaPartitionRootData,
		MediaPartitionRootHash,
	}
)

// EvidenceRecordContext prevents a parsed record from being detached from the
// exact result envelope that indexes it. CaptureID is context only: none of
// these public records treats it as an authenticated timestamp or proof of
// temporal freshness.
type EvidenceRecordContext struct {
	CampaignID string        `json:"campaign_id"`
	PlanDigest bundle.Digest `json:"plan_digest"`
	RunIndex   uint16        `json:"run_index"`
	RunID      string        `json:"run_id"`
	CaptureID  CaptureID     `json:"capture_id"`
}

func (context EvidenceRecordContext) validate() error {
	if !identifierPattern.MatchString(context.CampaignID) {
		return errors.New("record context campaign_id is not canonical")
	}
	if err := context.PlanDigest.Validate(); err != nil {
		return fmt.Errorf("record context plan_digest: %w", err)
	}
	if context.RunIndex == 0 {
		return errors.New("record context run_index must be positive")
	}
	if !evidenceRunIDPattern.MatchString(context.RunID) {
		return errors.New("record context run_id is not canonical")
	}
	if err := context.CaptureID.Validate(); err != nil {
		return fmt.Errorf("record context: %w", err)
	}
	return nil
}

// NewEvidenceRecordContext derives the only context accepted for one plan,
// run, and caller-generated capture nonce.
func NewEvidenceRecordContext(plan Plan, runIndex uint16, captureID CaptureID) (EvidenceRecordContext, error) {
	runs, err := ExpectedRuns(plan)
	if err != nil {
		return EvidenceRecordContext{}, err
	}
	if runIndex == 0 || int(runIndex) > len(runs) {
		return EvidenceRecordContext{}, fmt.Errorf("run_index must be between 1 and %d", len(runs))
	}
	if err := captureID.Validate(); err != nil {
		return EvidenceRecordContext{}, err
	}
	spec := runs[runIndex-1]
	return EvidenceRecordContext{
		CampaignID: plan.CampaignID,
		PlanDigest: plan.PlanDigest,
		RunIndex:   spec.Index,
		RunID:      spec.RunID,
		CaptureID:  captureID,
	}, nil
}

type MediaPartitionRole string

const (
	MediaPartitionBootFilesystem    MediaPartitionRole = "boot-filesystem"
	MediaPartitionReleaseFilesystem MediaPartitionRole = "release-filesystem"
	MediaPartitionRootData          MediaPartitionRole = "root-data"
	MediaPartitionRootHash          MediaPartitionRole = "root-hash"
)

// MediaPartitionBinding contains a caller-declared or record-reported whole
// partition digest. It deliberately has no host or device path.
type MediaPartitionBinding struct {
	Role      MediaPartitionRole `json:"role"`
	Digest    bundle.Digest      `json:"digest"`
	SizeBytes uint64             `json:"size_bytes"`
}

func validateMediaPartitionBindings(bindings []MediaPartitionBinding) error {
	if len(bindings) != len(fixedMediaPartitionRoles) {
		return fmt.Errorf("media partitions must contain exactly %d entries", len(fixedMediaPartitionRoles))
	}
	for index, role := range fixedMediaPartitionRoles {
		binding := bindings[index]
		if binding.Role != role {
			return fmt.Errorf("media partition %d role must be %q", index+1, role)
		}
		if err := binding.Digest.Validate(); err != nil {
			return fmt.Errorf("media partition %d digest: %w", index+1, err)
		}
		if binding.SizeBytes == 0 || binding.SizeBytes > math.MaxInt64 {
			return fmt.Errorf("media partition %d size_bytes must be between 1 and %d", index+1, int64(math.MaxInt64))
		}
	}
	return nil
}

// MediaReadbackRecord is the public contract for a claimed complete-partition
// readback. Evidence consistency checking compares it with caller-declared
// values; it cannot establish either declaration provenance or how the bytes
// were collected. CaptureAuthenticated and FreshnessEstablished therefore
// remain false until a trusted collector is introduced.
type MediaReadbackRecord struct {
	SchemaVersion            string                  `json:"schema_version"`
	Context                  EvidenceRecordContext   `json:"context"`
	Source                   string                  `json:"source"`
	ArtifactSetContentDigest bundle.Digest           `json:"artifact_set_content_digest"`
	Partitions               []MediaPartitionBinding `json:"partitions"`
	CaptureAuthenticated     bool                    `json:"capture_authenticated"`
	FreshnessEstablished     bool                    `json:"freshness_established"`
}

func (record MediaReadbackRecord) Validate() error {
	if record.SchemaVersion != MediaReadbackSchemaV1Alpha1 || record.Source != MediaReadbackSource {
		return errors.New("unsupported media-readback schema or source")
	}
	if err := record.Context.validate(); err != nil {
		return err
	}
	if err := record.ArtifactSetContentDigest.Validate(); err != nil {
		return fmt.Errorf("artifact_set_content_digest: %w", err)
	}
	if err := validateMediaPartitionBindings(record.Partitions); err != nil {
		return err
	}
	if record.CaptureAuthenticated || record.FreshnessEstablished {
		return errors.New("media-readback record cannot claim authenticated capture or freshness")
	}
	return nil
}

func (record MediaReadbackRecord) CanonicalJSON() ([]byte, error) {
	return canonicalSemanticRecord("media-readback record", record, record.Validate, MaximumSemanticRecordBytes)
}

func ParseMediaReadbackRecord(encoded []byte) (MediaReadbackRecord, error) {
	var record MediaReadbackRecord
	err := parseSemanticRecord(encoded, &record, func() ([]byte, error) {
		return record.CanonicalJSON()
	}, "media-readback record", MaximumSemanticRecordBytes)
	return record, err
}

func (record MediaReadbackRecord) Digest() (bundle.Digest, error) {
	return digestSemanticRecord(mediaReadbackDigestDomain, record.CanonicalJSON)
}

// AuthorityAuditRecord describes a claimed public authorization interaction
// for a run. It never contains a challenge, authorization token, private key,
// or assertion that its capture is authenticated or fresh.
type AuthorityAuditRecord struct {
	SchemaVersion        string                `json:"schema_version"`
	Context              EvidenceRecordContext `json:"context"`
	Source               string                `json:"source"`
	Event                string                `json:"event"`
	PolicyDigest         bundle.Digest         `json:"policy_digest"`
	ManifestDigest       bundle.Digest         `json:"manifest_digest"`
	BootstrapPublicKey   string                `json:"bootstrap_public_key"`
	OneBootPublicKey     string                `json:"one_boot_public_key,omitempty"`
	CaptureAuthenticated bool                  `json:"capture_authenticated"`
	FreshnessEstablished bool                  `json:"freshness_established"`
}

func (record AuthorityAuditRecord) Validate() error {
	if record.SchemaVersion != AuthorityAuditSchemaV1Alpha1 || record.Source != AuthorityAuditSource {
		return errors.New("unsupported authority-audit schema or source")
	}
	if err := record.Context.validate(); err != nil {
		return err
	}
	if err := validateReleaseDetails(record.PolicyDigest, record.ManifestDigest, record.BootstrapPublicKey); err != nil {
		return err
	}
	switch record.Event {
	case AuthorityEventAuthorizationIssued:
		if !evidencePublicKeyPattern.MatchString(record.OneBootPublicKey) {
			return errors.New("issued authorization requires a canonical one-boot public key")
		}
		if record.OneBootPublicKey == record.BootstrapPublicKey {
			return errors.New("issued authorization must use a one-boot public key distinct from the bootstrap public key")
		}
	case AuthorityEventOffline, AuthorityEventAuthorizationRejected:
		if record.OneBootPublicKey != "" {
			return errors.New("rejected authorization event must not claim an accepted one-boot public key")
		}
	default:
		return errors.New("unsupported authority-audit event")
	}
	if record.CaptureAuthenticated || record.FreshnessEstablished {
		return errors.New("authority-audit record cannot claim authenticated capture or freshness")
	}
	return nil
}

func (record AuthorityAuditRecord) CanonicalJSON() ([]byte, error) {
	return canonicalSemanticRecord("authority-audit record", record, record.Validate, MaximumSemanticRecordBytes)
}

func ParseAuthorityAuditRecord(encoded []byte) (AuthorityAuditRecord, error) {
	var record AuthorityAuditRecord
	err := parseSemanticRecord(encoded, &record, func() ([]byte, error) {
		return record.CanonicalJSON()
	}, "authority-audit record", MaximumSemanticRecordBytes)
	return record, err
}

func (record AuthorityAuditRecord) Digest() (bundle.Digest, error) {
	return digestSemanticRecord(authorityAuditDigestDomain, record.CanonicalJSON)
}

// ReleasedOSEventRecord is one bounded claimed public UART event from the
// released OS. Its event is checked against the fixed run matrix during
// evidence consistency checking.
type ReleasedOSEventRecord struct {
	SchemaVersion        string                `json:"schema_version"`
	Context              EvidenceRecordContext `json:"context"`
	Source               string                `json:"source"`
	Event                string                `json:"event"`
	PolicyDigest         bundle.Digest         `json:"policy_digest"`
	ManifestDigest       bundle.Digest         `json:"manifest_digest"`
	BootstrapPublicKey   string                `json:"bootstrap_public_key"`
	OneBootPublicKey     string                `json:"one_boot_public_key"`
	CaptureAuthenticated bool                  `json:"capture_authenticated"`
	FreshnessEstablished bool                  `json:"freshness_established"`
}

func (record ReleasedOSEventRecord) Validate() error {
	if record.SchemaVersion != ReleasedOSEventSchemaV1Alpha1 || record.Source != ReleasedOSEventSource {
		return errors.New("unsupported released-OS event schema or source")
	}
	if err := record.Context.validate(); err != nil {
		return err
	}
	if err := validateReleaseDetails(record.PolicyDigest, record.ManifestDigest, record.BootstrapPublicKey); err != nil {
		return err
	}
	if !evidencePublicKeyPattern.MatchString(record.OneBootPublicKey) {
		return errors.New("released-OS event requires a canonical one-boot public key")
	}
	if record.OneBootPublicKey == record.BootstrapPublicKey {
		return errors.New("released-OS event must use a one-boot public key distinct from the bootstrap public key")
	}
	switch record.Event {
	case ReleasedOSEventReady, ReleasedOSEventRootDataRejected, ReleasedOSEventRootHashRejected:
	default:
		return errors.New("unsupported released-OS event")
	}
	if record.CaptureAuthenticated || record.FreshnessEstablished {
		return errors.New("released-OS event cannot claim authenticated capture or freshness")
	}
	return nil
}

func (record ReleasedOSEventRecord) CanonicalJSON() ([]byte, error) {
	return canonicalSemanticRecord("released-OS event", record, record.Validate, verifierevents.MaxRecordBytes)
}

func ParseReleasedOSEventRecord(encoded []byte) (ReleasedOSEventRecord, error) {
	var record ReleasedOSEventRecord
	err := parseSemanticRecord(encoded, &record, func() ([]byte, error) {
		return record.CanonicalJSON()
	}, "released-OS event", verifierevents.MaxRecordBytes)
	return record, err
}

func (record ReleasedOSEventRecord) Digest() (bundle.Digest, error) {
	return digestSemanticRecord(releasedOSEventDigestDomain, record.CanonicalJSON)
}

// PowerObservationRecord is deliberately a manual public observation. The
// exact cold-power semantics are required, while the two provenance booleans
// prevent the record from representing authentication or freshness that the
// current campaign collector cannot establish.
type PowerObservationRecord struct {
	SchemaVersion        string                `json:"schema_version"`
	Context              EvidenceRecordContext `json:"context"`
	Source               string                `json:"source"`
	Event                string                `json:"event"`
	ObservationMode      string                `json:"observation_mode"`
	CompletePowerRemoval bool                  `json:"complete_power_removal"`
	CaptureAuthenticated bool                  `json:"capture_authenticated"`
	FreshnessEstablished bool                  `json:"freshness_established"`
}

func (record PowerObservationRecord) Validate() error {
	if record.SchemaVersion != PowerObservationSchemaV1Alpha1 || record.Source != PowerObservationSource {
		return errors.New("unsupported power-observation schema or source")
	}
	if err := record.Context.validate(); err != nil {
		return err
	}
	if record.Event != PowerObservationEventColdBoot || record.ObservationMode != PowerObservationModeManual || !record.CompletePowerRemoval {
		return errors.New("power observation must describe manual confirmation of complete power removal before a cold boot")
	}
	if record.CaptureAuthenticated || record.FreshnessEstablished {
		return errors.New("manual power observation cannot claim authenticated capture or freshness")
	}
	return nil
}

func (record PowerObservationRecord) CanonicalJSON() ([]byte, error) {
	return canonicalSemanticRecord("power-observation record", record, record.Validate, MaximumSemanticRecordBytes)
}

func ParsePowerObservationRecord(encoded []byte) (PowerObservationRecord, error) {
	var record PowerObservationRecord
	err := parseSemanticRecord(encoded, &record, func() ([]byte, error) {
		return record.CanonicalJSON()
	}, "power-observation record", MaximumSemanticRecordBytes)
	return record, err
}

func (record PowerObservationRecord) Digest() (bundle.Digest, error) {
	return digestSemanticRecord(powerObservationDigestDomain, record.CanonicalJSON)
}

func validateReleaseDetails(policyDigest, manifestDigest bundle.Digest, bootstrapPublicKey string) error {
	if err := policyDigest.Validate(); err != nil {
		return fmt.Errorf("policy_digest: %w", err)
	}
	if err := manifestDigest.Validate(); err != nil {
		return fmt.Errorf("manifest_digest: %w", err)
	}
	if !evidencePublicKeyPattern.MatchString(bootstrapPublicKey) {
		return errors.New("bootstrap_public_key is not a canonical Ed25519 public key")
	}
	return nil
}

func canonicalSemanticRecord(label string, value any, validate func() error, maximum int) ([]byte, error) {
	if err := validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", label, err)
	}
	if len(encoded) > maximum {
		return nil, fmt.Errorf("%s exceeds %d bytes", label, maximum)
	}
	return encoded, nil
}

func parseSemanticRecord(encoded []byte, destination any, canonical func() ([]byte, error), label string, maximum int) error {
	if len(encoded) == 0 || len(encoded) > maximum+1 {
		return fmt.Errorf("parse %s: size must be between 1 and %d bytes plus an optional trailing LF", label, maximum)
	}
	if err := strictCanonicalDecode(encoded, destination, canonical); err != nil {
		return fmt.Errorf("parse %s: %w", label, err)
	}
	return nil
}

func digestSemanticRecord(domain string, canonical func() ([]byte, error)) (bundle.Digest, error) {
	encoded, err := canonical()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain + "\x00"))
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

func equalMediaPartitionBindings(left, right []MediaPartitionBinding) bool {
	return slices.Equal(left, right)
}
