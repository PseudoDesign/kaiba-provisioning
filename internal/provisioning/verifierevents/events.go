// Package verifierevents emits the bounded, machine-readable UART records
// used by the stable-verifier spike. Records deliberately omit wall-clock time
// because the unfused target does not yet have a trusted clock.
package verifierevents

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	SchemaV1Alpha1 = "kaiba.provisioning.rpi5-stable-verifier-event/v1alpha1"
	SourceUART     = "verifier-uart"

	EventStarted            = "verifier-started"
	EventReleaseVerified    = "release-verified"
	EventBootstrapKeyReady  = "bootstrap-key-ready"
	EventAuthorizationReady = "authorization-granted"
	EventHandoffLoaded      = "handoff-loaded"
	EventHandoffExecuting   = "handoff-executing"
	EventFailed             = "verifier-failed"

	MaxRecordBytes = 16 * 1024
	maxSequence    = uint64(1<<32 - 1)
	eventDomain    = "kaiba.provisioning.rpi5-stable-verifier-event.v1alpha1"
)

var (
	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	publicKeyPattern  = regexp.MustCompile(`^ed25519:[0-9a-f]{64}$`)
	knownEvents       = map[string]struct{}{
		EventStarted: {}, EventReleaseVerified: {}, EventBootstrapKeyReady: {},
		EventAuthorizationReady: {}, EventHandoffLoaded: {}, EventHandoffExecuting: {}, EventFailed: {},
	}
)

// Details carries only public, release-bound information. Private material and
// target serials have no representation in this contract.
type Details struct {
	PolicyDigest       bundle.Digest
	ManifestDigest     bundle.Digest
	BootstrapPublicKey string
	OneBootPublicKey   string
	FailureCode        string
}

// Record is one canonical JSON line written to UART.
type Record struct {
	SchemaVersion      string        `json:"schema_version"`
	Sequence           uint64        `json:"sequence"`
	Source             string        `json:"source"`
	Event              string        `json:"event"`
	PolicyDigest       bundle.Digest `json:"policy_digest,omitempty"`
	ManifestDigest     bundle.Digest `json:"manifest_digest,omitempty"`
	BootstrapPublicKey string        `json:"bootstrap_public_key,omitempty"`
	OneBootPublicKey   string        `json:"one_boot_public_key,omitempty"`
	FailureCode        string        `json:"failure_code,omitempty"`
}

// Emitter serializes records and assigns a contiguous sequence. It returns a
// domain-separated digest suitable for the redacted spike-evidence contract.
type Emitter struct {
	mu       sync.Mutex
	output   io.Writer
	sequence uint64
}

func New(output io.Writer) (*Emitter, error) {
	if output == nil {
		return nil, errors.New("verifier event output is required")
	}
	return &Emitter{output: output}, nil
}

func (emitter *Emitter) Emit(event string, details Details) (Record, bundle.Digest, error) {
	if emitter == nil || emitter.output == nil {
		return Record{}, "", errors.New("verifier event emitter is required")
	}
	emitter.mu.Lock()
	defer emitter.mu.Unlock()
	if emitter.sequence >= maxSequence {
		return Record{}, "", errors.New("verifier event sequence is exhausted")
	}
	record := Record{
		SchemaVersion:      SchemaV1Alpha1,
		Sequence:           emitter.sequence + 1,
		Source:             SourceUART,
		Event:              event,
		PolicyDigest:       details.PolicyDigest,
		ManifestDigest:     details.ManifestDigest,
		BootstrapPublicKey: details.BootstrapPublicKey,
		OneBootPublicKey:   details.OneBootPublicKey,
		FailureCode:        details.FailureCode,
	}
	if err := record.Validate(); err != nil {
		return Record{}, "", err
	}
	encoded, err := record.canonicalJSON()
	if err != nil {
		return Record{}, "", err
	}
	digest, err := record.Digest()
	if err != nil {
		return Record{}, "", err
	}
	line := append(encoded, '\n')
	written, err := emitter.output.Write(line)
	if err != nil {
		return Record{}, "", fmt.Errorf("write verifier event: %w", err)
	}
	if written != len(line) {
		return Record{}, "", fmt.Errorf("write verifier event: %w", io.ErrShortWrite)
	}
	emitter.sequence = record.Sequence
	return record, digest, nil
}

func (record Record) Validate() error {
	if record.SchemaVersion != SchemaV1Alpha1 || record.Source != SourceUART {
		return errors.New("unsupported verifier event schema or source")
	}
	if record.Sequence == 0 || record.Sequence > maxSequence {
		return errors.New("verifier event sequence is out of range")
	}
	if _, exists := knownEvents[record.Event]; !exists {
		return errors.New("verifier event name is not supported")
	}
	for name, digest := range map[string]bundle.Digest{
		"policy_digest": record.PolicyDigest, "manifest_digest": record.ManifestDigest,
	} {
		if digest != "" {
			if err := digest.Validate(); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	for name, key := range map[string]string{
		"bootstrap_public_key": record.BootstrapPublicKey, "one_boot_public_key": record.OneBootPublicKey,
	} {
		if key != "" && !publicKeyPattern.MatchString(key) {
			return fmt.Errorf("%s is not a canonical Ed25519 public key", name)
		}
	}
	if record.FailureCode != "" && !identifierPattern.MatchString(record.FailureCode) {
		return errors.New("failure_code is not canonical")
	}
	if record.Event == EventFailed && record.FailureCode == "" {
		return errors.New("failed verifier event requires failure_code")
	}
	if record.Event != EventFailed && record.FailureCode != "" {
		return errors.New("only failed verifier events may contain failure_code")
	}
	stage := eventDetailStage(record)
	if stage < 0 {
		return errors.New("verifier event contains an incomplete detail stage")
	}
	switch record.Event {
	case EventStarted:
		if stage != 0 {
			return errors.New("verifier-started event must not contain release details")
		}
	case EventReleaseVerified:
		if stage != 1 {
			return errors.New("release-verified event requires only policy and manifest digests")
		}
	case EventBootstrapKeyReady:
		if stage != 2 {
			return errors.New("bootstrap-key-ready event requires release digests and the bootstrap public key")
		}
	case EventAuthorizationReady, EventHandoffLoaded, EventHandoffExecuting:
		if stage != 3 {
			return errors.New("post-authorization event requires release digests and both public keys")
		}
	}
	return nil
}

// eventDetailStage recognizes the only public-detail progressions emitted by
// the verifier. Failed events may report whichever complete stage was reached.
func eventDetailStage(record Record) int {
	hasPolicy := record.PolicyDigest != ""
	hasManifest := record.ManifestDigest != ""
	hasBootstrap := record.BootstrapPublicKey != ""
	hasOneBoot := record.OneBootPublicKey != ""
	switch {
	case !hasPolicy && !hasManifest && !hasBootstrap && !hasOneBoot:
		return 0
	case hasPolicy && hasManifest && !hasBootstrap && !hasOneBoot:
		return 1
	case hasPolicy && hasManifest && hasBootstrap && !hasOneBoot:
		return 2
	case hasPolicy && hasManifest && hasBootstrap && hasOneBoot:
		return 3
	default:
		return -1
	}
}
