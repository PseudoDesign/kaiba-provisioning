// Package stableevidence validates the closed, code-only result envelope for
// the Raspberry Pi 5 stable-verifier development spike. Raw UART, server logs,
// serial numbers, free-form observations, and private material have no field
// in this type.
package stableevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	SchemaV1Alpha1   = "kaiba.provisioning.rpi5-stable-verifier-spike-evidence/v1alpha1"
	CampaignV1Alpha1 = "kaiba.provisioning.rpi5-stable-verifier-campaign/v1alpha1"
	DeviceClass      = "raspberry-pi-5-model-b-v1alpha1"
	BoardRevision    = "a04171"
	Classification   = "development-only"
	OutcomeValidated = "validated"
	OutcomeBlocked   = "blocked"
	MaxBytes         = 1024 * 1024
)

var (
	identifierPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	sourceRevisionPattern   = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	firmwareRevisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	artifactVersionPattern  = regexp.MustCompile(`^[0-9a-z][0-9a-z.+_~-]{0,127}$`)
	mandatoryTestIDs        = []string{
		"approved-release-boots",
		"authorization-offline-rejected",
		"authorization-replay-rejected",
		"component-byte-mutations-rejected",
		"delegated-key-replacement-boots",
		"dm-verity-corruption-rejected",
		"kernel-command-line-observed",
		"manifest-field-mutations-rejected",
		"one-boot-key-bound",
		"released-os-bootstrap-reuse-rejected",
		"resolved-device-tree-observed",
		"revoked-delegated-key-rejected",
		"unsigned-release-rejected",
		"wrong-delegated-key-rejected",
	}
)

type Hardware struct {
	DeviceClass      string `json:"device_class"`
	BoardRevision    string `json:"board_revision"`
	SerialRedacted   bool   `json:"serial_redacted"`
	CustomerKeyState string `json:"customer_key_state"`
	OTPChanged       bool   `json:"otp_changed"`
	EEPROMChanged    bool   `json:"eeprom_changed"`
}

type Software struct {
	SourceRevision         string        `json:"source_revision"`
	VerifierVersion        uint64        `json:"verifier_version"`
	VerifierArtifactDigest bundle.Digest `json:"verifier_artifact_digest"`
	PolicyDigest           bundle.Digest `json:"policy_digest"`
	ManifestDigest         bundle.Digest `json:"manifest_digest"`
	KernelVersion          string        `json:"kernel_version"`
	FirmwareRevision       string        `json:"firmware_revision"`
	KexecVersion           string        `json:"kexec_version"`
}

type TestResult struct {
	TestID string `json:"test_id"`
	Result string `json:"result"`
}

type OrderedEvent struct {
	Source       string        `json:"source"`
	Event        string        `json:"event"`
	RecordDigest bundle.Digest `json:"record_digest"`
}

type Evidence struct {
	SchemaVersion          string         `json:"schema_version"`
	EvidenceID             string         `json:"evidence_id"`
	RecordedAt             string         `json:"recorded_at"`
	Classification         string         `json:"classification"`
	CampaignProfile        string         `json:"campaign_profile"`
	Hardware               Hardware       `json:"hardware"`
	Software               Software       `json:"software"`
	Outcome                string         `json:"outcome"`
	TestResults            []TestResult   `json:"test_results"`
	OrderedEvents          []OrderedEvent `json:"ordered_events"`
	PrivateMaterialPresent bool           `json:"private_material_present"`
	ProductionReady        bool           `json:"production_ready"`
}

func Parse(encoded []byte) (Evidence, error) {
	if len(encoded) == 0 || len(encoded) > MaxBytes {
		return Evidence{}, fmt.Errorf("stable-verifier evidence size must be between 1 and %d bytes", MaxBytes)
	}
	if err := rejectDuplicateKeysAndNulls(encoded); err != nil {
		return Evidence{}, fmt.Errorf("decode stable-verifier evidence: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var evidence Evidence
	if err := decoder.Decode(&evidence); err != nil {
		return Evidence{}, fmt.Errorf("decode stable-verifier evidence: %w", err)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return Evidence{}, fmt.Errorf("decode stable-verifier evidence: %w", err)
		}
		return Evidence{}, fmt.Errorf("decode stable-verifier evidence: trailing JSON value %v", token)
	}
	if err := evidence.Validate(); err != nil {
		return Evidence{}, err
	}
	canonical, err := evidence.CanonicalJSON()
	if err != nil {
		return Evidence{}, err
	}
	if !bytes.Equal(encoded, canonical) && !bytes.Equal(encoded, append(canonical, '\n')) {
		return Evidence{}, errors.New("stable-verifier evidence is not canonical JSON")
	}
	return evidence, nil
}

func (evidence Evidence) CanonicalJSON() ([]byte, error) {
	if err := evidence.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("encode stable-verifier evidence: %w", err)
	}
	if len(encoded) > MaxBytes {
		return nil, fmt.Errorf("stable-verifier evidence exceeds %d bytes", MaxBytes)
	}
	return encoded, nil
}

func (evidence Evidence) Validate() error {
	if evidence.SchemaVersion != SchemaV1Alpha1 {
		return fmt.Errorf("unsupported evidence schema_version %q", evidence.SchemaVersion)
	}
	if !identifierPattern.MatchString(evidence.EvidenceID) {
		return errors.New("evidence_id is not canonical")
	}
	recordedAt, err := time.Parse(time.RFC3339, evidence.RecordedAt)
	if err != nil || recordedAt.Location() != time.UTC || recordedAt.Format(time.RFC3339) != evidence.RecordedAt {
		return errors.New("recorded_at must be a canonical UTC RFC3339 timestamp")
	}
	if evidence.Classification != Classification || evidence.PrivateMaterialPresent || evidence.ProductionReady {
		return errors.New("evidence must remain development-only, private-material-free, and not production-ready")
	}
	if evidence.CampaignProfile != CampaignV1Alpha1 {
		return errors.New("evidence does not use the supported stable-verifier campaign profile")
	}
	if err := evidence.Hardware.validate(); err != nil {
		return err
	}
	if err := evidence.Software.validate(); err != nil {
		return err
	}
	if evidence.Outcome != OutcomeValidated && evidence.Outcome != OutcomeBlocked {
		return errors.New("outcome must be validated or blocked")
	}
	if len(evidence.TestResults) != len(mandatoryTestIDs) {
		return errors.New("test_results must contain the complete mandatory campaign test set")
	}
	allPassed := true
	for index, result := range evidence.TestResults {
		if result.TestID != mandatoryTestIDs[index] {
			return fmt.Errorf("test_results entry %d must be %q", index, mandatoryTestIDs[index])
		}
		switch result.Result {
		case "pass":
		case "fail", "blocked":
			allPassed = false
		default:
			return fmt.Errorf("test %q has unsupported result %q", result.TestID, result.Result)
		}
	}
	if evidence.Outcome == OutcomeValidated {
		if !allPassed {
			return errors.New("validated evidence cannot contain failed or blocked test results")
		}
	}
	if evidence.Outcome == OutcomeBlocked && allPassed {
		return errors.New("blocked evidence requires at least one failed or blocked test result")
	}
	if len(evidence.OrderedEvents) == 0 || len(evidence.OrderedEvents) > 4096 {
		return errors.New("ordered_events must contain between 1 and 4096 entries")
	}
	for index, event := range evidence.OrderedEvents {
		switch event.Source {
		case "verifier-uart", "authorization-server", "released-os-uart", "test-runner":
		default:
			return fmt.Errorf("ordered event %d has unsupported source %q", index+1, event.Source)
		}
		if !identifierPattern.MatchString(event.Event) {
			return fmt.Errorf("ordered event %d has invalid event name", index+1)
		}
		if err := event.RecordDigest.Validate(); err != nil {
			return fmt.Errorf("ordered event %d record_digest: %w", index+1, err)
		}
	}
	return nil
}

func (hardware Hardware) validate() error {
	if hardware.DeviceClass != DeviceClass || hardware.BoardRevision != BoardRevision {
		return errors.New("hardware must identify the approved a04171 Raspberry Pi 5 target")
	}
	if !hardware.SerialRedacted || hardware.CustomerKeyState != "unfused" || hardware.OTPChanged || hardware.EEPROMChanged {
		return errors.New("hardware evidence must redact the serial and attest no OTP or EEPROM changes")
	}
	return nil
}

func (software Software) validate() error {
	if !sourceRevisionPattern.MatchString(software.SourceRevision) || software.VerifierVersion == 0 ||
		!firmwareRevisionPattern.MatchString(software.FirmwareRevision) {
		return errors.New("software source, verifier version, or firmware revision is invalid")
	}
	for name, digest := range map[string]bundle.Digest{
		"verifier_artifact_digest": software.VerifierArtifactDigest,
		"policy_digest":            software.PolicyDigest,
		"manifest_digest":          software.ManifestDigest,
	} {
		if err := digest.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if !artifactVersionPattern.MatchString(software.KernelVersion) ||
		!artifactVersionPattern.MatchString(software.KexecVersion) {
		return errors.New("kernel_version and kexec_version must be canonical public version identifiers")
	}
	return nil
}

func rejectDuplicateKeysAndNulls(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if _, err := decodeUniqueValue(decoder, nil); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("trailing JSON value %v", token)
	}
	return nil
}

func decodeUniqueValue(decoder *json.Decoder, first json.Token) (any, error) {
	token := first
	var err error
	if token == nil {
		token, err = decoder.Token()
		if err != nil {
			return nil, err
		}
	}
	if token == nil {
		return nil, errors.New("JSON null is not permitted")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON object key is not a string")
			}
			if _, duplicate := object[key]; duplicate {
				return nil, fmt.Errorf("JSON object key %q is duplicated", key)
			}
			value, err := decodeUniqueValue(decoder, nil)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return nil, errors.New("JSON object is not closed")
		}
		return object, nil
	case '[':
		values := make([]any, 0)
		for decoder.More() {
			value, err := decodeUniqueValue(decoder, nil)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return nil, errors.New("JSON array is not closed")
		}
		return values, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

// SortTestResults applies the canonical ordering before Evidence validation.
func SortTestResults(results []TestResult) []TestResult {
	copyOfResults := append([]TestResult(nil), results...)
	sort.Slice(copyOfResults, func(left, right int) bool {
		return copyOfResults[left].TestID < copyOfResults[right].TestID
	})
	return copyOfResults
}

// MandatoryTestIDs returns the exact sorted test set required by the current
// campaign profile before evidence may claim a validated outcome.
func MandatoryTestIDs() []string {
	return append([]string(nil), mandatoryTestIDs...)
}
