package campaignqualification

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5kexecinput"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/verifierevents"
)

const (
	WitnessSchema       = "kaiba.provisioning.rpi5-campaign-reviewed-witness/v1alpha1"
	ReportSchema        = "kaiba.provisioning.rpi5-campaign-reviewed-acceptance/v1alpha1"
	ReviewedSatisfied   = "independently-reviewed-satisfied"
	CollectorRole       = "collector"
	ReviewerRole        = "independent-reviewer"
	MaximumWitnessBytes = 64 * 1024
)

// Session is selected before collection by the admission authority. It must
// not be reconstructed from the submitted result. Times are UTC Unix seconds.
type Session struct {
	Context           stablecampaign.EvidenceRecordContext `json:"context"`
	DeviceFingerprint bundle.Digest                        `json:"device_fingerprint"`
	ProfileDigest     bundle.Digest                        `json:"profile_digest"`
	ExpectationDigest bundle.Digest                        `json:"expectation_digest"`
	NotBefore         int64                                `json:"not_before"`
	Deadline          int64                                `json:"deadline"`
}

// TrustedKey is an independently provisioned public identity. The witness
// cannot supply its own key or authorize its own reviewer/collector role.
type TrustedKey struct {
	ID        string                            `json:"id"`
	PublicKey string                            `json:"public_key"` // exactly 32-byte Ed25519, lowercase hex
	Role      string                            `json:"role"`
	Kinds     []stablecampaign.ClaimWitnessKind `json:"kinds"`
}

type TrustPolicy struct {
	Keys []TrustedKey `json:"keys"`
}

type EvidenceBinding struct {
	Name      string        `json:"name"`
	Digest    bundle.Digest `json:"digest"`
	SizeBytes uint64        `json:"size_bytes"`
}

// WitnessStatement is testimony by a collector and an independent reviewer
// about one specific requirement. Supporting bytes are mandatory and hashed;
// a signature over a generic pass flag is never sufficient. The reviewer
// must inspect the stated requirement's semantics, including authentic
// authority transcripts, exact replay rejection, and physical provenance.
type WitnessStatement struct {
	SchemaVersion string                          `json:"schema_version"`
	Session       Session                         `json:"session"`
	ResultDigest  bundle.Digest                   `json:"result_digest"`
	Kind          stablecampaign.ClaimWitnessKind `json:"kind"`
	Conclusion    string                          `json:"conclusion"`
	CollectedAt   int64                           `json:"collected_at"`
	ReviewedAt    int64                           `json:"reviewed_at"`
	Evidence      []EvidenceBinding               `json:"evidence"`
}

type WitnessSignature struct {
	KeyID     string `json:"key_id"`
	Role      string `json:"role"`
	Signature string `json:"signature"` // 64-byte Ed25519, lowercase hex
}

type SignedWitness struct {
	Statement  WitnessStatement   `json:"statement"`
	Signatures []WitnessSignature `json:"signatures"`
}

type WitnessRequirement struct {
	Kind    stablecampaign.ClaimWitnessKind `json:"kind"`
	Sources []string                        `json:"sources"`
}

// Requirements returns the exact collector/reviewer checklist for this run.
func (expectation Expectation) Requirements() ([]WitnessRequirement, error) {
	if expectation.value.ExpectationDigest == "" {
		return nil, errors.New("uninitialized qualification expectation")
	}
	claims, err := stablecampaign.RequiredClaimWitnesses(expectation.plan, expectation.value.RunIndex)
	if err != nil {
		return nil, err
	}
	seen := map[stablecampaign.ClaimWitnessKind]bool{}
	result := []WitnessRequirement{}
	for _, claim := range claims {
		for _, kind := range claim.Kinds {
			if !seen[kind] {
				result = append(result, WitnessRequirement{Kind: kind, Sources: slices.Clone(witnessSources[kind])})
				seen[kind] = true
			}
		}
	}
	return result, nil
}

// SigningBytes exposes only a public, role-domain-separated preimage. Private
// signing and live-token use remain external to this library and command.
func (statement WitnessStatement) SigningBytes(role string) ([]byte, error) {
	if role != CollectorRole && role != ReviewerRole {
		return nil, errors.New("unsupported witness signing role")
	}
	encoded, err := json.Marshal(statement)
	if err != nil || len(encoded) > MaximumWitnessBytes {
		return nil, errors.New("invalid or oversized witness statement")
	}
	return append([]byte("kaiba.provisioning.rpi5-campaign-reviewed-witness.v1alpha1\x00"+role+"\x00"), encoded...), nil
}

func (witness SignedWitness) CanonicalJSON() ([]byte, error) {
	encoded, err := json.Marshal(witness)
	if err != nil || len(encoded) > MaximumWitnessBytes {
		return nil, errors.New("invalid or oversized signed witness")
	}
	return encoded, nil
}

func ParseWitness(encoded []byte) (SignedWitness, error) {
	var witness SignedWitness
	if err := DecodeCanonical(encoded, &witness, MaximumWitnessBytes); err != nil {
		return SignedWitness{}, err
	}
	return witness, nil
}

// DecodeCanonical rejects unknown fields, duplicate keys, alternate ordering,
// trailing data, and whitespace through exact reencoding. Required nonempty
// fields and collections are checked by the corresponding semantic validator.
func DecodeCanonical(encoded []byte, destination any, maximum int) error {
	if len(encoded) == 0 || len(encoded) > maximum {
		return errors.New("invalid JSON size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	expected, err := json.Marshal(destination)
	if err != nil {
		return err
	}
	if !bytes.Equal(bytes.TrimSuffix(encoded, []byte{'\n'}), expected) {
		return errors.New("JSON is not canonical")
	}
	return nil
}

// Admission must durably consume the preselected capture nonce at most once.
// It is called only after all semantic and signature checks succeed. Failure
// after a reservation is uncertain; it must not reopen the nonce for retry.
type Admission interface {
	Consume(Session, bundle.Digest) error
}

type reportRecord struct {
	SchemaVersion            string                        `json:"schema_version"`
	Assurance                string                        `json:"assurance"`
	Session                  Session                       `json:"session"`
	ResultDigest             bundle.Digest                 `json:"result_digest"`
	ArtifactSetContentDigest bundle.Digest                 `json:"artifact_set_content_digest"`
	LayoutDigest             bundle.Digest                 `json:"layout_digest"`
	TrustPolicyDigest        bundle.Digest                 `json:"trust_policy_digest"`
	ReviewedClaims           []stablecampaign.PlannedClaim `json:"reviewed_claims"`
	WitnessDigests           []bundle.Digest               `json:"witness_digests"`
	ProductionReady          bool                          `json:"production_ready"`
	EnrollmentReady          bool                          `json:"enrollment_ready"`
	ReportDigest             bundle.Digest                 `json:"report_digest,omitempty"`
}

// Report is accepted independent-review testimony, not hardware attestation
// or authority to set security_applied. Its value cannot be caller-authored.
type Report struct{ value reportRecord }

func (report Report) CanonicalJSON() ([]byte, error) {
	if report.value.ReportDigest == "" {
		return nil, errors.New("uninitialized reviewed acceptance report")
	}
	return json.Marshal(report.value)
}

// Validate requires an independently prepared expectation, the admission
// authority's preselected session/trust/time, full raw captures, and signed
// supporting witnesses. Legacy consistency reports are recomputed, never
// accepted as a prevalidated input. It admits a run only with exact coverage.
func Validate(expectation Expectation, session Session, now int64, policy TrustPolicy,
	result stablecampaign.ExecutionResult, raw map[stablecampaign.RawRole][]byte,
	witnesses []SignedWitness, supporting map[string][]byte, admission Admission) (Report, error) {
	if expectation.value.ExpectationDigest == "" || admission == nil {
		return Report{}, errors.New("sealed expectation and durable admission are required")
	}
	v := expectation.value
	context, err := stablecampaign.NewEvidenceRecordContext(expectation.plan, v.RunIndex, session.Context.CaptureID)
	if err != nil {
		return Report{}, err
	}
	if session.Context != context || session.DeviceFingerprint != v.DeviceFingerprint || session.ProfileDigest != v.ProfileDigest || session.ExpectationDigest != v.ExpectationDigest ||
		session.NotBefore <= 0 || session.Deadline <= session.NotBefore || now < session.NotBefore || now > session.Deadline {
		return Report{}, errors.New("wrong or expired independently selected qualification session")
	}
	if result.CaptureID != context.CaptureID {
		return Report{}, errors.New("execution capture differs from the preselected session")
	}
	// Own all bounded evidence before validating so mutable caller slices cannot
	// change what signatures authenticate after consistency checks.
	owned := make(map[stablecampaign.RawRole][]byte, len(raw))
	for role, encoded := range raw {
		maximum := stablecampaign.MaximumAuxiliaryEvidenceBytes
		if role == stablecampaign.RawRoleUARTCapture {
			maximum = stablecampaign.MaximumUARTCaptureBytes
		}
		if len(encoded) > maximum {
			return Report{}, errors.New("oversized raw evidence")
		}
		owned[role] = bytes.Clone(encoded)
	}
	declared := stablecampaign.DeclaredEvidenceContext{CampaignID: v.CampaignID, PlanDigest: v.PlanDigest, RunIndex: v.RunIndex, RunID: v.RunID,
		ArtifactSetContentDigest: v.ArtifactSetContentDigest, MediaPartitions: slices.Clone(v.MediaPartitions)}
	if _, err := result.CheckEvidenceConsistency(expectation.plan, owned, declared); err != nil {
		return Report{}, fmt.Errorf("complete raw evidence: %w", err)
	}
	for _, ref := range result.RecordRefs {
		if ref.Kind != stablecampaign.RecordKindVerifierEvent {
			continue
		}
		record, err := verifierevents.Parse(owned[ref.RawRole][ref.OffsetBytes : ref.OffsetBytes+ref.SizeBytes])
		if err != nil {
			return Report{}, err
		}
		if record.PolicyDigest != "" && (record.PolicyDigest != v.PolicyDigest || record.ManifestDigest != v.ManifestDigest) {
			return Report{}, errors.New("verifier release digests differ from independently resolved public bytes")
		}
	}
	keys, err := validateTrust(policy)
	if err != nil {
		return Report{}, err
	}
	requirements, err := stablecampaign.RequiredClaimWitnesses(expectation.plan, v.RunIndex)
	if err != nil {
		return Report{}, err
	}
	kinds := []stablecampaign.ClaimWitnessKind{}
	for _, requirement := range requirements {
		for _, kind := range requirement.Kinds {
			if !slices.Contains(kinds, kind) {
				kinds = append(kinds, kind)
			}
		}
	}
	if len(witnesses) != len(kinds) {
		return Report{}, fmt.Errorf("exactly %d required witnesses must be supplied", len(kinds))
	}
	if len(supporting) > 128 {
		return Report{}, errors.New("too many supporting evidence objects")
	}
	files := make(map[string][]byte, len(supporting)+len(owned)+1)
	for name, encoded := range supporting {
		if name == "expectation" || rawName(name) || len(encoded) == 0 || len(encoded) > stablecampaign.MaximumAuxiliaryEvidenceBytes {
			return Report{}, errors.New("invalid supporting evidence name or size")
		}
		files[name] = bytes.Clone(encoded)
	}
	for role, encoded := range owned {
		files[string(role)] = encoded
	}
	files["expectation"], _ = expectation.CanonicalJSON()
	used := make(map[string]bool)
	trustBytes, err := json.Marshal(policy)
	if err != nil {
		return Report{}, err
	}
	record := reportRecord{SchemaVersion: ReportSchema, Assurance: "authenticated-independent-review-testimony", Session: session, ResultDigest: result.ResultDigest,
		ArtifactSetContentDigest: v.ArtifactSetContentDigest, LayoutDigest: v.LayoutDigest,
		TrustPolicyDigest: domainDigest("kaiba.provisioning.rpi5-campaign-witness-trust-policy.v1alpha1", trustBytes)}
	for index, kind := range kinds {
		witness := witnesses[index]
		statement := witness.Statement
		if statement.SchemaVersion != WitnessSchema || statement.Session != session || statement.ResultDigest != result.ResultDigest || statement.Kind != kind || statement.Conclusion != ReviewedSatisfied ||
			statement.CollectedAt < session.NotBefore || statement.ReviewedAt < statement.CollectedAt || statement.ReviewedAt > now || statement.ReviewedAt > session.Deadline {
			return Report{}, fmt.Errorf("witness %d is missing, stale, reordered, or detached", index)
		}
		if err := verifySignatures(witness, keys); err != nil {
			return Report{}, fmt.Errorf("witness %s: %w", kind, err)
		}
		if len(statement.Evidence) == 0 || len(statement.Evidence) > 16 {
			return Report{}, errors.New("witness requires bounded supporting evidence")
		}
		seen := map[string]bool{}
		for _, binding := range statement.Evidence {
			encoded, ok := files[binding.Name]
			if !ok || seen[binding.Name] || uint64(len(encoded)) != binding.SizeBytes || bundle.Sum(encoded) != binding.Digest {
				return Report{}, fmt.Errorf("witness %s has missing, duplicate, altered, or truncated supporting bytes", kind)
			}
			seen[binding.Name], used[binding.Name] = true, true
		}
		if err := checkWitnessSources(kind, seen, files, v); err != nil {
			return Report{}, err
		}
		encoded, _ := witness.CanonicalJSON()
		record.WitnessDigests = append(record.WitnessDigests, domainDigest("kaiba.provisioning.rpi5-campaign-reviewed-witness-envelope.v1alpha1", encoded))
	}
	for name := range supporting {
		if !used[name] {
			return Report{}, fmt.Errorf("unbound supporting evidence %q", name)
		}
	}
	for _, requirement := range requirements {
		record.ReviewedClaims = append(record.ReviewedClaims, requirement.Claim)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return Report{}, err
	}
	record.ReportDigest = domainDigest("kaiba.provisioning.rpi5-campaign-reviewed-acceptance.v1alpha1", encoded)
	if err := admission.Consume(session, result.ResultDigest); err != nil {
		return Report{}, fmt.Errorf("durable capture admission: %w", err)
	}
	return Report{value: record}, nil
}

func validateTrust(policy TrustPolicy) (map[string]TrustedKey, error) {
	if len(policy.Keys) < 2 || len(policy.Keys) > 64 {
		return nil, errors.New("independent collector and reviewer trust keys are required")
	}
	keys := map[string]TrustedKey{}
	publicKeys := map[string]bool{}
	for _, key := range policy.Keys {
		public, err := hex.DecodeString(key.PublicKey)
		if key.ID == "" || keys[key.ID].ID != "" || publicKeys[key.PublicKey] || err != nil || len(public) != ed25519.PublicKeySize || hex.EncodeToString(public) != key.PublicKey ||
			(key.Role != CollectorRole && key.Role != ReviewerRole) || len(key.Kinds) == 0 {
			return nil, errors.New("invalid, duplicated, or role-reused trust key")
		}
		keys[key.ID], publicKeys[key.PublicKey] = key, true
	}
	return keys, nil
}

func verifySignatures(witness SignedWitness, keys map[string]TrustedKey) error {
	if len(witness.Signatures) != 2 {
		return errors.New("collector and independent reviewer signatures are both required")
	}
	for index, role := range []string{CollectorRole, ReviewerRole} {
		signature := witness.Signatures[index]
		key, ok := keys[signature.KeyID]
		if !ok || key.Role != role || signature.Role != role || !slices.Contains(key.Kinds, witness.Statement.Kind) {
			return errors.New("untrusted identity, role, or witness capability")
		}
		public, _ := hex.DecodeString(key.PublicKey)
		value, err := hex.DecodeString(signature.Signature)
		preimage, preimageErr := witness.Statement.SigningBytes(role)
		if err != nil || preimageErr != nil || len(value) != ed25519.SignatureSize || hex.EncodeToString(value) != signature.Signature || !ed25519.Verify(public, preimage, value) {
			return errors.New("invalid witness signature")
		}
	}
	return nil
}

func rawName(name string) bool {
	return name == "uart-capture" || name == "media-readback" || name == "authority-audit" || name == "power-observation"
}

// Fixed source roles ensure that unrelated signed documents cannot stand in
// for physical captures, replay transcripts, or the exact observed values.
// Source authenticity and physical truth remain the trusted signers' claim.
func checkWitnessSources(kind stablecampaign.ClaimWitnessKind, seen map[string]bool, files map[string][]byte, expected expectationRecord) error {

	required, ok := witnessSources[kind]
	if !ok {
		return errors.New("unsupported witness kind")
	}
	for _, name := range required {
		if !seen[name] {
			return fmt.Errorf("witness %s must bind %s", kind, name)
		}
	}
	for _, name := range []string{"expected-command-line", "observed-command-line"} {
		if seen[name] {
			line, err := rpi5kexecinput.ParseCommandLineFile(files[name])
			if err != nil || line != expected.KernelCommandLine {
				return errors.New("command-line witness differs from independently resolved bytes")
			}
		}
	}
	pairs := [][2]string{{"one-boot-proof", "one-boot-replay"}, {"bootstrap-request", "bootstrap-replay"}, {"pre-handoff-fdt", "post-handoff-fdt"}, {"prior-authorization", "replayed-authorization"}}
	for _, pair := range pairs {
		if seen[pair[0]] && seen[pair[1]] && !bytes.Equal(files[pair[0]], files[pair[1]]) {
			return fmt.Errorf("%s witness did not preserve exact bytes", pair[1])
		}
	}
	return nil
}

var witnessSources = map[stablecampaign.ClaimWitnessKind][]string{
	stablecampaign.WitnessIndependentlyResolvedRunArtifacts:   {"expectation", "artifact-review"},
	stablecampaign.WitnessExactRunMediaReadback:               {"media-readback"},
	stablecampaign.WitnessProvenancedColdPowerObservation:     {"power-observation"},
	stablecampaign.WitnessAuthenticatedCompleteVerifierTrace:  {"uart-capture"},
	stablecampaign.WitnessAuthorityAuthorizationTranscript:    {"authority-audit", "authorization-transcript"},
	stablecampaign.WitnessReleasedOSTerminalEvent:             {"uart-capture"},
	stablecampaign.WitnessExpectedKernelCommandLine:           {"expected-command-line"},
	stablecampaign.WitnessObservedKernelCommandLine:           {"observed-command-line", "uart-capture"},
	stablecampaign.WitnessSignedAuthorizationAndOneBootProof:  {"authorization-transcript", "one-boot-proof"},
	stablecampaign.WitnessOneBootProofAcceptedOnce:            {"one-boot-proof", "one-boot-acceptance"},
	stablecampaign.WitnessIdenticalOneBootProofReplayRejected: {"one-boot-proof", "one-boot-replay", "one-boot-rejection"},
	stablecampaign.WitnessExactBootstrapSignedRequestReplay:   {"bootstrap-request", "bootstrap-replay"},
	stablecampaign.WitnessBootstrapChallengeReplayRejected:    {"bootstrap-replay", "bootstrap-rejection"},
	stablecampaign.WitnessPreHandoffLiveFDTProjection:         {"pre-handoff-fdt"},
	stablecampaign.WitnessPostHandoffLiveFDTProjection:        {"pre-handoff-fdt", "post-handoff-fdt"},
	stablecampaign.WitnessRootSignedLiveFDTMarker:             {"root-signed-fdt-marker", "artifact-review"},
	stablecampaign.WitnessAuthorityUnavailable:                {"authority-audit"},
	stablecampaign.WitnessAuthorizationOfflineRejection:       {"uart-capture", "power-observation"},
	stablecampaign.WitnessExactPriorAuthorizationTranscript:   {"prior-authorization", "replayed-authorization"},
	stablecampaign.WitnessAuthorizationReplayRejected:         {"replayed-authorization", "uart-capture"},
	stablecampaign.WitnessReleaseVerificationRejected:         {"uart-capture"},
	stablecampaign.WitnessRuntimeDMVerityRejected:             {"uart-capture"},
}
