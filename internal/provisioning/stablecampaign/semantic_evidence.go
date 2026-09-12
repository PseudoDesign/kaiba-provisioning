package stablecampaign

import (
	"errors"
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/verifierevents"
)

// DeclaredEvidenceContext is a path-free set of caller-declared comparison
// values for one run. This type is deliberately not called an expectation: it
// is freely constructible, is not sealed, and does not prove that its values
// were independently derived from a reviewed artifact set or mutation recipe.
// CheckEvidenceConsistency can establish only that the supplied records agree
// with this declaration and each other.
type DeclaredEvidenceContext struct {
	CampaignID               string                  `json:"campaign_id"`
	PlanDigest               bundle.Digest           `json:"plan_digest"`
	RunIndex                 uint16                  `json:"run_index"`
	RunID                    string                  `json:"run_id"`
	ArtifactSetContentDigest bundle.Digest           `json:"artifact_set_content_digest"`
	MediaPartitions          []MediaPartitionBinding `json:"media_partitions"`
}

// CheckAgainst checks the declaration's shape and run binding. A nil error is
// not evidence that the declaration has independent or trusted provenance.
func (declared DeclaredEvidenceContext) CheckAgainst(plan Plan, result ExecutionResult) error {
	return declared.checkAgainst(plan, result)
}

func (declared DeclaredEvidenceContext) checkAgainst(plan Plan, result ExecutionResult) error {
	if err := result.ValidateAgainst(plan); err != nil {
		return fmt.Errorf("declared evidence context execution result: %w", err)
	}
	if declared.CampaignID != plan.CampaignID || declared.PlanDigest != plan.PlanDigest ||
		declared.RunIndex != result.RunIndex || declared.RunID != result.RunID {
		return errors.New("declared evidence context is detached from the campaign plan or execution run")
	}
	if err := declared.ArtifactSetContentDigest.Validate(); err != nil {
		return fmt.Errorf("declared evidence context artifact_set_content_digest: %w", err)
	}
	if err := validateMediaPartitionBindings(declared.MediaPartitions); err != nil {
		return fmt.Errorf("declared evidence context: %w", err)
	}
	return nil
}

// EvidenceConsistencyAssurance states the intentionally narrow meaning of a
// successful CheckEvidenceConsistency call.
type EvidenceConsistencyAssurance string

const (
	// EvidenceConsistencyUnauthenticatedRecords means strict parsing, digest
	// binding, and cross-record agreement only. It does not close a planned
	// claim or establish physical identity, collection provenance, or freshness.
	EvidenceConsistencyUnauthenticatedRecords EvidenceConsistencyAssurance = "unauthenticated-record-consistency-only"
)

// EvidenceConsistencyReport reports strict parsing and cross-record
// consistency only. It deliberately has no claim result, pass, outcome, or
// disposition field.
type EvidenceConsistencyReport struct {
	Assurance                  EvidenceConsistencyAssurance `json:"assurance"`
	Context                    EvidenceRecordContext        `json:"context"`
	Mechanical                 RawEvidenceValidation        `json:"mechanical"`
	ParsedRecordCount          int                          `json:"parsed_record_count"`
	MediaReadbackConsistent    bool                         `json:"media_readback_consistent"`
	ReleasedOSEventConsistent  bool                         `json:"released_os_event_consistent"`
	AuthorityAuditConsistent   bool                         `json:"authority_audit_consistent"`
	PowerObservationConsistent bool                         `json:"power_observation_consistent"`
}

// ErrClaimClosureUnavailable is returned because the current evidence
// contract lacks claim-specific authenticated witnesses and independently
// derived sealed expectations.
var ErrClaimClosureUnavailable = errors.New("planned claim closure is unavailable")

type parsedSemanticRecords struct {
	media     *MediaReadbackRecord
	released  *ReleasedOSEventRecord
	authority *AuthorityAuditRecord
	power     *PowerObservationRecord
	verifier  []verifierevents.Record
}

type verifierPublicDetails struct {
	policyDigest       bundle.Digest
	manifestDigest     bundle.Digest
	bootstrapPublicKey string
	oneBootPublicKey   string
}

// CheckEvidenceConsistency snapshots the bounded supplied slices, preserves
// the complete mechanical validation performed by ValidateRawEvidence, then
// strictly parses every auxiliary record, verifies its domain digest and
// result context, cross-checks shared public details, and checks agreement with
// the run plan and caller-declared context. A nil error means consistency only;
// the current public collectors are unauthenticated and the declared context
// has no independently sealed provenance. There is no writer, device, signing,
// private-material, authorization, or API that can assert claim closure here.
func (result ExecutionResult) CheckEvidenceConsistency(
	plan Plan,
	supplied map[RawRole][]byte,
	declared DeclaredEvidenceContext,
) (EvidenceConsistencyReport, error) {
	var report EvidenceConsistencyReport
	snapshot, err := snapshotSuppliedEvidence(result, plan, supplied)
	if err != nil {
		return report, err
	}
	mechanical, err := result.ValidateRawEvidence(plan, snapshot)
	if err != nil {
		return report, err
	}
	report.Assurance = EvidenceConsistencyUnauthenticatedRecords
	report.Mechanical = mechanical
	if err := declared.checkAgainst(plan, result); err != nil {
		return report, err
	}
	if err := verifyCompleteUARTVerifierEventCapture(snapshot[RawRoleUARTCapture], result.RecordRefs); err != nil {
		return report, fmt.Errorf("verify complete UART verifier-event capture: %w", err)
	}

	runs, err := ExpectedRuns(plan)
	if err != nil {
		return report, err
	}
	spec := runs[result.RunIndex-1]
	expectedContext := EvidenceRecordContext{
		CampaignID: plan.CampaignID,
		PlanDigest: plan.PlanDigest,
		RunIndex:   result.RunIndex,
		RunID:      result.RunID,
		CaptureID:  result.CaptureID,
	}
	report.Context = expectedContext

	records, err := parseSemanticRecords(result, snapshot, expectedContext)
	if err != nil {
		return report, err
	}
	if err := VerifyVerifierEventTrace(plan, result.RunIndex, records.verifier); err != nil {
		return report, err
	}
	details, err := collectVerifierPublicDetails(records.verifier)
	if err != nil {
		return report, err
	}

	if records.media == nil {
		return report, errors.New("semantic evidence is missing the required media-readback record")
	}
	if records.media.ArtifactSetContentDigest != declared.ArtifactSetContentDigest ||
		!equalMediaPartitionBindings(records.media.Partitions, declared.MediaPartitions) {
		return report, errors.New("media-readback record differs from the caller-declared run context")
	}
	report.MediaReadbackConsistent = true

	if records.power == nil {
		return report, errors.New("semantic evidence is missing the required cold-power observation")
	}
	report.PowerObservationConsistent = true

	expectedAuthority, authorityRequired, err := authorityEventForRun(spec)
	if err != nil {
		return report, err
	}
	if authorityRequired {
		if records.authority == nil {
			return report, errors.New("semantic evidence is missing the required authority-audit record")
		}
		if records.authority.Event != expectedAuthority {
			return report, fmt.Errorf("authority-audit event is %q, want %q", records.authority.Event, expectedAuthority)
		}
		if err := compareAuthorityDetails(*records.authority, details); err != nil {
			return report, err
		}
		report.AuthorityAuditConsistent = true
	} else if records.authority != nil {
		return report, errors.New("release-rejection run must not contain an authority-audit record")
	}

	expectedReleased, releasedRequired, err := releasedOSEventForRun(spec)
	if err != nil {
		return report, err
	}
	if releasedRequired {
		if records.released == nil {
			return report, errors.New("semantic evidence is missing the required released-OS event")
		}
		if records.released.Event != expectedReleased {
			return report, fmt.Errorf("released-OS event is %q, want %q", records.released.Event, expectedReleased)
		}
		if err := compareReleasedOSDetails(*records.released, details); err != nil {
			return report, err
		}
		report.ReleasedOSEventConsistent = true
	} else if records.released != nil {
		return report, errors.New("verifier-rejection run must not contain a released-OS event")
	}

	report.ParsedRecordCount = 2
	if report.AuthorityAuditConsistent {
		report.ParsedRecordCount++
	}
	if report.ReleasedOSEventConsistent {
		report.ParsedRecordCount++
	}
	return report, nil
}

// RequirePlannedClaimClosure is an explicit fail-closed boundary. It can never
// return nil with the current v1alpha2 execution contract because that contract
// has neither claim-specific authenticated witnesses nor independently derived
// sealed expectations. A future implementation must introduce and verify both
// before this method can produce a successful closure result.
func (result ExecutionResult) RequirePlannedClaimClosure(
	plan Plan,
	report EvidenceConsistencyReport,
) error {
	if err := result.ValidateAgainst(plan); err != nil {
		return fmt.Errorf("require planned claim closure: %w", err)
	}
	expectedContext := EvidenceRecordContext{
		CampaignID: plan.CampaignID,
		PlanDigest: plan.PlanDigest,
		RunIndex:   result.RunIndex,
		RunID:      result.RunID,
		CaptureID:  result.CaptureID,
	}
	if report.Assurance != EvidenceConsistencyUnauthenticatedRecords || report.Context != expectedContext {
		return errors.New("require planned claim closure: consistency report is detached from the execution result")
	}
	return fmt.Errorf(
		"%w: %d planned claims still require claim-specific authenticated witnesses and independently derived sealed expectations",
		ErrClaimClosureUnavailable,
		len(result.PlannedClaims),
	)
}

func snapshotSuppliedEvidence(
	result ExecutionResult,
	plan Plan,
	supplied map[RawRole][]byte,
) (map[RawRole][]byte, error) {
	if err := result.ValidateAgainst(plan); err != nil {
		return nil, fmt.Errorf("snapshot evidence envelope: %w", err)
	}
	if len(supplied) != len(result.RawFiles) {
		return nil, fmt.Errorf("supplied raw evidence must contain the exact %d bound roles", len(result.RawFiles))
	}
	snapshot := make(map[RawRole][]byte, len(result.RawFiles))
	for _, binding := range result.RawFiles {
		encoded, ok := supplied[binding.Role]
		if !ok {
			return nil, fmt.Errorf("supplied raw evidence is missing role %q", binding.Role)
		}
		if uint64(len(encoded)) != binding.SizeBytes {
			return nil, fmt.Errorf("supplied raw evidence role %q size differs from its bound size", binding.Role)
		}
		snapshot[binding.Role] = append([]byte(nil), encoded...)
	}
	return snapshot, nil
}

func parseSemanticRecords(
	result ExecutionResult,
	supplied map[RawRole][]byte,
	expectedContext EvidenceRecordContext,
) (parsedSemanticRecords, error) {
	parsed := parsedSemanticRecords{verifier: make([]verifierevents.Record, 0)}
	for index, reference := range result.RecordRefs {
		raw := supplied[reference.RawRole]
		end := reference.OffsetBytes + reference.SizeBytes
		rangeBytes := raw[int(reference.OffsetBytes):int(end)]
		switch reference.Kind {
		case RecordKindVerifierEvent:
			record, err := verifierevents.Parse(rangeBytes)
			if err != nil {
				return parsedSemanticRecords{}, fmt.Errorf("record_refs[%d] verifier event: %w", index, err)
			}
			parsed.verifier = append(parsed.verifier, record)
		case RecordKindMediaReadback:
			record, err := ParseMediaReadbackRecord(rangeBytes)
			if err != nil {
				return parsedSemanticRecords{}, fmt.Errorf("record_refs[%d]: %w", index, err)
			}
			if parsed.media != nil {
				return parsedSemanticRecords{}, errors.New("semantic evidence contains duplicate media-readback records")
			}
			if err := verifySemanticRecord(reference, record.Context, expectedContext, record.Digest); err != nil {
				return parsedSemanticRecords{}, fmt.Errorf("record_refs[%d] media-readback: %w", index, err)
			}
			parsed.media = &record
		case RecordKindReleasedOSEvent:
			record, err := ParseReleasedOSEventRecord(rangeBytes)
			if err != nil {
				return parsedSemanticRecords{}, fmt.Errorf("record_refs[%d]: %w", index, err)
			}
			if parsed.released != nil {
				return parsedSemanticRecords{}, errors.New("semantic evidence contains duplicate released-OS events")
			}
			if err := verifySemanticRecord(reference, record.Context, expectedContext, record.Digest); err != nil {
				return parsedSemanticRecords{}, fmt.Errorf("record_refs[%d] released-OS event: %w", index, err)
			}
			parsed.released = &record
		case RecordKindAuthorityAudit:
			record, err := ParseAuthorityAuditRecord(rangeBytes)
			if err != nil {
				return parsedSemanticRecords{}, fmt.Errorf("record_refs[%d]: %w", index, err)
			}
			if parsed.authority != nil {
				return parsedSemanticRecords{}, errors.New("semantic evidence contains duplicate authority-audit records")
			}
			if err := verifySemanticRecord(reference, record.Context, expectedContext, record.Digest); err != nil {
				return parsedSemanticRecords{}, fmt.Errorf("record_refs[%d] authority-audit: %w", index, err)
			}
			parsed.authority = &record
		case RecordKindPowerObservation:
			record, err := ParsePowerObservationRecord(rangeBytes)
			if err != nil {
				return parsedSemanticRecords{}, fmt.Errorf("record_refs[%d]: %w", index, err)
			}
			if parsed.power != nil {
				return parsedSemanticRecords{}, errors.New("semantic evidence contains duplicate power-observation records")
			}
			if err := verifySemanticRecord(reference, record.Context, expectedContext, record.Digest); err != nil {
				return parsedSemanticRecords{}, fmt.Errorf("record_refs[%d] power observation: %w", index, err)
			}
			parsed.power = &record
		default:
			return parsedSemanticRecords{}, fmt.Errorf("record_refs[%d] has unsupported record kind %q", index, reference.Kind)
		}
	}
	return parsed, nil
}

func verifySemanticRecord(
	reference RecordRef,
	actualContext, expectedContext EvidenceRecordContext,
	digest func() (bundle.Digest, error),
) error {
	if actualContext != expectedContext {
		return errors.New("record context differs from the sealed campaign, run, or capture")
	}
	derived, err := digest()
	if err != nil {
		return err
	}
	if derived != reference.RecordDigest {
		return errors.New("record_digest does not match the semantic record domain")
	}
	return nil
}

func collectVerifierPublicDetails(records []verifierevents.Record) (verifierPublicDetails, error) {
	var result verifierPublicDetails
	for _, record := range records {
		if record.PolicyDigest != "" {
			if result.policyDigest != "" && result.policyDigest != record.PolicyDigest {
				return verifierPublicDetails{}, errors.New("verifier policy digest changed within the trace")
			}
			result.policyDigest = record.PolicyDigest
		}
		if record.ManifestDigest != "" {
			if result.manifestDigest != "" && result.manifestDigest != record.ManifestDigest {
				return verifierPublicDetails{}, errors.New("verifier manifest digest changed within the trace")
			}
			result.manifestDigest = record.ManifestDigest
		}
		if record.BootstrapPublicKey != "" {
			if result.bootstrapPublicKey != "" && result.bootstrapPublicKey != record.BootstrapPublicKey {
				return verifierPublicDetails{}, errors.New("verifier bootstrap public key changed within the trace")
			}
			result.bootstrapPublicKey = record.BootstrapPublicKey
		}
		if record.OneBootPublicKey != "" {
			if result.oneBootPublicKey != "" && result.oneBootPublicKey != record.OneBootPublicKey {
				return verifierPublicDetails{}, errors.New("verifier one-boot public key changed within the trace")
			}
			result.oneBootPublicKey = record.OneBootPublicKey
		}
	}
	if result.bootstrapPublicKey != "" && result.oneBootPublicKey != "" &&
		result.bootstrapPublicKey == result.oneBootPublicKey {
		return verifierPublicDetails{}, errors.New("verifier trace reused the bootstrap public key as the one-boot public key")
	}
	return result, nil
}

func compareAuthorityDetails(record AuthorityAuditRecord, details verifierPublicDetails) error {
	if record.PolicyDigest != details.policyDigest || record.ManifestDigest != details.manifestDigest ||
		record.BootstrapPublicKey != details.bootstrapPublicKey {
		return errors.New("authority-audit release digest or bootstrap public key differs from the verifier trace")
	}
	if record.Event == AuthorityEventAuthorizationIssued {
		if record.OneBootPublicKey != details.oneBootPublicKey {
			return errors.New("authority-audit one-boot public key differs from the verifier trace")
		}
	} else if details.oneBootPublicKey != "" {
		return errors.New("rejected authorization trace unexpectedly introduced a one-boot public key")
	}
	return nil
}

func compareReleasedOSDetails(record ReleasedOSEventRecord, details verifierPublicDetails) error {
	if record.PolicyDigest != details.policyDigest || record.ManifestDigest != details.manifestDigest ||
		record.BootstrapPublicKey != details.bootstrapPublicKey || record.OneBootPublicKey != details.oneBootPublicKey {
		return errors.New("released-OS digests or public keys differ from the verifier trace")
	}
	return nil
}

func authorityEventForRun(spec RunSpec) (string, bool, error) {
	switch spec.VerifierTerminal.FailureCode {
	case "release-verification-failed":
		return "", false, nil
	case "challenge-request-failed":
		return AuthorityEventOffline, true, nil
	case "authorization-verification-failed":
		return AuthorityEventAuthorizationRejected, true, nil
	case "":
		return AuthorityEventAuthorizationIssued, true, nil
	default:
		return "", false, fmt.Errorf("run %q has unsupported authority semantics", spec.RunID)
	}
}

func releasedOSEventForRun(spec RunSpec) (string, bool, error) {
	switch spec.ExpectedDisposition {
	case DispositionVerifierRejected:
		return "", false, nil
	case DispositionReleasedOSBooted:
		return ReleasedOSEventReady, true, nil
	case DispositionReleasedOSRejected:
		if len(spec.PlannedClaims) != 1 || spec.PlannedClaims[0].TestID != "dm-verity-corruption-rejected" {
			return "", false, fmt.Errorf("run %q has unsupported released-OS rejection semantics", spec.RunID)
		}
		switch spec.PlannedClaims[0].SubcaseID {
		case "root-data":
			return ReleasedOSEventRootDataRejected, true, nil
		case "root-hash":
			return ReleasedOSEventRootHashRejected, true, nil
		default:
			return "", false, fmt.Errorf("run %q has unsupported dm-verity subcase", spec.RunID)
		}
	default:
		return "", false, fmt.Errorf("run %q has unsupported disposition", spec.RunID)
	}
}
