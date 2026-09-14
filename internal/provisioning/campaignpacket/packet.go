// Package campaignpacket checks the public preparation inputs for the first
// two stable-verifier campaign runs. It reads caller-owned public byte sources;
// it has no file-opening, device, signing, execution, or claim-closure API.
package campaignpacket

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

const SchemaVersion = "kaiba.provisioning.rpi5-stable-verifier-preparation-packet/v1alpha1"
const digestDomain = "kaiba.provisioning.rpi5-stable-verifier-preparation-packet.v1alpha1"

var revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Input requires independently parsed contracts and independently measured
// public sources. The caller owns all ReaderAt values and must keep their bytes
// unchanged until Prepare returns. SourceRevision is a caller assertion; these
// contracts cannot establish the reviewed Git revision or its CI status.
type Input struct {
	SourceRevision   string
	Plan             stablecampaign.Plan
	ArtifactSet      campaignmedia.ArtifactSet
	Materializations []campaignmedia.RunArtifactMaterialization
	StagingPlan      campaignmedia.StagingPlan
	Requirements     campaignmedia.RecoveryBackupRequirementsV1Alpha2
	Envelopes        []campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2
	PublicSources    stablecampaign.PublicArtifactSources
	Payloads         map[campaignmedia.PartitionRole]stablecampaign.PublicArtifactSource
}

type witnessRequirement struct {
	Claim                           stablecampaign.PlannedClaim       `json:"claim"`
	RequiredKinds                   []stablecampaign.ClaimWitnessKind `json:"required_kinds"`
	AuthenticatedWitnessesCollected bool                              `json:"authenticated_witnesses_collected"`
	ClaimClosed                     bool                              `json:"claim_closed"`
}

type traceEvent struct {
	Event       string                             `json:"event"`
	FailureCode string                             `json:"failure_code,omitempty"`
	DetailStage stablecampaign.VerifierDetailStage `json:"detail_stage"`
}

type runPreparation struct {
	RunIndex              uint16                                     `json:"run_index"`
	RunID                 string                                     `json:"run_id"`
	MaterializationDigest bundle.Digest                              `json:"materialization_digest"`
	ExpectedDisposition   stablecampaign.Disposition                 `json:"expected_disposition"`
	VerifierTerminal      stablecampaign.VerifierTerminalExpectation `json:"verifier_terminal"`
	VerifierTrace         []traceEvent                               `json:"verifier_trace"`
	RequiredRawRoles      []stablecampaign.RawRole                   `json:"required_raw_roles"`
	RequiredRecordKinds   []stablecampaign.RecordKind                `json:"required_record_kinds"`
	WitnessRequirements   []witnessRequirement                       `json:"witness_requirements"`
	HardwareObserved      bool                                       `json:"hardware_observed"`
}

type partitionBinding struct {
	Leg                          campaignmedia.Leg           `json:"leg"`
	Role                         campaignmedia.PartitionRole `json:"role"`
	OffsetBytes                  uint64                      `json:"offset_bytes"`
	CapacityBytes                uint64                      `json:"capacity_bytes"`
	SourceSizeBytes              uint64                      `json:"source_size_bytes"`
	SourceSHA256                 bundle.Digest               `json:"source_sha256"`
	ZeroTailBytes                uint64                      `json:"zero_tail_bytes"`
	ExpectedWholePartitionSHA256 bundle.Digest               `json:"expected_whole_partition_sha256"`
}

type envelopeBinding struct {
	Leg            campaignmedia.Leg `json:"leg"`
	EnvelopeDigest bundle.Digest     `json:"envelope_digest"`
}

type record struct {
	SchemaVersion                   string                                               `json:"schema_version"`
	Assurance                       string                                               `json:"assurance"`
	AssertedSourceRevision          string                                               `json:"asserted_source_revision"`
	SourceRevisionVerified          bool                                                 `json:"source_revision_verified"`
	CIStatusVerified                bool                                                 `json:"ci_status_verified"`
	CampaignID                      string                                               `json:"campaign_id"`
	PlanDigest                      bundle.Digest                                        `json:"plan_digest"`
	ArtifactSetContentDigest        bundle.Digest                                        `json:"artifact_set_content_digest"`
	StagingPlanDigest               bundle.Digest                                        `json:"staging_plan_digest"`
	RecoveryRequirementsDigest      bundle.Digest                                        `json:"recovery_requirements_digest"`
	InitialEnvelopes                []envelopeBinding                                    `json:"initial_envelopes"`
	PublicInputCount                int                                                  `json:"public_input_count"`
	ByteMutationTargetCount         int                                                  `json:"byte_mutation_target_count"`
	Partitions                      []partitionBinding                                   `json:"partitions"`
	Runs                            []runPreparation                                     `json:"runs"`
	MaximumUARTCaptureBytes         uint64                                               `json:"maximum_uart_capture_bytes"`
	MaximumAuxiliaryEvidenceBytes   uint64                                               `json:"maximum_auxiliary_evidence_bytes"`
	OutstandingRecoveryRequirements []campaignmedia.RecoveryBackupOutstandingRequirement `json:"outstanding_recovery_requirements"`
	OutstandingOperatorRecords      []string                                             `json:"outstanding_operator_records"`
	BackupCapturePerformed          bool                                                 `json:"backup_capture_performed"`
	BackupReadbackVerified          bool                                                 `json:"backup_readback_verified"`
	LiveAttachmentsVerified         bool                                                 `json:"live_attachments_verified"`
	OperatorApprovalBound           bool                                                 `json:"operator_approval_bound"`
	DestructiveStagingReady         bool                                                 `json:"destructive_staging_ready"`
	HardwareObserved                bool                                                 `json:"hardware_observed"`
	ClaimClosureAvailable           bool                                                 `json:"claim_closure_available"`
	SignatureVerificationPerformed  bool                                                 `json:"signature_verification_performed"`
	PacketDigest                    bundle.Digest                                        `json:"packet_digest,omitempty"`
}

// Report is an owned preparation projection, constructed only after the byte
// checks succeed. Its digest binds public declarations, not their provenance.
// It is not accepted as authority by any staging or evidence API.
type Report struct{ value record }

// CanonicalJSON returns compact deterministic JSON without a transport LF.
func (report Report) CanonicalJSON() ([]byte, error) {
	if report.value.SchemaVersion != SchemaVersion || report.value.PacketDigest == "" {
		return nil, errors.New("uninitialized preparation report")
	}
	return json.Marshal(report.value)
}

// Prepare cross-binds the independent contracts, resolves every public input
// and mutation recipe from its bytes, and rehashes the complete source and
// planned zero tail of each partition. Both selected runs must preserve the
// exact baseline payloads. No capture contents or physical bytes are read.
func Prepare(input Input) (Report, error) {
	if !revisionPattern.MatchString(input.SourceRevision) {
		return Report{}, errors.New("source revision must be exactly 40 lowercase hexadecimal characters")
	}
	if err := input.StagingPlan.ValidateAgainst(input.Plan, input.ArtifactSet); err != nil {
		return Report{}, fmt.Errorf("staging inputs: %w", err)
	}
	for _, device := range input.StagingPlan.Devices {
		if _, err := campaignmedia.FinalGPTWrites(device); err != nil {
			return Report{}, fmt.Errorf("final GPT for %s: %w", device.Identity.Leg, err)
		}
	}
	if err := input.Requirements.ValidateAgainst(input.StagingPlan, input.Envelopes); err != nil {
		return Report{}, fmt.Errorf("recovery inputs: %w", err)
	}
	if len(input.Materializations) != 2 || input.Materializations[0].RunIndex != 1 || input.Materializations[1].RunIndex != 2 {
		return Report{}, errors.New("materializations must contain exactly run 1 followed by run 2")
	}
	if len(input.Payloads) != len(input.ArtifactSet.Artifacts) {
		return Report{}, errors.New("payloads must contain exactly the four baseline partition roles")
	}
	for _, artifact := range input.ArtifactSet.Artifacts {
		source, ok := input.Payloads[artifact.Role]
		if !ok || source.SizeBytes != artifact.SizeBytes || nilReader(source.ReaderAt) {
			return Report{}, fmt.Errorf("payload %q has a missing source or wrong measured size", artifact.Role)
		}
	}
	resolved, err := stablecampaign.ResolvePublicArtifactSources(input.Plan, input.PublicSources)
	if err != nil {
		return Report{}, fmt.Errorf("public artifact bytes: %w", err)
	}
	if err := input.ArtifactSet.ValidateAgainstResolved(input.Plan, resolved); err != nil {
		return Report{}, fmt.Errorf("resolved artifact set: %w", err)
	}
	for _, materialization := range input.Materializations {
		if err := materialization.ValidateAgainst(input.Plan, input.ArtifactSet, resolved); err != nil {
			return Report{}, fmt.Errorf("run %d materialization: %w", materialization.RunIndex, err)
		}
		if materialization.Mutation != nil {
			return Report{}, errors.New("first-baseline packet cannot contain a media mutation")
		}
	}
	partitions := make([]partitionBinding, 0, 4)
	for _, device := range input.StagingPlan.Devices {
		for _, partition := range device.Partitions {
			if err := verifyPayload(input.Payloads[partition.Role], partition); err != nil {
				return Report{}, fmt.Errorf("payload %q: %w", partition.Role, err)
			}
			partitions = append(partitions, partitionBinding{
				Leg: device.Identity.Leg, Role: partition.Role, OffsetBytes: partition.ByteStart,
				CapacityBytes: partition.CapacityBytes, SourceSizeBytes: partition.SourceSizeBytes,
				SourceSHA256: partition.SourceSHA256, ZeroTailBytes: partition.ZeroTailBytes,
				ExpectedWholePartitionSHA256: partition.ExpectedWholePartitionSHA256,
			})
		}
	}
	runs, err := prepareRuns(input.Plan, input.Materializations)
	if err != nil {
		return Report{}, err
	}
	value := record{
		SchemaVersion: SchemaVersion, Assurance: "public-byte-and-contract-consistency-only",
		AssertedSourceRevision: input.SourceRevision, CampaignID: input.Plan.CampaignID,
		PlanDigest: input.Plan.PlanDigest, ArtifactSetContentDigest: input.ArtifactSet.ArtifactSetContentDigest,
		StagingPlanDigest: input.StagingPlan.PlanDigest, RecoveryRequirementsDigest: input.Requirements.RecoveryRequirementsDigest,
		PublicInputCount: len(input.PublicSources.PublicInputs), ByteMutationTargetCount: len(input.PublicSources.ByteMutationTargets),
		Partitions: partitions, Runs: runs, MaximumUARTCaptureBytes: stablecampaign.MaximumUARTCaptureBytes,
		MaximumAuxiliaryEvidenceBytes:   stablecampaign.MaximumAuxiliaryEvidenceBytes,
		OutstandingRecoveryRequirements: append([]campaignmedia.RecoveryBackupOutstandingRequirement(nil), input.Requirements.OutstandingRequirements...),
		OutstandingOperatorRecords: []string{
			"reviewed-source-and-matching-native-ci-provenance", "signed-verifier-policy-trust-and-platform-review",
			"exact-board-and-sd-nvme-attachment-review", "authority-configuration-and-public-certificate-validity",
			"pi-rtc-within-certificate-validity", "capture-operator-and-fixed-uart-power-topology",
			"capture-duration-limit-and-completeness", "explicit-execution-approval-and-stop-recovery-procedure",
			"authority-unavailability-observation-for-run-2",
		},
	}
	for _, envelope := range input.Envelopes {
		value.InitialEnvelopes = append(value.InitialEnvelopes, envelopeBinding{Leg: envelope.Identity.Leg, EnvelopeDigest: envelope.EnvelopeDigest})
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return Report{}, err
	}
	value.PacketDigest = bundle.Sum(append([]byte(digestDomain+"\x00"), encoded...))
	return Report{value: value}, nil
}

func prepareRuns(plan stablecampaign.Plan, materializations []campaignmedia.RunArtifactMaterialization) ([]runPreparation, error) {
	expected, err := stablecampaign.ExpectedRuns(plan)
	if err != nil {
		return nil, err
	}
	result := make([]runPreparation, 2)
	for index := range result {
		run := expected[index]
		witnesses, err := stablecampaign.RequiredClaimWitnesses(plan, run.Index)
		if err != nil {
			return nil, err
		}
		prepared := runPreparation{
			RunIndex: run.Index, RunID: run.RunID, MaterializationDigest: materializations[index].MaterializationDigest,
			ExpectedDisposition: run.ExpectedDisposition, VerifierTerminal: run.VerifierTerminal,
			RequiredRawRoles: run.RequiredRawRoles, RequiredRecordKinds: run.RequiredRecordKinds,
		}
		for _, event := range run.VerifierTrace {
			prepared.VerifierTrace = append(prepared.VerifierTrace, traceEvent{Event: event.Event, FailureCode: event.FailureCode, DetailStage: event.DetailStage})
		}
		for _, witness := range witnesses {
			prepared.WitnessRequirements = append(prepared.WitnessRequirements, witnessRequirement{Claim: witness.Claim, RequiredKinds: witness.Kinds})
		}
		result[index] = prepared
	}
	return result, nil
}

func verifyPayload(source stablecampaign.PublicArtifactSource, partition campaignmedia.Partition) error {
	if nilReader(source.ReaderAt) || source.SizeBytes == 0 || source.SizeBytes != partition.SourceSizeBytes ||
		partition.SourceSizeBytes > partition.CapacityBytes || partition.ZeroTailBytes != partition.CapacityBytes-partition.SourceSizeBytes {
		return errors.New("source size or partition padding differs from the plan")
	}
	hash := sha256.New()
	buffer := make([]byte, 128*1024)
	for offset := uint64(0); offset < source.SizeBytes; {
		count := min(uint64(len(buffer)), source.SizeBytes-offset)
		chunk := buffer[:int(count)]
		n, err := source.ReaderAt.ReadAt(chunk, int64(offset))
		if n != len(chunk) || (err != nil && !errors.Is(err, io.EOF)) {
			return fmt.Errorf("incomplete source read at byte %d: %d/%d bytes, %v", offset, n, len(chunk), err)
		}
		_, _ = hash.Write(chunk)
		offset += count
	}
	digest := func() bundle.Digest { return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))) }
	if digest() != partition.SourceSHA256 {
		return errors.New("source bytes differ from the artifact and staging bindings")
	}
	clear(buffer)
	for remaining := partition.ZeroTailBytes; remaining > 0; {
		count := min(uint64(len(buffer)), remaining)
		_, _ = hash.Write(buffer[:int(count)])
		remaining -= count
	}
	if digest() != partition.ExpectedWholePartitionSHA256 {
		return errors.New("complete partition bytes differ from the staging binding")
	}
	return nil
}

func nilReader(reader io.ReaderAt) bool {
	if reader == nil {
		return true
	}
	value := reflect.ValueOf(reader)
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return value.IsNil()
	default:
		return false
	}
}
