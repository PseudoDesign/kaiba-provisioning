package stablecampaign

import (
	"errors"
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/verifierevents"
)

// Disposition is the externally observable boundary at which a physical
// campaign run must terminate. It is derived from the fixed campaign matrix;
// execution-result producers cannot select it.
type Disposition string

const (
	DispositionVerifierRejected   Disposition = "verifier-rejected"
	DispositionReleasedOSBooted   Disposition = "released-os-booted"
	DispositionReleasedOSRejected Disposition = "released-os-rejected"
)

// PlannedClaim identifies one fixed logical subcase that a physical run is
// intended to exercise. Inclusion in a RunSpec does not say that the claim was
// observed, authenticated, or closed. The positive baseline intentionally
// carries five planned claims so it is executed once rather than being
// mislabeled as five separate boots.
type PlannedClaim struct {
	TestID    string `json:"test_id"`
	SubcaseID string `json:"subcase_id"`
}

// VerifierTerminalExpectation fixes the final verifier event and, for a
// verifier rejection, its exact failure code.
type VerifierTerminalExpectation struct {
	Event       string `json:"event"`
	FailureCode string `json:"failure_code,omitempty"`
}

// VerifierDetailStage identifies the exact public detail set an event must
// carry. The stages are cumulative: release adds the policy and manifest
// digests, bootstrap adds the bootstrap public key, and authorization adds the
// one-boot public key.
type VerifierDetailStage string

const (
	VerifierDetailNone          VerifierDetailStage = "none"
	VerifierDetailRelease       VerifierDetailStage = "release"
	VerifierDetailBootstrap     VerifierDetailStage = "bootstrap"
	VerifierDetailAuthorization VerifierDetailStage = "authorization"
)

// VerifierEventExpectation fixes one position in a run's complete verifier
// event trace. FailureCode is non-empty only for the terminal failed event.
type VerifierEventExpectation struct {
	Event       string
	FailureCode string
	DetailStage VerifierDetailStage
}

// RunSpec is a code-derived physical execution in the fixed campaign. It is
// deliberately not a caller-authored contract and contains no action or
// authorization field.
type RunSpec struct {
	Index               uint16
	RunID               string
	PlannedClaims       []PlannedClaim
	MutationRecipeID    string
	ExpectedDisposition Disposition
	VerifierTerminal    VerifierTerminalExpectation
	VerifierTrace       []VerifierEventExpectation
	RequiredRawRoles    []RawRole
	RequiredRecordKinds []RecordKind
}

// ExpectedRuns derives the exact physical campaign from a validated plan.
// The ordering is the fixed logical-case order, with later positive-baseline
// planned claims folded into the first run. The returned slices do not alias
// package state or the supplied plan.
func ExpectedRuns(plan Plan) ([]RunSpec, error) {
	if err := plan.Validate(); err != nil {
		return nil, fmt.Errorf("derive expected campaign runs: %w", err)
	}

	runs := make([]RunSpec, 0, 33)
	baselineIndex := -1
	for _, testCase := range fixedCases {
		for _, subcaseID := range testCase.Subcases {
			claim := PlannedClaim{TestID: testCase.TestID, SubcaseID: subcaseID}
			if subcaseID == "positive-baseline" {
				if baselineIndex >= 0 {
					runs[baselineIndex].PlannedClaims = append(runs[baselineIndex].PlannedClaims, claim)
					continue
				}
				baselineIndex = len(runs)
			}

			run, err := expectedRun(testCase.TestID, subcaseID)
			if err != nil {
				return nil, err
			}
			run.Index = uint16(len(runs) + 1)
			run.PlannedClaims = []PlannedClaim{claim}
			runs = append(runs, run)
		}
	}
	if len(runs) != 33 {
		return nil, fmt.Errorf("fixed campaign derived %d physical runs, want 33", len(runs))
	}
	return cloneRunSpecs(runs), nil
}

func expectedRun(testID, subcaseID string) (RunSpec, error) {
	run := RunSpec{RunID: recipeID(testID, subcaseID)}
	switch testID {
	case "approved-release-boots", "kernel-command-line-observed", "one-boot-key-bound",
		"released-os-bootstrap-reuse-rejected", "resolved-device-tree-observed":
		if subcaseID != "positive-baseline" {
			return RunSpec{}, errors.New("positive planned claim has an unsupported subcase")
		}
		run.RunID = "positive-baseline"
		run.ExpectedDisposition = DispositionReleasedOSBooted
		setVerifierTrace(&run, successfulHandoffVerifierTrace())
		run.RequiredRawRoles = successfulRunRawRoles()
		run.RequiredRecordKinds = successfulRunRecordKinds()
	case "delegated-key-replacement-boots":
		run.MutationRecipeID = recipeID(testID, subcaseID)
		run.ExpectedDisposition = DispositionReleasedOSBooted
		setVerifierTrace(&run, successfulHandoffVerifierTrace())
		run.RequiredRawRoles = successfulRunRawRoles()
		run.RequiredRecordKinds = successfulRunRecordKinds()
	case "dm-verity-corruption-rejected":
		run.MutationRecipeID = recipeID(testID, subcaseID)
		run.ExpectedDisposition = DispositionReleasedOSRejected
		setVerifierTrace(&run, successfulHandoffVerifierTrace())
		run.RequiredRawRoles = successfulRunRawRoles()
		run.RequiredRecordKinds = successfulRunRecordKinds()
	case "authorization-offline-rejected":
		run.ExpectedDisposition = DispositionVerifierRejected
		setVerifierTrace(&run, authorizationRejectionVerifierTrace("challenge-request-failed"))
		run.RequiredRawRoles = authorizationRejectionRawRoles()
		run.RequiredRecordKinds = authorizationRejectionRecordKinds()
	case "authorization-replay-rejected":
		run.ExpectedDisposition = DispositionVerifierRejected
		setVerifierTrace(&run, authorizationRejectionVerifierTrace("authorization-verification-failed"))
		run.RequiredRawRoles = authorizationRejectionRawRoles()
		run.RequiredRecordKinds = authorizationRejectionRecordKinds()
	case "component-byte-mutations-rejected", "manifest-field-mutations-rejected",
		"revoked-delegated-key-rejected", "unsigned-release-rejected", "wrong-delegated-key-rejected":
		run.MutationRecipeID = recipeID(testID, subcaseID)
		run.ExpectedDisposition = DispositionVerifierRejected
		setVerifierTrace(&run, releaseRejectionVerifierTrace())
		run.RequiredRawRoles = releaseRejectionRawRoles()
		run.RequiredRecordKinds = releaseRejectionRecordKinds()
	default:
		return RunSpec{}, fmt.Errorf("fixed campaign test %q has no execution semantics", testID)
	}
	return run, nil
}

func setVerifierTrace(run *RunSpec, trace []VerifierEventExpectation) {
	run.VerifierTrace = append([]VerifierEventExpectation(nil), trace...)
	terminal := trace[len(trace)-1]
	run.VerifierTerminal = VerifierTerminalExpectation{
		Event: terminal.Event, FailureCode: terminal.FailureCode,
	}
}

func releaseRejectionVerifierTrace() []VerifierEventExpectation {
	return []VerifierEventExpectation{
		{Event: verifierevents.EventStarted, DetailStage: VerifierDetailNone},
		{
			Event: verifierevents.EventFailed, FailureCode: "release-verification-failed",
			DetailStage: VerifierDetailNone,
		},
	}
}

func authorizationRejectionVerifierTrace(failureCode string) []VerifierEventExpectation {
	return []VerifierEventExpectation{
		{Event: verifierevents.EventStarted, DetailStage: VerifierDetailNone},
		{Event: verifierevents.EventReleaseVerified, DetailStage: VerifierDetailRelease},
		{Event: verifierevents.EventBootstrapKeyReady, DetailStage: VerifierDetailBootstrap},
		{
			Event: verifierevents.EventFailed, FailureCode: failureCode,
			DetailStage: VerifierDetailBootstrap,
		},
	}
}

func successfulHandoffVerifierTrace() []VerifierEventExpectation {
	return []VerifierEventExpectation{
		{Event: verifierevents.EventStarted, DetailStage: VerifierDetailNone},
		{Event: verifierevents.EventReleaseVerified, DetailStage: VerifierDetailRelease},
		{Event: verifierevents.EventBootstrapKeyReady, DetailStage: VerifierDetailBootstrap},
		{Event: verifierevents.EventAuthorizationReady, DetailStage: VerifierDetailAuthorization},
		{Event: verifierevents.EventHandoffLoaded, DetailStage: VerifierDetailAuthorization},
		{Event: verifierevents.EventHandoffExecuting, DetailStage: VerifierDetailAuthorization},
	}
}

func successfulRunRawRoles() []RawRole {
	return []RawRole{RawRoleMediaReadback, RawRoleUARTCapture, RawRoleAuthorityAudit, RawRolePowerObservation}
}

func successfulRunRecordKinds() []RecordKind {
	return []RecordKind{
		RecordKindMediaReadback,
		RecordKindVerifierEvent, RecordKindVerifierEvent, RecordKindVerifierEvent,
		RecordKindVerifierEvent, RecordKindVerifierEvent, RecordKindVerifierEvent,
		RecordKindReleasedOSEvent,
		RecordKindAuthorityAudit,
		RecordKindPowerObservation,
	}
}

func authorizationRejectionRawRoles() []RawRole {
	return []RawRole{RawRoleMediaReadback, RawRoleUARTCapture, RawRoleAuthorityAudit, RawRolePowerObservation}
}

func authorizationRejectionRecordKinds() []RecordKind {
	return []RecordKind{
		RecordKindMediaReadback,
		RecordKindVerifierEvent, RecordKindVerifierEvent, RecordKindVerifierEvent, RecordKindVerifierEvent,
		RecordKindAuthorityAudit,
		RecordKindPowerObservation,
	}
}

func releaseRejectionRawRoles() []RawRole {
	return []RawRole{RawRoleMediaReadback, RawRoleUARTCapture, RawRolePowerObservation}
}

func releaseRejectionRecordKinds() []RecordKind {
	return []RecordKind{
		RecordKindMediaReadback,
		RecordKindVerifierEvent, RecordKindVerifierEvent,
		RecordKindPowerObservation,
	}
}

func cloneRunSpecs(runs []RunSpec) []RunSpec {
	cloned := make([]RunSpec, len(runs))
	for index, run := range runs {
		cloned[index] = run
		cloned[index].PlannedClaims = append([]PlannedClaim(nil), run.PlannedClaims...)
		cloned[index].VerifierTrace = append([]VerifierEventExpectation(nil), run.VerifierTrace...)
		cloned[index].RequiredRawRoles = append([]RawRole(nil), run.RequiredRawRoles...)
		cloned[index].RequiredRecordKinds = append([]RecordKind(nil), run.RequiredRecordKinds...)
	}
	return cloned
}
