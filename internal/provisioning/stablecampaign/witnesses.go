package stablecampaign

import (
	"errors"
	"fmt"
)

// ClaimWitnessKind names one independently collected fact which a future
// qualification layer must authenticate before it can close a planned claim.
// These values are requirements only: their presence in this code-derived
// list does not say that a witness was collected or that a claim passed.
type ClaimWitnessKind string

const (
	WitnessIndependentlyResolvedRunArtifacts  ClaimWitnessKind = "independently-resolved-run-artifacts"
	WitnessExactRunMediaReadback              ClaimWitnessKind = "exact-run-media-readback"
	WitnessProvenancedColdPowerObservation    ClaimWitnessKind = "provenanced-cold-power-observation"
	WitnessAuthenticatedCompleteVerifierTrace ClaimWitnessKind = "authenticated-complete-verifier-trace"

	WitnessAuthorityAuthorizationTranscript    ClaimWitnessKind = "authenticated-authority-authorization-transcript"
	WitnessReleasedOSTerminalEvent             ClaimWitnessKind = "authenticated-released-os-terminal-event"
	WitnessExpectedKernelCommandLine           ClaimWitnessKind = "authenticated-expected-kernel-command-line"
	WitnessObservedKernelCommandLine           ClaimWitnessKind = "released-os-observed-kernel-command-line"
	WitnessSignedAuthorizationAndOneBootProof  ClaimWitnessKind = "signed-authorization-and-exact-one-boot-proof"
	WitnessOneBootProofAcceptedOnce            ClaimWitnessKind = "one-boot-proof-accepted-once"
	WitnessIdenticalOneBootProofReplayRejected ClaimWitnessKind = "identical-one-boot-proof-replay-rejected"
	WitnessExactBootstrapSignedRequestReplay   ClaimWitnessKind = "exact-bootstrap-signed-request-replayed-from-released-stage"
	WitnessBootstrapChallengeReplayRejected    ClaimWitnessKind = "bootstrap-challenge-replay-rejected"
	WitnessPreHandoffLiveFDTProjection         ClaimWitnessKind = "pre-handoff-live-fdt-invariant-projection"
	WitnessPostHandoffLiveFDTProjection        ClaimWitnessKind = "post-handoff-live-fdt-invariant-projection"
	WitnessRootSignedLiveFDTMarker             ClaimWitnessKind = "root-signed-live-fdt-marker"
	WitnessAuthorityUnavailable                ClaimWitnessKind = "authority-unavailability-observation"
	WitnessAuthorizationOfflineRejection       ClaimWitnessKind = "authorization-offline-rejection"
	WitnessExactPriorAuthorizationTranscript   ClaimWitnessKind = "exact-prior-authorization-transcript"
	WitnessAuthorizationReplayRejected         ClaimWitnessKind = "exact-authorization-replay-rejected"
	WitnessReleaseVerificationRejected         ClaimWitnessKind = "release-verification-rejection"
	WitnessRuntimeDMVerityRejected             ClaimWitnessKind = "runtime-dm-verity-rejection"
)

// ClaimWitnessRequirement describes the outstanding witness kinds for one
// plan-derived logical claim. It intentionally has no satisfied, pass,
// outcome, disposition, or closure field.
type ClaimWitnessRequirement struct {
	Claim PlannedClaim
	Kinds []ClaimWitnessKind
}

// RequiredClaimWitnesses derives the exact outstanding witness requirements
// for one physical run in the fixed campaign. The result is descriptive and
// cannot be supplied to RequirePlannedClaimClosure as proof.
func RequiredClaimWitnesses(plan Plan, runIndex uint16) ([]ClaimWitnessRequirement, error) {
	runs, err := ExpectedRuns(plan)
	if err != nil {
		return nil, fmt.Errorf("derive claim witness requirements: %w", err)
	}
	if runIndex == 0 || int(runIndex) > len(runs) {
		return nil, fmt.Errorf("derive claim witness requirements: run index must be between 1 and %d", len(runs))
	}
	run := runs[runIndex-1]
	requirements := make([]ClaimWitnessRequirement, len(run.PlannedClaims))
	for index, claim := range run.PlannedClaims {
		kinds, err := requiredWitnessKinds(claim)
		if err != nil {
			return nil, fmt.Errorf("derive claim witness requirements for run %d: %w", runIndex, err)
		}
		requirements[index] = ClaimWitnessRequirement{
			Claim: claim,
			Kinds: append([]ClaimWitnessKind(nil), kinds...),
		}
	}
	return requirements, nil
}

func requiredWitnessKinds(claim PlannedClaim) ([]ClaimWitnessKind, error) {
	base := []ClaimWitnessKind{
		WitnessIndependentlyResolvedRunArtifacts,
		WitnessExactRunMediaReadback,
		WitnessProvenancedColdPowerObservation,
		WitnessAuthenticatedCompleteVerifierTrace,
	}
	appendKinds := func(kinds ...ClaimWitnessKind) []ClaimWitnessKind {
		result := append([]ClaimWitnessKind(nil), base...)
		return append(result, kinds...)
	}
	if claim.SubcaseID == "" {
		return nil, errors.New("planned claim has an empty subcase")
	}
	switch claim.TestID {
	case "approved-release-boots":
		if claim.SubcaseID != "positive-baseline" {
			break
		}
		return appendKinds(WitnessAuthorityAuthorizationTranscript, WitnessReleasedOSTerminalEvent), nil
	case "kernel-command-line-observed":
		if claim.SubcaseID != "positive-baseline" {
			break
		}
		return appendKinds(WitnessExpectedKernelCommandLine, WitnessObservedKernelCommandLine), nil
	case "one-boot-key-bound":
		if claim.SubcaseID != "positive-baseline" {
			break
		}
		return appendKinds(
			WitnessSignedAuthorizationAndOneBootProof,
			WitnessOneBootProofAcceptedOnce,
			WitnessIdenticalOneBootProofReplayRejected,
		), nil
	case "released-os-bootstrap-reuse-rejected":
		if claim.SubcaseID != "positive-baseline" {
			break
		}
		return appendKinds(
			WitnessExactBootstrapSignedRequestReplay,
			WitnessBootstrapChallengeReplayRejected,
		), nil
	case "resolved-device-tree-observed":
		if claim.SubcaseID != "positive-baseline" {
			break
		}
		return appendKinds(
			WitnessPreHandoffLiveFDTProjection,
			WitnessPostHandoffLiveFDTProjection,
			WitnessRootSignedLiveFDTMarker,
		), nil
	case "delegated-key-replacement-boots":
		if claim.SubcaseID != "replacement-manifest" {
			break
		}
		return appendKinds(WitnessAuthorityAuthorizationTranscript, WitnessReleasedOSTerminalEvent), nil
	case "dm-verity-corruption-rejected":
		if claim.SubcaseID != "root-data" && claim.SubcaseID != "root-hash" {
			break
		}
		return appendKinds(WitnessAuthorityAuthorizationTranscript, WitnessRuntimeDMVerityRejected), nil
	case "authorization-offline-rejected":
		if claim.SubcaseID != "authority-offline" {
			break
		}
		return appendKinds(WitnessAuthorityUnavailable, WitnessAuthorizationOfflineRejection), nil
	case "authorization-replay-rejected":
		if claim.SubcaseID != "stale-authorization" {
			break
		}
		return appendKinds(WitnessExactPriorAuthorizationTranscript, WitnessAuthorizationReplayRejected), nil
	case "component-byte-mutations-rejected", "manifest-field-mutations-rejected",
		"revoked-delegated-key-rejected", "unsigned-release-rejected", "wrong-delegated-key-rejected":
		return appendKinds(WitnessReleaseVerificationRejected), nil
	}
	return nil, fmt.Errorf("unsupported planned claim %q:%q", claim.TestID, claim.SubcaseID)
}
