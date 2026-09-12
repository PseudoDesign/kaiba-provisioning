package stablecampaign

import (
	"slices"
	"testing"
)

func TestRequiredClaimWitnessesCoversExactCampaignWithoutClaimResults(t *testing.T) {
	plan := validPlan(t)
	runs, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, run := range runs {
		requirements, err := RequiredClaimWitnesses(plan, run.Index)
		if err != nil {
			t.Fatalf("run %d: %v", run.Index, err)
		}
		if len(requirements) != len(run.PlannedClaims) {
			t.Fatalf("run %d has %d requirements, want %d", run.Index, len(requirements), len(run.PlannedClaims))
		}
		for index, requirement := range requirements {
			total++
			if requirement.Claim != run.PlannedClaims[index] {
				t.Fatalf("run %d requirement %d is detached from its planned claim", run.Index, index)
			}
			if len(requirement.Kinds) < 5 {
				t.Fatalf("run %d claim %#v has an incomplete witness list: %#v", run.Index, requirement.Claim, requirement.Kinds)
			}
			seen := make(map[ClaimWitnessKind]struct{}, len(requirement.Kinds))
			for _, kind := range requirement.Kinds {
				if kind == "" {
					t.Fatalf("run %d claim %#v has an empty witness kind", run.Index, requirement.Claim)
				}
				if _, duplicate := seen[kind]; duplicate {
					t.Fatalf("run %d claim %#v repeats witness %q", run.Index, requirement.Claim, kind)
				}
				seen[kind] = struct{}{}
			}
			for _, common := range []ClaimWitnessKind{
				WitnessIndependentlyResolvedRunArtifacts,
				WitnessExactRunMediaReadback,
				WitnessProvenancedColdPowerObservation,
				WitnessAuthenticatedCompleteVerifierTrace,
			} {
				if _, ok := seen[common]; !ok {
					t.Fatalf("run %d claim %#v lacks common witness %q", run.Index, requirement.Claim, common)
				}
			}
		}
	}
	if total != 37 {
		t.Fatalf("derived %d claim witness requirements, want 37", total)
	}
}

func TestPositiveClaimsHaveSeparateSpecificWitnessRequirements(t *testing.T) {
	plan := validPlan(t)
	requirements, err := RequiredClaimWitnesses(plan, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(requirements) != 5 {
		t.Fatalf("positive run has %d claim requirements, want 5", len(requirements))
	}
	wantSpecific := map[string][]ClaimWitnessKind{
		"approved-release-boots": {
			WitnessAuthorityAuthorizationTranscript,
			WitnessReleasedOSTerminalEvent,
		},
		"kernel-command-line-observed": {
			WitnessExpectedKernelCommandLine,
			WitnessObservedKernelCommandLine,
		},
		"one-boot-key-bound": {
			WitnessSignedAuthorizationAndOneBootProof,
			WitnessOneBootProofAcceptedOnce,
			WitnessIdenticalOneBootProofReplayRejected,
		},
		"released-os-bootstrap-reuse-rejected": {
			WitnessExactBootstrapSignedRequestReplay,
			WitnessBootstrapChallengeReplayRejected,
		},
		"resolved-device-tree-observed": {
			WitnessPreHandoffLiveFDTProjection,
			WitnessPostHandoffLiveFDTProjection,
			WitnessRootSignedLiveFDTMarker,
		},
	}
	for _, requirement := range requirements {
		for _, kind := range wantSpecific[requirement.Claim.TestID] {
			if !slices.Contains(requirement.Kinds, kind) {
				t.Fatalf("claim %q lacks specific witness %q", requirement.Claim.TestID, kind)
			}
		}
	}
}

func TestNegativeClaimsRequireTheirExactFailureWitness(t *testing.T) {
	plan := validPlan(t)
	tests := []struct {
		runIndex uint16
		want     ClaimWitnessKind
	}{
		{2, WitnessAuthorityUnavailable},
		{3, WitnessExactPriorAuthorizationTranscript},
		{4, WitnessReleaseVerificationRejected},
		{13, WitnessRuntimeDMVerityRejected},
		{14, WitnessRuntimeDMVerityRejected},
		{31, WitnessReleaseVerificationRejected},
	}
	for _, test := range tests {
		requirements, err := RequiredClaimWitnesses(plan, test.runIndex)
		if err != nil {
			t.Fatalf("run %d: %v", test.runIndex, err)
		}
		if len(requirements) != 1 || !slices.Contains(requirements[0].Kinds, test.want) {
			t.Fatalf("run %d requirements %#v lack %q", test.runIndex, requirements, test.want)
		}
	}
}

func TestRequiredClaimWitnessesRejectsInvalidInputAndReturnsDefensiveCopies(t *testing.T) {
	plan := validPlan(t)
	for _, runIndex := range []uint16{0, 34} {
		if _, err := RequiredClaimWitnesses(plan, runIndex); err == nil {
			t.Fatalf("accepted invalid run index %d", runIndex)
		}
	}

	first, err := RequiredClaimWitnesses(plan, 1)
	if err != nil {
		t.Fatal(err)
	}
	first[0].Claim.TestID = "changed"
	first[0].Kinds[0] = "changed"
	second, err := RequiredClaimWitnesses(plan, 1)
	if err != nil {
		t.Fatal(err)
	}
	if second[0].Claim.TestID != "approved-release-boots" ||
		second[0].Kinds[0] != WitnessIndependentlyResolvedRunArtifacts {
		t.Fatal("RequiredClaimWitnesses exposed mutable derived state")
	}

	plan.PlanDigest = testDigest(9999)
	if _, err := RequiredClaimWitnesses(plan, 1); err == nil {
		t.Fatal("accepted an invalid plan")
	}
}
