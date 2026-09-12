package stablecampaign

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/verifierevents"
)

func TestExpectedRunsDerivesExactPhysicalMatrix(t *testing.T) {
	plan := validPlan(t)
	runs, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 33 {
		t.Fatalf("ExpectedRuns() returned %d runs, want 33", len(runs))
	}

	claimCount := 0
	recipeCount := 0
	dispositions := map[Disposition]int{}
	terminals := map[VerifierTerminalExpectation]int{}
	seenIDs := make(map[string]struct{}, len(runs))
	recipeIDs := make(map[string]struct{}, len(plan.ByteXORMutations)+len(plan.BoundReplacements))
	for _, recipe := range plan.ByteXORMutations {
		recipeIDs[recipe.RecipeID] = struct{}{}
	}
	for _, recipe := range plan.BoundReplacements {
		recipeIDs[recipe.RecipeID] = struct{}{}
	}
	for index, run := range runs {
		if run.Index != uint16(index+1) {
			t.Fatalf("run %d index = %d", index, run.Index)
		}
		if _, duplicate := seenIDs[run.RunID]; duplicate {
			t.Fatalf("duplicate run ID %q", run.RunID)
		}
		seenIDs[run.RunID] = struct{}{}
		claimCount += len(run.PlannedClaims)
		if run.MutationRecipeID != "" {
			recipeCount++
			if _, exists := recipeIDs[run.MutationRecipeID]; !exists {
				t.Fatalf("run %q refers to absent mutation recipe %q", run.RunID, run.MutationRecipeID)
			}
		}
		dispositions[run.ExpectedDisposition]++
		terminals[run.VerifierTerminal]++
		switch run.VerifierTerminal.FailureCode {
		case "release-verification-failed":
			if !slices.Equal(run.RequiredRawRoles, releaseRejectionRawRoles()) ||
				!slices.Equal(run.RequiredRecordKinds, releaseRejectionRecordKinds()) {
				t.Fatalf("release rejection run %q has the wrong evidence layout", run.RunID)
			}
		case "challenge-request-failed", "authorization-verification-failed":
			if !slices.Equal(run.RequiredRawRoles, authorizationRejectionRawRoles()) ||
				!slices.Equal(run.RequiredRecordKinds, authorizationRejectionRecordKinds()) {
				t.Fatalf("authorization rejection run %q has the wrong evidence layout", run.RunID)
			}
		case "":
			if !slices.Equal(run.RequiredRawRoles, successfulRunRawRoles()) ||
				!slices.Equal(run.RequiredRecordKinds, successfulRunRecordKinds()) {
				t.Fatalf("handoff run %q has the wrong evidence layout", run.RunID)
			}
		default:
			t.Fatalf("run %q has unexpected verifier failure code %q", run.RunID, run.VerifierTerminal.FailureCode)
		}
	}
	if claimCount != 37 {
		t.Fatalf("derived %d logical claims, want 37", claimCount)
	}
	if recipeCount != 30 {
		t.Fatalf("derived %d recipe-bound runs, want 30", recipeCount)
	}
	if dispositions[DispositionVerifierRejected] != 29 ||
		dispositions[DispositionReleasedOSBooted] != 2 ||
		dispositions[DispositionReleasedOSRejected] != 2 {
		t.Fatalf("unexpected disposition counts: %#v", dispositions)
	}
	if terminals[VerifierTerminalExpectation{
		Event: verifierevents.EventFailed, FailureCode: "release-verification-failed",
	}] != 27 {
		t.Fatalf("unexpected release rejection terminal counts: %#v", terminals)
	}
	if terminals[VerifierTerminalExpectation{
		Event: verifierevents.EventFailed, FailureCode: "challenge-request-failed",
	}] != 1 {
		t.Fatal("offline authorization terminal is not fixed")
	}
	if terminals[VerifierTerminalExpectation{
		Event: verifierevents.EventFailed, FailureCode: "authorization-verification-failed",
	}] != 1 {
		t.Fatal("stale authorization terminal is not fixed")
	}
	if terminals[VerifierTerminalExpectation{Event: verifierevents.EventHandoffExecuting}] != 4 {
		t.Fatal("successful verifier-handoff terminal count is not fixed")
	}

	baseline := runs[0]
	wantBaselineClaims := []PlannedClaim{
		{TestID: "approved-release-boots", SubcaseID: "positive-baseline"},
		{TestID: "kernel-command-line-observed", SubcaseID: "positive-baseline"},
		{TestID: "one-boot-key-bound", SubcaseID: "positive-baseline"},
		{TestID: "released-os-bootstrap-reuse-rejected", SubcaseID: "positive-baseline"},
		{TestID: "resolved-device-tree-observed", SubcaseID: "positive-baseline"},
	}
	if baseline.RunID != "positive-baseline" || baseline.MutationRecipeID != "" ||
		baseline.ExpectedDisposition != DispositionReleasedOSBooted {
		t.Fatalf("unexpected baseline semantics: %#v", baseline)
	}
	if err := validatePlannedClaims(baseline.PlannedClaims, wantBaselineClaims); err != nil {
		t.Fatal(err)
	}

	wantRunIDs := map[int]string{
		1:  "positive-baseline",
		2:  "authorization-offline-rejected:authority-offline",
		3:  "authorization-replay-rejected:stale-authorization",
		4:  "component-byte-mutations-rejected:kernel",
		12: "delegated-key-replacement-boots:replacement-manifest",
		13: "dm-verity-corruption-rejected:root-data",
		14: "dm-verity-corruption-rejected:root-hash",
		15: "manifest-field-mutations-rejected:schema-version",
		30: "manifest-field-mutations-rejected:signature-value",
		31: "revoked-delegated-key-rejected:revoked-manifest",
		32: "unsigned-release-rejected:unsigned-manifest",
		33: "wrong-delegated-key-rejected:wrong-key-manifest",
	}
	for oneBasedIndex, want := range wantRunIDs {
		if got := runs[oneBasedIndex-1].RunID; got != want {
			t.Fatalf("run %d ID = %q, want %q", oneBasedIndex, got, want)
		}
	}
}

func TestExpectedRunsRejectsInvalidPlanAndReturnsDefensiveCopies(t *testing.T) {
	plan := validPlan(t)
	first, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	first[0].RunID = "changed"
	first[0].PlannedClaims[0].TestID = "changed"
	first[0].RequiredRawRoles[0] = RawRoleUARTCapture
	first[0].RequiredRecordKinds[0] = RecordKindVerifierEvent
	second, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	if second[0].RunID != "positive-baseline" ||
		second[0].PlannedClaims[0].TestID != "approved-release-boots" ||
		second[0].RequiredRawRoles[0] != RawRoleMediaReadback ||
		second[0].RequiredRecordKinds[0] != RecordKindMediaReadback {
		t.Fatal("ExpectedRuns exposed mutable derived state")
	}

	plan.PlanDigest = testDigest(9000)
	if _, err := ExpectedRuns(plan); err == nil {
		t.Fatal("ExpectedRuns accepted an invalid plan")
	}
}

func TestExecutionResultCanonicalRoundTripAndDigest(t *testing.T) {
	plan := validPlan(t)
	result := validExecutionResult(t, plan, 1)
	encoded, err := result.CanonicalJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseExecutionResult(append(append([]byte(nil), encoded...), '\n'), plan)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ResultDigest != result.ResultDigest || parsed.RunID != "positive-baseline" {
		t.Fatalf("parsed result differs: %#v", parsed)
	}
	derived, err := parsed.DerivedDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	if derived != result.ResultDigest {
		t.Fatalf("derived result digest %q, want %q", derived, result.ResultDigest)
	}
	if bytes.Contains(encoded, []byte(`"recipe_id"`)) {
		t.Fatal("empty baseline recipe_id was serialized")
	}

	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &topLevel); err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{
		"claims", "pass", "status", "expected", "expected_disposition", "observed", "observed_disposition",
		"disposition", "outcome", "validated_claims", "claim_results",
		"private_key", "signing_authorized", "device_writes_authorized", "path",
	} {
		if _, exists := topLevel[prohibited]; exists {
			t.Fatalf("execution result exposes caller-controlled or unsafe field %q", prohibited)
		}
	}
	for _, prohibited := range []string{"BEGIN PRIVATE KEY", `"production_ready":true`, "/dev/", "/tmp/"} {
		if bytes.Contains(encoded, []byte(prohibited)) {
			t.Fatalf("execution result contains prohibited material %q", prohibited)
		}
	}
}

func TestExecutionResultConstructorDerivesIdentityAndCopiesInputs(t *testing.T) {
	plan := validPlan(t)
	runs, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	rawFiles, refs := validRawEvidence(runs[3], 4)
	result, err := NewExecutionResult(plan, 4, testCaptureID(4), rawFiles, refs)
	if err != nil {
		t.Fatal(err)
	}
	if result.RunID != runs[3].RunID || result.RecipeID != runs[3].MutationRecipeID ||
		result.PlannedClaims[0] != runs[3].PlannedClaims[0] || result.CaptureID != testCaptureID(4) {
		t.Fatalf("constructor did not derive run identity: %#v", result)
	}
	for index, binding := range result.RawFiles {
		if binding.CaptureID != result.CaptureID || binding.RawBindingDigest == "" {
			t.Fatalf("raw binding %d is not capture-bound: %#v", index, binding)
		}
	}
	for index, reference := range result.RecordRefs {
		if reference.CaptureID != result.CaptureID || reference.RecordBindingDigest == "" {
			t.Fatalf("record binding %d is not capture-bound: %#v", index, reference)
		}
	}
	rawFiles[0].Digest = testDigest(9990)
	refs[0].RecordDigest = testDigest(9991)
	if result.RawFiles[0].Digest == rawFiles[0].Digest || result.RecordRefs[0].RecordDigest == refs[0].RecordDigest {
		t.Fatal("constructor retained caller-owned evidence slices")
	}
	for _, index := range []uint16{0, 34} {
		if _, err := NewExecutionResult(plan, index, testCaptureID(index), nil, nil); err == nil {
			t.Fatalf("constructor accepted run index %d", index)
		}
	}
	for _, captureID := range []CaptureID{
		"", "capture:0", "capture:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"nonce:0000000000000000000000000000000000000000000000000000000000000001",
	} {
		if _, err := NewExecutionResult(plan, 4, captureID, rawFiles, refs); err == nil {
			t.Fatalf("constructor accepted noncanonical capture ID %q", captureID)
		}
	}
	if _, err := NewExecutionResult(plan, 4, testCaptureID(5), result.RawFiles, refs); err == nil {
		t.Fatal("constructor accepted already-bound raw evidence as transplantable input")
	}
	if _, err := NewExecutionResult(plan, 4, testCaptureID(5), rawFiles, result.RecordRefs); err == nil {
		t.Fatal("constructor accepted already-bound record evidence as transplantable input")
	}
}

func TestExecutionResultRejectsSemanticAndDigestTampering(t *testing.T) {
	plan := validPlan(t)
	baseline := validExecutionResult(t, plan, 1)
	tests := map[string]func(*ExecutionResult){
		"schema":      func(result *ExecutionResult) { result.SchemaVersion = "invented" },
		"campaign":    func(result *ExecutionResult) { result.CampaignID = "other-campaign" },
		"plan digest": func(result *ExecutionResult) { result.PlanDigest = testDigest(9100) },
		"zero index":  func(result *ExecutionResult) { result.RunIndex = 0 },
		"large index": func(result *ExecutionResult) { result.RunIndex = 34 },
		"run ID":      func(result *ExecutionResult) { result.RunID = "invented" },
		"capture ID":  func(result *ExecutionResult) { result.CaptureID = testCaptureID(800) },
		"missing planned claim": func(result *ExecutionResult) {
			result.PlannedClaims = result.PlannedClaims[:len(result.PlannedClaims)-1]
		},
		"changed planned claim": func(result *ExecutionResult) { result.PlannedClaims[0].TestID = "invented" },
		"claim order": func(result *ExecutionResult) {
			result.PlannedClaims[0], result.PlannedClaims[1] = result.PlannedClaims[1], result.PlannedClaims[0]
		},
		"invented recipe": func(result *ExecutionResult) { result.RecipeID = "invented" },
		"result digest":   func(result *ExecutionResult) { result.ResultDigest = testDigest(9101) },
		"raw capture ID":  func(result *ExecutionResult) { result.RawFiles[0].CaptureID = testCaptureID(801) },
		"raw binding":     func(result *ExecutionResult) { result.RawFiles[0].RawBindingDigest = testDigest(9102) },
		"range digest":    func(result *ExecutionResult) { result.RecordRefs[0].RawRangeDigest = testDigest(9103) },
		"record capture":  func(result *ExecutionResult) { result.RecordRefs[0].CaptureID = testCaptureID(802) },
		"record binding":  func(result *ExecutionResult) { result.RecordRefs[0].RecordBindingDigest = testDigest(9104) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := cloneExecutionResult(baseline)
			mutate(&result)
			if err := result.ValidateAgainst(plan); err == nil {
				t.Fatal("tampered execution result was accepted")
			}
		})
	}

	mutation := validExecutionResult(t, plan, 4)
	mutation.RecipeID = ""
	if err := mutation.ValidateAgainst(plan); err == nil {
		t.Fatal("missing mutation recipe binding was accepted")
	}
}

func TestExecutionResultRejectsInvalidRawBindings(t *testing.T) {
	plan := validPlan(t)
	baseline := validExecutionResult(t, plan, 1)
	tests := map[string]func(*ExecutionResult){
		"missing": func(result *ExecutionResult) {
			result.RawFiles = result.RawFiles[:len(result.RawFiles)-1]
		},
		"extra": func(result *ExecutionResult) {
			result.RawFiles = append(result.RawFiles, result.RawFiles[len(result.RawFiles)-1])
		},
		"order": func(result *ExecutionResult) {
			result.RawFiles[0], result.RawFiles[1] = result.RawFiles[1], result.RawFiles[0]
		},
		"duplicate role": func(result *ExecutionResult) { result.RawFiles[1].Role = result.RawFiles[0].Role },
		"unknown role":   func(result *ExecutionResult) { result.RawFiles[0].Role = "invented" },
		"bad digest":     func(result *ExecutionResult) { result.RawFiles[0].Digest = "sha256:ABC" },
		"duplicate digest": func(result *ExecutionResult) {
			result.RawFiles[1].Digest = result.RawFiles[0].Digest
		},
		"zero size": func(result *ExecutionResult) { result.RawFiles[0].SizeBytes = 0 },
		"oversized UART": func(result *ExecutionResult) {
			result.RawFiles[1].SizeBytes = MaximumUARTCaptureBytes + 1
		},
		"oversized auxiliary": func(result *ExecutionResult) {
			result.RawFiles[0].SizeBytes = MaximumAuxiliaryEvidenceBytes + 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := cloneExecutionResult(baseline)
			mutate(&result)
			if err := result.ValidateAgainst(plan); err == nil {
				t.Fatal("invalid raw binding was accepted")
			}
		})
	}
}

func TestExecutionResultRejectsInvalidRecordReferences(t *testing.T) {
	plan := validPlan(t)
	baseline := validExecutionResult(t, plan, 1)
	tests := map[string]func(*ExecutionResult){
		"missing": func(result *ExecutionResult) {
			result.RecordRefs = result.RecordRefs[:len(result.RecordRefs)-1]
		},
		"extra": func(result *ExecutionResult) {
			result.RecordRefs = append(result.RecordRefs, result.RecordRefs[len(result.RecordRefs)-1])
		},
		"wrong kind":     func(result *ExecutionResult) { result.RecordRefs[1].Kind = RecordKindReleasedOSEvent },
		"unknown kind":   func(result *ExecutionResult) { result.RecordRefs[1].Kind = "invented" },
		"wrong raw role": func(result *ExecutionResult) { result.RecordRefs[1].RawRole = RawRoleAuthorityAudit },
		"bad digest":     func(result *ExecutionResult) { result.RecordRefs[1].RecordDigest = "sha256:ABC" },
		"duplicate digest": func(result *ExecutionResult) {
			result.RecordRefs[2].RecordDigest = result.RecordRefs[1].RecordDigest
		},
		"zero size": func(result *ExecutionResult) { result.RecordRefs[1].SizeBytes = 0 },
		"oversized record": func(result *ExecutionResult) {
			result.RecordRefs[1].SizeBytes = verifierevents.MaxRecordBytes + 2
		},
		"outside raw file": func(result *ExecutionResult) {
			result.RecordRefs[1].OffsetBytes = result.RawFiles[1].SizeBytes
		},
		"overflow offset": func(result *ExecutionResult) { result.RecordRefs[1].OffsetBytes = ^uint64(0) },
		"overlap": func(result *ExecutionResult) {
			result.RecordRefs[2].OffsetBytes = result.RecordRefs[1].OffsetBytes
		},
		"backwards": func(result *ExecutionResult) {
			result.RecordRefs[2].OffsetBytes = result.RecordRefs[1].OffsetBytes - 1
		},
		"partial auxiliary": func(result *ExecutionResult) { result.RecordRefs[0].SizeBytes-- },
		"offset auxiliary":  func(result *ExecutionResult) { result.RecordRefs[0].OffsetBytes = 1 },
		"UART order": func(result *ExecutionResult) {
			result.RecordRefs[1], result.RecordRefs[2] = result.RecordRefs[2], result.RecordRefs[1]
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := cloneExecutionResult(baseline)
			mutate(&result)
			if err := result.ValidateAgainst(plan); err == nil {
				t.Fatal("invalid record reference was accepted")
			}
		})
	}
}

func TestCaptureIDChangesEveryEvidenceBindingAndResultDigest(t *testing.T) {
	plan := validPlan(t)
	runs, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	rawFiles, refs := validRawEvidence(runs[3], 4)
	first, err := NewExecutionResult(plan, 4, testCaptureID(400), rawFiles, refs)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewExecutionResult(plan, 4, testCaptureID(401), rawFiles, refs)
	if err != nil {
		t.Fatal(err)
	}
	if first.ResultDigest == second.ResultDigest {
		t.Fatal("capture ID did not change the result digest")
	}
	for index := range first.RawFiles {
		if first.RawFiles[index].RawBindingDigest == second.RawFiles[index].RawBindingDigest {
			t.Fatalf("capture ID did not change raw binding %d", index)
		}
	}
	for index := range first.RecordRefs {
		if first.RecordRefs[index].RecordBindingDigest == second.RecordRefs[index].RecordBindingDigest {
			t.Fatalf("capture ID did not change record binding %d", index)
		}
	}
}

func TestExecutionResultRejectsTransplantedEvidenceBindings(t *testing.T) {
	plan := validPlan(t)
	// Runs 4 and 5 have the same evidence layout, which makes the transplant
	// structurally plausible absent the campaign/run/capture binding digests.
	first := validExecutionResult(t, plan, 4)
	second := validExecutionResult(t, plan, 5)

	transplantedRaw := cloneExecutionResult(first)
	transplantedRaw.RawFiles[0] = second.RawFiles[0]
	transplantedRaw.RawFiles[0].CaptureID = first.CaptureID
	if _, err := transplantedRaw.Seal(plan); err == nil {
		t.Fatal("result accepted a raw binding transplanted from another run after relabeling its capture")
	}

	transplantedRecord := cloneExecutionResult(first)
	transplantedRecord.RecordRefs[0] = second.RecordRefs[0]
	transplantedRecord.RecordRefs[0].CaptureID = first.CaptureID
	if _, err := transplantedRecord.Seal(plan); err == nil {
		t.Fatal("result accepted a record binding transplanted from another run after relabeling its capture")
	}
}

func TestValidateRawEvidenceChecksBytesRangesAndVerifierDomains(t *testing.T) {
	plan := validPlan(t)
	rawFiles, refs, supplied := rawEvidenceFixture(t, plan, 1)
	result, err := NewExecutionResult(plan, 1, testCaptureID(700), rawFiles, refs)
	if err != nil {
		t.Fatal(err)
	}
	validation, err := result.ValidateRawEvidence(plan, supplied)
	if err != nil {
		t.Fatal(err)
	}
	if validation.RawBindingsVerified != 4 ||
		validation.RangeBindingsVerified != 10 ||
		validation.VerifierRecordsVerified != 6 {
		t.Fatalf("unexpected validation coverage: %#v", validation)
	}
	wantUnparsed := []RecordKind{
		RecordKindMediaReadback,
		RecordKindReleasedOSEvent,
		RecordKindAuthorityAudit,
		RecordKindPowerObservation,
	}
	if !slices.Equal(validation.UnparsedRecordKinds, wantUnparsed) {
		t.Fatalf("unparsed kinds = %#v, want %#v", validation.UnparsedRecordKinds, wantUnparsed)
	}

	t.Run("whole raw digest", func(t *testing.T) {
		tampered := cloneSuppliedRawEvidence(supplied)
		tampered[RawRoleMediaReadback][0] ^= 0x01
		if _, err := result.ValidateRawEvidence(plan, tampered); err == nil {
			t.Fatal("accepted raw bytes that differ from their complete-file digest")
		}
	})

	t.Run("missing role", func(t *testing.T) {
		tampered := cloneSuppliedRawEvidence(supplied)
		delete(tampered, RawRolePowerObservation)
		if _, err := result.ValidateRawEvidence(plan, tampered); err == nil {
			t.Fatal("accepted an incomplete raw-evidence map")
		}
	})

	t.Run("raw range digest", func(t *testing.T) {
		changedRefs := append([]RecordRef(nil), refs...)
		changedRefs[0].RawRangeDigest = testDigest(9750)
		changed, err := NewExecutionResult(plan, 1, testCaptureID(701), rawFiles, changedRefs)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := changed.ValidateRawEvidence(plan, supplied); err == nil {
			t.Fatal("accepted bytes that differ from their raw range digest")
		}
	})

	t.Run("verifier record domain digest", func(t *testing.T) {
		changedRefs := append([]RecordRef(nil), refs...)
		changedRefs[1].RecordDigest = testDigest(9751)
		changed, err := NewExecutionResult(plan, 1, testCaptureID(702), rawFiles, changedRefs)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := changed.ValidateRawEvidence(plan, supplied); err == nil {
			t.Fatal("accepted a verifier record with the wrong domain digest")
		}
	})
}

func TestStrictExecutionResultParsingRejectsAmbiguity(t *testing.T) {
	plan := validPlan(t)
	encoded, err := validExecutionResult(t, plan, 1).CanonicalJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"duplicate": bytes.Replace(encoded,
			[]byte(`"campaign_id":"campaign-1"`),
			[]byte(`"campaign_id":"campaign-1","campaign_id":"campaign-1"`), 1),
		"null": bytes.Replace(encoded,
			[]byte(`"run_id":"positive-baseline"`), []byte(`"run_id":null`), 1),
		"unknown": bytes.Replace(encoded,
			[]byte(`"run_id":"positive-baseline"`),
			[]byte(`"run_id":"positive-baseline","unexpected":false`), 1),
		"field order": bytes.Replace(encoded,
			[]byte(`{"schema_version":"`+ExecutionResultSchemaV1Alpha2+`","campaign_id":"campaign-1"`),
			[]byte(`{"campaign_id":"campaign-1","schema_version":"`+ExecutionResultSchemaV1Alpha2+`"`), 1),
		"whitespace":   append([]byte(" "), encoded...),
		"two newlines": append(append(append([]byte(nil), encoded...), '\n'), '\n'),
		"trailing":     append(append([]byte(nil), encoded...), []byte(`{}`)...),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseExecutionResult(input, plan); err == nil {
				t.Fatal("ambiguous or noncanonical execution result was accepted")
			}
		})
	}
}

func TestExecutionSetCanonicalRoundTripAndCompleteCoverage(t *testing.T) {
	plan := validPlan(t)
	set := validExecutionSet(t, plan)
	encoded, err := set.CanonicalJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseExecutionSet(append(append([]byte(nil), encoded...), '\n'), plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Results) != 33 || parsed.ExecutionSetDigest != set.ExecutionSetDigest {
		t.Fatalf("parsed execution set differs: %d results, digest %q", len(parsed.Results), parsed.ExecutionSetDigest)
	}
	derived, err := parsed.DerivedDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	if derived != set.ExecutionSetDigest {
		t.Fatalf("derived set digest %q, want %q", derived, set.ExecutionSetDigest)
	}
	if set.ExecutionSetDigest == set.Results[0].ResultDigest {
		t.Fatal("set and result digest domains were not separated")
	}
}

func TestExecutionSetRejectsMissingDuplicateReorderedAndTamperedResults(t *testing.T) {
	plan := validPlan(t)
	base := validExecutionSet(t, plan)
	tests := map[string]func(*ExecutionSet){
		"schema":   func(set *ExecutionSet) { set.SchemaVersion = "invented" },
		"campaign": func(set *ExecutionSet) { set.CampaignID = "other-campaign" },
		"plan":     func(set *ExecutionSet) { set.PlanDigest = testDigest(9200) },
		"missing":  func(set *ExecutionSet) { set.Results = set.Results[:len(set.Results)-1] },
		"extra": func(set *ExecutionSet) {
			set.Results = append(set.Results, cloneExecutionResult(set.Results[len(set.Results)-1]))
		},
		"reordered": func(set *ExecutionSet) { set.Results[0], set.Results[1] = set.Results[1], set.Results[0] },
		"duplicate": func(set *ExecutionSet) { set.Results[1] = cloneExecutionResult(set.Results[0]) },
		"nested result digest": func(set *ExecutionSet) {
			set.Results[1].ResultDigest = set.Results[0].ResultDigest
		},
		"nested raw binding": func(set *ExecutionSet) {
			set.Results[0].RawFiles[0].Digest = testDigest(9201)
		},
		"set digest": func(set *ExecutionSet) { set.ExecutionSetDigest = testDigest(9202) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			set := cloneExecutionSet(base)
			mutate(&set)
			if err := set.ValidateAgainst(plan); err == nil {
				t.Fatal("invalid execution set was accepted")
			}
		})
	}

	missing := cloneExecutionResults(base.Results[:len(base.Results)-1])
	if _, err := NewExecutionSet(plan, missing); err == nil {
		t.Fatal("constructor accepted an incomplete execution set")
	}
	reordered := cloneExecutionResults(base.Results)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	if _, err := NewExecutionSet(plan, reordered); err == nil {
		t.Fatal("constructor silently sorted reordered results")
	}

	runs, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	rawFiles, refs := validRawEvidence(runs[1], 2)
	duplicateCapture, err := NewExecutionResult(
		plan,
		2,
		base.Results[0].CaptureID,
		rawFiles,
		refs,
	)
	if err != nil {
		t.Fatal(err)
	}
	duplicateCaptureResults := cloneExecutionResults(base.Results)
	duplicateCaptureResults[1] = duplicateCapture
	if _, err := NewExecutionSet(plan, duplicateCaptureResults); err == nil {
		t.Fatal("execution set accepted a duplicate capture ID")
	}
}

func TestStrictExecutionSetParsingRejectsAmbiguity(t *testing.T) {
	plan := validPlan(t)
	encoded, err := validExecutionSet(t, plan).CanonicalJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"duplicate": bytes.Replace(encoded,
			[]byte(`"campaign_id":"campaign-1"`),
			[]byte(`"campaign_id":"campaign-1","campaign_id":"campaign-1"`), 1),
		"null": bytes.Replace(encoded, []byte(`"results":[`), []byte(`"results":null,"discarded":[`), 1),
		"unknown": bytes.Replace(encoded,
			[]byte(`"campaign_id":"campaign-1"`),
			[]byte(`"campaign_id":"campaign-1","unexpected":false`), 1),
		"field order": bytes.Replace(encoded,
			[]byte(`{"schema_version":"`+ExecutionSetSchemaV1Alpha2+`","campaign_id":"campaign-1"`),
			[]byte(`{"campaign_id":"campaign-1","schema_version":"`+ExecutionSetSchemaV1Alpha2+`"`), 1),
		"whitespace":   append([]byte(" "), encoded...),
		"two newlines": append(append(append([]byte(nil), encoded...), '\n'), '\n'),
		"trailing":     append(append([]byte(nil), encoded...), []byte(`{}`)...),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseExecutionSet(input, plan); err == nil {
				t.Fatal("ambiguous or noncanonical execution set was accepted")
			}
		})
	}
}

func validExecutionSet(t *testing.T, plan Plan) ExecutionSet {
	t.Helper()
	runs, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	results := make([]ExecutionResult, len(runs))
	for index := range runs {
		results[index] = validExecutionResult(t, plan, uint16(index+1))
	}
	set, err := NewExecutionSet(plan, results)
	if err != nil {
		t.Fatalf("construct valid execution set: %v", err)
	}
	return set
}

func validExecutionResult(t *testing.T, plan Plan, runIndex uint16) ExecutionResult {
	t.Helper()
	runs, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	if runIndex == 0 || int(runIndex) > len(runs) {
		t.Fatalf("invalid fixture run index %d", runIndex)
	}
	rawFiles, refs := validRawEvidence(runs[runIndex-1], int(runIndex))
	result, err := NewExecutionResult(plan, runIndex, testCaptureID(runIndex), rawFiles, refs)
	if err != nil {
		t.Fatalf("construct valid execution result %d: %v", runIndex, err)
	}
	return result
}

func validRawEvidence(spec RunSpec, seed int) ([]RawBinding, []RecordRef) {
	rawFiles := make([]RawBinding, len(spec.RequiredRawRoles))
	rawByRole := make(map[RawRole]RawBinding, len(rawFiles))
	for index, role := range spec.RequiredRawRoles {
		size := uint64(1024)
		if role == RawRoleUARTCapture {
			size = 64 * 1024
		}
		binding := RawBinding{
			Role: role, Digest: testDigest(seed*1000 + index + 1), SizeBytes: size,
		}
		rawFiles[index] = binding
		rawByRole[role] = binding
	}

	refs := make([]RecordRef, len(spec.RequiredRecordKinds))
	uartOffset := uint64(128)
	for index, kind := range spec.RequiredRecordKinds {
		role, _ := rawRoleForRecordKind(kind)
		offset := uint64(0)
		size := rawByRole[role].SizeBytes
		if role == RawRoleUARTCapture {
			offset = uartOffset
			size = 64
			uartOffset += 128
		}
		refs[index] = RecordRef{
			Kind: kind, RawRole: role, OffsetBytes: offset, SizeBytes: size,
			RawRangeDigest: testDigest(seed*1000 + 200 + index),
			RecordDigest:   testDigest(seed*1000 + 100 + index),
		}
	}
	return rawFiles, refs
}

type rawRecordFixture struct {
	offset       uint64
	size         uint64
	rangeDigest  bundle.Digest
	recordDigest bundle.Digest
}

func rawEvidenceFixture(
	t *testing.T,
	plan Plan,
	runIndex uint16,
) ([]RawBinding, []RecordRef, map[RawRole][]byte) {
	t.Helper()
	runs, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	if runIndex == 0 || int(runIndex) > len(runs) {
		t.Fatalf("invalid fixture run index %d", runIndex)
	}
	spec := runs[runIndex-1]

	supplied := map[RawRole][]byte{
		RawRoleMediaReadback:    []byte(`{"schema_version":"fixture-media-readback/v1","verified":true}`),
		RawRoleAuthorityAudit:   []byte(`{"schema_version":"fixture-authority-audit/v1","decision":"recorded"}`),
		RawRolePowerObservation: []byte(`{"schema_version":"fixture-power-observation/v1","cycle":"cold"}`),
	}

	var uart bytes.Buffer
	uart.WriteString("firmware diagnostic noise\n")
	emitter, err := verifierevents.New(&uart)
	if err != nil {
		t.Fatal(err)
	}
	verifierRanges := make([]rawRecordFixture, 0, len(spec.VerifierTrace))
	for _, expected := range spec.VerifierTrace {
		offset := uint64(uart.Len())
		record, recordDigest, err := emitter.Emit(
			expected.Event,
			verifierDetailsFixture(expected.DetailStage, expected.FailureCode),
		)
		if err != nil {
			t.Fatal(err)
		}
		if record.Event != expected.Event {
			t.Fatal("verifier event fixture emitted the wrong event")
		}
		size := uint64(uart.Len()) - offset
		verifierRanges = append(verifierRanges, rawRecordFixture{
			offset:       offset,
			size:         size,
			rangeDigest:  bundle.Sum(uart.Bytes()[int(offset):]),
			recordDigest: recordDigest,
		})
	}
	releasedOffset := uint64(uart.Len())
	uart.WriteString(`{"schema_version":"fixture-released-os-event/v1","event":"observed"}` + "\n")
	releasedRange := rawRecordFixture{
		offset:       releasedOffset,
		size:         uint64(uart.Len()) - releasedOffset,
		rangeDigest:  bundle.Sum(uart.Bytes()[int(releasedOffset):]),
		recordDigest: testDigest(9800 + int(runIndex)),
	}
	supplied[RawRoleUARTCapture] = append([]byte(nil), uart.Bytes()...)

	rawFiles := make([]RawBinding, len(spec.RequiredRawRoles))
	for index, role := range spec.RequiredRawRoles {
		raw := supplied[role]
		rawFiles[index] = RawBinding{
			Role: role, Digest: bundle.Sum(raw), SizeBytes: uint64(len(raw)),
		}
	}

	refs := make([]RecordRef, len(spec.RequiredRecordKinds))
	verifierIndex := 0
	for index, kind := range spec.RequiredRecordKinds {
		role, ok := rawRoleForRecordKind(kind)
		if !ok {
			t.Fatalf("unsupported fixture record kind %q", kind)
		}
		var fixture rawRecordFixture
		switch kind {
		case RecordKindVerifierEvent:
			fixture = verifierRanges[verifierIndex]
			verifierIndex++
		case RecordKindReleasedOSEvent:
			fixture = releasedRange
		default:
			fixture = rawRecordFixture{
				size:         uint64(len(supplied[role])),
				rangeDigest:  bundle.Sum(supplied[role]),
				recordDigest: testDigest(9900 + int(runIndex)*100 + index),
			}
		}
		refs[index] = RecordRef{
			Kind:           kind,
			RawRole:        role,
			OffsetBytes:    fixture.offset,
			SizeBytes:      fixture.size,
			RawRangeDigest: fixture.rangeDigest,
			RecordDigest:   fixture.recordDigest,
		}
	}
	return rawFiles, refs, supplied
}

func verifierDetailsFixture(stage VerifierDetailStage, failureCode string) verifierevents.Details {
	details := verifierevents.Details{FailureCode: failureCode}
	if stage == VerifierDetailNone {
		return details
	}
	details.PolicyDigest = testDigest(9600)
	details.ManifestDigest = testDigest(9601)
	if stage == VerifierDetailRelease {
		return details
	}
	details.BootstrapPublicKey = "ed25519:" + strings.Repeat("a", 64)
	if stage == VerifierDetailBootstrap {
		return details
	}
	details.OneBootPublicKey = "ed25519:" + strings.Repeat("b", 64)
	return details
}

func cloneSuppliedRawEvidence(supplied map[RawRole][]byte) map[RawRole][]byte {
	cloned := make(map[RawRole][]byte, len(supplied))
	for role, encoded := range supplied {
		cloned[role] = append([]byte(nil), encoded...)
	}
	return cloned
}

func testCaptureID(seed uint16) CaptureID {
	return CaptureID(fmt.Sprintf("capture:%064x", seed))
}

func cloneExecutionResult(result ExecutionResult) ExecutionResult {
	return cloneExecutionResults([]ExecutionResult{result})[0]
}

func cloneExecutionSet(set ExecutionSet) ExecutionSet {
	cloned := set
	cloned.Results = cloneExecutionResults(set.Results)
	return cloned
}

func TestExecutionContractsContainNoOutcomeVocabulary(t *testing.T) {
	plan := validPlan(t)
	encoded, err := validExecutionSet(t, plan).CanonicalJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		`"claims"`, `"pass"`, `"fail"`, `"blocked"`, `"outcome"`, `"disposition"`,
		`"validated_claims"`, `"claim_results"`,
		`"expected_disposition"`, `"observed_disposition"`,
		`"signing_authorized"`, `"device_writes_authorized"`, "private_key",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("execution contract contains forbidden caller-controlled vocabulary %q", forbidden)
		}
	}
}
