package stablecampaign

import (
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/verifierevents"
)

func TestExpectedRunsCarryExactVerifierTraces(t *testing.T) {
	plan := validPlan(t)
	runs, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 33 {
		t.Fatalf("derived %d runs, want 33", len(runs))
	}

	wantRelease := releaseRejectionVerifierTrace()
	wantOffline := authorizationRejectionVerifierTrace("challenge-request-failed")
	wantStale := authorizationRejectionVerifierTrace("authorization-verification-failed")
	wantHandoff := successfulHandoffVerifierTrace()
	counts := map[string]int{}
	for _, run := range runs {
		var want []VerifierEventExpectation
		switch run.VerifierTerminal.FailureCode {
		case "release-verification-failed":
			want = wantRelease
			counts["release"]++
		case "challenge-request-failed":
			want = wantOffline
			counts["offline"]++
		case "authorization-verification-failed":
			want = wantStale
			counts["stale"]++
		case "":
			want = wantHandoff
			counts["handoff"]++
		default:
			t.Fatalf("run %q has unexpected terminal %#v", run.RunID, run.VerifierTerminal)
		}
		assertVerifierTraceEqual(t, run.RunID, run.VerifierTrace, want)
		if len(run.VerifierTrace) == 0 {
			t.Fatalf("run %q has no verifier trace", run.RunID)
		}
		terminal := run.VerifierTrace[len(run.VerifierTrace)-1]
		if terminal.Event != run.VerifierTerminal.Event || terminal.FailureCode != run.VerifierTerminal.FailureCode {
			t.Fatalf("run %q terminal differs from its trace", run.RunID)
		}
	}
	if counts["release"] != 27 || counts["offline"] != 1 || counts["stale"] != 1 || counts["handoff"] != 4 {
		t.Fatalf("unexpected trace counts: %#v", counts)
	}
}

func TestExpectedRunsReturnsDefensiveVerifierTraceCopies(t *testing.T) {
	plan := validPlan(t)
	first, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	first[0].VerifierTrace[0].Event = verifierevents.EventFailed
	second, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	if second[0].VerifierTrace[0].Event != verifierevents.EventStarted {
		t.Fatal("ExpectedRuns exposed mutable verifier trace state")
	}
}

func TestVerifyVerifierEventTraceAcceptsEveryDerivedRun(t *testing.T) {
	plan := validPlan(t)
	runs, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range runs {
		t.Run(run.RunID, func(t *testing.T) {
			records := validVerifierTrace(t, run)
			if err := VerifyVerifierEventTrace(plan, run.Index, records); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVerifyVerifierEventTraceRejectsSequenceShapeAndTerminalChanges(t *testing.T) {
	plan := validPlan(t)
	runs, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	baseHandoff := validVerifierTrace(t, runs[0])
	baseRelease := validVerifierTrace(t, runs[3])

	tests := map[string]struct {
		runIndex uint16
		base     []verifierevents.Record
		mutate   func([]verifierevents.Record) []verifierevents.Record
	}{
		"missing record": {
			runIndex: 1, base: baseHandoff,
			mutate: func(records []verifierevents.Record) []verifierevents.Record {
				return records[:len(records)-1]
			},
		},
		"extra record": {
			runIndex: 4, base: baseRelease,
			mutate: func(records []verifierevents.Record) []verifierevents.Record {
				return append(records, records[len(records)-1])
			},
		},
		"sequence does not start at one": {
			runIndex: 1, base: baseHandoff,
			mutate: func(records []verifierevents.Record) []verifierevents.Record {
				records[0].Sequence = 2
				return records
			},
		},
		"sequence gap": {
			runIndex: 1, base: baseHandoff,
			mutate: func(records []verifierevents.Record) []verifierevents.Record {
				records[3].Sequence++
				return records
			},
		},
		"sequence duplicate": {
			runIndex: 1, base: baseHandoff,
			mutate: func(records []verifierevents.Record) []verifierevents.Record {
				records[3].Sequence = records[2].Sequence
				return records
			},
		},
		"wrong intermediate event": {
			runIndex: 1, base: baseHandoff,
			mutate: func(records []verifierevents.Record) []verifierevents.Record {
				records[3].Event = verifierevents.EventHandoffLoaded
				return records
			},
		},
		"wrong successful terminal": {
			runIndex: 1, base: baseHandoff,
			mutate: func(records []verifierevents.Record) []verifierevents.Record {
				records[len(records)-1].Event = verifierevents.EventHandoffLoaded
				return records
			},
		},
		"wrong failure code": {
			runIndex: 4, base: baseRelease,
			mutate: func(records []verifierevents.Record) []verifierevents.Record {
				records[len(records)-1].FailureCode = "challenge-request-failed"
				return records
			},
		},
		"invalid parsed record": {
			runIndex: 1, base: baseHandoff,
			mutate: func(records []verifierevents.Record) []verifierevents.Record {
				records[0].Source = "invented"
				return records
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			records := cloneVerifierRecords(test.base)
			records = test.mutate(records)
			if err := VerifyVerifierEventTrace(plan, test.runIndex, records); err == nil {
				t.Fatal("mutated verifier trace was accepted")
			}
		})
	}
}

func TestVerifyVerifierEventTraceRejectsWrongFailureDetailStage(t *testing.T) {
	plan := validPlan(t)
	runs, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("release rejection acquired release details", func(t *testing.T) {
		records := validVerifierTrace(t, runs[3])
		failed := &records[len(records)-1]
		failed.PolicyDigest = testDigest(41001)
		failed.ManifestDigest = testDigest(41002)
		if err := failed.Validate(); err != nil {
			t.Fatalf("adversarial failed record is not independently valid: %v", err)
		}
		if err := VerifyVerifierEventTrace(plan, 4, records); err == nil || !strings.Contains(err.Error(), "detail stage") {
			t.Fatalf("wrong release failure stage accepted: %v", err)
		}
	})

	t.Run("offline rejection acquired one-boot details", func(t *testing.T) {
		records := validVerifierTrace(t, runs[1])
		failed := &records[len(records)-1]
		failed.OneBootPublicKey = verifierTestOneBootKey
		if err := failed.Validate(); err != nil {
			t.Fatalf("adversarial failed record is not independently valid: %v", err)
		}
		if err := VerifyVerifierEventTrace(plan, 2, records); err == nil || !strings.Contains(err.Error(), "detail stage") {
			t.Fatalf("wrong offline failure stage accepted: %v", err)
		}
	})
}

func TestVerifyVerifierEventTraceRejectsChangedPublicInvariants(t *testing.T) {
	plan := validPlan(t)
	runs, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	base := validVerifierTrace(t, runs[0])
	tests := map[string]func([]verifierevents.Record){
		"policy digest": func(records []verifierevents.Record) {
			records[2].PolicyDigest = testDigest(42001)
		},
		"manifest digest": func(records []verifierevents.Record) {
			records[2].ManifestDigest = testDigest(42002)
		},
		"bootstrap public key": func(records []verifierevents.Record) {
			records[3].BootstrapPublicKey = "ed25519:" + strings.Repeat("e", 64)
		},
		"one-boot public key": func(records []verifierevents.Record) {
			records[4].OneBootPublicKey = "ed25519:" + strings.Repeat("f", 64)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			records := cloneVerifierRecords(base)
			mutate(records)
			for index, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatalf("adversarial record %d is not independently valid: %v", index+1, err)
				}
			}
			if err := VerifyVerifierEventTrace(plan, 1, records); err == nil || !strings.Contains(err.Error(), "changed") {
				t.Fatalf("changed invariant accepted: %v", err)
			}
		})
	}
}

func TestVerifyVerifierEventTraceRejectsInvalidPlanAndRunIndex(t *testing.T) {
	plan := validPlan(t)
	runs, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	records := validVerifierTrace(t, runs[0])

	invalidPlan := plan
	invalidPlan.PlanDigest = testDigest(43001)
	if err := VerifyVerifierEventTrace(invalidPlan, 1, records); err == nil {
		t.Fatal("invalid campaign plan was accepted")
	}
	for _, runIndex := range []uint16{0, 34} {
		if err := VerifyVerifierEventTrace(plan, runIndex, records); err == nil {
			t.Fatalf("invalid run index %d was accepted", runIndex)
		}
	}
}

const (
	verifierTestBootstrapKey = "ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	verifierTestOneBootKey   = "ed25519:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

func validVerifierTrace(t *testing.T, run RunSpec) []verifierevents.Record {
	t.Helper()
	records := make([]verifierevents.Record, len(run.VerifierTrace))
	for index, expected := range run.VerifierTrace {
		record := verifierevents.Record{
			SchemaVersion: verifierevents.SchemaV1Alpha1,
			Sequence:      uint64(index + 1),
			Source:        verifierevents.SourceUART,
			Event:         expected.Event,
			FailureCode:   expected.FailureCode,
		}
		switch expected.DetailStage {
		case VerifierDetailNone:
		case VerifierDetailRelease:
			record.PolicyDigest = testDigest(40001)
			record.ManifestDigest = testDigest(40002)
		case VerifierDetailBootstrap:
			record.PolicyDigest = testDigest(40001)
			record.ManifestDigest = testDigest(40002)
			record.BootstrapPublicKey = verifierTestBootstrapKey
		case VerifierDetailAuthorization:
			record.PolicyDigest = testDigest(40001)
			record.ManifestDigest = testDigest(40002)
			record.BootstrapPublicKey = verifierTestBootstrapKey
			record.OneBootPublicKey = verifierTestOneBootKey
		default:
			t.Fatalf("run %q has unsupported detail stage %q", run.RunID, expected.DetailStage)
		}
		if err := record.Validate(); err != nil {
			t.Fatalf("construct trace for run %q record %d: %v", run.RunID, index+1, err)
		}
		records[index] = record
	}
	return records
}

func cloneVerifierRecords(records []verifierevents.Record) []verifierevents.Record {
	return append([]verifierevents.Record(nil), records...)
}

func assertVerifierTraceEqual(
	t *testing.T,
	runID string,
	actual, expected []VerifierEventExpectation,
) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("run %q trace length = %d, want %d", runID, len(actual), len(expected))
	}
	for index := range expected {
		if actual[index] != expected[index] {
			t.Fatalf("run %q trace position %d = %#v, want %#v", runID, index+1, actual[index], expected[index])
		}
	}
}
