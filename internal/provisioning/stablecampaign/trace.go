package stablecampaign

import (
	"errors"
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/verifierevents"
)

// VerifyVerifierEventTrace verifies the complete parsed verifier trace for one
// physical run. It derives the expectation from the independently validated
// campaign plan and run index; callers cannot supply an expected outcome.
func VerifyVerifierEventTrace(
	plan Plan,
	runIndex uint16,
	records []verifierevents.Record,
) error {
	runs, err := ExpectedRuns(plan)
	if err != nil {
		return fmt.Errorf("verify verifier event trace: %w", err)
	}
	if runIndex == 0 || int(runIndex) > len(runs) {
		return fmt.Errorf("verify verifier event trace: run_index must be between 1 and %d", len(runs))
	}
	expected := runs[runIndex-1].VerifierTrace
	if len(records) != len(expected) {
		return fmt.Errorf(
			"verify verifier event trace for run %d: got %d records, want exactly %d",
			runIndex,
			len(records),
			len(expected),
		)
	}

	var invariants verifierTraceInvariants
	for index, record := range records {
		position := index + 1
		if err := record.Validate(); err != nil {
			return fmt.Errorf("verify verifier event trace for run %d record %d: %w", runIndex, position, err)
		}
		if record.Sequence != uint64(position) {
			return fmt.Errorf(
				"verify verifier event trace for run %d record %d: sequence is %d, want %d",
				runIndex,
				position,
				record.Sequence,
				position,
			)
		}

		want := expected[index]
		if record.Event != want.Event {
			return fmt.Errorf(
				"verify verifier event trace for run %d record %d: event is %q, want %q",
				runIndex,
				position,
				record.Event,
				want.Event,
			)
		}
		if record.FailureCode != want.FailureCode {
			return fmt.Errorf(
				"verify verifier event trace for run %d record %d: failure_code is %q, want %q",
				runIndex,
				position,
				record.FailureCode,
				want.FailureCode,
			)
		}
		stage, err := verifierRecordDetailStage(record)
		if err != nil {
			return fmt.Errorf("verify verifier event trace for run %d record %d: %w", runIndex, position, err)
		}
		if stage != want.DetailStage {
			return fmt.Errorf(
				"verify verifier event trace for run %d record %d: detail stage is %q, want %q",
				runIndex,
				position,
				stage,
				want.DetailStage,
			)
		}
		if err := invariants.observe(record); err != nil {
			return fmt.Errorf("verify verifier event trace for run %d record %d: %w", runIndex, position, err)
		}
	}
	return nil
}

func verifierRecordDetailStage(record verifierevents.Record) (VerifierDetailStage, error) {
	hasPolicy := record.PolicyDigest != ""
	hasManifest := record.ManifestDigest != ""
	hasBootstrap := record.BootstrapPublicKey != ""
	hasOneBoot := record.OneBootPublicKey != ""
	switch {
	case !hasPolicy && !hasManifest && !hasBootstrap && !hasOneBoot:
		return VerifierDetailNone, nil
	case hasPolicy && hasManifest && !hasBootstrap && !hasOneBoot:
		return VerifierDetailRelease, nil
	case hasPolicy && hasManifest && hasBootstrap && !hasOneBoot:
		return VerifierDetailBootstrap, nil
	case hasPolicy && hasManifest && hasBootstrap && hasOneBoot:
		return VerifierDetailAuthorization, nil
	default:
		return "", errors.New("record contains an incomplete verifier detail stage")
	}
}

type verifierTraceInvariants struct {
	policyDigest       string
	manifestDigest     string
	bootstrapPublicKey string
	oneBootPublicKey   string
}

func (invariants *verifierTraceInvariants) observe(record verifierevents.Record) error {
	if err := observeVerifierInvariant(
		"policy_digest",
		string(record.PolicyDigest),
		&invariants.policyDigest,
	); err != nil {
		return err
	}
	if err := observeVerifierInvariant(
		"manifest_digest",
		string(record.ManifestDigest),
		&invariants.manifestDigest,
	); err != nil {
		return err
	}
	if err := observeVerifierInvariant(
		"bootstrap_public_key",
		record.BootstrapPublicKey,
		&invariants.bootstrapPublicKey,
	); err != nil {
		return err
	}
	return observeVerifierInvariant(
		"one_boot_public_key",
		record.OneBootPublicKey,
		&invariants.oneBootPublicKey,
	)
}

func observeVerifierInvariant(name, value string, retained *string) error {
	if value == "" {
		return nil
	}
	if *retained == "" {
		*retained = value
		return nil
	}
	if value != *retained {
		return fmt.Errorf("%s changed after it was introduced", name)
	}
	return nil
}
