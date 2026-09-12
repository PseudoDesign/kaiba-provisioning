package stablecampaign

import (
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/verifierevents"
)

// RawEvidenceValidation reports only the mechanical and parser coverage that
// ValidateRawEvidence completed. It deliberately has no pass, status, or
// observed-disposition field.
type RawEvidenceValidation struct {
	RawBindingsVerified     int
	RangeBindingsVerified   int
	VerifierRecordsVerified int
	UnparsedRecordKinds     []RecordKind
}

// ValidateRawEvidence verifies the supplied in-memory public evidence against
// a sealed result. It checks every whole-file size and SHA-256 binding, every
// referenced byte-range SHA-256 binding, each verifier-event domain digest,
// and the exact verifier trace derived from plan.
//
// The media-readback, released-OS, authority-audit, and power-observation
// records are intentionally left semantically unparsed by this mechanical
// method: their bytes are integrity-checked and their kinds are returned in
// UnparsedRecordKinds. CheckEvidenceConsistency is the separate, stricter API
// that parses and cross-checks them without deriving a claim result or
// disposition. CaptureID prevents a sealed binding from being transplanted
// across campaign/run/capture contexts; without a trusted source that emits or
// attests the ID, it is not proof of temporal freshness by itself.
func (result ExecutionResult) ValidateRawEvidence(
	plan Plan,
	supplied map[RawRole][]byte,
) (RawEvidenceValidation, error) {
	var validation RawEvidenceValidation
	if err := result.ValidateAgainst(plan); err != nil {
		return validation, fmt.Errorf("validate raw evidence envelope: %w", err)
	}
	if len(supplied) != len(result.RawFiles) {
		return validation, fmt.Errorf(
			"supplied raw evidence must contain the exact %d bound roles",
			len(result.RawFiles),
		)
	}

	for index, binding := range result.RawFiles {
		encoded, ok := supplied[binding.Role]
		if !ok {
			return validation, fmt.Errorf("supplied raw evidence is missing role %q", binding.Role)
		}
		if uint64(len(encoded)) != binding.SizeBytes {
			return validation, fmt.Errorf(
				"raw_files[%d] role %q size is %d, want %d",
				index,
				binding.Role,
				len(encoded),
				binding.SizeBytes,
			)
		}
		if digest := bundle.Sum(encoded); digest != binding.Digest {
			return validation, fmt.Errorf(
				"raw_files[%d] role %q digest does not match supplied bytes",
				index,
				binding.Role,
			)
		}
		validation.RawBindingsVerified++
	}

	verifierRecords := make([]verifierevents.Record, 0)
	unparsed := make(map[RecordKind]struct{})
	for index, reference := range result.RecordRefs {
		raw := supplied[reference.RawRole]
		end := reference.OffsetBytes + reference.SizeBytes
		// ValidateAgainst has already proved the range is nonempty, in bounds,
		// and non-overflowing. Raw evidence is bounded to four MiB, so these
		// conversions are safe on every supported Go architecture.
		rangeBytes := raw[int(reference.OffsetBytes):int(end)]
		if digest := bundle.Sum(rangeBytes); digest != reference.RawRangeDigest {
			return validation, fmt.Errorf(
				"record_refs[%d] raw_range_digest does not match the referenced bytes",
				index,
			)
		}
		validation.RangeBindingsVerified++

		switch reference.Kind {
		case RecordKindVerifierEvent:
			record, err := verifierevents.Parse(rangeBytes)
			if err != nil {
				return validation, fmt.Errorf("record_refs[%d] verifier event: %w", index, err)
			}
			digest, err := record.Digest()
			if err != nil {
				return validation, fmt.Errorf("record_refs[%d] verifier event digest: %w", index, err)
			}
			if digest != reference.RecordDigest {
				return validation, fmt.Errorf(
					"record_refs[%d].record_digest does not match the verifier event",
					index,
				)
			}
			verifierRecords = append(verifierRecords, record)
			validation.VerifierRecordsVerified++
		default:
			if _, seen := unparsed[reference.Kind]; !seen {
				unparsed[reference.Kind] = struct{}{}
				validation.UnparsedRecordKinds = append(validation.UnparsedRecordKinds, reference.Kind)
			}
		}
	}

	if err := VerifyVerifierEventTrace(plan, result.RunIndex, verifierRecords); err != nil {
		return validation, err
	}
	return validation, nil
}
