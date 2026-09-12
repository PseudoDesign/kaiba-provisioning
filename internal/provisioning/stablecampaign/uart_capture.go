package stablecampaign

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/verifierevents"
)

var (
	verifierEventSchemaFamilyMarker = []byte("kaiba.provisioning.rpi5-stable-verifier-event/")
	verifierEventCanonicalLead      = []byte(`{"schema_version":"`)
)

// verifyCompleteUARTVerifierEventCapture treats the supplied UART bytes as the
// complete bounded capture for recognized verifier-event schema lines. Console
// framing before a canonical JSON event is permitted, but each schema-family
// marker must identify exactly one strict event and that event must be covered
// by the next verifier-event RecordRef at its exact JSON range (with at most the
// line's trailing LF included).
func verifyCompleteUARTVerifierEventCapture(raw []byte, references []RecordRef) error {
	verifierReferences := make([]RecordRef, 0)
	for _, reference := range references {
		if reference.Kind == RecordKindVerifierEvent {
			verifierReferences = append(verifierReferences, reference)
		}
	}

	seenDigests := make(map[bundle.Digest]uint64, len(verifierReferences))
	referenceIndex := 0
	for lineStart := 0; lineStart < len(raw); {
		lineEnd := len(raw)
		if relativeLF := bytes.IndexByte(raw[lineStart:], '\n'); relativeLF >= 0 {
			lineEnd = lineStart + relativeLF + 1
		}
		line := raw[lineStart:lineEnd]
		content := line
		hasLF := false
		hasCRLF := false
		if len(content) > 0 && content[len(content)-1] == '\n' {
			hasLF = true
			content = content[:len(content)-1]
			if len(content) > 0 && content[len(content)-1] == '\r' {
				hasCRLF = true
				content = content[:len(content)-1]
			}
		}

		markerCount := bytes.Count(content, verifierEventSchemaFamilyMarker)
		if markerCount > 1 {
			return fmt.Errorf(
				"UART line at byte %d contains %d recognized verifier schema-family markers; want at most one",
				lineStart,
				markerCount,
			)
		}
		if markerCount == 1 {
			markerOffset := bytes.Index(content, verifierEventSchemaFamilyMarker)
			candidateStartInLine := markerOffset - len(verifierEventCanonicalLead)
			if candidateStartInLine < 0 ||
				!bytes.Equal(content[candidateStartInLine:markerOffset], verifierEventCanonicalLead) {
				return fmt.Errorf(
					"UART line at byte %d contains a malformed or noncanonical recognized verifier event",
					lineStart,
				)
			}

			candidate := content[candidateStartInLine:]
			record, err := verifierevents.Parse(candidate)
			if err != nil {
				return fmt.Errorf(
					"UART line at byte %d contains an invalid recognized verifier event: %w",
					lineStart,
					err,
				)
			}
			digest, err := record.Digest()
			if err != nil {
				return fmt.Errorf("digest recognized UART verifier event at byte %d: %w", lineStart, err)
			}
			candidateOffset := uint64(lineStart + candidateStartInLine)
			if previousOffset, duplicate := seenDigests[digest]; duplicate {
				return fmt.Errorf(
					"UART verifier event at byte %d duplicates the recognized event at byte %d",
					candidateOffset,
					previousOffset,
				)
			}
			seenDigests[digest] = candidateOffset

			if referenceIndex >= len(verifierReferences) {
				return fmt.Errorf("recognized UART verifier event at byte %d is not indexed by record_refs", candidateOffset)
			}
			reference := verifierReferences[referenceIndex]
			if reference.RawRole != RawRoleUARTCapture {
				return errors.New("verifier-event record_ref is not bound to the UART capture")
			}
			canonicalEnd := candidateOffset + uint64(len(candidate))
			referenceEnd := reference.OffsetBytes + reference.SizeBytes
			endMatches := referenceEnd == canonicalEnd
			// A bare LF may be included in the strict verifier event range.
			// For raw serial CRLF framing the range must end at the canonical
			// JSON: including CR would make the verifier record noncanonical,
			// and a range cannot skip CR to include only LF.
			if hasLF && !hasCRLF {
				endMatches = endMatches || referenceEnd == canonicalEnd+1
			}
			if reference.OffsetBytes != candidateOffset || !endMatches {
				return fmt.Errorf(
					"recognized UART verifier event at byte %d is not covered by verifier record_ref %d at its exact canonical range and order",
					candidateOffset,
					referenceIndex,
				)
			}
			if reference.RecordDigest != digest {
				return fmt.Errorf(
					"recognized UART verifier event at byte %d differs from verifier record_ref %d domain digest",
					candidateOffset,
					referenceIndex,
				)
			}
			referenceIndex++
		}
		lineStart = lineEnd
	}

	if referenceIndex != len(verifierReferences) {
		return fmt.Errorf(
			"UART capture contains %d recognized verifier events, but record_refs indexes %d",
			referenceIndex,
			len(verifierReferences),
		)
	}
	return nil
}
