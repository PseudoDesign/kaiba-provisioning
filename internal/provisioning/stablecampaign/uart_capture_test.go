package stablecampaign

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/verifierevents"
)

func TestEvidenceConsistencyAcceptsFramedVerifierEventsAndUnrelatedUARTLines(t *testing.T) {
	plan := validPlan(t)
	result, supplied, declared := semanticEvidenceFixture(t, plan, 1, nil)

	firstVerifierOffset := uint64(0)
	for _, reference := range result.RecordRefs {
		if reference.Kind == RecordKindVerifierEvent {
			firstVerifierOffset = reference.OffsetBytes
			break
		}
	}
	if firstVerifierOffset == 0 {
		t.Fatal("fixture has no verifier event after its console-noise prefix")
	}

	const framing = "[    0.812345] initramfs-verifier: "
	uart := supplied[RawRoleUARTCapture]
	framed := make([]byte, 0, len(uart)+len(framing))
	framed = append(framed, uart[:int(firstVerifierOffset)]...)
	framed = append(framed, framing...)
	framed = append(framed, uart[int(firstVerifierOffset):]...)
	result, supplied = rebindSemanticUARTFixture(t, plan, result, supplied, framed, func(references []RecordRef) {
		for index := range references {
			if references[index].RawRole == RawRoleUARTCapture &&
				references[index].OffsetBytes >= firstVerifierOffset {
				references[index].OffsetBytes += uint64(len(framing))
			}
		}
	})

	unrelated := []byte("ordinary released-kernel console output\n" +
		`{"schema_version":"another-console-schema/v1","event":"diagnostic"}` + "\n")
	framed = append(append([]byte(nil), supplied[RawRoleUARTCapture]...), unrelated...)
	result, supplied = rebindSemanticUARTFixture(t, plan, result, supplied, framed, nil)

	if _, err := result.CheckEvidenceConsistency(plan, supplied, declared); err != nil {
		t.Fatalf("framed verifier event or unrelated UART line was rejected: %v", err)
	}
}

func TestCompleteUARTScannerAcceptsRawSerialCRLFOutsideCanonicalEventRange(t *testing.T) {
	canonical := bytes.TrimSuffix(verifierEventTestLine(t, verifierevents.Record{
		SchemaVersion: verifierevents.SchemaV1Alpha1,
		Sequence:      1,
		Source:        verifierevents.SourceUART,
		Event:         verifierevents.EventStarted,
	}), []byte{'\n'})
	prefix := []byte("[    0.812345] initramfs-verifier: ")
	raw := append(append(append([]byte(nil), prefix...), canonical...), '\r', '\n')
	record, err := verifierevents.Parse(canonical)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := record.Digest()
	if err != nil {
		t.Fatal(err)
	}
	reference := RecordRef{
		Kind: RecordKindVerifierEvent, RawRole: RawRoleUARTCapture,
		OffsetBytes: uint64(len(prefix)), SizeBytes: uint64(len(canonical)), RecordDigest: digest,
	}
	if err := verifyCompleteUARTVerifierEventCapture(raw, []RecordRef{reference}); err != nil {
		t.Fatalf("raw serial CRLF framing was rejected: %v", err)
	}

	for name, suffix := range map[string][]byte{
		"stray CR before suffix": {'\r', 'x', '\n'},
		"CR without LF":          {'\r'},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := append(append(append([]byte(nil), prefix...), canonical...), suffix...)
			if err := verifyCompleteUARTVerifierEventCapture(mutated, []RecordRef{reference}); err == nil {
				t.Fatal("non-CRLF suffix was accepted")
			}
		})
	}
}

func TestEvidenceConsistencyRejectsUnaccountedVerifierSchemaLines(t *testing.T) {
	plan := validPlan(t)
	baselineResult, baselineSupplied, baselineDeclared := semanticEvidenceFixture(t, plan, 1, nil)
	firstVerifierLine := firstVerifierRecordBytes(t, baselineResult, baselineSupplied)

	validFailure := verifierEventTestLine(t, verifierevents.Record{
		SchemaVersion:      verifierevents.SchemaV1Alpha1,
		Sequence:           7,
		Source:             verifierevents.SourceUART,
		Event:              verifierevents.EventFailed,
		PolicyDigest:       testDigest(9600),
		ManifestDigest:     testDigest(9601),
		BootstrapPublicKey: semanticPublicKey('a'),
		OneBootPublicKey:   semanticPublicKey('b'),
		FailureCode:        "injected-contradiction",
	})
	validUnreferenced := verifierEventTestLine(t, verifierevents.Record{
		SchemaVersion: verifierevents.SchemaV1Alpha1,
		Sequence:      7,
		Source:        verifierevents.SourceUART,
		Event:         verifierevents.EventStarted,
	})
	malformed := []byte(`{"schema_version":"` + verifierevents.SchemaV1Alpha1 +
		`","sequence":7,"source":"verifier-uart","event":` + "\n")
	suffixed := append(append([]byte(nil), bytes.TrimSuffix(validUnreferenced, []byte{'\n'})...), []byte(" trailing-bytes\n")...)
	multiple := append(append([]byte(nil), bytes.TrimSuffix(validUnreferenced, []byte{'\n'})...), validFailure...)

	tests := []struct {
		name string
		line []byte
		want string
	}{
		{name: "extra contradictory failure", line: validFailure, want: "not indexed"},
		{name: "duplicate recognized event", line: firstVerifierLine, want: "duplicates"},
		{name: "malformed recognized-schema JSON", line: malformed, want: "recognized verifier event"},
		{name: "unreferenced recognized event", line: validUnreferenced, want: "not indexed"},
		{name: "suffix after canonical event", line: suffixed, want: "invalid recognized verifier event"},
		{name: "multiple recognized candidates on one line", line: multiple, want: "schema-family markers"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			uart := append(append([]byte(nil), baselineSupplied[RawRoleUARTCapture]...), test.line...)
			result, supplied := rebindSemanticUARTFixture(
				t, plan, baselineResult, baselineSupplied, uart, nil,
			)
			_, err := result.CheckEvidenceConsistency(plan, supplied, baselineDeclared)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("consistency error = %v, want rejection containing %q", err, test.want)
			}
		})
	}

	t.Run("extra contradictory success after a rejection trace", func(t *testing.T) {
		result, supplied, declared := semanticEvidenceFixture(t, plan, 2, nil)
		extraSuccess := verifierEventTestLine(t, verifierevents.Record{
			SchemaVersion:      verifierevents.SchemaV1Alpha1,
			Sequence:           5,
			Source:             verifierevents.SourceUART,
			Event:              verifierevents.EventHandoffExecuting,
			PolicyDigest:       testDigest(9600),
			ManifestDigest:     testDigest(9601),
			BootstrapPublicKey: semanticPublicKey('a'),
			OneBootPublicKey:   semanticPublicKey('b'),
		})
		uart := append(append([]byte(nil), supplied[RawRoleUARTCapture]...), extraSuccess...)
		result, supplied = rebindSemanticUARTFixture(t, plan, result, supplied, uart, nil)
		if _, err := result.CheckEvidenceConsistency(plan, supplied, declared); err == nil ||
			!strings.Contains(err.Error(), "not indexed") {
			t.Fatalf("extra contradictory success error = %v, want unindexed-event rejection", err)
		}
	})
}

func verifierEventTestLine(t *testing.T, record verifierevents.Record) []byte {
	t.Helper()
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if _, err := verifierevents.Parse(encoded); err != nil {
		t.Fatalf("test verifier event is not canonical: %v", err)
	}
	return encoded
}

func firstVerifierRecordBytes(
	t *testing.T,
	result ExecutionResult,
	supplied map[RawRole][]byte,
) []byte {
	t.Helper()
	for _, reference := range result.RecordRefs {
		if reference.Kind != RecordKindVerifierEvent {
			continue
		}
		end := reference.OffsetBytes + reference.SizeBytes
		return append([]byte(nil), supplied[RawRoleUARTCapture][int(reference.OffsetBytes):int(end)]...)
	}
	t.Fatal("fixture has no verifier-event reference")
	return nil
}

func rebindSemanticUARTFixture(
	t *testing.T,
	plan Plan,
	result ExecutionResult,
	supplied map[RawRole][]byte,
	uart []byte,
	adjustReferences func([]RecordRef),
) (ExecutionResult, map[RawRole][]byte) {
	t.Helper()
	changedSupplied := make(map[RawRole][]byte, len(supplied))
	for role, encoded := range supplied {
		changedSupplied[role] = append([]byte(nil), encoded...)
	}
	changedSupplied[RawRoleUARTCapture] = append([]byte(nil), uart...)

	rawFiles := append([]RawBinding(nil), result.RawFiles...)
	for index := range rawFiles {
		rawFiles[index].CaptureID = ""
		rawFiles[index].RawBindingDigest = ""
		if rawFiles[index].Role == RawRoleUARTCapture {
			rawFiles[index].Digest = bundle.Sum(uart)
			rawFiles[index].SizeBytes = uint64(len(uart))
		}
	}
	references := append([]RecordRef(nil), result.RecordRefs...)
	if adjustReferences != nil {
		adjustReferences(references)
	}
	for index := range references {
		references[index].CaptureID = ""
		references[index].RecordBindingDigest = ""
	}

	changed, err := NewExecutionResult(
		plan,
		result.RunIndex,
		result.CaptureID,
		rawFiles,
		references,
	)
	if err != nil {
		t.Fatalf("rebind UART fixture: %v", err)
	}
	return changed, changedSupplied
}
