package verifierevents

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const canonicalStartedRecord = `{"schema_version":"kaiba.provisioning.rpi5-stable-verifier-event/v1alpha1","sequence":1,"source":"verifier-uart","event":"verifier-started"}`

func TestEmitterProducesContiguousCanonicalRecords(t *testing.T) {
	var output bytes.Buffer
	emitter, err := New(&output)
	if err != nil {
		t.Fatal(err)
	}
	first, firstDigest, err := emitter.Emit(EventStarted, Details{})
	if err != nil {
		t.Fatal(err)
	}
	second, secondDigest, err := emitter.Emit(EventReleaseVerified, Details{
		PolicyDigest: testDigest, ManifestDigest: testDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 1 || second.Sequence != 2 {
		t.Fatalf("unexpected sequences %d and %d", first.Sequence, second.Sequence)
	}
	if firstDigest == secondDigest || firstDigest == "" || secondDigest == "" {
		t.Fatalf("unexpected record digests %q and %q", firstDigest, secondDigest)
	}
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) != 2 || !strings.Contains(lines[1], `"event":"release-verified"`) {
		t.Fatalf("unexpected UART records %q", output.String())
	}
}

func TestParseRoundTripsEmitterWithOptionalTrailingLF(t *testing.T) {
	var output bytes.Buffer
	emitter, err := New(&output)
	if err != nil {
		t.Fatal(err)
	}
	emitted, emittedDigest, err := emitter.Emit(EventStarted, Details{})
	if err != nil {
		t.Fatal(err)
	}
	if output.String() != canonicalStartedRecord+"\n" {
		t.Fatalf("emitted record = %q, want canonical record with one LF", output.String())
	}

	for name, encoded := range map[string][]byte{
		"canonical JSON":      []byte(canonicalStartedRecord),
		"canonical JSON line": []byte(canonicalStartedRecord + "\n"),
	} {
		t.Run(name, func(t *testing.T) {
			parsed, err := Parse(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if parsed != emitted {
				t.Fatalf("parsed record = %#v, want %#v", parsed, emitted)
			}
			parsedDigest, err := parsed.Digest()
			if err != nil {
				t.Fatal(err)
			}
			if parsedDigest != emittedDigest {
				t.Fatalf("parsed digest = %q, emitted digest = %q", parsedDigest, emittedDigest)
			}
		})
	}
}

func TestRecordDigestMatchesEmitterDomain(t *testing.T) {
	record := Record{
		SchemaVersion: SchemaV1Alpha1,
		Sequence:      1,
		Source:        SourceUART,
		Event:         EventStarted,
	}
	digest, err := record.Digest()
	if err != nil {
		t.Fatal(err)
	}
	const expected = "sha256:2692a7f0fa143a86fc5c54320533fcb71df5cc5e7cd19c73464732aa97986ebc"
	if digest != expected {
		t.Fatalf("record digest = %q, want %q", digest, expected)
	}
	if _, err := (Record{}).Digest(); err == nil {
		t.Fatal("invalid record produced a digest")
	}
}

func TestPopulatedRecordDigestFixedVector(t *testing.T) {
	record := Record{
		SchemaVersion:      SchemaV1Alpha1,
		Sequence:           7,
		Source:             SourceUART,
		Event:              EventHandoffExecuting,
		PolicyDigest:       testDigest,
		ManifestDigest:     "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		BootstrapPublicKey: "ed25519:" + strings.Repeat("c", 64),
		OneBootPublicKey:   "ed25519:" + strings.Repeat("d", 64),
	}
	digest, err := record.Digest()
	if err != nil {
		t.Fatal(err)
	}
	const expected = "sha256:3b3ba111044a5942075bd51e5fabbc3297bfb80f2a522f67a5ebe2e369b25fb3"
	if digest != expected {
		t.Fatalf("populated record digest = %q, want %q", digest, expected)
	}
}

func TestParseEnforcesEncodedBounds(t *testing.T) {
	tests := map[string][]byte{
		"one byte over without LF": bytes.Repeat([]byte{'x'}, MaxRecordBytes+1),
		"one byte over plus LF":    append(bytes.Repeat([]byte{'x'}, MaxRecordBytes+1), '\n'),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(encoded)
			if err == nil || !strings.Contains(err.Error(), "size") {
				t.Fatalf("Parse() error = %v, want size rejection", err)
			}
		})
	}
}

func TestParseRejectsAmbiguousOrNoncanonicalRecords(t *testing.T) {
	tests := []struct {
		name    string
		encoded []byte
	}{
		{name: "empty"},
		{name: "newline only", encoded: []byte("\n")},
		{name: "malformed", encoded: []byte("{")},
		{name: "top-level null", encoded: []byte("null")},
		{
			name:    "field null",
			encoded: []byte(`{"schema_version":"kaiba.provisioning.rpi5-stable-verifier-event/v1alpha1","sequence":1,"source":"verifier-uart","event":null}`),
		},
		{
			name:    "duplicate key",
			encoded: []byte(`{"schema_version":"kaiba.provisioning.rpi5-stable-verifier-event/v1alpha1","sequence":1,"source":"verifier-uart","event":"verifier-started","event":"verifier-started"}`),
		},
		{
			name:    "escaped equivalent duplicate key",
			encoded: []byte(`{"schema_version":"kaiba.provisioning.rpi5-stable-verifier-event/v1alpha1","sequence":1,"source":"verifier-uart","event":"verifier-started","\u0065vent":"verifier-started"}`),
		},
		{
			name:    "unknown field",
			encoded: []byte(`{"schema_version":"kaiba.provisioning.rpi5-stable-verifier-event/v1alpha1","sequence":1,"source":"verifier-uart","event":"verifier-started","future":"value"}`),
		},
		{name: "trailing value", encoded: []byte(canonicalStartedRecord + `{}`)},
		{name: "double trailing LF", encoded: []byte(canonicalStartedRecord + "\n\n")},
		{name: "CRLF", encoded: []byte(canonicalStartedRecord + "\r\n")},
		{name: "leading whitespace", encoded: []byte(" " + canonicalStartedRecord)},
		{name: "trailing whitespace", encoded: []byte(canonicalStartedRecord + " ")},
		{
			name:    "noncanonical field order",
			encoded: []byte(`{"sequence":1,"schema_version":"kaiba.provisioning.rpi5-stable-verifier-event/v1alpha1","source":"verifier-uart","event":"verifier-started"}`),
		},
		{
			name:    "noncanonical explicit empty optional field",
			encoded: []byte(canonicalStartedRecord[:len(canonicalStartedRecord)-1] + `,"failure_code":""}`),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if record, err := Parse(test.encoded); err == nil {
				t.Fatalf("Parse() accepted %#v", record)
			}
		})
	}
}

func TestInspectJSONRejectsNestedDuplicateKeysAndNulls(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
		want    string
	}{
		{
			name:    "duplicate key in nested object",
			encoded: `{"outer":{"value":"first","value":"second"}}`,
			want:    `duplicate JSON key "value" at $.outer`,
		},
		{
			name:    "null in object nested in array",
			encoded: `{"outer":[{"value":null}]}`,
			want:    `JSON null is not allowed at $.outer[0].value`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := inspectJSON([]byte(test.encoded))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("inspectJSON() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestInspectJSONBoundsNestingBeforeTypedDecode(t *testing.T) {
	encoded := strings.Repeat(`{"nested":`, 65) + `true` + strings.Repeat(`}`, 65)
	err := inspectJSON([]byte(encoded))
	if err == nil || !strings.Contains(err.Error(), "nesting exceeds 64 levels") {
		t.Fatalf("inspectJSON() deep-nesting error = %v", err)
	}
}

func TestParseRejectsSemanticallyInvalidRecords(t *testing.T) {
	record := func(sequence uint64, event, details string) []byte {
		return []byte(fmt.Sprintf(
			`{"schema_version":"%s","sequence":%d,"source":"%s","event":"%s"%s}`,
			SchemaV1Alpha1,
			sequence,
			SourceUART,
			event,
			details,
		))
	}
	tests := map[string][]byte{
		"zero sequence":          record(0, EventStarted, ""),
		"sequence above maximum": record(maxSequence+1, EventStarted, ""),
		"incomplete release stage": record(
			1,
			EventReleaseVerified,
			`,"policy_digest":"`+testDigest+`"`,
		),
		"invalid digest": record(
			1,
			EventReleaseVerified,
			`,"policy_digest":"sha256:bad","manifest_digest":"`+testDigest+`"`,
		),
		"invalid bootstrap key": record(
			1,
			EventBootstrapKeyReady,
			`,"policy_digest":"`+testDigest+`","manifest_digest":"`+testDigest+`","bootstrap_public_key":"ed25519:bad"`,
		),
		"failed event without failure code": record(1, EventFailed, ""),
		"non-failed event with failure code": record(
			1,
			EventStarted,
			`,"failure_code":"unexpected"`,
		),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			if parsed, err := Parse(encoded); err == nil {
				t.Fatalf("Parse() accepted semantically invalid record %#v", parsed)
			}
		})
	}
}

func TestEmitterRequiresFailureCode(t *testing.T) {
	emitter, err := New(&bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := emitter.Emit(EventFailed, Details{}); err == nil {
		t.Fatal("failed event without a failure code was accepted")
	}
	if _, _, err := emitter.Emit(EventStarted, Details{FailureCode: "unexpected"}); err == nil {
		t.Fatal("non-failure event with a failure code was accepted")
	}
}

func TestEmitterRejectsPrivateKeyShapedField(t *testing.T) {
	emitter, err := New(&bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := emitter.Emit(EventBootstrapKeyReady, Details{
		BootstrapPublicKey: "ed25519:" + strings.Repeat("f", 128),
	}); err == nil {
		t.Fatal("private-key-sized value was accepted as a public key")
	}
}

func TestEmitterRejectsUnknownAndIncompleteStageEvents(t *testing.T) {
	emitter, err := New(&bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := emitter.Emit("future-event", Details{}); err == nil {
		t.Fatal("unknown event was accepted")
	}
	if _, _, err := emitter.Emit(EventReleaseVerified, Details{PolicyDigest: testDigest}); err == nil {
		t.Fatal("release event with a partial digest stage was accepted")
	}
	if _, _, err := emitter.Emit(EventAuthorizationReady, Details{
		PolicyDigest: testDigest, ManifestDigest: testDigest,
		BootstrapPublicKey: "ed25519:" + strings.Repeat("a", 64),
	}); err == nil {
		t.Fatal("authorization event without the one-boot key was accepted")
	}
}

type shortWriter struct{}

func (shortWriter) Write(value []byte) (int, error) {
	return len(value) - 1, nil
}

func TestEmitterRejectsShortWritesWithoutAdvancingSequence(t *testing.T) {
	emitter, err := New(shortWriter{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := emitter.Emit(EventStarted, Details{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write error = %v, want io.ErrShortWrite", err)
	}
	if emitter.sequence != 0 {
		t.Fatalf("sequence advanced to %d after a short write", emitter.sequence)
	}
}
