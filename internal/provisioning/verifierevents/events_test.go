package verifierevents

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

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
