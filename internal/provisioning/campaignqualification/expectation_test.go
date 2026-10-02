package campaignqualification

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

type unreadable struct{}

func (unreadable) ReadAt([]byte, int64) (int, error) {
	return 0, errors.New("injected unreadable payload")
}

type shortReader struct{}

func (shortReader) ReadAt(p []byte, _ int64) (int, error) { return len(p) - 1, io.EOF }

func TestActualPayloadHashIncludesTheCompleteZeroTail(t *testing.T) {
	data := bytes.Repeat([]byte{0x17}, 512)
	artifact := campaignmedia.ArtifactSetEntry{SizeBytes: uint64(len(data)), Digest: digest(string(data))}
	actual, err := hashPayload(stablecampaign.PublicArtifactSource{ReaderAt: bytes.NewReader(data), SizeBytes: uint64(len(data))}, artifact, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if actual != digest(string(append(bytes.Clone(data), make([]byte, 512)...))) {
		t.Fatal("whole partition hash did not include the complete zero tail")
	}
	for _, source := range []stablecampaign.PublicArtifactSource{{ReaderAt: bytes.NewReader([]byte("altered")), SizeBytes: 512}, {ReaderAt: unreadable{}, SizeBytes: 512}, {ReaderAt: shortReader{}, SizeBytes: 512}, {ReaderAt: bytes.NewReader(data), SizeBytes: 511}, {SizeBytes: 512}} {
		if _, err := hashPayload(source, artifact, 1024); err == nil {
			t.Fatal("invalid actual payload accepted")
		}
	}
}

func TestDeclarationsCannotInitializeAnExpectation(t *testing.T) {
	if _, err := Prepare(Input{}); err == nil {
		t.Fatal("declarations without reviewed byte sources initialized an expectation")
	}
	if _, err := (Expectation{}).CanonicalJSON(); err == nil {
		t.Fatal("zero expectation serialized")
	}
	f := newFixture(t, 2)
	if _, err := Validate(Expectation{}, f.session, 1300, f.policy, f.result, f.raw, f.witnesses, f.supporting, &f.admission); err == nil {
		t.Fatal("zero expectation accepted")
	}
}
