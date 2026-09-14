package campaignpacket

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

func TestPayloadChecksActualSourceAndCompleteZeroTail(t *testing.T) {
	for _, size := range []int{1, 128*1024 - 1, 128 * 1024, 128*1024 + 1, 256*1024 + 7} {
		contents := bytes.Repeat([]byte{0xa7}, size)
		complete := append(append([]byte(nil), contents...), make([]byte, 128*1024+3)...)
		partition := campaignmedia.Partition{
			SourceSizeBytes: uint64(len(contents)), SourceSHA256: bundle.Sum(contents),
			CapacityBytes: uint64(len(complete)), ZeroTailBytes: uint64(len(complete) - len(contents)),
			ExpectedWholePartitionSHA256: bundle.Sum(complete),
		}
		source := stablecampaign.PublicArtifactSource{SizeBytes: uint64(size), ReaderAt: bytes.NewReader(contents)}
		if err := verifyPayload(source, partition); err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		changedSource := append([]byte(nil), contents...)
		changedSource[len(changedSource)-1] ^= 1
		changed := source
		changed.ReaderAt = bytes.NewReader(changedSource)
		if err := verifyPayload(changed, partition); err == nil {
			t.Fatal("accepted substituted payload bytes")
		}
		changedPartition := partition
		changedPartition.ExpectedWholePartitionSHA256 = bundle.Sum(append(contents, 1))
		if err := verifyPayload(source, changedPartition); err == nil {
			t.Fatal("accepted incorrect padded partition digest")
		}
		changedPartition = partition
		changedPartition.ZeroTailBytes--
		if err := verifyPayload(source, changedPartition); err == nil {
			t.Fatal("accepted detached padding geometry")
		}
	}
}

type failingReader struct{}

func (failingReader) ReadAt([]byte, int64) (int, error) {
	return 0, errors.New("injected source I/O failure")
}

type fullEOFReader struct{ *bytes.Reader }

func (reader fullEOFReader) ReadAt(buffer []byte, offset int64) (int, error) {
	n, _ := reader.Reader.ReadAt(buffer, offset)
	return n, io.EOF
}

func TestPayloadFailsClosedOnUnreadableOrMisSizedSource(t *testing.T) {
	contents := []byte("source bytes")
	partition := campaignmedia.Partition{SourceSizeBytes: uint64(len(contents)), CapacityBytes: uint64(len(contents)), SourceSHA256: bundle.Sum(contents), ExpectedWholePartitionSHA256: bundle.Sum(contents)}
	for _, source := range []stablecampaign.PublicArtifactSource{
		{SizeBytes: uint64(len(contents)), ReaderAt: failingReader{}},
		{SizeBytes: uint64(len(contents)), ReaderAt: bytes.NewReader(contents[:len(contents)-1])},
		{SizeBytes: uint64(len(contents))},
		{SizeBytes: uint64(len(contents)), ReaderAt: (*bytes.Reader)(nil)},
		{SizeBytes: uint64(len(contents) - 1), ReaderAt: bytes.NewReader(contents)},
	} {
		if err := verifyPayload(source, partition); err == nil {
			t.Fatal("accepted missing, truncated, or failed source")
		}
	}
	if err := verifyPayload(stablecampaign.PublicArtifactSource{SizeBytes: uint64(len(contents)), ReaderAt: fullEOFReader{bytes.NewReader(contents)}}, partition); err != nil {
		t.Fatalf("complete EOF read is valid ReaderAt behavior: %v", err)
	}
}

func TestSourceRevisionCannotBeAnAmbiguousGitReference(t *testing.T) {
	for _, revision := range []string{"", "main", strings.Repeat("a", 39), strings.Repeat("A", 40), strings.Repeat("a", 40) + "\n", "$(id)"} {
		if _, err := Prepare(Input{SourceRevision: revision}); err == nil || !strings.Contains(err.Error(), "source revision") {
			t.Fatalf("revision %q did not fail before source processing: %v", revision, err)
		}
	}
	if _, err := (Report{}).CanonicalJSON(); err == nil {
		t.Fatal("zero value fabricated a preparation packet")
	}
}
