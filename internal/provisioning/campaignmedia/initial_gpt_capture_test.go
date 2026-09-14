package campaignmedia

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Metadata fixtures deliberately cannot serve payload bytes. A missing capture
// region is an error, rather than an invented zero-filled part of the device.
type initialGPTMetadataCapture struct {
	SchemaVersion          string `json:"schema_version"`
	SourceKind             string `json:"source_kind"`
	SourceDescription      string `json:"source_description"`
	CapturedAt             string `json:"captured_at"`
	CaptureToolSHA256      string `json:"capture_tool_sha256"`
	CapacityBytes          uint64 `json:"capacity_bytes"`
	LogicalSectorSizeBytes uint64 `json:"logical_sector_size_bytes"`
	Regions                []struct {
		OffsetBytes uint64 `json:"offset_bytes"`
		Data        []byte `json:"data_base64"`
		SHA256      string `json:"sha256"`
	} `json:"regions"`
}

func decodeInitialGPTMetadataCapture(encoded []byte) (*initialGPTMetadataCapture, error) {
	if len(encoded) > 128*1024 {
		return nil, fmt.Errorf("metadata capture exceeds 128 KiB")
	}
	var capture initialGPTMetadataCapture
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&capture); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("metadata capture has trailing JSON")
	}
	if capture.SchemaVersion != "kaiba-gpt-metadata-capture-v1" || capture.LogicalSectorSizeBytes != LogicalSectorSizeBytes ||
		capture.CapacityBytes < 68*LogicalSectorSizeBytes || capture.CapacityBytes%LogicalSectorSizeBytes != 0 || strings.TrimSpace(capture.SourceDescription) == "" {
		return nil, fmt.Errorf("invalid metadata capture format, geometry, or provenance")
	}
	switch capture.SourceKind {
	case "synthetic-reconstruction":
		if capture.CapturedAt != "" || capture.CaptureToolSHA256 != "" {
			return nil, fmt.Errorf("reconstructed fixture must not claim a capture timestamp or tool digest")
		}
	case "image-file", "block-device-readback":
		if _, err := time.Parse(time.RFC3339Nano, capture.CapturedAt); err != nil {
			return nil, fmt.Errorf("capture timestamp: %w", err)
		}
		if digest, err := hex.DecodeString(capture.CaptureToolSHA256); err != nil || len(digest) != sha256.Size {
			return nil, fmt.Errorf("capture tool digest is missing or invalid")
		}
	default:
		return nil, fmt.Errorf("unknown capture source kind %q", capture.SourceKind)
	}
	var end, total uint64
	for _, region := range capture.Regions {
		size := uint64(len(region.Data))
		if size == 0 || region.OffsetBytes%LogicalSectorSizeBytes != 0 || size%LogicalSectorSizeBytes != 0 ||
			region.OffsetBytes < end || region.OffsetBytes > capture.CapacityBytes || size > capture.CapacityBytes-region.OffsetBytes {
			return nil, fmt.Errorf("invalid, overlapping, or out-of-bounds capture region")
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(region.Data)); got != region.SHA256 {
			return nil, fmt.Errorf("capture region digest mismatch at %d", region.OffsetBytes)
		}
		end = region.OffsetBytes + size
		total += size
	}
	if total == 0 || total > 100*LogicalSectorSizeBytes {
		return nil, fmt.Errorf("capture must contain at most 100 sectors of GPT metadata")
	}
	return &capture, nil
}

func (capture *initialGPTMetadataCapture) ReadAt(destination []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, fmt.Errorf("negative metadata offset")
	}
	for _, region := range capture.Regions {
		if uint64(offset) >= region.OffsetBytes && uint64(offset) < region.OffsetBytes+uint64(len(region.Data)) {
			count := copy(destination, region.Data[uint64(offset)-region.OffsetBytes:])
			if count == len(destination) {
				return count, nil
			}
			return count, io.ErrUnexpectedEOF
		}
	}
	return 0, fmt.Errorf("byte range at %d was not captured", offset)
}

func TestInitialGPTMetadataCaptureCorpus(t *testing.T) {
	paths, err := filepath.Glob("testdata/gpt-captures/*.capture.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("find metadata captures: %v (%d fixtures)", err, len(paths))
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			encoded, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			capture, err := decodeInitialGPTMetadataCapture(encoded)
			if err != nil {
				t.Fatal(err)
			}
			var expected struct {
				Leg              Leg                        `json:"leg"`
				DiskGUID         string                     `json:"disk_guid"`
				FirstUsableLBA   uint64                     `json:"first_usable_lba"`
				Placement        InitialGPTPlacement        `json:"placement"`
				PhysicalEndState InitialGPTPhysicalEndState `json:"physical_end_state"`
			}
			encoded, err = os.ReadFile(strings.TrimSuffix(path, ".capture.json") + ".expect.json")
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded, &expected); err != nil {
				t.Fatal(err)
			}
			identity := testInitialGPTIdentity()
			policy := initialGPTUsableRangeStrict
			switch expected.Leg {
			case LegMalakSD:
			case LegPiLocalNVMe:
				identity = testInitialGPTNVMeIdentity()
				policy = initialGPTUsableRangeV1Alpha2PiLocalNVMe
			default:
				t.Fatalf("unknown fixture leg %q", expected.Leg)
			}
			identity.DiskGUID = expected.DiskGUID
			if err := identity.Validate(); err != nil {
				t.Fatal(err)
			}
			if capture.CapacityBytes != identity.CapacityBytes {
				t.Fatal("capture capacity does not match the fixed campaign identity")
			}
			snapshot, captured, err := captureInitialGPTWithPhysicalEndPolicy(capture, capture.CapacityBytes, false, policy)
			if err != nil {
				t.Fatal(err)
			}
			if err := snapshot.validateWithUsableRangePolicy(identity, policy); err != nil {
				t.Fatal(err)
			}
			if snapshot.FirstUsableLBA != expected.FirstUsableLBA || snapshot.Placement != expected.Placement {
				t.Fatalf("metadata differs from reviewed expectation: %+v", snapshot)
			}
			state := InitialGPTPhysicalEndSelectedLineageBackup
			if snapshot.Placement == InitialGPTPlacementImageSized {
				state = InitialGPTPhysicalEndNonGPTPreimage
				header, ok := capturedInitialGPTBytes(captured, capture.CapacityBytes-LogicalSectorSizeBytes, LogicalSectorSizeBytes)
				if !ok {
					t.Fatal("physical-end sector was not captured")
				}
				if bytes.Equal(header[:8], []byte("EFI PART")) {
					if _, _, err := inspectPhysicalEndBackupLineage(capture, identity, snapshot, header); err != nil {
						t.Fatal(err)
					}
					state = InitialGPTPhysicalEndDistinctBackupLineage
				}
			}
			if state != expected.PhysicalEndState {
				t.Fatalf("physical-end state = %q; want %q", state, expected.PhysicalEndState)
			}
		})
	}
}

func TestInitialGPTMetadataCaptureRejectsChangedOrMissingBytes(t *testing.T) {
	encoded, err := os.ReadFile("testdata/gpt-captures/reconstructed-aligned-nvme.capture.json")
	if err != nil {
		t.Fatal(err)
	}
	capture, err := decodeInitialGPTMetadataCapture(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := capture.ReadAt(make([]byte, LogicalSectorSizeBytes), int64(PiLocalNVMeReleaseStartBytes)); err == nil {
		t.Fatal("metadata-only capture invented payload bytes")
	}
	capture.Regions[0].Data[0] ^= 1
	changed, err := json.Marshal(capture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeInitialGPTMetadataCapture(changed); err == nil {
		t.Fatal("metadata capture accepted bytes that differ from its recorded digest")
	}
}
