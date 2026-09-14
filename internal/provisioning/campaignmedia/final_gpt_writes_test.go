package campaignmedia

import (
	"bytes"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

func TestFinalGPTWritesMatchIndependentStrictFixtures(t *testing.T) {
	plan := mustTestPlan(t)
	for i, device := range plan.Devices {
		t.Run(string(device.Identity.Leg), func(t *testing.T) {
			fixture := newInitialGPTFixture(t)
			if i == 1 {
				fixture = newInitialGPTNVMeFixture(t)
			}
			fixture.embeddedLBAs = device.Identity.CapacityBytes / LogicalSectorSizeBytes
			fixture.lastUsableLBA = fixture.embeddedLBAs - 34
			fixture.reader.regions = make(map[int64][]byte)
			fixture.rebuild(t)
			// The campaign's deterministic protective entry leaves legacy CHS
			// fields zero; the independently strict GPT parser accepts it.
			mbr := fixture.reader.regions[0]
			clear(mbr[447:450])
			clear(mbr[451:454])
			for _, span := range []*ByteRangeDigest{&device.GPT.ProtectiveMBR, &device.GPT.PrimaryHeader, &device.GPT.PrimaryEntryArray, &device.GPT.BackupEntryArray, &device.GPT.BackupHeader} {
				b := make([]byte, span.SizeBytes)
				if _, err := fixture.reader.ReadAt(b, int64(span.OffsetBytes)); err != nil {
					t.Fatal(err)
				}
				span.SHA256 = bundle.Sum(b)
			}
			writes, err := FinalGPTWrites(device)
			if err != nil {
				t.Fatal(err)
			}
			order := []GPTRegionRole{GPTBackupEntryArray, GPTBackupHeader, GPTPrimaryEntryArray, GPTPrimaryHeader, GPTProtectiveMBR}
			if len(writes) != len(order) {
				t.Fatal("wrong GPT write count")
			}
			assembled := &initialGPTSparseReader{size: int64(device.Identity.CapacityBytes), regions: make(map[int64][]byte)}
			for j, w := range writes {
				if w.Role != order[j] {
					t.Fatal("GPT durability order changed")
				}
				expected := make([]byte, w.Range.SizeBytes)
				if _, err := fixture.reader.ReadAt(expected, int64(w.Range.OffsetBytes)); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(w.Data, expected) || bundle.Sum(w.Data) != w.Range.SHA256 {
					t.Fatal("derived GPT differs from independent fixture")
				}
				assembled.put(w.Range.OffsetBytes, w.Data)
			}
			snapshot, _, err := captureInitialGPTWithPhysicalEndPolicy(assembled, device.Identity.CapacityBytes, false, initialGPTUsableRangeStrict)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.DiskGUID != device.Identity.DiskGUID || len(snapshot.Partitions) != len(device.Partitions) || snapshot.FirstUsableLBA != 34 {
				t.Fatal("strict final GPT interpretation differs")
			}
			device.GPT.BackupHeader.SHA256 = testDigest("wrong final GPT bytes")
			if _, err := FinalGPTWrites(device); err == nil {
				t.Fatal("independent derivation trusted an opaque plan hash")
			}
		})
	}
}

func TestFinalGPTWritesRejectInvalidGeometry(t *testing.T) {
	d := mustTestPlan(t).Devices[0]
	d.GPT.BackupHeaderLBA--
	if _, err := FinalGPTWrites(d); err == nil {
		t.Fatal("invalid physical-end geometry accepted")
	}
}
