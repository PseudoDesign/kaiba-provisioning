package campaignmedia

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	testPhysicalEndDiskGUID = "c9a1ecae-6d32-46b2-8d9b-9257424f50e2"
	testPhysicalEndBootGUID = "6dd777cd-1675-4468-8894-24fdad0bf6cf"
	testPhysicalEndRootGUID = "4add7481-a58e-4be7-8f99-c8917ed6fa71"
	testPhysicalEndHashGUID = "714e1d5a-8761-493f-a291-6eb074aad30d"
)

type initialGPTV1Alpha2PhysicalEndFixture struct {
	headerOffset   uint64
	entriesOffset  uint64
	header         []byte
	entries        []byte
	diskGUID       string
	partitionGUIDs [3]string
}

func installReviewedLegacyPhysicalEndGPTV1Alpha2(t *testing.T, fixture *initialGPTFixture) initialGPTV1Alpha2PhysicalEndFixture {
	t.Helper()
	physicalTotalLBAs := MalakSDCapacityBytes / LogicalSectorSizeBytes
	result := initialGPTV1Alpha2PhysicalEndFixture{
		headerOffset:   (physicalTotalLBAs - 1) * LogicalSectorSizeBytes,
		entriesOffset:  (physicalTotalLBAs - 33) * LogicalSectorSizeBytes,
		entries:        append([]byte(nil), fixture.primaryEntries...),
		diskGUID:       testPhysicalEndDiskGUID,
		partitionGUIDs: [3]string{testPhysicalEndBootGUID, testSDRootDataGUID, testSDRootHashGUID},
	}
	for index, guid := range result.partitionGUIDs {
		copy(result.entries[index*int(initialGPTEntrySizeBytes)+16:index*int(initialGPTEntrySizeBytes)+32], initialGPTTestGUIDBytes(t, guid))
	}
	legacy := reviewedLegacySDPhysicalEndPartitions()
	for index, partition := range legacy {
		entry := result.entries[index*int(initialGPTEntrySizeBytes) : (index+1)*int(initialGPTEntrySizeBytes)]
		binary.LittleEndian.PutUint64(entry[32:40], partition.byteStart/LogicalSectorSizeBytes)
		binary.LittleEndian.PutUint64(entry[40:48], (partition.byteStart+partition.capacity)/LogicalSectorSizeBytes-1)
	}
	result.header = initialGPTTestHeader(
		t,
		physicalTotalLBAs-1,
		1,
		physicalTotalLBAs-33,
		34,
		physicalTotalLBAs-34,
		result.diskGUID,
		crc32.ChecksumIEEE(result.entries),
	)
	fixture.reader.put(result.entriesOffset, result.entries)
	fixture.reader.put(result.headerOffset, result.header)
	return result
}

func rebuildPhysicalEndGPTV1Alpha2(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
	t.Helper()
	physicalTotalLBAs := MalakSDCapacityBytes / LogicalSectorSizeBytes
	physical.header = initialGPTTestHeader(
		t,
		physicalTotalLBAs-1,
		1,
		physicalTotalLBAs-33,
		34,
		physicalTotalLBAs-34,
		physical.diskGUID,
		crc32.ChecksumIEEE(physical.entries),
	)
	fixture.reader.put(physical.entriesOffset, physical.entries)
	fixture.reader.put(physical.headerOffset, physical.header)
}

func findInitialRecoveryRangeV1Alpha2(t *testing.T, envelope InitialGPTRecoveryEnvelopeV1Alpha2, purpose InitialRecoveryRangePurpose) InitialRecoveryRangeV1Alpha2 {
	t.Helper()
	for _, recoveryRange := range envelope.RecoveryRanges {
		for _, candidate := range recoveryRange.Purposes {
			if candidate == purpose {
				return recoveryRange
			}
		}
	}
	t.Fatalf("v1alpha2 recovery purpose %q is absent", purpose)
	return InitialRecoveryRangeV1Alpha2{}
}

func TestInitialGPTRecoveryV1Alpha2CapturesReviewedLegacyPhysicalEndBackupLineage(t *testing.T) {
	fixture := newInitialGPTFixture(t)
	physical := installReviewedLegacyPhysicalEndGPTV1Alpha2(t, fixture)
	embeddedHeaderOffset := (fixture.embeddedLBAs - 1) * LogicalSectorSizeBytes
	embeddedEntriesOffset := (fixture.embeddedLBAs - 33) * LogicalSectorSizeBytes
	onePass := &initialGPTSingleReadMetadataReader{
		base: fixture.reader,
		watched: []initialGPTWatchedRange{
			{offset: 0, size: int64(LogicalSectorSizeBytes)},
			{offset: int64(LogicalSectorSizeBytes), size: int64(LogicalSectorSizeBytes)},
			{offset: int64(2 * LogicalSectorSizeBytes), size: int64(initialGPTEntryArrayBytes)},
			{offset: int64(embeddedEntriesOffset), size: int64(initialGPTEntryArrayBytes)},
			{offset: int64(embeddedHeaderOffset), size: int64(LogicalSectorSizeBytes)},
			{offset: int64(physical.entriesOffset), size: int64(initialGPTEntryArrayBytes)},
			{offset: int64(physical.headerOffset), size: int64(LogicalSectorSizeBytes)},
		},
	}

	envelope, err := InspectInitialGPTRecoveryV1Alpha2(
		onePass,
		testInitialGPTIdentity(),
		testInitialGPTCaptureID("v1alpha2-dual-lineage"),
		testInitialGPTPlannedRanges(),
	)
	if err != nil {
		t.Fatalf("InspectInitialGPTRecoveryV1Alpha2: %v", err)
	}
	for _, watched := range onePass.watched {
		if watched.reads != 1 {
			t.Fatalf("metadata range %d:%d read %d times; want exactly once", watched.offset, watched.size, watched.reads)
		}
	}
	if envelope.SchemaVersion != InitialGPTRecoveryEnvelopeSchemaV1Alpha2 ||
		string(envelope.PhysicalEndState) != "distinct-valid-backup-lineage" || envelope.PhysicalEndBackupLineage == nil {
		t.Fatalf("unexpected v1alpha2 topology: schema=%q state=%q physical=%#v", envelope.SchemaVersion, envelope.PhysicalEndState, envelope.PhysicalEndBackupLineage)
	}
	if envelope.SelectedLineage.Placement != InitialGPTPlacementImageSized ||
		envelope.SelectedLineage.DiskGUID != testSDDiskGUID || envelope.SelectedLineage.BackupHeaderLBA != fixture.embeddedLBAs-1 {
		t.Fatalf("selected primary-anchored lineage changed: %#v", envelope.SelectedLineage)
	}
	tail := envelope.PhysicalEndBackupLineage
	physicalTotalLBAs := MalakSDCapacityBytes / LogicalSectorSizeBytes
	if string(tail.Completeness) != "valid-standalone-backup-copy" ||
		string(tail.Relationship) != "reviewed-legacy-layout-distinct-disk-and-boot-guids-shared-root-guids" ||
		tail.HeaderLBA != physicalTotalLBAs-1 || tail.AlternateHeaderLBA != 1 ||
		tail.EntryArrayLBA != physicalTotalLBAs-33 || tail.FirstUsableLBA != 34 ||
		tail.LastUsableLBA != physicalTotalLBAs-34 || tail.DiskGUID != physical.diskGUID ||
		tail.PartitionEntryCount != initialGPTEntryCount || tail.PartitionEntrySizeBytes != initialGPTEntrySizeBytes ||
		tail.PartitionEntryArrayCRC32 != crc32.ChecksumIEEE(physical.entries) || len(tail.Partitions) != 3 {
		t.Fatalf("physical-end backup lineage was not captured exactly: %#v", tail)
	}
	selectedLayout, _ := fixedIdentityFor(LegMalakSD)
	legacyLayout := reviewedLegacySDPhysicalEndPartitions()
	for index, guid := range physical.partitionGUIDs {
		if tail.Partitions[index].UniqueGUID != guid {
			t.Fatalf("physical-end partition %d GUID = %q; want %q", index+1, tail.Partitions[index].UniqueGUID, guid)
		}
		selected := envelope.SelectedLineage.Partitions[index]
		physicalPartition := tail.Partitions[index]
		if !initialGPTPartitionMatchesFixed(selected, selectedLayout.partitions[index]) {
			t.Fatalf("selected partition %d does not retain the exact current layout: %#v", index+1, selected)
		}
		if !initialGPTPartitionMatchesFixed(physicalPartition, legacyLayout[index]) {
			t.Fatalf("physical-end partition %d does not retain the exact legacy layout: %#v", index+1, physicalPartition)
		}
		if !fixedPlannedCaptureCovers(physicalPartition, selectedLayout.partitions) {
			t.Fatalf("physical-end partition %d is outside the fixed planned capture ranges: %#v", index+1, physicalPartition)
		}
		if selected.EntryNumber != physicalPartition.EntryNumber || selected.TypeGUID != physicalPartition.TypeGUID ||
			selected.Attributes != physicalPartition.Attributes || selected.Name != physicalPartition.Name {
			t.Fatalf("partition %d does not retain its entry, type, attributes, and name across lineages: selected=%#v physical=%#v", index+1, selected, physicalPartition)
		}
		if index == 0 && selected.UniqueGUID == physicalPartition.UniqueGUID {
			t.Fatalf("boot partition GUID is not distinct: selected=%#v physical=%#v", selected, physicalPartition)
		}
		if index > 0 && selected.UniqueGUID != physicalPartition.UniqueGUID {
			t.Fatalf("root partition %d GUID is not shared across lineages: selected=%#v physical=%#v", index+1, selected, physicalPartition)
		}
	}
	if tail.HeaderSHA256 != bundle.Sum(physical.header) || tail.EntryArraySHA256 != bundle.Sum(physical.entries) || tail.LineageDigest == "" {
		t.Fatalf("physical-end raw-byte or lineage digests are detached: %#v", tail)
	}
	if envelope.DestructiveStagingReady {
		t.Fatal("a dual-lineage evidence envelope overstated destructive staging readiness")
	}

	physicalEntries := findInitialRecoveryRangeV1Alpha2(t, envelope, InitialRecoveryPhysicalEndBackupEntries)
	physicalHeader := findInitialRecoveryRangeV1Alpha2(t, envelope, InitialRecoveryPhysicalEndBackupHeader)
	if physicalEntries.OffsetBytes != physical.entriesOffset || physicalEntries.SizeBytes != initialGPTEntryArrayBytes ||
		physicalEntries.PreimageSHA256 != tail.EntryArraySHA256 ||
		physicalHeader.OffsetBytes != physical.headerOffset || physicalHeader.SizeBytes != LogicalSectorSizeBytes ||
		physicalHeader.PreimageSHA256 != tail.HeaderSHA256 {
		t.Fatalf("physical lineage is not bound to its exact recovery ranges: entries=%#v header=%#v", physicalEntries, physicalHeader)
	}
	if len(physicalEntries.Purposes) != 2 || physicalEntries.Purposes[0] != InitialRecoveryFinalBackupEntries ||
		physicalEntries.Purposes[1] != InitialRecoveryPhysicalEndBackupEntries ||
		len(physicalHeader.Purposes) != 2 || physicalHeader.Purposes[0] != InitialRecoveryFinalBackupHeader ||
		physicalHeader.Purposes[1] != InitialRecoveryPhysicalEndBackupHeader {
		t.Fatalf("physical lineage/final-destination aliases are not canonical: entries=%#v header=%#v", physicalEntries.Purposes, physicalHeader.Purposes)
	}
	if findInitialRecoveryRangeV1Alpha2(t, envelope, InitialRecoveryExistingBackupEntries).OffsetBytes == physicalEntries.OffsetBytes ||
		findInitialRecoveryRangeV1Alpha2(t, envelope, InitialRecoveryExistingBackupHeader).OffsetBytes == physicalHeader.OffsetBytes {
		t.Fatal("embedded and physical-end GPT lineage ranges were incorrectly merged")
	}
	if err := envelope.VerifyAgainst(fixture.reader); err != nil {
		t.Fatalf("VerifyAgainst: %v", err)
	}
}

func TestInitialGPTRecoveryV1Alpha2FixtureMatchesRetainedDevelopmentSDGPTHashes(t *testing.T) {
	fixture := newInitialGPTFixture(t)
	physical := installReviewedLegacyPhysicalEndGPTV1Alpha2(t, fixture)
	embeddedHeaderOffset := (fixture.embeddedLBAs - 1) * LogicalSectorSizeBytes
	embeddedEntriesOffset := (fixture.embeddedLBAs - 33) * LogicalSectorSizeBytes
	// The retained card uses the parser's accepted all-zero protective-entry
	// CHS encoding rather than the conventional sentinel used by the generic
	// GPT test fixture.
	mbr := append([]byte(nil), fixture.reader.regions[0]...)
	clear(mbr[447:450])
	clear(mbr[451:454])
	fixture.reader.put(0, mbr)

	region := func(offset uint64) []byte {
		t.Helper()
		value, ok := fixture.reader.regions[int64(offset)]
		if !ok {
			t.Fatalf("fixture region at offset %d is absent", offset)
		}
		return value
	}
	for _, test := range []struct {
		name   string
		bytes  []byte
		digest bundle.Digest
	}{
		{"protective MBR", region(0), "sha256:922929c7e2be6bad4039c8e7a10a18b04d472ee60341463e80c886a00959065d"},
		{"primary header", region(LogicalSectorSizeBytes), "sha256:31070fe3adf6c10125e5dbe61f8c6ec47bab3be420c4fa9f9c40ae26dc5cd35e"},
		{"primary entries", fixture.primaryEntries, "sha256:f2d1092ca01873e50524a7b74d909144d013f22f2bb78875e601a63dc39c7b5f"},
		{"image backup entries", region(embeddedEntriesOffset), "sha256:f2d1092ca01873e50524a7b74d909144d013f22f2bb78875e601a63dc39c7b5f"},
		{"image backup header", region(embeddedHeaderOffset), "sha256:7223d681a11d1828fc7e15c5189abbb70d8101778928a2c31f6479c4bc907164"},
		{"physical-end entries", physical.entries, "sha256:377f26148f458d28b62fbc41dafe5f8be483315e29daa573c98b9f6f731d1e25"},
		{"physical-end header", physical.header, "sha256:f85198640f005040076b178a8d44b1f7ebbf339dc10268dddd29eb79513221ac"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if actual := bundle.Sum(test.bytes); actual != test.digest {
				t.Fatalf("fixture digest = %q; want retained development SD digest %q", actual, test.digest)
			}
		})
	}
}

func TestInitialGPTRecoveryV1Alpha2RejectsMalformedOrRelationshipIncompatiblePhysicalEndLineage(t *testing.T) {
	tests := map[string]func(*testing.T, *initialGPTFixture, *initialGPTV1Alpha2PhysicalEndFixture){
		"invalid physical header CRC": func(_ *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			physical.header[16] ^= 0x80
			fixture.reader.put(physical.headerOffset, physical.header)
		},
		"physical header points at wrong entry array": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			binary.LittleEndian.PutUint64(physical.header[72:80], 2)
			recomputeInitialGPTTestHeaderCRC(physical.header)
			fixture.reader.put(physical.headerOffset, physical.header)
		},
		"same disk GUID": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			physical.diskGUID = fixture.diskGUID
			rebuildPhysicalEndGPTV1Alpha2(t, fixture, physical)
		},
		"physical disk GUID collides with selected partition": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			physical.diskGUID = testSDBootGUID
			rebuildPhysicalEndGPTV1Alpha2(t, fixture, physical)
		},
		"same boot partition GUID": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			copy(physical.entries[16:32], fixture.primaryEntries[16:32])
			rebuildPhysicalEndGPTV1Alpha2(t, fixture, physical)
		},
		"boot partition GUID collides with selected root partition": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			copy(physical.entries[16:32], fixture.primaryEntries[128+16:128+32])
			rebuildPhysicalEndGPTV1Alpha2(t, fixture, physical)
		},
		"different root-data partition GUID": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			copy(physical.entries[128+16:128+32], initialGPTTestGUIDBytes(t, testPhysicalEndRootGUID))
			rebuildPhysicalEndGPTV1Alpha2(t, fixture, physical)
		},
		"different root-hash partition GUID": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			copy(physical.entries[256+16:256+32], initialGPTTestGUIDBytes(t, testPhysicalEndHashGUID))
			rebuildPhysicalEndGPTV1Alpha2(t, fixture, physical)
		},
		"current root extents instead of reviewed legacy extents": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			copy(physical.entries[128+32:128+48], fixture.primaryEntries[128+32:128+48])
			copy(physical.entries[256+32:256+48], fixture.primaryEntries[256+32:256+48])
			rebuildPhysicalEndGPTV1Alpha2(t, fixture, physical)
		},
		"legacy root-data end off by one": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			end := binary.LittleEndian.Uint64(physical.entries[128+40 : 128+48])
			binary.LittleEndian.PutUint64(physical.entries[128+40:128+48], end+1)
			rebuildPhysicalEndGPTV1Alpha2(t, fixture, physical)
		},
		"legacy root-hash start off by one": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			start := binary.LittleEndian.Uint64(physical.entries[256+32 : 256+40])
			binary.LittleEndian.PutUint64(physical.entries[256+32:256+40], start+1)
			rebuildPhysicalEndGPTV1Alpha2(t, fixture, physical)
		},
		"legacy root-hash end off by one": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			end := binary.LittleEndian.Uint64(physical.entries[256+40 : 256+48])
			binary.LittleEndian.PutUint64(physical.entries[256+40:256+48], end-1)
			rebuildPhysicalEndGPTV1Alpha2(t, fixture, physical)
		},
		"selected root-data extent is not the fixed current extent": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			legacyEnd := binary.LittleEndian.Uint64(physical.entries[128+40 : 128+48])
			binary.LittleEndian.PutUint64(fixture.primaryEntries[128+40:128+48], legacyEnd)
			fixture.backupEntries = append([]byte(nil), fixture.primaryEntries...)
			fixture.rebuild(t)
		},
		"selected root-hash extent is not the fixed current extent": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			start := binary.LittleEndian.Uint64(fixture.primaryEntries[256+32 : 256+40])
			binary.LittleEndian.PutUint64(fixture.primaryEntries[256+32:256+40], start+1)
			fixture.backupEntries = append([]byte(nil), fixture.primaryEntries...)
			fixture.rebuild(t)
		},
		"different partition start": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			binary.LittleEndian.PutUint64(physical.entries[32:40], MalakSDBootStartBytes/LogicalSectorSizeBytes+1)
			rebuildPhysicalEndGPTV1Alpha2(t, fixture, physical)
		},
		"different partition type": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			copy(physical.entries[:16], initialGPTTestGUIDBytes(t, LinuxFilesystemTypeGUID))
			rebuildPhysicalEndGPTV1Alpha2(t, fixture, physical)
		},
		"different partition name": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			binary.LittleEndian.PutUint16(physical.entries[56:58], 'X')
			rebuildPhysicalEndGPTV1Alpha2(t, fixture, physical)
		},
		"different partition attributes": func(t *testing.T, fixture *initialGPTFixture, physical *initialGPTV1Alpha2PhysicalEndFixture) {
			binary.LittleEndian.PutUint64(physical.entries[48:56], 1)
			rebuildPhysicalEndGPTV1Alpha2(t, fixture, physical)
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newInitialGPTFixture(t)
			physical := installReviewedLegacyPhysicalEndGPTV1Alpha2(t, fixture)
			mutate(t, fixture, &physical)
			if _, err := InspectInitialGPTRecoveryV1Alpha2(
				fixture.reader,
				testInitialGPTIdentity(),
				testInitialGPTCaptureID("v1alpha2-invalid-physical-lineage"),
				testInitialGPTPlannedRanges(),
			); err == nil {
				t.Fatal("malformed or relationship-incompatible physical-end GPT was accepted")
			}
		})
	}
}

func TestInitialGPTRecoveryV1Alpha2VerifyAgainstDetectsLineageAndPayloadMutation(t *testing.T) {
	fixture := newInitialGPTFixture(t)
	physical := installReviewedLegacyPhysicalEndGPTV1Alpha2(t, fixture)
	envelope, err := InspectInitialGPTRecoveryV1Alpha2(
		fixture.reader,
		testInitialGPTIdentity(),
		testInitialGPTCaptureID("v1alpha2-mutation"),
		testInitialGPTPlannedRanges(),
	)
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*testing.T, *initialGPTSparseReader){
		"physical header valid GUID change": func(t *testing.T, reader *initialGPTSparseReader) {
			header := append([]byte(nil), physical.header...)
			copy(header[56:72], initialGPTTestGUIDBytes(t, "1f4215d8-61da-4c10-a4da-9dc7ed9b53f0"))
			recomputeInitialGPTTestHeaderCRC(header)
			reader.put(physical.headerOffset, header)
		},
		"physical entries valid GUID change": func(t *testing.T, reader *initialGPTSparseReader) {
			entries := append([]byte(nil), physical.entries...)
			copy(entries[16:32], initialGPTTestGUIDBytes(t, "d1651c04-214a-4cba-a2b5-7c900245aa26"))
			header := append([]byte(nil), physical.header...)
			binary.LittleEndian.PutUint32(header[88:92], crc32.ChecksumIEEE(entries))
			recomputeInitialGPTTestHeaderCRC(header)
			reader.put(physical.entriesOffset, entries)
			reader.put(physical.headerOffset, header)
		},
		"planned boot preimage": func(_ *testing.T, reader *initialGPTSparseReader) {
			reader.put(MalakSDBootStartBytes+4096, []byte{0x7e})
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := fixture.reader.clone()
			mutate(t, mutated)
			if err := envelope.VerifyAgainst(mutated); err == nil {
				t.Fatal("VerifyAgainst accepted a changed v1alpha2 lineage or recovery preimage")
			}
		})
	}
}

func TestInitialGPTRecoveryV1Alpha2CanonicalRoundTripAndVersionIsolation(t *testing.T) {
	fixture := newInitialGPTFixture(t)
	installReviewedLegacyPhysicalEndGPTV1Alpha2(t, fixture)
	v2, err := InspectInitialGPTRecoveryV1Alpha2(
		fixture.reader,
		testInitialGPTIdentity(),
		testInitialGPTCaptureID("v1alpha2-canonical-roundtrip"),
		testInitialGPTPlannedRanges(),
	)
	if err != nil {
		t.Fatal(err)
	}
	encodedV2, err := v2.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsedV2, err := ParseInitialGPTRecoveryEnvelopeV1Alpha2(append(append([]byte(nil), encodedV2...), '\n'))
	if err != nil {
		t.Fatalf("ParseInitialGPTRecoveryEnvelopeV1Alpha2: %v", err)
	}
	reencodedV2, err := parsedV2.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encodedV2, reencodedV2) || parsedV2.EnvelopeDigest != v2.EnvelopeDigest {
		t.Fatal("v1alpha2 canonical round trip changed bytes or envelope digest")
	}
	if _, err := ParseInitialGPTRecoveryEnvelope(encodedV2); err == nil {
		t.Fatal("v1alpha1 parser accepted a v1alpha2 dual-lineage envelope")
	}

	v1Fixture := newInitialGPTFixture(t)
	v1, err := InspectInitialGPTRecovery(
		v1Fixture.reader,
		testInitialGPTIdentity(),
		testInitialGPTCaptureID("v1-cannot-cross-parse-as-v2"),
		testInitialGPTPlannedRanges(),
	)
	if err != nil {
		t.Fatal(err)
	}
	encodedV1, err := v1.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseInitialGPTRecoveryEnvelopeV1Alpha2(encodedV1); err == nil {
		t.Fatal("v1alpha2 parser accepted a v1alpha1 envelope")
	}

	tamperedRelationship := bytes.Replace(
		encodedV2,
		[]byte("reviewed-legacy-layout-distinct-disk-and-boot-guids-shared-root-guids"),
		[]byte("reviewed-legacy-layout-distinct-disk-and-boot-GUIDs-shared-root-guids"),
		1,
	)
	if bytes.Equal(tamperedRelationship, encodedV2) || !strings.Contains(string(tamperedRelationship), "boot-GUIDs") {
		t.Fatal("test did not alter the relationship field")
	}
	if _, err := ParseInitialGPTRecoveryEnvelopeV1Alpha2(tamperedRelationship); err == nil {
		t.Fatal("v1alpha2 parser accepted a changed or non-canonical relationship")
	}
}

func TestInitialGPTRecoveryV1Alpha2ClassifiesSingleLineageMedia(t *testing.T) {
	t.Run("image-sized selected lineage with non-GPT physical-end preimage", func(t *testing.T) {
		fixture := newInitialGPTFixture(t)
		envelope, err := InspectInitialGPTRecoveryV1Alpha2(
			fixture.reader,
			testInitialGPTIdentity(),
			testInitialGPTCaptureID("v1alpha2-image-sized-single-lineage"),
			testInitialGPTPlannedRanges(),
		)
		if err != nil {
			t.Fatal(err)
		}
		if envelope.PhysicalEndState != InitialGPTPhysicalEndNonGPTPreimage ||
			envelope.PhysicalEndBackupLineage != nil || len(envelope.RecoveryRanges) != 10 ||
			envelope.DestructiveStagingReady {
			t.Fatalf("unexpected image-sized single-lineage classification: %#v", envelope)
		}
	})

	t.Run("canonical NVMe selected lineage backup", func(t *testing.T) {
		fixture := newInitialGPTNVMeFixture(t)
		envelope, err := InspectInitialGPTRecoveryV1Alpha2(
			fixture.reader,
			testInitialGPTNVMeIdentity(),
			testInitialGPTCaptureID("v1alpha2-canonical-nvme"),
			testInitialGPTNVMePlannedRanges(),
		)
		if err != nil {
			t.Fatal(err)
		}
		if envelope.SelectedLineage.Placement != InitialGPTPlacementCanonicalPhysical ||
			envelope.PhysicalEndState != InitialGPTPhysicalEndSelectedLineageBackup ||
			envelope.PhysicalEndBackupLineage != nil || len(envelope.RecoveryRanges) != 6 ||
			envelope.DestructiveStagingReady {
			t.Fatalf("unexpected canonical NVMe classification: %#v", envelope)
		}
		if err := envelope.VerifyAgainst(fixture.reader); err != nil {
			t.Fatalf("VerifyAgainst canonical NVMe: %v", err)
		}
	})
}
