package campaignmedia

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math/bits"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"
)

const testImageSizedGPTTotalLBAs = uint64(6_291_456)

type initialGPTSparseReader struct {
	size    int64
	regions map[int64][]byte
}

type initialGPTSingleReadMetadataReader struct {
	base    io.ReaderAt
	watched []initialGPTWatchedRange
}

type initialGPTWatchedRange struct {
	offset int64
	size   int64
	reads  int
}

func (reader *initialGPTSingleReadMetadataReader) ReadAt(destination []byte, offset int64) (int, error) {
	requestEnd := offset + int64(len(destination))
	for index := range reader.watched {
		watched := &reader.watched[index]
		if requestEnd > watched.offset && offset < watched.offset+watched.size {
			watched.reads++
			if watched.reads > 1 {
				return 0, fmt.Errorf("metadata range %d:%d was read more than once", watched.offset, watched.size)
			}
		}
	}
	return reader.base.ReadAt(destination, offset)
}

func (reader *initialGPTSparseReader) ReadAt(destination []byte, offset int64) (int, error) {
	if offset < 0 || offset >= reader.size {
		return 0, io.EOF
	}
	available := reader.size - offset
	count := len(destination)
	if int64(count) > available {
		count = int(available)
	}
	clear(destination[:count])
	for regionOffset, region := range reader.regions {
		regionEnd := regionOffset + int64(len(region))
		requestEnd := offset + int64(count)
		if regionEnd <= offset || regionOffset >= requestEnd {
			continue
		}
		copyStart := regionOffset
		if copyStart < offset {
			copyStart = offset
		}
		copyEnd := regionEnd
		if copyEnd > requestEnd {
			copyEnd = requestEnd
		}
		copy(destination[copyStart-offset:copyEnd-offset], region[copyStart-regionOffset:copyEnd-regionOffset])
	}
	if count != len(destination) {
		return count, io.EOF
	}
	return count, nil
}

func (reader *initialGPTSparseReader) put(offset uint64, value []byte) {
	reader.regions[int64(offset)] = append([]byte(nil), value...)
}

func (reader *initialGPTSparseReader) clone() *initialGPTSparseReader {
	result := &initialGPTSparseReader{size: reader.size, regions: make(map[int64][]byte, len(reader.regions))}
	for offset, region := range reader.regions {
		result.regions[offset] = append([]byte(nil), region...)
	}
	return result
}

type initialGPTFixture struct {
	reader         *initialGPTSparseReader
	embeddedLBAs   uint64
	firstUsableLBA uint64
	lastUsableLBA  uint64
	diskGUID       string
	primaryEntries []byte
	backupEntries  []byte
}

func newInitialGPTFixture(t *testing.T) *initialGPTFixture {
	t.Helper()
	fixture := &initialGPTFixture{
		reader: &initialGPTSparseReader{
			size: int64(MalakSDCapacityBytes), regions: make(map[int64][]byte),
		},
		embeddedLBAs:   testImageSizedGPTTotalLBAs,
		firstUsableLBA: 34,
		lastUsableLBA:  testImageSizedGPTTotalLBAs - 34,
		diskGUID:       testSDDiskGUID,
		primaryEntries: make([]byte, initialGPTEntryArrayBytes),
	}
	writeInitialGPTTestEntry(t, fixture.primaryEntries[0:128], ESPTypeGUID, testSDBootGUID,
		MalakSDBootStartBytes/LogicalSectorSizeBytes,
		(MalakSDBootStartBytes+MalakSDBootCapacityBytes)/LogicalSectorSizeBytes-1, "kaiba-boot")
	writeInitialGPTTestEntry(t, fixture.primaryEntries[128:256], ARM64RootTypeGUID, testSDRootDataGUID,
		MalakSDRootDataStartBytes/LogicalSectorSizeBytes,
		(MalakSDRootDataStartBytes+MalakSDRootDataCapacityBytes)/LogicalSectorSizeBytes-1, "kaiba-root")
	writeInitialGPTTestEntry(t, fixture.primaryEntries[256:384], ARM64VerityTypeGUID, testSDRootHashGUID,
		MalakSDRootHashStartBytes/LogicalSectorSizeBytes,
		(MalakSDRootHashStartBytes+MalakSDRootHashCapacityBytes)/LogicalSectorSizeBytes-1, "kaiba-root-verity")
	fixture.backupEntries = append([]byte(nil), fixture.primaryEntries...)
	fixture.rebuild(t)
	return fixture
}

func newInitialGPTNVMeFixture(t *testing.T) *initialGPTFixture {
	t.Helper()
	totalLBAs := PiLocalNVMeCapacityBytes / LogicalSectorSizeBytes
	fixture := &initialGPTFixture{
		reader: &initialGPTSparseReader{
			size: int64(PiLocalNVMeCapacityBytes), regions: make(map[int64][]byte),
		},
		embeddedLBAs:   totalLBAs,
		firstUsableLBA: 34,
		lastUsableLBA:  totalLBAs - 34,
		diskGUID:       testNVMeDiskGUID,
		primaryEntries: make([]byte, initialGPTEntryArrayBytes),
	}
	writeInitialGPTTestEntry(t, fixture.primaryEntries[0:128], LinuxFilesystemTypeGUID, testNVMeReleaseGUID,
		PiLocalNVMeReleaseStartBytes/LogicalSectorSizeBytes,
		(PiLocalNVMeReleaseStartBytes+PiLocalNVMeReleaseCapacityBytes)/LogicalSectorSizeBytes-1, "KAIBA_RELEASE")
	fixture.backupEntries = append([]byte(nil), fixture.primaryEntries...)
	fixture.rebuild(t)
	return fixture
}

func (fixture *initialGPTFixture) rebuild(t *testing.T) {
	t.Helper()
	backupHeaderLBA := fixture.embeddedLBAs - 1
	primaryCRC := crc32.ChecksumIEEE(fixture.primaryEntries)
	backupCRC := crc32.ChecksumIEEE(fixture.backupEntries)
	mbr := make([]byte, LogicalSectorSizeBytes)
	entry := mbr[446:462]
	entry[1], entry[2], entry[3] = 0x00, 0x02, 0x00
	entry[4] = 0xee
	entry[5], entry[6], entry[7] = 0xff, 0xff, 0xff
	binary.LittleEndian.PutUint32(entry[8:12], 1)
	protectiveSize := backupHeaderLBA
	if protectiveSize > uint64(^uint32(0)) {
		protectiveSize = uint64(^uint32(0))
	}
	binary.LittleEndian.PutUint32(entry[12:16], uint32(protectiveSize))
	mbr[510], mbr[511] = 0x55, 0xaa
	fixture.reader.put(0, mbr)
	fixture.reader.put(LogicalSectorSizeBytes, initialGPTTestHeader(t, 1, backupHeaderLBA, 2,
		fixture.firstUsableLBA, fixture.lastUsableLBA, fixture.diskGUID, primaryCRC))
	fixture.reader.put(2*LogicalSectorSizeBytes, fixture.primaryEntries)
	fixture.reader.put((backupHeaderLBA-32)*LogicalSectorSizeBytes, fixture.backupEntries)
	fixture.reader.put(backupHeaderLBA*LogicalSectorSizeBytes, initialGPTTestHeader(t, backupHeaderLBA, 1, backupHeaderLBA-32,
		fixture.firstUsableLBA, fixture.lastUsableLBA, fixture.diskGUID, backupCRC))
}

func initialGPTTestHeader(t *testing.T, current, alternate, entriesLBA, firstUsable, lastUsable uint64, diskGUID string, entriesCRC uint32) []byte {
	t.Helper()
	header := make([]byte, LogicalSectorSizeBytes)
	copy(header[:8], "EFI PART")
	binary.LittleEndian.PutUint32(header[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(header[12:16], initialGPTHeaderSizeBytes)
	binary.LittleEndian.PutUint64(header[24:32], current)
	binary.LittleEndian.PutUint64(header[32:40], alternate)
	binary.LittleEndian.PutUint64(header[40:48], firstUsable)
	binary.LittleEndian.PutUint64(header[48:56], lastUsable)
	copy(header[56:72], initialGPTTestGUIDBytes(t, diskGUID))
	binary.LittleEndian.PutUint64(header[72:80], entriesLBA)
	binary.LittleEndian.PutUint32(header[80:84], initialGPTEntryCount)
	binary.LittleEndian.PutUint32(header[84:88], initialGPTEntrySizeBytes)
	binary.LittleEndian.PutUint32(header[88:92], entriesCRC)
	binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(header[:initialGPTHeaderSizeBytes]))
	return header
}

func writeInitialGPTTestEntry(t *testing.T, entry []byte, typeGUID, uniqueGUID string, first, last uint64, name string) {
	t.Helper()
	copy(entry[:16], initialGPTTestGUIDBytes(t, typeGUID))
	copy(entry[16:32], initialGPTTestGUIDBytes(t, uniqueGUID))
	binary.LittleEndian.PutUint64(entry[32:40], first)
	binary.LittleEndian.PutUint64(entry[40:48], last)
	nameUnits := utf16.Encode([]rune(name))
	if len(nameUnits) > 36 {
		t.Fatal("test GPT name is too long")
	}
	for index, unit := range nameUnits {
		binary.LittleEndian.PutUint16(entry[56+index*2:58+index*2], unit)
	}
}

func initialGPTTestGUIDBytes(t *testing.T, guid string) []byte {
	t.Helper()
	var first uint32
	var second, third uint16
	var tail [8]byte
	if _, err := fmtSscanfGUID(guid, &first, &second, &third, &tail); err != nil {
		t.Fatalf("parse test GUID %q: %v", guid, err)
	}
	result := make([]byte, 16)
	binary.LittleEndian.PutUint32(result[0:4], first)
	binary.LittleEndian.PutUint16(result[4:6], second)
	binary.LittleEndian.PutUint16(result[6:8], third)
	copy(result[8:], tail[:])
	return result
}

// fmtSscanfGUID is deliberately small and test-only; using hex.DecodeString
// after removing hyphens would encode the GPT's first three fields backwards.
func fmtSscanfGUID(guid string, first *uint32, second, third *uint16, tail *[8]byte) (int, error) {
	return fmt.Sscanf(guid, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		first, second, third, &tail[0], &tail[1], &tail[2], &tail[3], &tail[4], &tail[5], &tail[6], &tail[7])
}

func testInitialGPTIdentity() DeviceIdentity {
	return DeviceIdentity{
		Leg: LegMalakSD, ConfigID: MalakSDConfigID, Hostname: MalakSDHostname, Selector: MalakSDSelector,
		CapacityBytes: MalakSDCapacityBytes, LogicalSectorSizeBytes: LogicalSectorSizeBytes, DiskGUID: testSDDiskGUID,
	}
}

func testInitialGPTNVMeIdentity() DeviceIdentity {
	return DeviceIdentity{
		Leg: LegPiLocalNVMe, ConfigID: PiLocalNVMeConfigID, Hostname: PiLocalNVMeHostname, Selector: PiLocalNVMeSelector,
		CapacityBytes: PiLocalNVMeCapacityBytes, LogicalSectorSizeBytes: LogicalSectorSizeBytes, DiskGUID: testNVMeDiskGUID,
	}
}

func testInitialGPTPlannedRanges() []PlannedPayloadRange {
	return []PlannedPayloadRange{
		{Role: PartitionRootHash, PartitionNumber: 3, OffsetBytes: MalakSDRootHashStartBytes, SizeBytes: MalakSDRootHashCapacityBytes},
		{Role: PartitionBootFilesystem, PartitionNumber: 1, OffsetBytes: MalakSDBootStartBytes, SizeBytes: MalakSDBootCapacityBytes},
		{Role: PartitionRootData, PartitionNumber: 2, OffsetBytes: MalakSDRootDataStartBytes, SizeBytes: MalakSDRootDataCapacityBytes},
	}
}

func testInitialGPTNVMePlannedRanges() []PlannedPayloadRange {
	return []PlannedPayloadRange{{
		Role: PartitionReleaseFilesystem, PartitionNumber: 1,
		OffsetBytes: PiLocalNVMeReleaseStartBytes, SizeBytes: PiLocalNVMeReleaseCapacityBytes,
	}}
}

func testInitialGPTCaptureID(label string) string {
	return "capture:" + strings.TrimPrefix(string(testDigest(label)), "sha256:")
}

func TestPlannedPayloadRangesFromDevicePlanBindsCompleteFixedGeometry(t *testing.T) {
	device := mustTestPlan(t).Devices[0]
	ranges, err := PlannedPayloadRangesFromDevicePlan(device)
	if err != nil {
		t.Fatalf("PlannedPayloadRangesFromDevicePlan: %v", err)
	}
	if len(ranges) != 3 || ranges[0].Role != PartitionBootFilesystem ||
		ranges[1].Role != PartitionRootData || ranges[2].Role != PartitionRootHash {
		t.Fatalf("derived payload ranges do not retain the complete fixed SD geometry: %+v", ranges)
	}
	if ranges[0].OffsetBytes != MalakSDBootStartBytes || ranges[0].SizeBytes != MalakSDBootCapacityBytes ||
		ranges[1].OffsetBytes != MalakSDRootDataStartBytes || ranges[1].SizeBytes != MalakSDRootDataCapacityBytes ||
		ranges[2].OffsetBytes != MalakSDRootHashStartBytes || ranges[2].SizeBytes != MalakSDRootHashCapacityBytes {
		t.Fatal("derived payload ranges changed a fixed partition start or capacity")
	}
	device.Partitions[0].ByteStart += LogicalSectorSizeBytes
	if _, err := PlannedPayloadRangesFromDevicePlan(device); err == nil {
		t.Fatal("invalid detached device plan produced recovery ranges")
	}

	nvmeRanges, err := PlannedPayloadRangesFromDevicePlan(mustTestPlan(t).Devices[1])
	if err != nil {
		t.Fatalf("PlannedPayloadRangesFromDevicePlan NVMe: %v", err)
	}
	if len(nvmeRanges) != 1 || nvmeRanges[0] != (PlannedPayloadRange{
		Role: PartitionReleaseFilesystem, PartitionNumber: 1,
		OffsetBytes: PiLocalNVMeReleaseStartBytes, SizeBytes: PiLocalNVMeReleaseCapacityBytes,
	}) {
		t.Fatalf("derived payload ranges do not retain the complete fixed NVMe geometry: %+v", nvmeRanges)
	}
}

func TestInitialGPTRecoveryCapturesImageSizedSDGeometry(t *testing.T) {
	fixture := newInitialGPTFixture(t)
	backupHeaderOffset := (fixture.embeddedLBAs - 1) * LogicalSectorSizeBytes
	backupEntriesOffset := (fixture.embeddedLBAs - 33) * LogicalSectorSizeBytes
	physicalEndHeaderOffset := MalakSDCapacityBytes - LogicalSectorSizeBytes
	onePass := &initialGPTSingleReadMetadataReader{
		base: fixture.reader,
		watched: []initialGPTWatchedRange{
			{offset: 0, size: int64(LogicalSectorSizeBytes)},
			{offset: int64(LogicalSectorSizeBytes), size: int64(LogicalSectorSizeBytes)},
			{offset: int64(2 * LogicalSectorSizeBytes), size: int64(initialGPTEntryArrayBytes)},
			{offset: int64(backupEntriesOffset), size: int64(initialGPTEntryArrayBytes)},
			{offset: int64(backupHeaderOffset), size: int64(LogicalSectorSizeBytes)},
			{offset: int64(physicalEndHeaderOffset), size: int64(LogicalSectorSizeBytes)},
		},
	}
	envelope, err := InspectInitialGPTRecovery(onePass, testInitialGPTIdentity(), testInitialGPTCaptureID("sd-prewrite-20260911"), testInitialGPTPlannedRanges())
	if err != nil {
		t.Fatalf("InspectInitialGPTRecovery: %v", err)
	}
	for _, watched := range onePass.watched {
		if watched.reads != 1 {
			t.Fatalf("metadata range %d:%d read %d times; want exactly once for parse and digest", watched.offset, watched.size, watched.reads)
		}
	}
	if envelope.Snapshot.Placement != InitialGPTPlacementImageSized ||
		envelope.Snapshot.PhysicalTotalLBAs != MalakSDCapacityBytes/LogicalSectorSizeBytes ||
		envelope.Snapshot.EmbeddedGPTTotalLBAs != testImageSizedGPTTotalLBAs ||
		envelope.Snapshot.BackupHeaderLBA != 6_291_455 {
		t.Fatalf("unexpected truncated-SD classification: %+v", envelope.Snapshot)
	}
	if len(envelope.Snapshot.Partitions) != 3 || envelope.DestructiveStagingReady {
		t.Fatal("capture lost the three initial partitions or overstated staging readiness")
	}
	wantPartitions := []InitialGPTPartition{
		{
			EntryNumber: 1, TypeGUID: ESPTypeGUID, UniqueGUID: testSDBootGUID,
			FirstLBA: MalakSDBootStartBytes / LogicalSectorSizeBytes,
			LastLBA:  (MalakSDBootStartBytes+MalakSDBootCapacityBytes)/LogicalSectorSizeBytes - 1,
			Name:     "kaiba-boot",
		},
		{
			EntryNumber: 2, TypeGUID: ARM64RootTypeGUID, UniqueGUID: testSDRootDataGUID,
			FirstLBA: MalakSDRootDataStartBytes / LogicalSectorSizeBytes,
			LastLBA:  (MalakSDRootDataStartBytes+MalakSDRootDataCapacityBytes)/LogicalSectorSizeBytes - 1,
			Name:     "kaiba-root",
		},
		{
			EntryNumber: 3, TypeGUID: ARM64VerityTypeGUID, UniqueGUID: testSDRootHashGUID,
			FirstLBA: MalakSDRootHashStartBytes / LogicalSectorSizeBytes,
			LastLBA:  (MalakSDRootHashStartBytes+MalakSDRootHashCapacityBytes)/LogicalSectorSizeBytes - 1,
			Name:     "kaiba-root-verity",
		},
	}
	for index, want := range wantPartitions {
		if got := envelope.Snapshot.Partitions[index]; got != want {
			t.Fatalf("initial SD partition %d = %+v; want %+v", index+1, got, want)
		}
	}
	if len(envelope.RecoveryRanges) != 10 {
		t.Fatalf("recovery range count = %d; want 10 distinct initial spans", len(envelope.RecoveryRanges))
	}
	oldEntries := findInitialRecoveryRange(t, envelope, InitialRecoveryExistingBackupEntries)
	finalEntries := findInitialRecoveryRange(t, envelope, InitialRecoveryFinalBackupEntries)
	oldHeader := findInitialRecoveryRange(t, envelope, InitialRecoveryExistingBackupHeader)
	finalHeader := findInitialRecoveryRange(t, envelope, InitialRecoveryFinalBackupHeader)
	if oldEntries.OffsetBytes == finalEntries.OffsetBytes || oldHeader.OffsetBytes == finalHeader.OffsetBytes {
		t.Fatal("image-sized existing and physical-end final GPT preimages were incorrectly merged")
	}
	if oldHeader.OffsetBytes != 6_291_455*LogicalSectorSizeBytes ||
		finalHeader.OffsetBytes != MalakSDCapacityBytes-LogicalSectorSizeBytes {
		t.Fatal("old or final backup header range has the wrong exact location")
	}
	if err := envelope.VerifyAgainst(fixture.reader); err != nil {
		t.Fatalf("VerifyAgainst: %v", err)
	}
	encoded, err := envelope.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseInitialGPTRecoveryEnvelope(append(encoded, '\n'))
	if err != nil {
		t.Fatalf("ParseInitialGPTRecoveryEnvelope: %v", err)
	}
	if parsed.EnvelopeDigest != envelope.EnvelopeDigest {
		t.Fatal("canonical round trip changed the envelope digest")
	}
}

func TestInitialGPTRecoveryRejectsConflictingPhysicalEndGPT(t *testing.T) {
	physicalTotalLBAs := MalakSDCapacityBytes / LogicalSectorSizeBytes
	zeroEntriesCRC := crc32.ChecksumIEEE(make([]byte, initialGPTEntryArrayBytes))
	validHeader := initialGPTTestHeader(t,
		physicalTotalLBAs-1, 1, physicalTotalLBAs-33,
		34, physicalTotalLBAs-34, testSDDiskGUID, zeroEntriesCRC,
	)
	signatureOnly := make([]byte, LogicalSectorSizeBytes)
	copy(signatureOnly, "EFI PART")
	for name, conflictingSector := range map[string][]byte{
		"valid header":   validHeader,
		"signature only": signatureOnly,
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newInitialGPTFixture(t)
			fixture.reader.put(MalakSDCapacityBytes-LogicalSectorSizeBytes, conflictingSector)
			if _, err := InspectInitialGPTRecovery(
				fixture.reader, testInitialGPTIdentity(), testInitialGPTCaptureID("conflicting-physical-end-gpt"), testInitialGPTPlannedRanges(),
			); err == nil || !strings.Contains(err.Error(), "conflicts with a GPT header signature at the physical end") {
				t.Fatalf("conflicting physical-end GPT was not rejected unambiguously: %v", err)
			}
		})
	}
}

func TestInitialGPTRecoveryMergesCanonicalBackupAliasesWithoutOverlap(t *testing.T) {
	fixture := newInitialGPTFixture(t)
	fixture.embeddedLBAs = MalakSDCapacityBytes / LogicalSectorSizeBytes
	fixture.lastUsableLBA = fixture.embeddedLBAs - 34
	fixture.rebuild(t)
	backupHeaderOffset := (fixture.embeddedLBAs - 1) * LogicalSectorSizeBytes
	backupEntriesOffset := (fixture.embeddedLBAs - 33) * LogicalSectorSizeBytes
	onePass := &initialGPTSingleReadMetadataReader{
		base: fixture.reader,
		watched: []initialGPTWatchedRange{
			{offset: 0, size: int64(LogicalSectorSizeBytes)},
			{offset: int64(LogicalSectorSizeBytes), size: int64(LogicalSectorSizeBytes)},
			{offset: int64(2 * LogicalSectorSizeBytes), size: int64(initialGPTEntryArrayBytes)},
			{offset: int64(backupEntriesOffset), size: int64(initialGPTEntryArrayBytes)},
			{offset: int64(backupHeaderOffset), size: int64(LogicalSectorSizeBytes)},
		},
	}
	envelope, err := InspectInitialGPTRecovery(
		onePass, testInitialGPTIdentity(), testInitialGPTCaptureID("canonical-physical-gpt"), testInitialGPTPlannedRanges(),
	)
	if err != nil {
		t.Fatalf("InspectInitialGPTRecovery: %v", err)
	}
	for _, watched := range onePass.watched {
		if watched.reads != 1 {
			t.Fatalf("canonical metadata range %d:%d read %d times; want exactly once across parse and range hashing", watched.offset, watched.size, watched.reads)
		}
	}
	if envelope.Snapshot.Placement != InitialGPTPlacementCanonicalPhysical || len(envelope.RecoveryRanges) != 8 {
		t.Fatalf("canonical placement/ranges = %q/%d; want canonical/8", envelope.Snapshot.Placement, len(envelope.RecoveryRanges))
	}
	if len(findInitialRecoveryRange(t, envelope, InitialRecoveryExistingBackupHeader).Purposes) != 2 ||
		len(findInitialRecoveryRange(t, envelope, InitialRecoveryExistingBackupEntries).Purposes) != 2 {
		t.Fatal("canonical existing/final backup aliases were not merged into nonoverlapping ranges")
	}
}

func TestInitialGPTRecoveryVerifyAgainstDetectsEveryNonMetadataPreimageMutation(t *testing.T) {
	fixture := newInitialGPTFixture(t)
	finalHeaderOffset := MalakSDCapacityBytes - LogicalSectorSizeBytes
	finalEntriesOffset := finalHeaderOffset - initialGPTEntryArrayBytes
	targets := []struct {
		name    string
		purpose InitialRecoveryRangePurpose
		offset  uint64
		value   byte
	}{
		{"boot payload", InitialRecoveryPlannedBoot, MalakSDBootStartBytes + 4096, 0x11},
		{"root-data payload", InitialRecoveryPlannedRootData, MalakSDRootDataStartBytes + 4096, 0x22},
		{"root-hash payload", InitialRecoveryPlannedRootHash, MalakSDRootHashStartBytes + 4096, 0x33},
		{"physical-end entry-array preimage", InitialRecoveryFinalBackupEntries, finalEntriesOffset + 4096, 0x44},
		{"physical-end header preimage", InitialRecoveryFinalBackupHeader, finalHeaderOffset + 64, 0x55},
	}
	for _, target := range targets {
		fixture.reader.put(target.offset, []byte{target.value})
	}
	envelope, err := InspectInitialGPTRecovery(
		fixture.reader, testInitialGPTIdentity(), testInitialGPTCaptureID("nonzero-preimage-sentinels"), testInitialGPTPlannedRanges(),
	)
	if err != nil {
		t.Fatalf("InspectInitialGPTRecovery: %v", err)
	}

	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			recoveryRange := findInitialRecoveryRange(t, envelope, target.purpose)
			if target.offset < recoveryRange.OffsetBytes || target.offset >= recoveryRange.OffsetBytes+recoveryRange.SizeBytes {
				t.Fatalf("sentinel offset %d is outside recovery range %+v", target.offset, recoveryRange)
			}
			mutated := fixture.reader.clone()
			mutated.put(target.offset, []byte{target.value ^ 0xff})
			if err := envelope.VerifyAgainst(mutated); err == nil {
				t.Fatalf("VerifyAgainst accepted changed %s bytes", target.name)
			}
		})
	}
}

func TestInitialGPTRecoveryDerivesCanonicalNVMeGeometry(t *testing.T) {
	fixture := newInitialGPTNVMeFixture(t)
	identity := testInitialGPTNVMeIdentity()
	snapshot, captured, err := captureInitialGPT(fixture.reader, identity.CapacityBytes)
	if err != nil {
		t.Fatalf("captureInitialGPT NVMe: %v", err)
	}
	if err := snapshot.validate(identity); err != nil {
		t.Fatalf("validate NVMe snapshot: %v", err)
	}
	wantPartition := InitialGPTPartition{
		EntryNumber: 1, TypeGUID: LinuxFilesystemTypeGUID, UniqueGUID: testNVMeReleaseGUID,
		FirstLBA: PiLocalNVMeReleaseStartBytes / LogicalSectorSizeBytes,
		LastLBA:  (PiLocalNVMeReleaseStartBytes+PiLocalNVMeReleaseCapacityBytes)/LogicalSectorSizeBytes - 1,
		Name:     "KAIBA_RELEASE",
	}
	if snapshot.Placement != InitialGPTPlacementCanonicalPhysical || snapshot.PhysicalTotalLBAs != PiLocalNVMeCapacityBytes/LogicalSectorSizeBytes ||
		len(snapshot.Partitions) != 1 || snapshot.Partitions[0] != wantPartition {
		t.Fatalf("unexpected canonical NVMe snapshot: %+v", snapshot)
	}
	planned := testInitialGPTNVMePlannedRanges()
	if err := validatePlannedPayloadRanges(identity, planned); err != nil {
		t.Fatalf("validate NVMe planned range: %v", err)
	}
	specs, err := expectedInitialRecoveryRangeSpecs(identity, snapshot, planned)
	if err != nil {
		t.Fatalf("expectedInitialRecoveryRangeSpecs NVMe: %v", err)
	}
	if len(specs) != 6 {
		t.Fatalf("canonical NVMe recovery range count = %d; want 6", len(specs))
	}
	release := findInitialRecoverySpec(t, specs, InitialRecoveryPlannedRelease)
	if release.offsetBytes != PiLocalNVMeReleaseStartBytes || release.sizeBytes != PiLocalNVMeReleaseCapacityBytes {
		t.Fatalf("NVMe release recovery range changed: %+v", release)
	}
	if _, ok := captured.digest(PiLocalNVMeCapacityBytes-LogicalSectorSizeBytes, LogicalSectorSizeBytes); !ok {
		t.Fatal("canonical NVMe backup header was not retained for one-pass recovery hashing")
	}
}

func TestInitialGPTRecoveryRejectsInvalidCRCsDivergenceAndPartitionGeometry(t *testing.T) {
	tests := map[string]func(*testing.T, *initialGPTFixture){
		"protective MBR": func(t *testing.T, fixture *initialGPTFixture) {
			mbr := append([]byte(nil), fixture.reader.regions[0]...)
			mbr[511] = 0
			fixture.reader.put(0, mbr)
		},
		"primary header CRC": func(t *testing.T, fixture *initialGPTFixture) {
			header := append([]byte(nil), fixture.reader.regions[int64(LogicalSectorSizeBytes)]...)
			header[24] ^= 1
			fixture.reader.put(LogicalSectorSizeBytes, header)
		},
		"backup header CRC": func(t *testing.T, fixture *initialGPTFixture) {
			offset := (fixture.embeddedLBAs - 1) * LogicalSectorSizeBytes
			header := append([]byte(nil), fixture.reader.regions[int64(offset)]...)
			header[24] ^= 1
			fixture.reader.put(offset, header)
		},
		"reciprocal header divergence": func(t *testing.T, fixture *initialGPTFixture) {
			offset := (fixture.embeddedLBAs - 1) * LogicalSectorSizeBytes
			header := append([]byte(nil), fixture.reader.regions[int64(offset)]...)
			copy(header[56:72], initialGPTTestGUIDBytes(t, testNVMeDiskGUID))
			recomputeInitialGPTTestHeaderCRC(header)
			fixture.reader.put(offset, header)
		},
		"entry geometry": func(t *testing.T, fixture *initialGPTFixture) {
			header := append([]byte(nil), fixture.reader.regions[int64(LogicalSectorSizeBytes)]...)
			binary.LittleEndian.PutUint32(header[80:84], 127)
			recomputeInitialGPTTestHeaderCRC(header)
			fixture.reader.put(LogicalSectorSizeBytes, header)
		},
		"entry array CRC": func(t *testing.T, fixture *initialGPTFixture) {
			entries := append([]byte(nil), fixture.primaryEntries...)
			entries[56] ^= 1
			fixture.reader.put(2*LogicalSectorSizeBytes, entries)
		},
		"divergent matching-CRC arrays": func(t *testing.T, fixture *initialGPTFixture) {
			fixture.backupEntries[56] = 'x'
			forgeInitialGPTCRC32Suffix(t, fixture.backupEntries, crc32.ChecksumIEEE(fixture.primaryEntries))
			fixture.rebuild(t)
		},
		"overlapping partitions": func(t *testing.T, fixture *initialGPTFixture) {
			binary.LittleEndian.PutUint64(fixture.primaryEntries[128+32:128+40], MalakSDBootStartBytes/LogicalSectorSizeBytes)
			fixture.backupEntries = append([]byte(nil), fixture.primaryEntries...)
			fixture.rebuild(t)
		},
		"out-of-bounds partition": func(t *testing.T, fixture *initialGPTFixture) {
			binary.LittleEndian.PutUint64(fixture.primaryEntries[40:48], fixture.lastUsableLBA+1)
			fixture.backupEntries = append([]byte(nil), fixture.primaryEntries...)
			fixture.rebuild(t)
		},
		"unprintable partition name": func(t *testing.T, fixture *initialGPTFixture) {
			binary.LittleEndian.PutUint16(fixture.primaryEntries[56:58], '\n')
			fixture.backupEntries = append([]byte(nil), fixture.primaryEntries...)
			fixture.rebuild(t)
		},
		"duplicate partition GUID": func(t *testing.T, fixture *initialGPTFixture) {
			copy(fixture.primaryEntries[128+16:128+32], fixture.primaryEntries[16:32])
			fixture.backupEntries = append([]byte(nil), fixture.primaryEntries...)
			fixture.rebuild(t)
		},
		"partition GUID equals disk GUID": func(t *testing.T, fixture *initialGPTFixture) {
			copy(fixture.primaryEntries[16:32], initialGPTTestGUIDBytes(t, fixture.diskGUID))
			fixture.backupEntries = append([]byte(nil), fixture.primaryEntries...)
			fixture.rebuild(t)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newInitialGPTFixture(t)
			mutate(t, fixture)
			if _, err := parseInitialGPT(fixture.reader, MalakSDCapacityBytes); err == nil {
				t.Fatal("invalid initial GPT was accepted")
			}
		})
	}
}

func TestInitialGPTRecoveryRejectsOverlappingOrOutOfBoundsPlannedRanges(t *testing.T) {
	fixture := newInitialGPTFixture(t)
	tests := map[string]func([]PlannedPayloadRange) []PlannedPayloadRange{
		"missing fixed payload": func(planned []PlannedPayloadRange) []PlannedPayloadRange { return planned[:2] },
		"payload overlap": func(planned []PlannedPayloadRange) []PlannedPayloadRange {
			planned[1].OffsetBytes = planned[0].OffsetBytes
			return planned
		},
		"primary metadata overlap": func(planned []PlannedPayloadRange) []PlannedPayloadRange {
			planned[0].OffsetBytes = LogicalSectorSizeBytes
			return planned
		},
		"existing backup overlap": func(planned []PlannedPayloadRange) []PlannedPayloadRange {
			planned[0].OffsetBytes = (testImageSizedGPTTotalLBAs - 32) * LogicalSectorSizeBytes
			return planned
		},
		"physical end": func(planned []PlannedPayloadRange) []PlannedPayloadRange {
			planned[0].OffsetBytes = MalakSDCapacityBytes - LogicalSectorSizeBytes
			return planned
		},
		"wrong leg role": func(planned []PlannedPayloadRange) []PlannedPayloadRange {
			planned[0].Role = PartitionReleaseFilesystem
			return planned
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			planned := testInitialGPTPlannedRanges()
			sort.Slice(planned, func(i, j int) bool { return planned[i].OffsetBytes < planned[j].OffsetBytes })
			if _, err := InspectInitialGPTRecovery(fixture.reader, testInitialGPTIdentity(), testInitialGPTCaptureID("invalid-range"), mutate(planned)); err == nil {
				t.Fatal("invalid planned recovery range was accepted")
			}
		})
	}
}

func TestInitialGPTRecoveryContextBindingsRejectReplayAndChangedBytes(t *testing.T) {
	fixture := newInitialGPTFixture(t)
	wrongIdentity := testInitialGPTIdentity()
	wrongIdentity.DiskGUID = testNVMeDiskGUID
	if _, err := InspectInitialGPTRecovery(fixture.reader, wrongIdentity, testInitialGPTCaptureID("wrong-device"), testInitialGPTPlannedRanges()); err == nil {
		t.Fatal("GPT bytes were accepted under a different fixed device disk GUID")
	}

	envelope := structurallyValidInitialGPTEnvelope(t, fixture, testInitialGPTCaptureID("capture-a"))
	replayed := envelope
	replayed.CaptureID = testInitialGPTCaptureID("capture-b")
	replayed.EnvelopeDigest = ""
	if _, err := replayed.Seal(); err == nil {
		t.Fatal("range bindings were accepted under a different capture ID")
	}

	changed := append([]byte(nil), fixture.reader.regions[int64(0)]...)
	changed[0] = 1
	fixture.reader.put(0, changed)
	if err := envelope.VerifyAgainst(fixture.reader); err == nil {
		t.Fatal("VerifyAgainst accepted changed captured bytes")
	}

	tampered := envelope
	tampered.RecoveryRanges = append([]InitialRecoveryRange(nil), envelope.RecoveryRanges...)
	tampered.RecoveryRanges[0].SizeBytes++
	if err := tampered.Validate(); err == nil {
		t.Fatal("envelope accepted tampered range geometry")
	}
}

func findInitialRecoveryRange(t *testing.T, envelope InitialGPTRecoveryEnvelope, purpose InitialRecoveryRangePurpose) InitialRecoveryRange {
	t.Helper()
	for _, recoveryRange := range envelope.RecoveryRanges {
		for _, candidate := range recoveryRange.Purposes {
			if candidate == purpose {
				return recoveryRange
			}
		}
	}
	t.Fatalf("recovery purpose %q is absent", purpose)
	return InitialRecoveryRange{}
}

func findInitialRecoverySpec(t *testing.T, specs []initialRecoveryRangeSpec, purpose InitialRecoveryRangePurpose) initialRecoveryRangeSpec {
	t.Helper()
	for _, spec := range specs {
		for _, candidate := range spec.purposes {
			if candidate == purpose {
				return spec
			}
		}
	}
	t.Fatalf("recovery purpose %q is absent", purpose)
	return initialRecoveryRangeSpec{}
}

func structurallyValidInitialGPTEnvelope(t *testing.T, fixture *initialGPTFixture, captureID string) InitialGPTRecoveryEnvelope {
	t.Helper()
	identity := testInitialGPTIdentity()
	snapshot, err := parseInitialGPT(fixture.reader, identity.CapacityBytes)
	if err != nil {
		t.Fatal(err)
	}
	planned := testInitialGPTPlannedRanges()
	sort.Slice(planned, func(i, j int) bool { return planned[i].OffsetBytes < planned[j].OffsetBytes })
	identityDigest, err := deriveInitialGPTIdentityDigest(identity)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := expectedInitialRecoveryRangeSpecs(identity, snapshot, planned)
	if err != nil {
		t.Fatal(err)
	}
	ranges := make([]InitialRecoveryRange, len(specs))
	for index, spec := range specs {
		ranges[index] = InitialRecoveryRange{
			CaptureID: captureID, DeviceIdentityDigest: identityDigest,
			Purposes:    append([]InitialRecoveryRangePurpose(nil), spec.purposes...),
			OffsetBytes: spec.offsetBytes, SizeBytes: spec.sizeBytes,
			PreimageSHA256: testDigest(fmt.Sprintf("structural preimage %d", index)),
		}
		ranges[index].BindingDigest, err = ranges[index].derivedBindingDigest()
		if err != nil {
			t.Fatal(err)
		}
	}
	envelope, err := (InitialGPTRecoveryEnvelope{
		SchemaVersion: InitialGPTRecoveryEnvelopeSchemaV1Alpha1,
		CaptureID:     captureID, Identity: identity, DeviceIdentityDigest: identityDigest,
		Snapshot: snapshot, PlannedPayloadRanges: planned,
		RecoveryScope:  RecoveryScopeInspectedInitialGPTAndPlannedPayloads,
		RecoveryRanges: ranges, DestructiveStagingReady: false,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func forgeInitialGPTCRC32Suffix(t *testing.T, value []byte, target uint32) {
	t.Helper()
	if len(value) < 4 {
		t.Fatal("CRC fixture is too short")
	}
	patch := value[len(value)-4:]
	clear(patch)
	baseline := crc32.ChecksumIEEE(value)
	var rows [32]uint64
	for inputBit := 0; inputBit < 32; inputBit++ {
		patch[inputBit/8] = 1 << (inputBit % 8)
		influence := crc32.ChecksumIEEE(value) ^ baseline
		patch[inputBit/8] = 0
		for outputBit := 0; outputBit < 32; outputBit++ {
			if influence&(uint32(1)<<outputBit) != 0 {
				rows[outputBit] |= uint64(1) << inputBit
			}
		}
	}
	delta := target ^ baseline
	for outputBit := 0; outputBit < 32; outputBit++ {
		if delta&(uint32(1)<<outputBit) != 0 {
			rows[outputBit] |= uint64(1) << 32
		}
	}
	pivotRow := 0
	for column := 0; column < 32; column++ {
		selected := -1
		for row := pivotRow; row < 32; row++ {
			if rows[row]&(uint64(1)<<column) != 0 {
				selected = row
				break
			}
		}
		if selected < 0 {
			continue
		}
		rows[pivotRow], rows[selected] = rows[selected], rows[pivotRow]
		for row := 0; row < 32; row++ {
			if row != pivotRow && rows[row]&(uint64(1)<<column) != 0 {
				rows[row] ^= rows[pivotRow]
			}
		}
		pivotRow++
	}
	if pivotRow != 32 {
		t.Fatal("CRC32 patch matrix was unexpectedly singular")
	}
	var solution uint32
	for row := 0; row < 32; row++ {
		coefficient := rows[row] & ((uint64(1) << 32) - 1)
		column := bits.TrailingZeros64(coefficient)
		if rows[row]&(uint64(1)<<32) != 0 {
			solution |= uint32(1) << column
		}
	}
	binary.LittleEndian.PutUint32(patch, solution)
	if crc32.ChecksumIEEE(value) != target {
		t.Fatal("failed to construct a same-CRC divergent GPT entry array")
	}
}

func recomputeInitialGPTTestHeaderCRC(header []byte) {
	binary.LittleEndian.PutUint32(header[16:20], 0)
	binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(header[:initialGPTHeaderSizeBytes]))
}

func TestInitialGPTErrorMessagesRemainBounded(t *testing.T) {
	fixture := newInitialGPTFixture(t)
	_, err := InspectInitialGPTRecovery(fixture.reader, testInitialGPTIdentity(), "capture:"+strings.Repeat("X", 64), testInitialGPTPlannedRanges())
	if err == nil || len(err.Error()) > 512 {
		t.Fatal("invalid capture ID was accepted or produced an unbounded diagnostic")
	}
}
