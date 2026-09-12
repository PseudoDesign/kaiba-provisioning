package campaignmedia

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"regexp"
	"sort"
	"unicode/utf16"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	InitialGPTRecoveryEnvelopeSchemaV1Alpha1 = "kaiba.provisioning.rpi5-stable-verifier-initial-gpt-recovery-envelope/v1alpha1"

	// RecoveryScopeInspectedInitialGPTAndPlannedPayloads means the envelope
	// binds only the parsed GPT metadata ranges, the physical-end GPT
	// preimages, and the planned payload ranges explicitly listed in it. It is
	// not an authorization or a complete destructive-staging contract.
	RecoveryScopeInspectedInitialGPTAndPlannedPayloads = "inspected-initial-gpt-physical-end-gpt-preimages-and-listed-planned-payloads"

	initialGPTHeaderSizeBytes = uint32(92)
	initialGPTEntryCount      = uint32(128)
	initialGPTEntrySizeBytes  = uint32(128)
	initialGPTEntryArrayBytes = uint64(initialGPTEntryCount) * uint64(initialGPTEntrySizeBytes)
)

const (
	initialGPTIdentityDigestDomain = "kaiba.provisioning.rpi5-stable-verifier-initial-gpt-device-identity.v1alpha1"
	initialGPTRangeDigestDomain    = "kaiba.provisioning.rpi5-stable-verifier-initial-gpt-recovery-range.v1alpha1"
	initialGPTEnvelopeDigestDomain = "kaiba.provisioning.rpi5-stable-verifier-initial-gpt-recovery-envelope.v1alpha1"
)

var initialGPTCaptureIDPattern = regexp.MustCompile(`^capture:[0-9a-f]{64}$`)

// InitialGPTPlacement classifies where a fully valid, internally canonical
// GPT container ends relative to the reviewed physical device capacity.
type InitialGPTPlacement string

const (
	InitialGPTPlacementCanonicalPhysical InitialGPTPlacement = "canonical-full-physical-device"
	InitialGPTPlacementImageSized        InitialGPTPlacement = "valid-image-sized-gpt-on-larger-physical-device"
)

// InitialGPTPartition is one allocated entry decoded from the matching GPT
// entry arrays. Byte offsets are intentionally not duplicated here: callers
// can derive them from the fixed 512-byte logical sector size without risking
// disagreement between two representations.
type InitialGPTPartition struct {
	EntryNumber uint32 `json:"entry_number"`
	TypeGUID    string `json:"type_guid"`
	UniqueGUID  string `json:"unique_guid"`
	FirstLBA    uint64 `json:"first_lba"`
	LastLBA     uint64 `json:"last_lba"`
	Attributes  uint64 `json:"attributes"`
	Name        string `json:"name"`
}

// InitialGPTSnapshot is the strict semantic view established by parsing the
// protective MBR and both CRC-checked GPT copies. EmbeddedGPTTotalLBAs is the
// size of the GPT container, which may be smaller than PhysicalTotalLBAs.
type InitialGPTSnapshot struct {
	Placement                InitialGPTPlacement   `json:"placement"`
	PhysicalTotalLBAs        uint64                `json:"physical_total_lbas"`
	EmbeddedGPTTotalLBAs     uint64                `json:"embedded_gpt_total_lbas"`
	ProtectiveMBRLastLBA     uint64                `json:"protective_mbr_last_lba"`
	PrimaryHeaderLBA         uint64                `json:"primary_header_lba"`
	PrimaryHeaderCRC32       uint32                `json:"primary_header_crc32"`
	PrimaryEntryArrayLBA     uint64                `json:"primary_entry_array_lba"`
	BackupEntryArrayLBA      uint64                `json:"backup_entry_array_lba"`
	BackupHeaderLBA          uint64                `json:"backup_header_lba"`
	BackupHeaderCRC32        uint32                `json:"backup_header_crc32"`
	FirstUsableLBA           uint64                `json:"first_usable_lba"`
	LastUsableLBA            uint64                `json:"last_usable_lba"`
	DiskGUID                 string                `json:"disk_guid"`
	PartitionEntryCount      uint32                `json:"partition_entry_count"`
	PartitionEntrySizeBytes  uint32                `json:"partition_entry_size_bytes"`
	PartitionEntryArrayCRC32 uint32                `json:"partition_entry_array_crc32"`
	Partitions               []InitialGPTPartition `json:"partitions"`
}

// PlannedPayloadRange is a caller-supplied partition range whose complete
// preimage must be captured before that range can ever be staged. This layer
// binds the supplied geometry but deliberately does not claim it matches a
// StagingPlan; that independent cross-binding is a later eligibility gate.
type PlannedPayloadRange struct {
	Role            PartitionRole `json:"role"`
	PartitionNumber uint32        `json:"partition_number"`
	OffsetBytes     uint64        `json:"offset_bytes"`
	SizeBytes       uint64        `json:"size_bytes"`
}

// InitialRecoveryRangePurpose is a closed role for one byte range. When an
// initial GPT is already anchored at the physical end, the existing and final
// backup purposes intentionally share one range rather than overlap.
type InitialRecoveryRangePurpose string

const (
	InitialRecoveryProtectiveMBR         InitialRecoveryRangePurpose = "initial-protective-mbr"
	InitialRecoveryPrimaryHeader         InitialRecoveryRangePurpose = "initial-primary-gpt-header"
	InitialRecoveryPrimaryEntryArray     InitialRecoveryRangePurpose = "initial-primary-gpt-entry-array"
	InitialRecoveryExistingBackupEntries InitialRecoveryRangePurpose = "initial-existing-backup-gpt-entry-array"
	InitialRecoveryExistingBackupHeader  InitialRecoveryRangePurpose = "initial-existing-backup-gpt-header"
	InitialRecoveryFinalBackupEntries    InitialRecoveryRangePurpose = "initial-physical-end-final-backup-gpt-entry-array-preimage"
	InitialRecoveryFinalBackupHeader     InitialRecoveryRangePurpose = "initial-physical-end-final-backup-gpt-header-preimage"
	InitialRecoveryPlannedBoot           InitialRecoveryRangePurpose = "initial-planned-payload-boot-filesystem"
	InitialRecoveryPlannedRootData       InitialRecoveryRangePurpose = "initial-planned-payload-root-data"
	InitialRecoveryPlannedRootHash       InitialRecoveryRangePurpose = "initial-planned-payload-root-hash"
	InitialRecoveryPlannedRelease        InitialRecoveryRangePurpose = "initial-planned-payload-release-filesystem"
)

// InitialRecoveryRange binds one exact pre-write byte span. BindingDigest
// context-binds the preimage digest and geometry to both the reviewed fixed
// identity and the operator-supplied capture ID; it is not merely a content
// digest that could be replayed across captures or devices.
type InitialRecoveryRange struct {
	CaptureID            string                        `json:"capture_id"`
	DeviceIdentityDigest bundle.Digest                 `json:"device_identity_digest"`
	Purposes             []InitialRecoveryRangePurpose `json:"purposes"`
	OffsetBytes          uint64                        `json:"offset_bytes"`
	SizeBytes            uint64                        `json:"size_bytes"`
	PreimageSHA256       bundle.Digest                 `json:"preimage_sha256"`
	BindingDigest        bundle.Digest                 `json:"binding_digest"`
}

// InitialGPTRecoveryEnvelope is a read-only evidence artifact. False is the
// only valid value of DestructiveStagingReady in v1alpha1: this package has no
// writer, and this envelope has not been cross-bound to a complete staging
// plan, device-open proof, approval, or durable backup storage.
type InitialGPTRecoveryEnvelope struct {
	SchemaVersion           string                 `json:"schema_version"`
	CaptureID               string                 `json:"capture_id"`
	Identity                DeviceIdentity         `json:"identity"`
	DeviceIdentityDigest    bundle.Digest          `json:"device_identity_digest"`
	Snapshot                InitialGPTSnapshot     `json:"snapshot"`
	PlannedPayloadRanges    []PlannedPayloadRange  `json:"planned_payload_ranges"`
	RecoveryScope           string                 `json:"recovery_scope"`
	RecoveryRanges          []InitialRecoveryRange `json:"recovery_ranges"`
	DestructiveStagingReady bool                   `json:"destructive_staging_ready"`
	EnvelopeDigest          bundle.Digest          `json:"envelope_digest"`
}

type initialGPTHeader struct {
	currentLBA     uint64
	alternateLBA   uint64
	firstUsableLBA uint64
	lastUsableLBA  uint64
	diskGUID       string
	entriesLBA     uint64
	entryCount     uint32
	entrySize      uint32
	entriesCRC32   uint32
	headerCRC32    uint32
}

// InspectInitialGPTRecovery strictly parses a captured 512-byte-sector GPT
// from reader and hashes every exact recovery range. reader is only required
// to implement io.ReaderAt; the API contains no filesystem or write operation.
func InspectInitialGPTRecovery(reader io.ReaderAt, identity DeviceIdentity, captureID string, planned []PlannedPayloadRange) (InitialGPTRecoveryEnvelope, error) {
	if reader == nil {
		return InitialGPTRecoveryEnvelope{}, errors.New("inspect initial GPT: reader is nil")
	}
	if err := identity.Validate(); err != nil {
		return InitialGPTRecoveryEnvelope{}, fmt.Errorf("inspect initial GPT: identity: %w", err)
	}
	if !initialGPTCaptureIDPattern.MatchString(captureID) {
		return InitialGPTRecoveryEnvelope{}, errors.New("inspect initial GPT: capture_id must use the exact capture:<64 lowercase hex> form")
	}
	planned = append(make([]PlannedPayloadRange, 0, len(planned)), planned...)
	sort.Slice(planned, func(i, j int) bool {
		if planned[i].OffsetBytes != planned[j].OffsetBytes {
			return planned[i].OffsetBytes < planned[j].OffsetBytes
		}
		return planned[i].PartitionNumber < planned[j].PartitionNumber
	})
	if err := validatePlannedPayloadRanges(identity, planned); err != nil {
		return InitialGPTRecoveryEnvelope{}, fmt.Errorf("inspect initial GPT: planned payloads: %w", err)
	}

	snapshot, capturedMetadata, err := captureInitialGPT(reader, identity.CapacityBytes)
	if err != nil {
		return InitialGPTRecoveryEnvelope{}, fmt.Errorf("inspect initial GPT: %w", err)
	}
	identityDigest, err := deriveInitialGPTIdentityDigest(identity)
	if err != nil {
		return InitialGPTRecoveryEnvelope{}, fmt.Errorf("inspect initial GPT: %w", err)
	}
	specs, err := expectedInitialRecoveryRangeSpecs(identity, snapshot, planned)
	if err != nil {
		return InitialGPTRecoveryEnvelope{}, fmt.Errorf("inspect initial GPT: recovery ranges: %w", err)
	}
	ranges := make([]InitialRecoveryRange, len(specs))
	for index, spec := range specs {
		preimageDigest, err := digestCapturedInitialGPTRange(reader, capturedMetadata, spec.offsetBytes, spec.sizeBytes)
		if err != nil {
			return InitialGPTRecoveryEnvelope{}, fmt.Errorf("inspect initial GPT: hash recovery range %d: %w", index+1, err)
		}
		rangeBinding := InitialRecoveryRange{
			CaptureID: captureID, DeviceIdentityDigest: identityDigest,
			Purposes:    append([]InitialRecoveryRangePurpose(nil), spec.purposes...),
			OffsetBytes: spec.offsetBytes, SizeBytes: spec.sizeBytes, PreimageSHA256: preimageDigest,
		}
		rangeBinding.BindingDigest, err = rangeBinding.derivedBindingDigest()
		if err != nil {
			return InitialGPTRecoveryEnvelope{}, fmt.Errorf("inspect initial GPT: bind recovery range %d: %w", index+1, err)
		}
		ranges[index] = rangeBinding
	}

	envelope := InitialGPTRecoveryEnvelope{
		SchemaVersion: InitialGPTRecoveryEnvelopeSchemaV1Alpha1,
		CaptureID:     captureID, Identity: identity, DeviceIdentityDigest: identityDigest,
		Snapshot: snapshot, PlannedPayloadRanges: planned,
		RecoveryScope:  RecoveryScopeInspectedInitialGPTAndPlannedPayloads,
		RecoveryRanges: ranges, DestructiveStagingReady: false,
	}
	return envelope.Seal()
}

// VerifyAgainst re-reads the supplied capture source, repeats all semantic GPT
// checks and range hashes, and requires an exact envelope digest match.
func (envelope InitialGPTRecoveryEnvelope) VerifyAgainst(reader io.ReaderAt) error {
	if err := envelope.Validate(); err != nil {
		return err
	}
	rebuilt, err := InspectInitialGPTRecovery(reader, envelope.Identity, envelope.CaptureID, envelope.PlannedPayloadRanges)
	if err != nil {
		return err
	}
	if rebuilt.EnvelopeDigest != envelope.EnvelopeDigest {
		return errors.New("initial GPT recovery envelope differs from the supplied captured bytes")
	}
	return nil
}

// PlannedPayloadRangesFromDevicePlan returns the complete payload-range view
// of an independently validated campaign DevicePlan. It is the intended
// bridge from the current staging-plan schema into this read-only inspector;
// it performs no device I/O.
func PlannedPayloadRangesFromDevicePlan(device DevicePlan) ([]PlannedPayloadRange, error) {
	if err := device.Validate(); err != nil {
		return nil, fmt.Errorf("derive planned payload recovery ranges: %w", err)
	}
	result := make([]PlannedPayloadRange, len(device.Partitions))
	for index, partition := range device.Partitions {
		result[index] = PlannedPayloadRange{
			Role: partition.Role, PartitionNumber: partition.Number,
			OffsetBytes: partition.ByteStart, SizeBytes: partition.CapacityBytes,
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].OffsetBytes < result[j].OffsetBytes })
	return result, nil
}

type capturedInitialGPTRange struct {
	offsetBytes uint64
	bytes       []byte
}

type capturedInitialGPTMetadata []capturedInitialGPTRange

func (captured capturedInitialGPTMetadata) digest(offset, size uint64) (bundle.Digest, bool) {
	for _, candidate := range captured {
		if candidate.offsetBytes == offset && uint64(len(candidate.bytes)) == size {
			return bundle.Sum(candidate.bytes), true
		}
	}
	return "", false
}

// parseInitialGPT is the narrow semantic-only helper used by parser tests.
// captureInitialGPT is the production primitive so callers can reuse the same
// exact bytes when sealing metadata preimage digests.
func parseInitialGPT(reader io.ReaderAt, capacityBytes uint64) (InitialGPTSnapshot, error) {
	snapshot, _, err := captureInitialGPT(reader, capacityBytes)
	return snapshot, err
}

func captureInitialGPT(reader io.ReaderAt, capacityBytes uint64) (InitialGPTSnapshot, capturedInitialGPTMetadata, error) {
	if capacityBytes%LogicalSectorSizeBytes != 0 {
		return InitialGPTSnapshot{}, nil, errors.New("physical capacity is not a whole number of 512-byte sectors")
	}
	physicalTotalLBAs := capacityBytes / LogicalSectorSizeBytes
	if physicalTotalLBAs < 68 {
		return InitialGPTSnapshot{}, nil, errors.New("physical device is too small for GPT")
	}

	mbr := make([]byte, LogicalSectorSizeBytes)
	if err := readInitialGPTExact(reader, 0, mbr); err != nil {
		return InitialGPTSnapshot{}, nil, fmt.Errorf("read protective MBR: %w", err)
	}
	primarySector := make([]byte, LogicalSectorSizeBytes)
	if err := readInitialGPTExact(reader, LogicalSectorSizeBytes, primarySector); err != nil {
		return InitialGPTSnapshot{}, nil, fmt.Errorf("read primary header: %w", err)
	}
	primary, err := parseInitialGPTHeaderSector(primarySector, physicalTotalLBAs)
	if err != nil {
		return InitialGPTSnapshot{}, nil, fmt.Errorf("primary header: %w", err)
	}
	if primary.currentLBA != 1 || primary.entriesLBA != 2 ||
		primary.entryCount != initialGPTEntryCount || primary.entrySize != initialGPTEntrySizeBytes {
		return InitialGPTSnapshot{}, nil, errors.New("primary GPT is not in the required 128x128 canonical geometry")
	}
	if primary.alternateLBA < 67 || primary.alternateLBA >= physicalTotalLBAs {
		return InitialGPTSnapshot{}, nil, errors.New("primary GPT alternate LBA is outside the physical device")
	}
	embeddedTotalLBAs := primary.alternateLBA + 1
	if primary.firstUsableLBA != 34 || primary.lastUsableLBA != primary.alternateLBA-33 {
		return InitialGPTSnapshot{}, nil, errors.New("primary GPT usable range does not match its embedded container")
	}
	if err := verifyInitialProtectiveMBR(mbr, primary.alternateLBA); err != nil {
		return InitialGPTSnapshot{}, nil, err
	}

	backupHeaderOffset := primary.alternateLBA * LogicalSectorSizeBytes
	backupSector := make([]byte, LogicalSectorSizeBytes)
	if err := readInitialGPTExact(reader, backupHeaderOffset, backupSector); err != nil {
		return InitialGPTSnapshot{}, nil, fmt.Errorf("read backup header at declared alternate LBA: %w", err)
	}
	backup, err := parseInitialGPTHeaderSector(backupSector, physicalTotalLBAs)
	if err != nil {
		return InitialGPTSnapshot{}, nil, fmt.Errorf("backup header at declared alternate LBA: %w", err)
	}
	if backup.currentLBA != primary.alternateLBA || backup.alternateLBA != 1 ||
		backup.entriesLBA != primary.alternateLBA-32 ||
		backup.firstUsableLBA != primary.firstUsableLBA || backup.lastUsableLBA != primary.lastUsableLBA ||
		backup.diskGUID != primary.diskGUID || backup.entryCount != primary.entryCount ||
		backup.entrySize != primary.entrySize || backup.entriesCRC32 != primary.entriesCRC32 {
		return InitialGPTSnapshot{}, nil, errors.New("primary and backup GPT headers do not describe the same reciprocal table")
	}
	if err := validateInitialGPTGUID("disk GUID", primary.diskGUID); err != nil {
		return InitialGPTSnapshot{}, nil, err
	}

	primaryEntries, err := readInitialGPTEntriesOnce(reader, primary)
	if err != nil {
		return InitialGPTSnapshot{}, nil, fmt.Errorf("primary entries: %w", err)
	}
	backupEntries, err := readInitialGPTEntriesOnce(reader, backup)
	if err != nil {
		return InitialGPTSnapshot{}, nil, fmt.Errorf("backup entries: %w", err)
	}
	if !bytes.Equal(primaryEntries, backupEntries) {
		return InitialGPTSnapshot{}, nil, errors.New("primary and backup GPT entry arrays differ")
	}
	partitions, err := parseInitialGPTPartitions(primaryEntries, primary.firstUsableLBA, primary.lastUsableLBA, primary.diskGUID)
	if err != nil {
		return InitialGPTSnapshot{}, nil, err
	}

	placement := InitialGPTPlacementCanonicalPhysical
	var physicalEndSector []byte
	if embeddedTotalLBAs < physicalTotalLBAs {
		placement = InitialGPTPlacementImageSized
		// A second GPT header at the physical end makes the device ambiguous to
		// readers that probe there rather than follow the primary header's
		// declared alternate LBA. Capture this sector once, reject the ambiguous
		// signature, and reuse the same bytes for its recovery-range digest.
		physicalEndOffset := capacityBytes - LogicalSectorSizeBytes
		physicalEndSector = make([]byte, LogicalSectorSizeBytes)
		if err := readInitialGPTExact(reader, physicalEndOffset, physicalEndSector); err != nil {
			return InitialGPTSnapshot{}, nil, fmt.Errorf("read physical-end GPT preimage: %w", err)
		}
		if bytes.Equal(physicalEndSector[:8], []byte("EFI PART")) {
			return InitialGPTSnapshot{}, nil, errors.New("image-sized GPT conflicts with a GPT header signature at the physical end")
		}
	}
	snapshot := InitialGPTSnapshot{
		Placement: placement, PhysicalTotalLBAs: physicalTotalLBAs,
		EmbeddedGPTTotalLBAs: embeddedTotalLBAs, ProtectiveMBRLastLBA: primary.alternateLBA,
		PrimaryHeaderLBA: 1, PrimaryHeaderCRC32: primary.headerCRC32,
		PrimaryEntryArrayLBA: primary.entriesLBA, BackupEntryArrayLBA: backup.entriesLBA,
		BackupHeaderLBA: backup.currentLBA, BackupHeaderCRC32: backup.headerCRC32,
		FirstUsableLBA: primary.firstUsableLBA, LastUsableLBA: primary.lastUsableLBA,
		DiskGUID: primary.diskGUID, PartitionEntryCount: primary.entryCount,
		PartitionEntrySizeBytes: primary.entrySize, PartitionEntryArrayCRC32: primary.entriesCRC32,
		Partitions: partitions,
	}
	captured := capturedInitialGPTMetadata{
		{offsetBytes: 0, bytes: mbr},
		{offsetBytes: LogicalSectorSizeBytes, bytes: primarySector},
		{offsetBytes: primary.entriesLBA * LogicalSectorSizeBytes, bytes: primaryEntries},
		{offsetBytes: backup.entriesLBA * LogicalSectorSizeBytes, bytes: backupEntries},
		{offsetBytes: backupHeaderOffset, bytes: backupSector},
	}
	if physicalEndSector != nil {
		captured = append(captured, capturedInitialGPTRange{
			offsetBytes: capacityBytes - LogicalSectorSizeBytes,
			bytes:       physicalEndSector,
		})
	}
	return snapshot, captured, nil
}

func verifyInitialProtectiveMBR(mbr []byte, embeddedLastLBA uint64) error {
	if len(mbr) != int(LogicalSectorSizeBytes) || mbr[510] != 0x55 || mbr[511] != 0xaa {
		return errors.New("protective MBR signature is invalid")
	}
	if !initialGPTAllZero(mbr[:446]) || !initialGPTAllZero(mbr[462:510]) {
		return errors.New("protective MBR contains boot code, a disk signature, or hybrid entries")
	}
	entry := mbr[446:462]
	if entry[0] != 0 || entry[4] != 0xee || binary.LittleEndian.Uint32(entry[8:12]) != 1 {
		return errors.New("protective MBR does not contain the required 0xEE entry at LBA 1")
	}
	zeroCHS := initialGPTAllZero(entry[1:4]) && initialGPTAllZero(entry[5:8])
	conventionalCHS := bytes.Equal(entry[1:4], []byte{0x00, 0x02, 0x00}) && bytes.Equal(entry[5:8], []byte{0xff, 0xff, 0xff})
	if !zeroCHS && !conventionalCHS {
		return errors.New("protective MBR contains an unsupported CHS encoding")
	}
	expectedSize := embeddedLastLBA
	if expectedSize > math.MaxUint32 {
		expectedSize = math.MaxUint32
	}
	if uint64(binary.LittleEndian.Uint32(entry[12:16])) != expectedSize {
		return errors.New("protective MBR size does not cover exactly the embedded GPT container")
	}
	return nil
}

func parseInitialGPTHeaderSector(sector []byte, physicalTotalLBAs uint64) (initialGPTHeader, error) {
	if len(sector) != int(LogicalSectorSizeBytes) {
		return initialGPTHeader{}, errors.New("GPT header must be exactly one logical sector")
	}
	if string(sector[:8]) != "EFI PART" || binary.LittleEndian.Uint32(sector[8:12]) != 0x00010000 ||
		binary.LittleEndian.Uint32(sector[12:16]) != initialGPTHeaderSizeBytes || binary.LittleEndian.Uint32(sector[20:24]) != 0 {
		return initialGPTHeader{}, errors.New("signature, revision, header size, or reserved field is invalid")
	}
	storedCRC32 := binary.LittleEndian.Uint32(sector[16:20])
	crcMaterial := append([]byte(nil), sector[:initialGPTHeaderSizeBytes]...)
	for index := 16; index < 20; index++ {
		crcMaterial[index] = 0
	}
	if crc32.ChecksumIEEE(crcMaterial) != storedCRC32 {
		return initialGPTHeader{}, errors.New("header CRC32 is invalid")
	}
	if !initialGPTAllZero(sector[initialGPTHeaderSizeBytes:]) {
		return initialGPTHeader{}, errors.New("GPT header sector contains non-zero trailing bytes")
	}
	header := initialGPTHeader{
		currentLBA: binary.LittleEndian.Uint64(sector[24:32]), alternateLBA: binary.LittleEndian.Uint64(sector[32:40]),
		firstUsableLBA: binary.LittleEndian.Uint64(sector[40:48]), lastUsableLBA: binary.LittleEndian.Uint64(sector[48:56]),
		diskGUID: initialGPTGUIDFromBytes(sector[56:72]), entriesLBA: binary.LittleEndian.Uint64(sector[72:80]),
		entryCount: binary.LittleEndian.Uint32(sector[80:84]), entrySize: binary.LittleEndian.Uint32(sector[84:88]),
		entriesCRC32: binary.LittleEndian.Uint32(sector[88:92]), headerCRC32: storedCRC32,
	}
	if header.currentLBA >= physicalTotalLBAs || header.alternateLBA >= physicalTotalLBAs ||
		header.firstUsableLBA > header.lastUsableLBA || header.lastUsableLBA >= physicalTotalLBAs ||
		header.entriesLBA >= physicalTotalLBAs {
		return initialGPTHeader{}, errors.New("header contains an out-of-range LBA")
	}
	return header, nil
}

func readInitialGPTEntriesOnce(reader io.ReaderAt, header initialGPTHeader) ([]byte, error) {
	if header.entryCount != initialGPTEntryCount || header.entrySize != initialGPTEntrySizeBytes {
		return nil, errors.New("GPT entry geometry is not exactly 128 entries of 128 bytes")
	}
	entries := make([]byte, initialGPTEntryArrayBytes)
	if err := readInitialGPTExact(reader, header.entriesLBA*LogicalSectorSizeBytes, entries); err != nil {
		return nil, err
	}
	if crc32.ChecksumIEEE(entries) != header.entriesCRC32 {
		return nil, errors.New("GPT entry-array CRC32 is invalid")
	}
	return entries, nil
}

func parseInitialGPTPartitions(entries []byte, firstUsableLBA, lastUsableLBA uint64, diskGUID string) ([]InitialGPTPartition, error) {
	partitions := make([]InitialGPTPartition, 0)
	seenGUIDs := map[string]struct{}{diskGUID: {}}
	for index := uint32(0); index < initialGPTEntryCount; index++ {
		entry := entries[uint64(index)*uint64(initialGPTEntrySizeBytes) : uint64(index+1)*uint64(initialGPTEntrySizeBytes)]
		if initialGPTAllZero(entry[:16]) {
			if !initialGPTAllZero(entry) {
				return nil, fmt.Errorf("unused GPT entry %d contains non-zero data", index+1)
			}
			continue
		}
		typeGUID := initialGPTGUIDFromBytes(entry[:16])
		uniqueGUID := initialGPTGUIDFromBytes(entry[16:32])
		if err := validateInitialGPTGUID(fmt.Sprintf("partition %d type GUID", index+1), typeGUID); err != nil {
			return nil, err
		}
		if err := validateInitialGPTGUID(fmt.Sprintf("partition %d unique GUID", index+1), uniqueGUID); err != nil {
			return nil, err
		}
		if _, duplicate := seenGUIDs[uniqueGUID]; duplicate {
			return nil, fmt.Errorf("partition %d repeats a unique GUID", index+1)
		}
		seenGUIDs[uniqueGUID] = struct{}{}
		firstLBA := binary.LittleEndian.Uint64(entry[32:40])
		lastLBA := binary.LittleEndian.Uint64(entry[40:48])
		if firstLBA > lastLBA || firstLBA < firstUsableLBA || lastLBA > lastUsableLBA {
			return nil, fmt.Errorf("partition %d is outside the GPT usable range", index+1)
		}
		name, err := decodeInitialGPTName(entry[56:128])
		if err != nil {
			return nil, fmt.Errorf("partition %d name: %w", index+1, err)
		}
		partitions = append(partitions, InitialGPTPartition{
			EntryNumber: index + 1, TypeGUID: typeGUID, UniqueGUID: uniqueGUID,
			FirstLBA: firstLBA, LastLBA: lastLBA,
			Attributes: binary.LittleEndian.Uint64(entry[48:56]), Name: name,
		})
	}
	byStart := append([]InitialGPTPartition(nil), partitions...)
	sort.Slice(byStart, func(i, j int) bool { return byStart[i].FirstLBA < byStart[j].FirstLBA })
	for index := 1; index < len(byStart); index++ {
		if byStart[index].FirstLBA <= byStart[index-1].LastLBA {
			return nil, fmt.Errorf("partitions %d and %d overlap", byStart[index-1].EntryNumber, byStart[index].EntryNumber)
		}
	}
	return partitions, nil
}

func decodeInitialGPTName(raw []byte) (string, error) {
	units := make([]uint16, 0, len(raw)/2)
	terminated := false
	for index := 0; index < len(raw); index += 2 {
		unit := binary.LittleEndian.Uint16(raw[index : index+2])
		if unit == 0 {
			terminated = true
			continue
		}
		if terminated {
			return "", errors.New("contains non-zero data after its terminator")
		}
		units = append(units, unit)
	}
	decoded := string(utf16.Decode(units))
	if err := validateInitialGPTPrintableName(decoded); err != nil {
		return "", err
	}
	return decoded, nil
}

func validateInitialGPTPrintableName(name string) error {
	values := []rune(name)
	if len(values) == 0 {
		return errors.New("must not be empty")
	}
	if len(values) > 36 {
		return errors.New("must fit in the 36-code-unit GPT name field")
	}
	for _, value := range values {
		if value < 0x20 || value > 0x7e {
			return errors.New("must contain only printable ASCII")
		}
	}
	return nil
}

func validateInitialGPTGUID(label, value string) error {
	if value == "00000000-0000-0000-0000-000000000000" || !guidPattern.MatchString(value) {
		return fmt.Errorf("%s must be a non-zero canonical lowercase GUID", label)
	}
	return nil
}

func initialGPTGUIDFromBytes(value []byte) string {
	if len(value) != 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(value[0:4]), binary.LittleEndian.Uint16(value[4:6]),
		binary.LittleEndian.Uint16(value[6:8]), value[8], value[9], value[10], value[11],
		value[12], value[13], value[14], value[15])
}

func initialGPTAllZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func readInitialGPTExact(reader io.ReaderAt, offset uint64, buffer []byte) error {
	if offset > math.MaxInt64 || uint64(len(buffer)) > math.MaxInt64-offset {
		return errors.New("byte range exceeds io.ReaderAt limits")
	}
	n, err := reader.ReadAt(buffer, int64(offset))
	if n != len(buffer) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

type initialRecoveryRangeSpec struct {
	purposes    []InitialRecoveryRangePurpose
	offsetBytes uint64
	sizeBytes   uint64
}

func expectedInitialRecoveryRangeSpecs(identity DeviceIdentity, snapshot InitialGPTSnapshot, planned []PlannedPayloadRange) ([]initialRecoveryRangeSpec, error) {
	finalHeaderOffset := identity.CapacityBytes - LogicalSectorSizeBytes
	finalEntriesOffset := finalHeaderOffset - initialGPTEntryArrayBytes
	existingHeaderOffset := snapshot.BackupHeaderLBA * LogicalSectorSizeBytes
	existingEntriesOffset := snapshot.BackupEntryArrayLBA * LogicalSectorSizeBytes
	specs := []initialRecoveryRangeSpec{
		{[]InitialRecoveryRangePurpose{InitialRecoveryProtectiveMBR}, 0, LogicalSectorSizeBytes},
		{[]InitialRecoveryRangePurpose{InitialRecoveryPrimaryHeader}, LogicalSectorSizeBytes, LogicalSectorSizeBytes},
		{[]InitialRecoveryRangePurpose{InitialRecoveryPrimaryEntryArray}, 2 * LogicalSectorSizeBytes, initialGPTEntryArrayBytes},
		{[]InitialRecoveryRangePurpose{InitialRecoveryExistingBackupEntries}, existingEntriesOffset, initialGPTEntryArrayBytes},
		{[]InitialRecoveryRangePurpose{InitialRecoveryExistingBackupHeader}, existingHeaderOffset, LogicalSectorSizeBytes},
		{[]InitialRecoveryRangePurpose{InitialRecoveryFinalBackupEntries}, finalEntriesOffset, initialGPTEntryArrayBytes},
		{[]InitialRecoveryRangePurpose{InitialRecoveryFinalBackupHeader}, finalHeaderOffset, LogicalSectorSizeBytes},
	}
	for _, payload := range planned {
		purpose, err := initialRecoveryPurposeForPartition(payload.Role)
		if err != nil {
			return nil, err
		}
		specs = append(specs, initialRecoveryRangeSpec{[]InitialRecoveryRangePurpose{purpose}, payload.OffsetBytes, payload.SizeBytes})
	}
	sort.SliceStable(specs, func(i, j int) bool {
		if specs[i].offsetBytes != specs[j].offsetBytes {
			return specs[i].offsetBytes < specs[j].offsetBytes
		}
		return specs[i].sizeBytes < specs[j].sizeBytes
	})
	merged := make([]initialRecoveryRangeSpec, 0, len(specs))
	for _, spec := range specs {
		if len(merged) > 0 {
			previous := &merged[len(merged)-1]
			if spec.offsetBytes == previous.offsetBytes && spec.sizeBytes == previous.sizeBytes {
				// Only the existing/final backup-GPT aliases may describe the
				// same canonical physical-end bytes.
				if !mergeableInitialGPTMetadataPurposes(previous.purposes, spec.purposes) {
					return nil, errors.New("two recovery purposes name the same byte range")
				}
				previous.purposes = append(previous.purposes, spec.purposes...)
				continue
			}
			previousEnd := previous.offsetBytes + previous.sizeBytes
			if spec.offsetBytes < previousEnd {
				return nil, errors.New("recovery byte ranges overlap")
			}
		}
		merged = append(merged, spec)
	}
	return merged, nil
}

func mergeableInitialGPTMetadataPurposes(left, right []InitialRecoveryRangePurpose) bool {
	if len(left) != 1 || len(right) != 1 {
		return false
	}
	pair := map[InitialRecoveryRangePurpose]bool{left[0]: true, right[0]: true}
	return (pair[InitialRecoveryExistingBackupEntries] && pair[InitialRecoveryFinalBackupEntries]) ||
		(pair[InitialRecoveryExistingBackupHeader] && pair[InitialRecoveryFinalBackupHeader])
}

func initialRecoveryPurposeForPartition(role PartitionRole) (InitialRecoveryRangePurpose, error) {
	switch role {
	case PartitionBootFilesystem:
		return InitialRecoveryPlannedBoot, nil
	case PartitionRootData:
		return InitialRecoveryPlannedRootData, nil
	case PartitionRootHash:
		return InitialRecoveryPlannedRootHash, nil
	case PartitionReleaseFilesystem:
		return InitialRecoveryPlannedRelease, nil
	default:
		return "", fmt.Errorf("unsupported planned payload role %q", role)
	}
}

func validatePlannedPayloadRanges(identity DeviceIdentity, planned []PlannedPayloadRange) error {
	fixed, _ := fixedIdentityFor(identity.Leg)
	if len(planned) != len(fixed.partitions) {
		return fmt.Errorf("leg %q must bind exactly all %d fixed planned payload ranges", identity.Leg, len(fixed.partitions))
	}
	var previousEnd uint64
	for index, payload := range planned {
		expected := fixed.partitions[index]
		if payload.Role != expected.role || payload.PartitionNumber != expected.number ||
			payload.OffsetBytes != expected.byteStart || payload.SizeBytes != expected.capacity {
			return fmt.Errorf("range %d differs from the fixed role, partition number, start, or capacity for leg %q", index+1, identity.Leg)
		}
		if payload.SizeBytes == 0 || payload.OffsetBytes%LogicalSectorSizeBytes != 0 || payload.SizeBytes%LogicalSectorSizeBytes != 0 {
			return fmt.Errorf("range %d must be a positive, sector-aligned byte range", index+1)
		}
		if payload.OffsetBytes > math.MaxUint64-payload.SizeBytes ||
			payload.OffsetBytes+payload.SizeBytes > identity.CapacityBytes-initialGPTEntryArrayBytes-LogicalSectorSizeBytes {
			return fmt.Errorf("range %d extends into or beyond the final backup GPT", index+1)
		}
		if index > 0 && payload.OffsetBytes < previousEnd {
			return errors.New("planned payload ranges overlap")
		}
		previousEnd = payload.OffsetBytes + payload.SizeBytes
	}
	return nil
}

func deriveInitialGPTIdentityDigest(identity DeviceIdentity) (bundle.Digest, error) {
	if err := identity.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", fmt.Errorf("encode device identity digest material: %w", err)
	}
	return domainDigest(initialGPTIdentityDigestDomain, encoded), nil
}

type initialRecoveryRangeDigestMaterial struct {
	CaptureID            string                        `json:"capture_id"`
	DeviceIdentityDigest bundle.Digest                 `json:"device_identity_digest"`
	Purposes             []InitialRecoveryRangePurpose `json:"purposes"`
	OffsetBytes          uint64                        `json:"offset_bytes"`
	SizeBytes            uint64                        `json:"size_bytes"`
	PreimageSHA256       bundle.Digest                 `json:"preimage_sha256"`
}

func (recoveryRange InitialRecoveryRange) derivedBindingDigest() (bundle.Digest, error) {
	material := initialRecoveryRangeDigestMaterial{
		CaptureID: recoveryRange.CaptureID, DeviceIdentityDigest: recoveryRange.DeviceIdentityDigest,
		Purposes:    append([]InitialRecoveryRangePurpose(nil), recoveryRange.Purposes...),
		OffsetBytes: recoveryRange.OffsetBytes, SizeBytes: recoveryRange.SizeBytes,
		PreimageSHA256: recoveryRange.PreimageSHA256,
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", fmt.Errorf("encode recovery range digest material: %w", err)
	}
	return domainDigest(initialGPTRangeDigestDomain, encoded), nil
}

func digestCapturedInitialGPTRange(reader io.ReaderAt, captured capturedInitialGPTMetadata, offset, size uint64) (bundle.Digest, error) {
	if digest, ok := captured.digest(offset, size); ok {
		return digest, nil
	}
	return digestReaderRange(reader, offset, size)
}

func digestReaderRange(reader io.ReaderAt, offset, size uint64) (bundle.Digest, error) {
	if size == 0 || offset > math.MaxUint64-size || offset > math.MaxInt64 || size > math.MaxInt64-offset {
		return "", errors.New("invalid reader byte range")
	}
	hash := sha256.New()
	buffer := make([]byte, 1024*1024)
	position := uint64(0)
	for position < size {
		chunk := size - position
		if chunk > uint64(len(buffer)) {
			chunk = uint64(len(buffer))
		}
		if err := readInitialGPTExact(reader, offset+position, buffer[:int(chunk)]); err != nil {
			return "", err
		}
		_, _ = hash.Write(buffer[:int(chunk)])
		position += chunk
	}
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

// DerivedDigest returns the context-bound envelope digest with envelope_digest
// empty. It validates every semantic and per-range binding first.
func (envelope InitialGPTRecoveryEnvelope) DerivedDigest() (bundle.Digest, error) {
	material := envelope
	material.EnvelopeDigest = ""
	if err := material.validate(false); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", fmt.Errorf("encode initial GPT recovery envelope digest material: %w", err)
	}
	return domainDigest(initialGPTEnvelopeDigestDomain, encoded), nil
}

// Seal returns a copy with its derived envelope digest populated.
func (envelope InitialGPTRecoveryEnvelope) Seal() (InitialGPTRecoveryEnvelope, error) {
	digest, err := envelope.DerivedDigest()
	if err != nil {
		return InitialGPTRecoveryEnvelope{}, err
	}
	envelope.EnvelopeDigest = digest
	if err := envelope.Validate(); err != nil {
		return InitialGPTRecoveryEnvelope{}, err
	}
	return envelope, nil
}

// Validate checks the sealed descriptive envelope. It does not re-read the
// device; use VerifyAgainst for that content-aware check.
func (envelope InitialGPTRecoveryEnvelope) Validate() error { return envelope.validate(true) }

func (envelope InitialGPTRecoveryEnvelope) validate(requireDigest bool) error {
	if envelope.SchemaVersion != InitialGPTRecoveryEnvelopeSchemaV1Alpha1 {
		return fmt.Errorf("unsupported initial GPT recovery envelope schema_version %q", envelope.SchemaVersion)
	}
	if !initialGPTCaptureIDPattern.MatchString(envelope.CaptureID) {
		return errors.New("capture_id must use the exact capture:<64 lowercase hex> form")
	}
	if err := envelope.Identity.Validate(); err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	identityDigest, err := deriveInitialGPTIdentityDigest(envelope.Identity)
	if err != nil {
		return err
	}
	if envelope.DeviceIdentityDigest != identityDigest {
		return errors.New("device_identity_digest does not bind the fixed identity")
	}
	if err := envelope.Snapshot.validate(envelope.Identity); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	if err := validatePlannedPayloadRanges(envelope.Identity, envelope.PlannedPayloadRanges); err != nil {
		return fmt.Errorf("planned payloads: %w", err)
	}
	if envelope.RecoveryScope != RecoveryScopeInspectedInitialGPTAndPlannedPayloads || envelope.DestructiveStagingReady {
		return errors.New("v1alpha1 recovery envelope must remain descriptive and ineligible for destructive staging")
	}
	expected, err := expectedInitialRecoveryRangeSpecs(envelope.Identity, envelope.Snapshot, envelope.PlannedPayloadRanges)
	if err != nil {
		return err
	}
	if len(envelope.RecoveryRanges) != len(expected) {
		return errors.New("recovery_ranges does not contain exactly every computed nonoverlapping range")
	}
	for index, expectedRange := range expected {
		actual := envelope.RecoveryRanges[index]
		if actual.CaptureID != envelope.CaptureID || actual.DeviceIdentityDigest != identityDigest ||
			actual.OffsetBytes != expectedRange.offsetBytes || actual.SizeBytes != expectedRange.sizeBytes ||
			!equalInitialRecoveryPurposes(actual.Purposes, expectedRange.purposes) {
			return fmt.Errorf("recovery range %d differs from its context-bound computed geometry", index+1)
		}
		if err := validateDigest(fmt.Sprintf("recovery range %d preimage_sha256", index+1), actual.PreimageSHA256); err != nil {
			return err
		}
		derived, err := actual.derivedBindingDigest()
		if err != nil {
			return err
		}
		if actual.BindingDigest != derived {
			return fmt.Errorf("recovery range %d binding_digest is detached from its context and preimage", index+1)
		}
	}
	if requireDigest {
		if err := validateDigest("envelope_digest", envelope.EnvelopeDigest); err != nil {
			return err
		}
		derived, err := envelope.DerivedDigest()
		if err != nil {
			return err
		}
		if envelope.EnvelopeDigest != derived {
			return errors.New("envelope_digest does not bind the initial GPT recovery envelope")
		}
	}
	return nil
}

func (snapshot InitialGPTSnapshot) validate(identity DeviceIdentity) error {
	physicalTotalLBAs := identity.CapacityBytes / LogicalSectorSizeBytes
	if snapshot.PhysicalTotalLBAs != physicalTotalLBAs || snapshot.EmbeddedGPTTotalLBAs < 68 ||
		snapshot.EmbeddedGPTTotalLBAs > physicalTotalLBAs || snapshot.ProtectiveMBRLastLBA != snapshot.EmbeddedGPTTotalLBAs-1 {
		return errors.New("physical and embedded GPT sizes are inconsistent with the fixed identity")
	}
	expectedPlacement := InitialGPTPlacementCanonicalPhysical
	if snapshot.EmbeddedGPTTotalLBAs < physicalTotalLBAs {
		expectedPlacement = InitialGPTPlacementImageSized
	}
	if snapshot.Placement != expectedPlacement {
		return errors.New("GPT placement classification differs from its physical and embedded capacities")
	}
	if snapshot.PrimaryHeaderLBA != 1 || snapshot.PrimaryEntryArrayLBA != 2 ||
		snapshot.BackupHeaderLBA != snapshot.EmbeddedGPTTotalLBAs-1 ||
		snapshot.BackupEntryArrayLBA != snapshot.BackupHeaderLBA-32 ||
		snapshot.FirstUsableLBA != 34 || snapshot.LastUsableLBA != snapshot.BackupHeaderLBA-33 ||
		snapshot.PartitionEntryCount != initialGPTEntryCount || snapshot.PartitionEntrySizeBytes != initialGPTEntrySizeBytes {
		return errors.New("snapshot does not describe the required reciprocal 128x128 GPT geometry")
	}
	if err := validateInitialGPTGUID("snapshot disk GUID", snapshot.DiskGUID); err != nil {
		return err
	}
	if snapshot.DiskGUID != identity.DiskGUID {
		return errors.New("snapshot disk GUID differs from the fixed device identity")
	}
	seenGUIDs := map[string]struct{}{snapshot.DiskGUID: {}}
	byStart := append([]InitialGPTPartition(nil), snapshot.Partitions...)
	for index, partition := range snapshot.Partitions {
		if partition.EntryNumber == 0 || partition.EntryNumber > initialGPTEntryCount || (index > 0 && partition.EntryNumber <= snapshot.Partitions[index-1].EntryNumber) {
			return errors.New("snapshot partitions must retain unique increasing GPT entry numbers")
		}
		if err := validateInitialGPTGUID("snapshot partition type GUID", partition.TypeGUID); err != nil {
			return err
		}
		if err := validateInitialGPTGUID("snapshot partition unique GUID", partition.UniqueGUID); err != nil {
			return err
		}
		if _, duplicate := seenGUIDs[partition.UniqueGUID]; duplicate {
			return errors.New("snapshot repeats a partition unique GUID")
		}
		seenGUIDs[partition.UniqueGUID] = struct{}{}
		if partition.FirstLBA > partition.LastLBA || partition.FirstLBA < snapshot.FirstUsableLBA || partition.LastLBA > snapshot.LastUsableLBA {
			return errors.New("snapshot partition is outside its GPT usable range")
		}
		if err := validateInitialGPTPrintableName(partition.Name); err != nil {
			return fmt.Errorf("snapshot partition name: %w", err)
		}
	}
	sort.Slice(byStart, func(i, j int) bool { return byStart[i].FirstLBA < byStart[j].FirstLBA })
	for index := 1; index < len(byStart); index++ {
		if byStart[index].FirstLBA <= byStart[index-1].LastLBA {
			return errors.New("snapshot partitions overlap")
		}
	}
	return nil
}

func equalInitialRecoveryPurposes(left, right []InitialRecoveryRangePurpose) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// CanonicalJSON returns the compact canonical envelope encoding.
func (envelope InitialGPTRecoveryEnvelope) CanonicalJSON() ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	return marshalWithinLimit("initial GPT recovery envelope", envelope)
}

// ParseInitialGPTRecoveryEnvelope accepts strict canonical JSON, optionally
// followed by one LF. VerifyAgainst is still required to re-establish its byte
// and semantic relationship to a captured device image.
func ParseInitialGPTRecoveryEnvelope(encoded []byte) (InitialGPTRecoveryEnvelope, error) {
	var envelope InitialGPTRecoveryEnvelope
	if err := strictCanonicalDecode(encoded, &envelope, func() ([]byte, error) { return envelope.CanonicalJSON() }); err != nil {
		return InitialGPTRecoveryEnvelope{}, fmt.Errorf("parse initial GPT recovery envelope: %w", err)
	}
	return envelope, nil
}
