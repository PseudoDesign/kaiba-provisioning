package campaignmedia

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	InitialGPTRecoveryEnvelopeSchemaV1Alpha2 = "kaiba.provisioning.rpi5-stable-verifier-initial-gpt-recovery-envelope/v1alpha2"

	// RecoveryScopeInspectedInitialGPTLineagesAndPlannedPayloads records every
	// selected-lineage GPT range, a strictly parsed physical-end backup lineage
	// when one is present, and the fixed planned payload ranges. It remains a
	// descriptive read-only scope, not recovery storage or write authority.
	RecoveryScopeInspectedInitialGPTLineagesAndPlannedPayloads = "inspected-selected-gpt-and-physical-end-gpt-lineages-and-listed-planned-payloads"

	InitialGPTPhysicalEndBackupCompleteness = "valid-standalone-backup-copy"
	InitialGPTPhysicalEndBackupRelationship = "same-partition-layout-distinct-disk-and-partition-guids"
)

const (
	initialGPTIdentityDigestDomainV1Alpha2           = "kaiba.provisioning.rpi5-stable-verifier-initial-gpt-device-identity.v1alpha2"
	initialGPTRangeDigestDomainV1Alpha2              = "kaiba.provisioning.rpi5-stable-verifier-initial-gpt-recovery-range.v1alpha2"
	initialGPTPhysicalEndLineageDigestDomainV1Alpha2 = "kaiba.provisioning.rpi5-stable-verifier-physical-end-gpt-lineage.v1alpha2"
	initialGPTEnvelopeDigestDomainV1Alpha2           = "kaiba.provisioning.rpi5-stable-verifier-initial-gpt-recovery-envelope.v1alpha2"
)

// InitialGPTPhysicalEndState says what the strict inspector established at
// the last physical LBA. A signature that is neither the selected lineage's
// canonical backup nor a completely valid distinct backup copy is rejected;
// it is never downgraded to an opaque preimage.
type InitialGPTPhysicalEndState string

const (
	InitialGPTPhysicalEndSelectedLineageBackup InitialGPTPhysicalEndState = "selected-lineage-backup"
	InitialGPTPhysicalEndNonGPTPreimage        InitialGPTPhysicalEndState = "non-gpt-preimage"
	InitialGPTPhysicalEndDistinctBackupLineage InitialGPTPhysicalEndState = "distinct-valid-backup-lineage"
)

const (
	InitialRecoveryPhysicalEndBackupEntries InitialRecoveryRangePurpose = "initial-valid-distinct-physical-end-backup-lineage-entry-array"
	InitialRecoveryPhysicalEndBackupHeader  InitialRecoveryRangePurpose = "initial-valid-distinct-physical-end-backup-lineage-header"
)

// InitialGPTPhysicalEndBackupLineage is the semantic and byte-digest view of
// one valid backup GPT copy found at the physical end. It deliberately says
// "standalone backup copy": its header points to LBA 1, but the selected LBA 1
// primary belongs to the other reciprocal lineage captured in SelectedLineage.
type InitialGPTPhysicalEndBackupLineage struct {
	Completeness             string                `json:"completeness"`
	Relationship             string                `json:"relationship"`
	HeaderLBA                uint64                `json:"header_lba"`
	AlternateHeaderLBA       uint64                `json:"alternate_header_lba"`
	EntryArrayLBA            uint64                `json:"entry_array_lba"`
	HeaderCRC32              uint32                `json:"header_crc32"`
	FirstUsableLBA           uint64                `json:"first_usable_lba"`
	LastUsableLBA            uint64                `json:"last_usable_lba"`
	DiskGUID                 string                `json:"disk_guid"`
	PartitionEntryCount      uint32                `json:"partition_entry_count"`
	PartitionEntrySizeBytes  uint32                `json:"partition_entry_size_bytes"`
	PartitionEntryArrayCRC32 uint32                `json:"partition_entry_array_crc32"`
	Partitions               []InitialGPTPartition `json:"partitions"`
	HeaderSHA256             bundle.Digest         `json:"header_sha256"`
	EntryArraySHA256         bundle.Digest         `json:"entry_array_sha256"`
	LineageDigest            bundle.Digest         `json:"lineage_digest"`
}

// InitialRecoveryRangeV1Alpha2 uses a version-separated binding domain so a
// v1alpha1 range cannot be transplanted into a dual-lineage envelope.
type InitialRecoveryRangeV1Alpha2 struct {
	CaptureID            string                        `json:"capture_id"`
	DeviceIdentityDigest bundle.Digest                 `json:"device_identity_digest"`
	Purposes             []InitialRecoveryRangePurpose `json:"purposes"`
	OffsetBytes          uint64                        `json:"offset_bytes"`
	SizeBytes            uint64                        `json:"size_bytes"`
	PreimageSHA256       bundle.Digest                 `json:"preimage_sha256"`
	BindingDigest        bundle.Digest                 `json:"binding_digest"`
}

// InitialGPTRecoveryEnvelopeV1Alpha2 is a read-only evidence artifact that
// distinguishes the primary-selected reciprocal GPT lineage from an older,
// valid physical-end backup copy. It contains no recovery bytes, approval, or
// write capability, and DestructiveStagingReady must always remain false.
type InitialGPTRecoveryEnvelopeV1Alpha2 struct {
	SchemaVersion            string                              `json:"schema_version"`
	CaptureID                string                              `json:"capture_id"`
	Identity                 DeviceIdentity                      `json:"identity"`
	DeviceIdentityDigest     bundle.Digest                       `json:"device_identity_digest"`
	SelectedLineage          InitialGPTSnapshot                  `json:"selected_lineage"`
	PhysicalEndState         InitialGPTPhysicalEndState          `json:"physical_end_state"`
	PhysicalEndBackupLineage *InitialGPTPhysicalEndBackupLineage `json:"physical_end_backup_lineage"`
	PlannedPayloadRanges     []PlannedPayloadRange               `json:"planned_payload_ranges"`
	RecoveryScope            string                              `json:"recovery_scope"`
	RecoveryRanges           []InitialRecoveryRangeV1Alpha2      `json:"recovery_ranges"`
	DestructiveStagingReady  bool                                `json:"destructive_staging_ready"`
	EnvelopeDigest           bundle.Digest                       `json:"envelope_digest"`
}

// InspectInitialGPTRecoveryV1Alpha2 performs the same read-only selected-GPT
// inspection as v1alpha1 and additionally accepts a GPT signature at the
// physical end only after strictly parsing and relationship-checking it.
func InspectInitialGPTRecoveryV1Alpha2(reader io.ReaderAt, identity DeviceIdentity, captureID string, planned []PlannedPayloadRange) (InitialGPTRecoveryEnvelopeV1Alpha2, error) {
	if reader == nil {
		return InitialGPTRecoveryEnvelopeV1Alpha2{}, errors.New("inspect initial GPT v1alpha2: reader is nil")
	}
	if err := identity.Validate(); err != nil {
		return InitialGPTRecoveryEnvelopeV1Alpha2{}, fmt.Errorf("inspect initial GPT v1alpha2: identity: %w", err)
	}
	if !initialGPTCaptureIDPattern.MatchString(captureID) {
		return InitialGPTRecoveryEnvelopeV1Alpha2{}, errors.New("inspect initial GPT v1alpha2: capture_id must use the exact capture:<64 lowercase hex> form")
	}
	planned = append(make([]PlannedPayloadRange, 0, len(planned)), planned...)
	sort.Slice(planned, func(i, j int) bool {
		if planned[i].OffsetBytes != planned[j].OffsetBytes {
			return planned[i].OffsetBytes < planned[j].OffsetBytes
		}
		return planned[i].PartitionNumber < planned[j].PartitionNumber
	})
	if err := validatePlannedPayloadRanges(identity, planned); err != nil {
		return InitialGPTRecoveryEnvelopeV1Alpha2{}, fmt.Errorf("inspect initial GPT v1alpha2: planned payloads: %w", err)
	}

	selected, captured, err := captureInitialGPTWithPhysicalEndPolicy(reader, identity.CapacityBytes, false)
	if err != nil {
		return InitialGPTRecoveryEnvelopeV1Alpha2{}, fmt.Errorf("inspect initial GPT v1alpha2: %w", err)
	}
	state := InitialGPTPhysicalEndSelectedLineageBackup
	var physicalEnd *InitialGPTPhysicalEndBackupLineage
	if selected.Placement == InitialGPTPlacementImageSized {
		state = InitialGPTPhysicalEndNonGPTPreimage
		headerOffset := identity.CapacityBytes - LogicalSectorSizeBytes
		headerBytes, ok := capturedInitialGPTBytes(captured, headerOffset, LogicalSectorSizeBytes)
		if !ok {
			return InitialGPTRecoveryEnvelopeV1Alpha2{}, errors.New("inspect initial GPT v1alpha2: physical-end header capture is absent")
		}
		if bytes.Equal(headerBytes[:8], []byte("EFI PART")) {
			lineage, entries, err := inspectPhysicalEndBackupLineage(reader, identity, selected, headerBytes)
			if err != nil {
				return InitialGPTRecoveryEnvelopeV1Alpha2{}, fmt.Errorf("inspect initial GPT v1alpha2: physical-end GPT: %w", err)
			}
			captured = append(captured, capturedInitialGPTRange{
				offsetBytes: lineage.EntryArrayLBA * LogicalSectorSizeBytes,
				bytes:       entries,
			})
			physicalEnd = &lineage
			state = InitialGPTPhysicalEndDistinctBackupLineage
		}
	}

	identityDigest, err := deriveInitialGPTIdentityDigestV1Alpha2(identity)
	if err != nil {
		return InitialGPTRecoveryEnvelopeV1Alpha2{}, fmt.Errorf("inspect initial GPT v1alpha2: %w", err)
	}
	specs, err := expectedInitialRecoveryRangeSpecsV1Alpha2(identity, selected, planned, state)
	if err != nil {
		return InitialGPTRecoveryEnvelopeV1Alpha2{}, fmt.Errorf("inspect initial GPT v1alpha2: recovery ranges: %w", err)
	}
	ranges := make([]InitialRecoveryRangeV1Alpha2, len(specs))
	for index, spec := range specs {
		preimageDigest, err := digestCapturedInitialGPTRange(reader, captured, spec.offsetBytes, spec.sizeBytes)
		if err != nil {
			return InitialGPTRecoveryEnvelopeV1Alpha2{}, fmt.Errorf("inspect initial GPT v1alpha2: hash recovery range %d: %w", index+1, err)
		}
		rangeBinding := InitialRecoveryRangeV1Alpha2{
			CaptureID: captureID, DeviceIdentityDigest: identityDigest,
			Purposes:    append([]InitialRecoveryRangePurpose(nil), spec.purposes...),
			OffsetBytes: spec.offsetBytes, SizeBytes: spec.sizeBytes, PreimageSHA256: preimageDigest,
		}
		rangeBinding.BindingDigest, err = rangeBinding.derivedBindingDigest()
		if err != nil {
			return InitialGPTRecoveryEnvelopeV1Alpha2{}, fmt.Errorf("inspect initial GPT v1alpha2: bind recovery range %d: %w", index+1, err)
		}
		ranges[index] = rangeBinding
	}

	envelope := InitialGPTRecoveryEnvelopeV1Alpha2{
		SchemaVersion: InitialGPTRecoveryEnvelopeSchemaV1Alpha2,
		CaptureID:     captureID, Identity: identity, DeviceIdentityDigest: identityDigest,
		SelectedLineage: selected, PhysicalEndState: state, PhysicalEndBackupLineage: physicalEnd,
		PlannedPayloadRanges: planned,
		RecoveryScope:        RecoveryScopeInspectedInitialGPTLineagesAndPlannedPayloads,
		RecoveryRanges:       ranges, DestructiveStagingReady: false,
	}
	return envelope.Seal()
}

func inspectPhysicalEndBackupLineage(reader io.ReaderAt, identity DeviceIdentity, selected InitialGPTSnapshot, headerBytes []byte) (InitialGPTPhysicalEndBackupLineage, []byte, error) {
	physicalTotalLBAs := identity.CapacityBytes / LogicalSectorSizeBytes
	header, err := parseInitialGPTHeaderSector(headerBytes, physicalTotalLBAs)
	if err != nil {
		return InitialGPTPhysicalEndBackupLineage{}, nil, err
	}
	if header.currentLBA != physicalTotalLBAs-1 || header.alternateLBA != 1 ||
		header.entriesLBA != physicalTotalLBAs-33 || header.firstUsableLBA != 34 ||
		header.lastUsableLBA != physicalTotalLBAs-34 || header.entryCount != initialGPTEntryCount ||
		header.entrySize != initialGPTEntrySizeBytes {
		return InitialGPTPhysicalEndBackupLineage{}, nil, errors.New("backup header is not in the required canonical physical-end 128x128 geometry")
	}
	if err := validateInitialGPTGUID("physical-end disk GUID", header.diskGUID); err != nil {
		return InitialGPTPhysicalEndBackupLineage{}, nil, err
	}
	entries, err := readInitialGPTEntriesOnce(reader, header)
	if err != nil {
		return InitialGPTPhysicalEndBackupLineage{}, nil, fmt.Errorf("backup entries: %w", err)
	}
	partitions, err := parseInitialGPTPartitions(entries, header.firstUsableLBA, header.lastUsableLBA, header.diskGUID)
	if err != nil {
		return InitialGPTPhysicalEndBackupLineage{}, nil, err
	}
	lineage := InitialGPTPhysicalEndBackupLineage{
		Completeness: InitialGPTPhysicalEndBackupCompleteness,
		Relationship: InitialGPTPhysicalEndBackupRelationship,
		HeaderLBA:    header.currentLBA, AlternateHeaderLBA: header.alternateLBA,
		EntryArrayLBA: header.entriesLBA, HeaderCRC32: header.headerCRC32,
		FirstUsableLBA: header.firstUsableLBA, LastUsableLBA: header.lastUsableLBA,
		DiskGUID: header.diskGUID, PartitionEntryCount: header.entryCount,
		PartitionEntrySizeBytes: header.entrySize, PartitionEntryArrayCRC32: header.entriesCRC32,
		Partitions: partitions, HeaderSHA256: bundle.Sum(headerBytes), EntryArraySHA256: bundle.Sum(entries),
	}
	if err := lineage.validate(identity, selected, false); err != nil {
		return InitialGPTPhysicalEndBackupLineage{}, nil, err
	}
	lineage.LineageDigest, err = lineage.derivedDigest()
	if err != nil {
		return InitialGPTPhysicalEndBackupLineage{}, nil, err
	}
	if err := lineage.validate(identity, selected, true); err != nil {
		return InitialGPTPhysicalEndBackupLineage{}, nil, err
	}
	return lineage, entries, nil
}

func capturedInitialGPTBytes(captured capturedInitialGPTMetadata, offset, size uint64) ([]byte, bool) {
	for _, candidate := range captured {
		if candidate.offsetBytes == offset && uint64(len(candidate.bytes)) == size {
			return candidate.bytes, true
		}
	}
	return nil, false
}

func expectedInitialRecoveryRangeSpecsV1Alpha2(identity DeviceIdentity, snapshot InitialGPTSnapshot, planned []PlannedPayloadRange, state InitialGPTPhysicalEndState) ([]initialRecoveryRangeSpec, error) {
	specs, err := expectedInitialRecoveryRangeSpecs(identity, snapshot, planned)
	if err != nil {
		return nil, err
	}
	if state != InitialGPTPhysicalEndDistinctBackupLineage {
		return specs, nil
	}
	headerOffset := identity.CapacityBytes - LogicalSectorSizeBytes
	entriesOffset := headerOffset - initialGPTEntryArrayBytes
	foundHeader, foundEntries := false, false
	for index := range specs {
		switch {
		case specs[index].offsetBytes == entriesOffset && specs[index].sizeBytes == initialGPTEntryArrayBytes:
			specs[index].purposes = append(specs[index].purposes, InitialRecoveryPhysicalEndBackupEntries)
			foundEntries = true
		case specs[index].offsetBytes == headerOffset && specs[index].sizeBytes == LogicalSectorSizeBytes:
			specs[index].purposes = append(specs[index].purposes, InitialRecoveryPhysicalEndBackupHeader)
			foundHeader = true
		}
	}
	if !foundHeader || !foundEntries {
		return nil, errors.New("physical-end backup lineage is detached from its recovery ranges")
	}
	return specs, nil
}

func deriveInitialGPTIdentityDigestV1Alpha2(identity DeviceIdentity) (bundle.Digest, error) {
	if err := identity.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", fmt.Errorf("encode device identity digest material: %w", err)
	}
	return domainDigest(initialGPTIdentityDigestDomainV1Alpha2, encoded), nil
}

func (recoveryRange InitialRecoveryRangeV1Alpha2) derivedBindingDigest() (bundle.Digest, error) {
	material := initialRecoveryRangeDigestMaterial{
		CaptureID: recoveryRange.CaptureID, DeviceIdentityDigest: recoveryRange.DeviceIdentityDigest,
		Purposes:    append([]InitialRecoveryRangePurpose(nil), recoveryRange.Purposes...),
		OffsetBytes: recoveryRange.OffsetBytes, SizeBytes: recoveryRange.SizeBytes,
		PreimageSHA256: recoveryRange.PreimageSHA256,
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", fmt.Errorf("encode v1alpha2 recovery range digest material: %w", err)
	}
	return domainDigest(initialGPTRangeDigestDomainV1Alpha2, encoded), nil
}

func (lineage InitialGPTPhysicalEndBackupLineage) derivedDigest() (bundle.Digest, error) {
	material := lineage
	material.LineageDigest = ""
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", fmt.Errorf("encode physical-end GPT lineage digest material: %w", err)
	}
	return domainDigest(initialGPTPhysicalEndLineageDigestDomainV1Alpha2, encoded), nil
}

func (lineage InitialGPTPhysicalEndBackupLineage) validate(identity DeviceIdentity, selected InitialGPTSnapshot, requireDigest bool) error {
	physicalTotalLBAs := identity.CapacityBytes / LogicalSectorSizeBytes
	if lineage.Completeness != InitialGPTPhysicalEndBackupCompleteness || lineage.Relationship != InitialGPTPhysicalEndBackupRelationship {
		return errors.New("physical-end GPT lineage completeness or relationship is unsupported")
	}
	if lineage.HeaderLBA != physicalTotalLBAs-1 || lineage.AlternateHeaderLBA != 1 ||
		lineage.EntryArrayLBA != physicalTotalLBAs-33 || lineage.FirstUsableLBA != 34 ||
		lineage.LastUsableLBA != physicalTotalLBAs-34 || lineage.PartitionEntryCount != initialGPTEntryCount ||
		lineage.PartitionEntrySizeBytes != initialGPTEntrySizeBytes {
		return errors.New("physical-end GPT lineage does not describe canonical physical-device backup geometry")
	}
	if err := validateInitialGPTGUID("physical-end lineage disk GUID", lineage.DiskGUID); err != nil {
		return err
	}
	if lineage.DiskGUID == selected.DiskGUID {
		return errors.New("physical-end GPT lineage must have a disk GUID distinct from the selected lineage")
	}
	if err := validateDigest("physical-end lineage header_sha256", lineage.HeaderSHA256); err != nil {
		return err
	}
	if err := validateDigest("physical-end lineage entry_array_sha256", lineage.EntryArraySHA256); err != nil {
		return err
	}
	if len(lineage.Partitions) != len(selected.Partitions) {
		return errors.New("physical-end GPT lineage partition count differs from the selected lineage")
	}
	seen := map[string]struct{}{selected.DiskGUID: {}}
	for _, partition := range selected.Partitions {
		seen[partition.UniqueGUID] = struct{}{}
	}
	if _, collision := seen[lineage.DiskGUID]; collision {
		return errors.New("physical-end GPT disk GUID collides with a selected-lineage identifier")
	}
	seen[lineage.DiskGUID] = struct{}{}
	var previousEntry uint32
	byStart := append([]InitialGPTPartition(nil), lineage.Partitions...)
	for index, partition := range lineage.Partitions {
		selectedPartition := selected.Partitions[index]
		if partition.EntryNumber == 0 || partition.EntryNumber > initialGPTEntryCount || (index > 0 && partition.EntryNumber <= previousEntry) {
			return errors.New("physical-end GPT partitions must retain unique increasing entry numbers")
		}
		previousEntry = partition.EntryNumber
		if err := validateInitialGPTGUID("physical-end partition type GUID", partition.TypeGUID); err != nil {
			return err
		}
		if err := validateInitialGPTGUID("physical-end partition unique GUID", partition.UniqueGUID); err != nil {
			return err
		}
		if _, collision := seen[partition.UniqueGUID]; collision {
			return errors.New("physical-end GPT lineage reuses a disk or partition identifier")
		}
		seen[partition.UniqueGUID] = struct{}{}
		if partition.FirstLBA > partition.LastLBA || partition.FirstLBA < lineage.FirstUsableLBA || partition.LastLBA > lineage.LastUsableLBA {
			return errors.New("physical-end GPT partition is outside its usable range")
		}
		if err := validateInitialGPTPrintableName(partition.Name); err != nil {
			return fmt.Errorf("physical-end GPT partition name: %w", err)
		}
		if partition.EntryNumber != selectedPartition.EntryNumber || partition.TypeGUID != selectedPartition.TypeGUID ||
			partition.FirstLBA != selectedPartition.FirstLBA || partition.LastLBA != selectedPartition.LastLBA ||
			partition.Attributes != selectedPartition.Attributes || partition.Name != selectedPartition.Name {
			return fmt.Errorf("physical-end GPT partition %d differs from the selected lineage's non-identifier layout", index+1)
		}
	}
	sort.Slice(byStart, func(i, j int) bool { return byStart[i].FirstLBA < byStart[j].FirstLBA })
	for index := 1; index < len(byStart); index++ {
		if byStart[index].FirstLBA <= byStart[index-1].LastLBA {
			return errors.New("physical-end GPT partitions overlap")
		}
	}
	if requireDigest {
		if err := validateDigest("physical-end lineage lineage_digest", lineage.LineageDigest); err != nil {
			return err
		}
		derived, err := lineage.derivedDigest()
		if err != nil {
			return err
		}
		if lineage.LineageDigest != derived {
			return errors.New("physical-end GPT lineage_digest is detached from its semantics and byte digests")
		}
	}
	return nil
}

// VerifyAgainst repeats both semantic parses and every range hash, requiring
// the rebuilt v1alpha2 envelope to match exactly.
func (envelope InitialGPTRecoveryEnvelopeV1Alpha2) VerifyAgainst(reader io.ReaderAt) error {
	if err := envelope.Validate(); err != nil {
		return err
	}
	rebuilt, err := InspectInitialGPTRecoveryV1Alpha2(reader, envelope.Identity, envelope.CaptureID, envelope.PlannedPayloadRanges)
	if err != nil {
		return err
	}
	if rebuilt.EnvelopeDigest != envelope.EnvelopeDigest {
		return errors.New("initial GPT recovery envelope v1alpha2 differs from the supplied captured bytes")
	}
	return nil
}

// DerivedDigest returns the version-separated envelope digest with its digest
// field empty after validating all structural and per-range relationships.
func (envelope InitialGPTRecoveryEnvelopeV1Alpha2) DerivedDigest() (bundle.Digest, error) {
	material := envelope
	material.EnvelopeDigest = ""
	if err := material.validate(false); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", fmt.Errorf("encode initial GPT recovery envelope v1alpha2 digest material: %w", err)
	}
	return domainDigest(initialGPTEnvelopeDigestDomainV1Alpha2, encoded), nil
}

// Seal returns a validated copy with its derived v1alpha2 digest populated.
func (envelope InitialGPTRecoveryEnvelopeV1Alpha2) Seal() (InitialGPTRecoveryEnvelopeV1Alpha2, error) {
	digest, err := envelope.DerivedDigest()
	if err != nil {
		return InitialGPTRecoveryEnvelopeV1Alpha2{}, err
	}
	envelope.EnvelopeDigest = digest
	if err := envelope.Validate(); err != nil {
		return InitialGPTRecoveryEnvelopeV1Alpha2{}, err
	}
	return envelope, nil
}

// Validate checks only the sealed descriptive record. VerifyAgainst is still
// required to re-establish its relationship to a device capture.
func (envelope InitialGPTRecoveryEnvelopeV1Alpha2) Validate() error { return envelope.validate(true) }

func (envelope InitialGPTRecoveryEnvelopeV1Alpha2) validate(requireDigest bool) error {
	if envelope.SchemaVersion != InitialGPTRecoveryEnvelopeSchemaV1Alpha2 {
		return fmt.Errorf("unsupported initial GPT recovery envelope v1alpha2 schema_version %q", envelope.SchemaVersion)
	}
	if !initialGPTCaptureIDPattern.MatchString(envelope.CaptureID) {
		return errors.New("capture_id must use the exact capture:<64 lowercase hex> form")
	}
	if err := envelope.Identity.Validate(); err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	identityDigest, err := deriveInitialGPTIdentityDigestV1Alpha2(envelope.Identity)
	if err != nil {
		return err
	}
	if envelope.DeviceIdentityDigest != identityDigest {
		return errors.New("device_identity_digest does not bind the fixed identity under v1alpha2")
	}
	if err := envelope.SelectedLineage.validate(envelope.Identity); err != nil {
		return fmt.Errorf("selected lineage: %w", err)
	}
	if err := validatePlannedPayloadRanges(envelope.Identity, envelope.PlannedPayloadRanges); err != nil {
		return fmt.Errorf("planned payloads: %w", err)
	}
	if envelope.RecoveryScope != RecoveryScopeInspectedInitialGPTLineagesAndPlannedPayloads || envelope.DestructiveStagingReady {
		return errors.New("v1alpha2 recovery envelope must remain descriptive and ineligible for destructive staging")
	}
	switch envelope.PhysicalEndState {
	case InitialGPTPhysicalEndSelectedLineageBackup:
		if envelope.SelectedLineage.Placement != InitialGPTPlacementCanonicalPhysical || envelope.PhysicalEndBackupLineage != nil {
			return errors.New("selected-lineage physical-end state differs from the selected GPT placement")
		}
	case InitialGPTPhysicalEndNonGPTPreimage:
		if envelope.SelectedLineage.Placement != InitialGPTPlacementImageSized || envelope.PhysicalEndBackupLineage != nil {
			return errors.New("non-GPT physical-end state differs from the selected GPT placement")
		}
	case InitialGPTPhysicalEndDistinctBackupLineage:
		if envelope.SelectedLineage.Placement != InitialGPTPlacementImageSized || envelope.PhysicalEndBackupLineage == nil {
			return errors.New("distinct physical-end GPT state lacks its image-sized selected lineage or backup snapshot")
		}
		if err := envelope.PhysicalEndBackupLineage.validate(envelope.Identity, envelope.SelectedLineage, true); err != nil {
			return fmt.Errorf("physical-end backup lineage: %w", err)
		}
	default:
		return fmt.Errorf("unsupported physical_end_state %q", envelope.PhysicalEndState)
	}

	expected, err := expectedInitialRecoveryRangeSpecsV1Alpha2(envelope.Identity, envelope.SelectedLineage, envelope.PlannedPayloadRanges, envelope.PhysicalEndState)
	if err != nil {
		return err
	}
	if len(envelope.RecoveryRanges) != len(expected) {
		return errors.New("recovery_ranges does not contain exactly every computed nonoverlapping v1alpha2 range")
	}
	var physicalHeaderSHA, physicalEntriesSHA bundle.Digest
	for index, expectedRange := range expected {
		actual := envelope.RecoveryRanges[index]
		if actual.CaptureID != envelope.CaptureID || actual.DeviceIdentityDigest != identityDigest ||
			actual.OffsetBytes != expectedRange.offsetBytes || actual.SizeBytes != expectedRange.sizeBytes ||
			!equalInitialRecoveryPurposes(actual.Purposes, expectedRange.purposes) {
			return fmt.Errorf("recovery range %d differs from its context-bound computed v1alpha2 geometry", index+1)
		}
		if err := validateDigest(fmt.Sprintf("recovery range %d preimage_sha256", index+1), actual.PreimageSHA256); err != nil {
			return err
		}
		derived, err := actual.derivedBindingDigest()
		if err != nil {
			return err
		}
		if actual.BindingDigest != derived {
			return fmt.Errorf("recovery range %d binding_digest is detached from its v1alpha2 context and preimage", index+1)
		}
		for _, purpose := range actual.Purposes {
			switch purpose {
			case InitialRecoveryPhysicalEndBackupHeader:
				physicalHeaderSHA = actual.PreimageSHA256
			case InitialRecoveryPhysicalEndBackupEntries:
				physicalEntriesSHA = actual.PreimageSHA256
			}
		}
	}
	if envelope.PhysicalEndState == InitialGPTPhysicalEndDistinctBackupLineage &&
		(envelope.PhysicalEndBackupLineage.HeaderSHA256 != physicalHeaderSHA || envelope.PhysicalEndBackupLineage.EntryArraySHA256 != physicalEntriesSHA) {
		return errors.New("physical-end GPT lineage byte digests are detached from its recovery ranges")
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
			return errors.New("envelope_digest does not bind the initial GPT recovery envelope v1alpha2")
		}
	}
	return nil
}

// CanonicalJSON returns the compact canonical v1alpha2 envelope encoding.
func (envelope InitialGPTRecoveryEnvelopeV1Alpha2) CanonicalJSON() ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	return marshalWithinLimit("initial GPT recovery envelope v1alpha2", envelope)
}

// ParseInitialGPTRecoveryEnvelopeV1Alpha2 accepts strict canonical JSON,
// optionally followed by one LF. VerifyAgainst is still required for bytes.
func ParseInitialGPTRecoveryEnvelopeV1Alpha2(encoded []byte) (InitialGPTRecoveryEnvelopeV1Alpha2, error) {
	var envelope InitialGPTRecoveryEnvelopeV1Alpha2
	if err := strictCanonicalDecode(encoded, &envelope, func() ([]byte, error) { return envelope.CanonicalJSON() }); err != nil {
		return InitialGPTRecoveryEnvelopeV1Alpha2{}, fmt.Errorf("parse initial GPT recovery envelope v1alpha2: %w", err)
	}
	return envelope, nil
}
