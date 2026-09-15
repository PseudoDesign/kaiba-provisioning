package campaignmedia

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

// StagingGUIDs supplies identities for the two fixed disks and their four
// partitions. Geometry, device selectors, partition types and names are fixed
// by this package. Root GUIDs must match the artifact set's dm-verity binding.
type StagingGUIDs struct {
	SDDisk, NVMeDisk                  string
	Boot, RootData, RootHash, Release string
}

// PayloadSource is an exact public artifact exposed by a caller-owned reader.
// The caller must keep its underlying bytes stable while preparing the plan.
// The constructor has no filesystem, device-opening or device-writing API.
type PayloadSource struct {
	Reader    io.ReaderAt
	SizeBytes uint64
}

// PrepareStagingPlan derives canonical full-device GPT digests and complete
// partition hashes from the four actual payloads. Each source must match the
// independently validated campaign artifact set. Whole-partition hashes cover
// every source byte followed by the exact zero tail; no capacity-sized buffer
// is allocated. The returned plan still has all readiness claims false.
func PrepareStagingPlan(plan stablecampaign.Plan, artifacts ArtifactSet, guids StagingGUIDs, sources map[PartitionRole]PayloadSource) (StagingPlan, error) {
	return prepareStagingPlan(plan, artifacts, guids, sources, hashPayload)
}

type payloadHasher func(PayloadSource, uint64) (bundle.Digest, bundle.Digest, error)

func prepareStagingPlan(plan stablecampaign.Plan, artifacts ArtifactSet, guids StagingGUIDs, sources map[PartitionRole]PayloadSource, hash payloadHasher) (StagingPlan, error) {
	if err := artifacts.ValidateAgainst(plan); err != nil {
		return StagingPlan{}, fmt.Errorf("campaign artifact set: %w", err)
	}
	allGUIDs := []string{guids.SDDisk, guids.NVMeDisk, guids.Boot, guids.RootData, guids.RootHash, guids.Release}
	seen := make(map[string]bool)
	for _, guid := range allGUIDs {
		if err := validateGUID("staging GUID", guid); err != nil {
			return StagingPlan{}, err
		}
		if seen[guid] {
			return StagingPlan{}, errors.New("disk and partition GUIDs must be unique across both campaign devices")
		}
		seen[guid] = true
	}
	if guids.RootData != artifacts.Verity.DataPartitionGUID || guids.RootHash != artifacts.Verity.HashPartitionGUID {
		return StagingPlan{}, errors.New("root partition GUIDs differ from the artifact-set dm-verity contract")
	}
	if len(sources) != len(fixedArtifactSetEntries) {
		return StagingPlan{}, errors.New("sources must contain exactly the four fixed payload roles")
	}
	// Validate every role and size before reading any payload. In particular,
	// an invalid later input cannot cause gigabytes of earlier input to be read.
	for _, fixed := range fixedIdentities {
		for _, partition := range fixed.partitions {
			source, ok := sources[partition.role]
			entry, exists := artifactForRole(artifacts, partition.role)
			if !ok || !exists || nilPayloadReader(source.Reader) || source.SizeBytes != entry.SizeBytes ||
				source.SizeBytes == 0 || source.SizeBytes > partition.capacity || source.SizeBytes%LogicalSectorSizeBytes != 0 {
				return StagingPlan{}, fmt.Errorf("source %q must have the artifact-set size and fit its fixed partition", partition.role)
			}
		}
	}
	if hash == nil {
		return StagingPlan{}, errors.New("payload hasher is unavailable")
	}
	campaign := CampaignBinding{CampaignID: plan.CampaignID, StableCampaignPlanDigest: plan.PlanDigest, CampaignArtifactSetContentDigest: artifacts.ArtifactSetContentDigest}
	partitionGUIDs := map[PartitionRole]string{
		PartitionBootFilesystem: guids.Boot, PartitionRootData: guids.RootData,
		PartitionRootHash: guids.RootHash, PartitionReleaseFilesystem: guids.Release,
	}
	diskGUIDs := []string{guids.SDDisk, guids.NVMeDisk}
	devices := make([]DevicePlan, 0, len(fixedIdentities))
	for index, fixed := range fixedIdentities {
		identity := DeviceIdentity{Leg: fixed.leg, ConfigID: fixed.configID, Hostname: fixed.hostname,
			Selector: fixed.selector, CapacityBytes: fixed.capacity, LogicalSectorSizeBytes: LogicalSectorSizeBytes,
			DiskGUID: diskGUIDs[index]}
		device := DevicePlan{Campaign: campaign, Identity: identity, GPT: finalGPTMetadata(identity)}
		for _, partition := range fixed.partitions {
			source := sources[partition.role]
			digest, whole, err := hash(source, partition.capacity)
			if err != nil {
				return StagingPlan{}, fmt.Errorf("hash %s: %w", partition.role, err)
			}
			entry, _ := artifactForRole(artifacts, partition.role)
			if digest != entry.Digest {
				return StagingPlan{}, fmt.Errorf("source %q digest differs from the campaign artifact set", partition.role)
			}
			device.Partitions = append(device.Partitions, Partition{
				Role: partition.role, Number: partition.number, TypeGUID: partition.typeGUID,
				UniqueGUID: partitionGUIDs[partition.role], GPTName: partition.name,
				ByteStart: partition.byteStart, CapacityBytes: partition.capacity,
				SourceSizeBytes: source.SizeBytes, SourceSHA256: digest,
				ZeroTailBytes: partition.capacity - source.SizeBytes, ExpectedWholePartitionSHA256: whole,
			})
		}
		writes, err := renderFinalGPTWrites(device)
		if err != nil {
			return StagingPlan{}, err
		}
		for _, write := range writes {
			*finalGPTRange(&device.GPT, write.Role) = write.Range
		}
		if _, err := FinalGPTWrites(device); err != nil {
			return StagingPlan{}, err
		}
		devices = append(devices, device)
	}
	prepared, err := NewStagingPlan(campaign, devices)
	if err != nil {
		return StagingPlan{}, err
	}
	if err := prepared.ValidateAgainst(plan, artifacts); err != nil {
		return StagingPlan{}, err
	}
	return prepared, nil
}

// finalGPTMetadata supplies only fixed geometry. Hashes are filled exclusively
// from rendered GPT bytes before this value can enter a validated device plan.
func finalGPTMetadata(identity DeviceIdentity) GPTMetadata {
	totalLBAs := identity.CapacityBytes / LogicalSectorSizeBytes
	metadata := GPTMetadata{
		ProtectiveMBRLastLBA: totalLBAs - 1, PrimaryHeaderLBA: 1, PrimaryEntryArrayLBA: 2,
		FirstUsableLBA: 34, LastUsableLBA: totalLBAs - 34,
		BackupEntryArrayLBA: totalLBAs - 33, BackupHeaderLBA: totalLBAs - 1,
		PartitionEntryCount: 128, PartitionEntrySizeBytes: 128,
	}
	for _, span := range expectedGPTRanges(identity) {
		*finalGPTRange(&metadata, span.role) = ByteRangeDigest{OffsetBytes: span.offsetBytes, SizeBytes: span.sizeBytes}
	}
	return metadata
}

func hashPayload(source PayloadSource, capacity uint64) (bundle.Digest, bundle.Digest, error) {
	if nilPayloadReader(source.Reader) || source.SizeBytes == 0 || source.SizeBytes > capacity || capacity > PiLocalNVMeReleaseCapacityBytes {
		return "", "", errors.New("invalid bounded payload source")
	}
	hash := sha256.New()
	buffer := make([]byte, 1024*1024)
	read := io.NewSectionReader(source.Reader, 0, int64(source.SizeBytes))
	size, err := io.CopyBuffer(hash, read, buffer)
	if err != nil || uint64(size) != source.SizeBytes {
		return "", "", errors.New("payload source was truncated or unreadable")
	}
	var trailing [1]byte
	if n, err := source.Reader.ReadAt(trailing[:], int64(source.SizeBytes)); n != 0 || err != io.EOF {
		return "", "", errors.New("payload source has trailing bytes or an invalid end-of-file")
	}
	sourceDigest := bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil)))
	clear(buffer)
	for remaining := capacity - source.SizeBytes; remaining > 0; {
		count := min(remaining, uint64(len(buffer)))
		_, _ = hash.Write(buffer[:count])
		remaining -= count
	}
	wholeDigest := bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil)))
	return sourceDigest, wholeDigest, nil
}

func nilPayloadReader(reader io.ReaderAt) bool {
	if reader == nil {
		return true
	}
	value := reflect.ValueOf(reader)
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return value.IsNil()
	default:
		return false
	}
}
