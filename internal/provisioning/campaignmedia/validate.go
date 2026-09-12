package campaignmedia

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

const (
	stagingPlanDigestDomain    = "kaiba.provisioning.rpi5-stable-verifier-campaign-media-staging-plan.v1alpha1"
	stagingDeviceDigestDomain  = "kaiba.provisioning.rpi5-stable-verifier-campaign-media-staging-device.v1alpha1"
	backupManifestDigestDomain = "kaiba.provisioning.rpi5-stable-verifier-campaign-media-backup-manifest.v1alpha1"
	rollbackPlanDigestDomain   = "kaiba.provisioning.rpi5-stable-verifier-campaign-media-rollback-plan.v1alpha1"
)

var (
	campaignIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,127}$`)
	guidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type fixedIdentity struct {
	leg        Leg
	configID   string
	hostname   string
	selector   string
	capacity   uint64
	partitions []fixedPartition
}

type fixedPartition struct {
	role      PartitionRole
	number    uint32
	typeGUID  string
	name      string
	byteStart uint64
	capacity  uint64
}

var fixedIdentities = []fixedIdentity{
	{
		leg: LegMalakSD, configID: MalakSDConfigID, hostname: MalakSDHostname,
		selector: MalakSDSelector, capacity: MalakSDCapacityBytes,
		partitions: []fixedPartition{
			{PartitionBootFilesystem, 1, ESPTypeGUID, "kaiba-boot", MalakSDBootStartBytes, MalakSDBootCapacityBytes},
			{PartitionRootData, 2, ARM64RootTypeGUID, "kaiba-root", MalakSDRootDataStartBytes, MalakSDRootDataCapacityBytes},
			{PartitionRootHash, 3, ARM64VerityTypeGUID, "kaiba-root-verity", MalakSDRootHashStartBytes, MalakSDRootHashCapacityBytes},
		},
	},
	{
		leg: LegPiLocalNVMe, configID: PiLocalNVMeConfigID, hostname: PiLocalNVMeHostname,
		selector: PiLocalNVMeSelector, capacity: PiLocalNVMeCapacityBytes,
		partitions: []fixedPartition{
			{PartitionReleaseFilesystem, 1, LinuxFilesystemTypeGUID, "KAIBA_RELEASE", PiLocalNVMeReleaseStartBytes, PiLocalNVMeReleaseCapacityBytes},
		},
	},
}

func fixedIdentityFor(leg Leg) (fixedIdentity, bool) {
	for _, identity := range fixedIdentities {
		if identity.leg == leg {
			return identity, true
		}
	}
	return fixedIdentity{}, false
}

func (binding CampaignBinding) Validate() error {
	if !campaignIDPattern.MatchString(binding.CampaignID) {
		return errors.New("campaign_id must be a canonical lowercase campaign identifier")
	}
	if err := validateDigest("stable_campaign_plan_digest", binding.StableCampaignPlanDigest); err != nil {
		return err
	}
	return validateDigest("campaign_artifact_set_content_digest", binding.CampaignArtifactSetContentDigest)
}

func (identity DeviceIdentity) Validate() error {
	fixed, ok := fixedIdentityFor(identity.Leg)
	if !ok {
		return fmt.Errorf("unsupported campaign media leg %q", identity.Leg)
	}
	if identity.ConfigID != fixed.configID || identity.Hostname != fixed.hostname ||
		identity.Selector != fixed.selector || identity.CapacityBytes != fixed.capacity {
		return fmt.Errorf("identity for leg %q differs from the fixed reviewed configuration", identity.Leg)
	}
	if identity.LogicalSectorSizeBytes != LogicalSectorSizeBytes {
		return fmt.Errorf("identity logical_sector_size_bytes must be %d", LogicalSectorSizeBytes)
	}
	if err := validateGUID("identity.disk_guid", identity.DiskGUID); err != nil {
		return err
	}
	return nil
}

func (metadata GPTMetadata) validate(identity DeviceIdentity) error {
	totalLBAs := identity.CapacityBytes / LogicalSectorSizeBytes
	if metadata.ProtectiveMBRLastLBA != totalLBAs-1 ||
		metadata.PrimaryHeaderLBA != 1 || metadata.PrimaryEntryArrayLBA != 2 ||
		metadata.FirstUsableLBA != 34 || metadata.LastUsableLBA != totalLBAs-34 ||
		metadata.BackupEntryArrayLBA != totalLBAs-33 || metadata.BackupHeaderLBA != totalLBAs-1 {
		return errors.New("GPT metadata must describe a canonical table whose protective MBR and backup GPT cover the complete physical device")
	}
	if metadata.PartitionEntryCount != 128 || metadata.PartitionEntrySizeBytes != 128 {
		return errors.New("GPT metadata must bind exactly 128 entries of 128 bytes")
	}
	actual := []struct {
		role         GPTRegionRole
		rangeBinding ByteRangeDigest
	}{
		{GPTProtectiveMBR, metadata.ProtectiveMBR},
		{GPTPrimaryHeader, metadata.PrimaryHeader},
		{GPTPrimaryEntryArray, metadata.PrimaryEntryArray},
		{GPTBackupEntryArray, metadata.BackupEntryArray},
		{GPTBackupHeader, metadata.BackupHeader},
	}
	expected := expectedGPTRanges(identity)
	for index := range expected {
		if actual[index].role != expected[index].role ||
			actual[index].rangeBinding.OffsetBytes != expected[index].offsetBytes ||
			actual[index].rangeBinding.SizeBytes != expected[index].sizeBytes {
			return fmt.Errorf("GPT %q digest does not cover its exact final-layout byte range", expected[index].role)
		}
		if err := validateDigest("GPT "+string(expected[index].role)+" sha256", actual[index].rangeBinding.SHA256); err != nil {
			return err
		}
	}
	if metadata.PrimaryEntryArray.SHA256 != metadata.BackupEntryArray.SHA256 {
		return errors.New("primary and backup GPT entry arrays must contain identical canonical partition entries")
	}
	return nil
}

type fixedGPTRange struct {
	role        GPTRegionRole
	offsetBytes uint64
	sizeBytes   uint64
}

func expectedGPTRanges(identity DeviceIdentity) []fixedGPTRange {
	totalLBAs := identity.CapacityBytes / LogicalSectorSizeBytes
	entryArrayBytes := uint64(128 * 128)
	return []fixedGPTRange{
		{GPTProtectiveMBR, 0, LogicalSectorSizeBytes},
		{GPTPrimaryHeader, LogicalSectorSizeBytes, LogicalSectorSizeBytes},
		{GPTPrimaryEntryArray, 2 * LogicalSectorSizeBytes, entryArrayBytes},
		{GPTBackupEntryArray, (totalLBAs - 33) * LogicalSectorSizeBytes, entryArrayBytes},
		{GPTBackupHeader, (totalLBAs - 1) * LogicalSectorSizeBytes, LogicalSectorSizeBytes},
	}
}

func (device DevicePlan) Validate() error {
	if err := device.Campaign.Validate(); err != nil {
		return fmt.Errorf("device campaign: %w", err)
	}
	if err := device.Identity.Validate(); err != nil {
		return err
	}
	if err := device.GPT.validate(device.Identity); err != nil {
		return fmt.Errorf("leg %q: %w", device.Identity.Leg, err)
	}
	fixed, _ := fixedIdentityFor(device.Identity.Leg)
	if len(device.Partitions) != len(fixed.partitions) {
		return fmt.Errorf("leg %q must contain exactly %d allowed GPT entries", device.Identity.Leg, len(fixed.partitions))
	}
	seenGUIDs := map[string]struct{}{device.Identity.DiskGUID: {}}
	var previousEnd uint64
	for index, expected := range fixed.partitions {
		partition := device.Partitions[index]
		if err := partition.validate(expected, device.Identity); err != nil {
			return fmt.Errorf("leg %q partition %d: %w", device.Identity.Leg, index+1, err)
		}
		if _, duplicate := seenGUIDs[partition.UniqueGUID]; duplicate {
			return fmt.Errorf("leg %q contains a duplicate disk or partition GUID", device.Identity.Leg)
		}
		seenGUIDs[partition.UniqueGUID] = struct{}{}
		if index > 0 && partition.ByteStart < previousEnd {
			return fmt.Errorf("leg %q partitions overlap or are not ordered", device.Identity.Leg)
		}
		previousEnd = partition.ByteStart + partition.CapacityBytes
	}
	return nil
}

func (partition Partition) validate(expected fixedPartition, identity DeviceIdentity) error {
	if partition.Role != expected.role || partition.Number != expected.number ||
		partition.TypeGUID != expected.typeGUID || partition.GPTName != expected.name ||
		partition.ByteStart != expected.byteStart || partition.CapacityBytes != expected.capacity {
		return errors.New("GPT entry differs from the fixed role, number, type, name, start, or capacity")
	}
	if partition.GPTAttributes != 0 {
		return errors.New("gpt_attributes must be zero")
	}
	if err := validateGUID("unique_guid", partition.UniqueGUID); err != nil {
		return err
	}
	if partition.ByteStart%AlignmentBytes != 0 || partition.CapacityBytes%AlignmentBytes != 0 {
		return fmt.Errorf("byte_start and capacity_bytes must be aligned to %d bytes", AlignmentBytes)
	}
	if partition.ByteStart > math.MaxUint64-partition.CapacityBytes ||
		partition.ByteStart+partition.CapacityBytes > identity.CapacityBytes-AlignmentBytes {
		return errors.New("partition range does not fit before the reserved trailing GPT region")
	}
	if partition.SourceSizeBytes == 0 || partition.SourceSizeBytes > partition.CapacityBytes ||
		partition.SourceSizeBytes%LogicalSectorSizeBytes != 0 {
		return errors.New("source_size_bytes must be a positive sector-aligned size within the partition")
	}
	if partition.ZeroTailBytes != partition.CapacityBytes-partition.SourceSizeBytes {
		return errors.New("zero_tail_bytes must exactly cover capacity_bytes after the immutable source")
	}
	if err := validateDigest("source_sha256", partition.SourceSHA256); err != nil {
		return err
	}
	if err := validateDigest("expected_whole_partition_sha256", partition.ExpectedWholePartitionSHA256); err != nil {
		return err
	}
	if partition.ZeroTailBytes == 0 && partition.ExpectedWholePartitionSHA256 != partition.SourceSHA256 {
		return errors.New("an unpadded partition must have identical source and whole-partition digests")
	}
	return nil
}

// DerivedDigest returns the domain-separated digest used to bind this exact
// device plan from backup and rollback contracts.
func (device DevicePlan) DerivedDigest() (bundle.Digest, error) {
	if err := device.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(device)
	if err != nil {
		return "", fmt.Errorf("encode staging device digest material: %w", err)
	}
	return domainDigest(stagingDeviceDigestDomain, encoded), nil
}

// NewStagingPlan constructs and seals a two-leg staging plan. Devices must be
// supplied in the fixed malak-SD, Pi-local-NVMe order.
func NewStagingPlan(campaign CampaignBinding, devices []DevicePlan) (StagingPlan, error) {
	plan := StagingPlan{
		SchemaVersion:           StagingPlanSchemaV1Alpha1,
		Campaign:                campaign,
		Devices:                 cloneDevicePlans(devices),
		RecoveryScope:           RecoveryScopeFinalLayoutRanges,
		InitialGPTRecoveryBound: false,
		DestructiveStagingReady: false,
	}
	return plan.Seal()
}

func (plan StagingPlan) validate(requireDigest bool) error {
	if plan.SchemaVersion != StagingPlanSchemaV1Alpha1 {
		return fmt.Errorf("unsupported staging plan schema_version %q", plan.SchemaVersion)
	}
	if err := plan.Campaign.Validate(); err != nil {
		return err
	}
	if len(plan.Devices) != len(fixedIdentities) {
		return errors.New("devices must contain exactly malak SD followed by Pi-local NVMe")
	}
	if plan.RecoveryScope != RecoveryScopeFinalLayoutRanges || plan.InitialGPTRecoveryBound || plan.DestructiveStagingReady {
		return errors.New("v1alpha1 binds only partition payloads and intended final GPT ranges and is not ready for destructive staging")
	}
	seenGUIDs := make(map[string]struct{})
	for index, fixed := range fixedIdentities {
		device := plan.Devices[index]
		if device.Identity.Leg != fixed.leg {
			return errors.New("devices must contain exactly malak SD followed by Pi-local NVMe")
		}
		if device.Campaign != plan.Campaign {
			return fmt.Errorf("device %q campaign binding differs from its staging plan", device.Identity.Leg)
		}
		if err := device.Validate(); err != nil {
			return err
		}
		for _, guid := range append([]string{device.Identity.DiskGUID}, partitionGUIDs(device.Partitions)...) {
			if _, duplicate := seenGUIDs[guid]; duplicate {
				return errors.New("disk and partition GUIDs must be unique across both campaign devices")
			}
			seenGUIDs[guid] = struct{}{}
		}
	}
	if requireDigest {
		if err := validateDigest("plan_digest", plan.PlanDigest); err != nil {
			return err
		}
		derived, err := plan.DerivedDigest()
		if err != nil {
			return err
		}
		if plan.PlanDigest != derived {
			return errors.New("plan_digest does not bind the canonical staging plan")
		}
	}
	return nil
}

// Validate checks the complete sealed staging plan.
func (plan StagingPlan) Validate() error { return plan.validate(true) }

// ValidateForDestructiveStaging always fails for v1alpha1 after first checking
// the complete contract. A future schema may enable staging only after an
// independently parsed initial-GPT recovery contract is bound.
func (plan StagingPlan) ValidateForDestructiveStaging() error {
	if err := plan.Validate(); err != nil {
		return err
	}
	return errors.New("staging plan v1alpha1 is intentionally ineligible for destructive staging: initial GPT recovery is not bound")
}

// ValidateAgainst cross-binds this physical layout to an independently parsed
// campaign plan and artifact set. It does not make the plan eligible for I/O.
func (plan StagingPlan) ValidateAgainst(campaignPlan stablecampaign.Plan, artifactSet ArtifactSet) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if err := campaignPlan.Validate(); err != nil {
		return fmt.Errorf("stable campaign plan: %w", err)
	}
	if err := artifactSet.ValidateAgainst(campaignPlan); err != nil {
		return err
	}
	if plan.Campaign.CampaignID != campaignPlan.CampaignID ||
		plan.Campaign.StableCampaignPlanDigest != campaignPlan.PlanDigest ||
		plan.Campaign.CampaignArtifactSetContentDigest != artifactSet.ArtifactSetContentDigest {
		return errors.New("staging plan campaign binding differs from the independently supplied campaign plan or artifact set")
	}
	entries := make(map[PartitionRole]ArtifactSetEntry, len(artifactSet.Artifacts))
	for _, entry := range artifactSet.Artifacts {
		entries[entry.Role] = entry
	}
	for _, device := range plan.Devices {
		for _, partition := range device.Partitions {
			entry, ok := entries[partition.Role]
			if !ok || partition.SourceSHA256 != entry.Digest || partition.SourceSizeBytes != entry.SizeBytes {
				return fmt.Errorf("partition %q source does not match the independently supplied artifact set", partition.Role)
			}
			switch partition.Role {
			case PartitionRootData:
				if partition.UniqueGUID != artifactSet.Verity.DataPartitionGUID {
					return errors.New("root-data GPT GUID differs from the artifact-set dm-verity contract")
				}
			case PartitionRootHash:
				if partition.UniqueGUID != artifactSet.Verity.HashPartitionGUID {
					return errors.New("root-hash GPT GUID differs from the artifact-set dm-verity contract")
				}
			}
		}
	}
	return nil
}

func partitionGUIDs(partitions []Partition) []string {
	result := make([]string, len(partitions))
	for index := range partitions {
		result[index] = partitions[index].UniqueGUID
	}
	return result
}

func cloneDevicePlans(devices []DevicePlan) []DevicePlan {
	result := make([]DevicePlan, len(devices))
	for index := range devices {
		result[index] = devices[index]
		result[index].Partitions = append([]Partition(nil), devices[index].Partitions...)
	}
	return result
}

func (backup BackupDevice) validate(campaign CampaignBinding, stagingPlanDigest bundle.Digest) error {
	if backup.Campaign != campaign || backup.StagingPlanDigest != stagingPlanDigest {
		return errors.New("backup device is detached from its campaign or staging plan")
	}
	if err := backup.Identity.Validate(); err != nil {
		return err
	}
	if err := validateDigest("staging_device_digest", backup.StagingDeviceDigest); err != nil {
		return err
	}
	fixed, _ := fixedIdentityFor(backup.Identity.Leg)
	if len(backup.Partitions) != len(fixed.partitions) {
		return fmt.Errorf("backup for leg %q must contain every full partition", backup.Identity.Leg)
	}
	seenGUIDs := make(map[string]struct{})
	for index, expected := range fixed.partitions {
		preimage := backup.Partitions[index]
		if preimage.Role != expected.role || preimage.Number != expected.number ||
			preimage.ByteStart != expected.byteStart || preimage.SizeBytes != expected.capacity {
			return fmt.Errorf("backup for leg %q partition %d differs from the fixed full-partition geometry", backup.Identity.Leg, index+1)
		}
		if err := validateGUID("backup unique_guid", preimage.UniqueGUID); err != nil {
			return err
		}
		if _, duplicate := seenGUIDs[preimage.UniqueGUID]; duplicate {
			return fmt.Errorf("backup for leg %q contains a duplicate partition GUID", backup.Identity.Leg)
		}
		seenGUIDs[preimage.UniqueGUID] = struct{}{}
		if err := validateDigest("preimage_sha256", preimage.PreimageSHA256); err != nil {
			return err
		}
	}
	expectedRanges := expectedGPTRanges(backup.Identity)
	if len(backup.GPTPreimages) != len(expectedRanges) {
		return fmt.Errorf("backup for leg %q must contain every intended final-layout GPT range", backup.Identity.Leg)
	}
	for index, expected := range expectedRanges {
		preimage := backup.GPTPreimages[index]
		if preimage.Role != expected.role || preimage.OffsetBytes != expected.offsetBytes || preimage.SizeBytes != expected.sizeBytes {
			return fmt.Errorf("backup for leg %q GPT range %d differs from the fixed final-layout range", backup.Identity.Leg, index+1)
		}
		if err := validateDigest("GPT preimage_sha256", preimage.PreimageSHA256); err != nil {
			return err
		}
	}
	return nil
}

// NewBackupManifest validates the supplied full-partition and listed GPT-range
// preimages against the independently sealed staging plan and seals them.
func NewBackupManifest(plan StagingPlan, devices []BackupDevice) (BackupManifest, error) {
	if err := plan.Validate(); err != nil {
		return BackupManifest{}, err
	}
	manifest := BackupManifest{
		SchemaVersion:     BackupManifestSchemaV1Alpha1,
		Campaign:          plan.Campaign,
		StagingPlanDigest: plan.PlanDigest,
		Devices:           cloneBackupDevices(devices),
	}
	sealed, err := manifest.Seal()
	if err != nil {
		return BackupManifest{}, err
	}
	if err := sealed.ValidateAgainst(plan); err != nil {
		return BackupManifest{}, err
	}
	return sealed, nil
}

func (manifest BackupManifest) validate(requireDigest bool) error {
	if manifest.SchemaVersion != BackupManifestSchemaV1Alpha1 {
		return fmt.Errorf("unsupported backup manifest schema_version %q", manifest.SchemaVersion)
	}
	if err := manifest.Campaign.Validate(); err != nil {
		return err
	}
	if err := validateDigest("staging_plan_digest", manifest.StagingPlanDigest); err != nil {
		return err
	}
	if len(manifest.Devices) != len(fixedIdentities) {
		return errors.New("backup devices must contain exactly malak SD followed by Pi-local NVMe")
	}
	for index, fixed := range fixedIdentities {
		if manifest.Devices[index].Identity.Leg != fixed.leg {
			return errors.New("backup devices must contain exactly malak SD followed by Pi-local NVMe")
		}
		if err := manifest.Devices[index].validate(manifest.Campaign, manifest.StagingPlanDigest); err != nil {
			return err
		}
	}
	if requireDigest {
		if err := validateDigest("backup_manifest_digest", manifest.BackupManifestDigest); err != nil {
			return err
		}
		derived, err := manifest.DerivedDigest()
		if err != nil {
			return err
		}
		if manifest.BackupManifestDigest != derived {
			return errors.New("backup_manifest_digest does not bind the canonical backup manifest")
		}
	}
	return nil
}

// Validate checks the complete sealed backup manifest.
func (manifest BackupManifest) Validate() error { return manifest.validate(true) }

// ValidateAgainst proves that every backup entry covers the exact full
// partition or listed final-layout GPT range and device identity named by the
// independently sealed plan. It does not establish initial-GPT discovery.
func (manifest BackupManifest) ValidateAgainst(plan StagingPlan) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	if manifest.Campaign != plan.Campaign || manifest.StagingPlanDigest != plan.PlanDigest {
		return errors.New("backup manifest does not bind the supplied staging plan")
	}
	for index := range plan.Devices {
		planned := plan.Devices[index]
		backup := manifest.Devices[index]
		if backup.Identity != planned.Identity {
			return fmt.Errorf("backup identity for leg %q differs from the staging plan", planned.Identity.Leg)
		}
		deviceDigest, err := planned.DerivedDigest()
		if err != nil {
			return err
		}
		if backup.StagingDeviceDigest != deviceDigest {
			return fmt.Errorf("backup for leg %q does not bind its staging device plan", planned.Identity.Leg)
		}
		for partitionIndex := range planned.Partitions {
			partition := planned.Partitions[partitionIndex]
			preimage := backup.Partitions[partitionIndex]
			if preimage.Role != partition.Role || preimage.Number != partition.Number ||
				preimage.UniqueGUID != partition.UniqueGUID || preimage.ByteStart != partition.ByteStart ||
				preimage.SizeBytes != partition.CapacityBytes {
				return fmt.Errorf("backup for leg %q does not cover the exact planned full partition %d", planned.Identity.Leg, partition.Number)
			}
		}
	}
	return nil
}

func cloneBackupDevices(devices []BackupDevice) []BackupDevice {
	result := make([]BackupDevice, len(devices))
	for index := range devices {
		result[index] = devices[index]
		result[index].Partitions = append([]PartitionPreimage(nil), devices[index].Partitions...)
		result[index].GPTPreimages = append([]GPTPreimage(nil), devices[index].GPTPreimages...)
	}
	return result
}

var fixedRollbackOrder = []struct {
	leg           Leg
	kind          RecoveryStepKind
	partitionRole PartitionRole
	gptRole       GPTRegionRole
}{
	{leg: LegPiLocalNVMe, kind: RecoveryStepPartition, partitionRole: PartitionReleaseFilesystem},
	{leg: LegMalakSD, kind: RecoveryStepPartition, partitionRole: PartitionRootData},
	{leg: LegMalakSD, kind: RecoveryStepPartition, partitionRole: PartitionRootHash},
	{leg: LegPiLocalNVMe, kind: RecoveryStepGPT, gptRole: GPTBackupEntryArray},
	{leg: LegPiLocalNVMe, kind: RecoveryStepGPT, gptRole: GPTBackupHeader},
	{leg: LegPiLocalNVMe, kind: RecoveryStepGPT, gptRole: GPTPrimaryEntryArray},
	{leg: LegPiLocalNVMe, kind: RecoveryStepGPT, gptRole: GPTPrimaryHeader},
	{leg: LegPiLocalNVMe, kind: RecoveryStepGPT, gptRole: GPTProtectiveMBR},
	{leg: LegMalakSD, kind: RecoveryStepGPT, gptRole: GPTBackupEntryArray},
	{leg: LegMalakSD, kind: RecoveryStepGPT, gptRole: GPTBackupHeader},
	{leg: LegMalakSD, kind: RecoveryStepGPT, gptRole: GPTPrimaryEntryArray},
	{leg: LegMalakSD, kind: RecoveryStepGPT, gptRole: GPTPrimaryHeader},
	{leg: LegMalakSD, kind: RecoveryStepGPT, gptRole: GPTProtectiveMBR},
	{leg: LegMalakSD, kind: RecoveryStepPartition, partitionRole: PartitionBootFilesystem},
}

// NewRollbackPlan derives the sole accepted recovery sequence from a sealed
// staging plan and its validated, explicitly incomplete preimage manifest.
func NewRollbackPlan(plan StagingPlan, backup BackupManifest) (RollbackPlan, error) {
	if err := backup.ValidateAgainst(plan); err != nil {
		return RollbackPlan{}, err
	}
	steps := make([]RollbackStep, 0, len(fixedRollbackOrder))
	for index, expected := range fixedRollbackOrder {
		deviceIndex := 0
		if expected.leg == LegPiLocalNVMe {
			deviceIndex = 1
		}
		planned := plan.Devices[deviceIndex]
		backedUp := backup.Devices[deviceIndex]
		deviceDigest, err := planned.DerivedDigest()
		if err != nil {
			return RollbackPlan{}, err
		}
		step := RollbackStep{
			StepNumber:          uint8(index + 1),
			Leg:                 expected.leg,
			StagingDeviceDigest: deviceDigest,
			Kind:                expected.kind,
		}
		if expected.kind == RecoveryStepPartition {
			partitionIndex := partitionIndexByRole(planned.Partitions, expected.partitionRole)
			partition := planned.Partitions[partitionIndex]
			preimage := backedUp.Partitions[partitionIndex]
			step.Role = string(expected.partitionRole)
			step.PartitionNumber = partition.Number
			step.ByteStart = partition.ByteStart
			step.SizeBytes = partition.CapacityBytes
			step.PreimageSHA256 = preimage.PreimageSHA256
		} else {
			preimageIndex := gptPreimageIndexByRole(backedUp.GPTPreimages, expected.gptRole)
			preimage := backedUp.GPTPreimages[preimageIndex]
			step.Role = string(expected.gptRole)
			step.ByteStart = preimage.OffsetBytes
			step.SizeBytes = preimage.SizeBytes
			step.PreimageSHA256 = preimage.PreimageSHA256
		}
		steps = append(steps, step)
	}
	rollback := RollbackPlan{
		SchemaVersion:        RollbackPlanSchemaV1Alpha1,
		Campaign:             plan.Campaign,
		StagingPlanDigest:    plan.PlanDigest,
		BackupManifestDigest: backup.BackupManifestDigest,
		Steps:                steps,
	}
	sealed, err := rollback.Seal()
	if err != nil {
		return RollbackPlan{}, err
	}
	if err := sealed.ValidateAgainst(plan, backup); err != nil {
		return RollbackPlan{}, err
	}
	return sealed, nil
}

func gptPreimageIndexByRole(preimages []GPTPreimage, role GPTRegionRole) int {
	for index := range preimages {
		if preimages[index].Role == role {
			return index
		}
	}
	panic("fixed campaign GPT range absent after validation")
}

func partitionIndexByRole(partitions []Partition, role PartitionRole) int {
	for index := range partitions {
		if partitions[index].Role == role {
			return index
		}
	}
	panic("fixed campaign partition role absent after validation")
}

func (rollback RollbackPlan) validate(requireDigest bool) error {
	if rollback.SchemaVersion != RollbackPlanSchemaV1Alpha1 {
		return fmt.Errorf("unsupported rollback plan schema_version %q", rollback.SchemaVersion)
	}
	if err := rollback.Campaign.Validate(); err != nil {
		return err
	}
	if err := validateDigest("staging_plan_digest", rollback.StagingPlanDigest); err != nil {
		return err
	}
	if err := validateDigest("backup_manifest_digest", rollback.BackupManifestDigest); err != nil {
		return err
	}
	if len(rollback.Steps) != len(fixedRollbackOrder) {
		return errors.New("rollback steps must contain all four full partitions and every listed final-layout GPT range in the fixed boot-last order")
	}
	for index, expected := range fixedRollbackOrder {
		step := rollback.Steps[index]
		fixed, _ := fixedIdentityFor(expected.leg)
		if step.StepNumber != uint8(index+1) || step.Leg != expected.leg || step.Kind != expected.kind {
			return errors.New("rollback steps must contain all four full partitions in the fixed boot-last order and geometry")
		}
		if expected.kind == RecoveryStepPartition {
			partition := fixed.partitions[0]
			for _, candidate := range fixed.partitions {
				if candidate.role == expected.partitionRole {
					partition = candidate
					break
				}
			}
			if step.Role != string(expected.partitionRole) || step.PartitionNumber != partition.number ||
				step.ByteStart != partition.byteStart || step.SizeBytes != partition.capacity {
				return errors.New("rollback partition step differs from the fixed boot-last order and geometry")
			}
		} else {
			ranges := expectedGPTRanges(DeviceIdentity{Leg: expected.leg, CapacityBytes: fixed.capacity})
			rangeIndex := fixedGPTRangeIndexByRole(ranges, expected.gptRole)
			rangeBinding := ranges[rangeIndex]
			if step.Role != string(expected.gptRole) || step.PartitionNumber != 0 ||
				step.ByteStart != rangeBinding.offsetBytes || step.SizeBytes != rangeBinding.sizeBytes {
				return errors.New("rollback GPT step differs from the fixed dependency-first metadata order and geometry")
			}
		}
		if err := validateDigest("rollback staging_device_digest", step.StagingDeviceDigest); err != nil {
			return err
		}
		if err := validateDigest("rollback preimage_sha256", step.PreimageSHA256); err != nil {
			return err
		}
	}
	if requireDigest {
		if err := validateDigest("rollback_plan_digest", rollback.RollbackPlanDigest); err != nil {
			return err
		}
		derived, err := rollback.DerivedDigest()
		if err != nil {
			return err
		}
		if rollback.RollbackPlanDigest != derived {
			return errors.New("rollback_plan_digest does not bind the canonical rollback plan")
		}
	}
	return nil
}

func fixedGPTRangeIndexByRole(ranges []fixedGPTRange, role GPTRegionRole) int {
	for index := range ranges {
		if ranges[index].role == role {
			return index
		}
	}
	panic("fixed campaign GPT range role absent after validation")
}

// Validate checks the complete sealed rollback description.
func (rollback RollbackPlan) Validate() error { return rollback.validate(true) }

// ValidateAgainst binds every rollback step to the corresponding planned
// partition or listed GPT range and its validated preimage.
func (rollback RollbackPlan) ValidateAgainst(plan StagingPlan, backup BackupManifest) error {
	if err := rollback.Validate(); err != nil {
		return err
	}
	if err := backup.ValidateAgainst(plan); err != nil {
		return err
	}
	if rollback.Campaign != plan.Campaign || rollback.StagingPlanDigest != plan.PlanDigest ||
		rollback.BackupManifestDigest != backup.BackupManifestDigest {
		return errors.New("rollback plan is detached from its staging plan or backup manifest")
	}
	for index, expected := range fixedRollbackOrder {
		deviceIndex := 0
		if expected.leg == LegPiLocalNVMe {
			deviceIndex = 1
		}
		deviceDigest, err := plan.Devices[deviceIndex].DerivedDigest()
		if err != nil {
			return err
		}
		step := rollback.Steps[index]
		if step.StagingDeviceDigest != deviceDigest {
			return fmt.Errorf("rollback step %d does not bind the planned device and complete backup preimage", index+1)
		}
		if expected.kind == RecoveryStepPartition {
			partitionIndex := partitionIndexByRole(plan.Devices[deviceIndex].Partitions, expected.partitionRole)
			partition := plan.Devices[deviceIndex].Partitions[partitionIndex]
			preimage := backup.Devices[deviceIndex].Partitions[partitionIndex]
			if step.PartitionNumber != partition.Number || step.ByteStart != partition.ByteStart ||
				step.SizeBytes != partition.CapacityBytes || step.PreimageSHA256 != preimage.PreimageSHA256 {
				return fmt.Errorf("rollback step %d does not bind the planned partition and complete backup preimage", index+1)
			}
		} else {
			preimageIndex := gptPreimageIndexByRole(backup.Devices[deviceIndex].GPTPreimages, expected.gptRole)
			preimage := backup.Devices[deviceIndex].GPTPreimages[preimageIndex]
			if step.ByteStart != preimage.OffsetBytes || step.SizeBytes != preimage.SizeBytes ||
				step.PreimageSHA256 != preimage.PreimageSHA256 {
				return fmt.Errorf("rollback step %d does not bind the planned GPT range and complete backup preimage", index+1)
			}
		}
	}
	return nil
}

func validateDigest(label string, digest bundle.Digest) error {
	if err := digest.Validate(); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return nil
}

func validateGUID(label, value string) error {
	if !guidPattern.MatchString(value) || value == "00000000-0000-0000-0000-000000000000" {
		return fmt.Errorf("%s must be one non-zero canonical lowercase GUID", label)
	}
	return nil
}
