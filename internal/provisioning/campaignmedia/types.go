// Package campaignmedia defines path-free, digest-sealed descriptions of the
// two media devices used by the Raspberry Pi 5 stable-verifier development
// campaign. The v1alpha1 recovery scope is intentionally incomplete and is not
// eligible for destructive staging. The separate v1alpha2 evidence envelope
// can strictly describe an additional valid physical-end GPT backup lineage
// but remains equally ineligible. Both initial-GPT inspectors accept only a
// caller-owned io.ReaderAt abstraction; the package contains no filesystem,
// device-opening, writer, command, signing, private-material, or authorization
// API.
package campaignmedia

import "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"

const (
	StagingPlanSchemaV1Alpha1    = "kaiba.provisioning.rpi5-stable-verifier-campaign-media-staging-plan/v1alpha1"
	BackupManifestSchemaV1Alpha1 = "kaiba.provisioning.rpi5-stable-verifier-campaign-media-backup-manifest/v1alpha1"
	RollbackPlanSchemaV1Alpha1   = "kaiba.provisioning.rpi5-stable-verifier-campaign-media-rollback-plan/v1alpha1"
	ArtifactSetSchemaV1Alpha1    = "kaiba.provisioning.rpi5-stable-verifier-campaign-artifact-set/v1alpha1"

	// RecoveryScopeFinalLayoutRanges is deliberately incomplete. It covers the
	// four payload partitions and the five metadata ranges at each device's
	// intended final GPT locations. In particular, it does not discover or bind
	// a pre-existing backup GPT at some other LBA.
	RecoveryScopeFinalLayoutRanges = "partition-payloads-and-final-layout-gpt-ranges-only"

	LogicalSectorSizeBytes = uint64(512)
	AlignmentBytes         = uint64(1024 * 1024)

	MalakSDCapacityBytes     = uint64(31_268_536_320)
	PiLocalNVMeCapacityBytes = uint64(256_060_514_304)

	MalakSDConfigID = "hardware-configuration:malak-rpi5-sacrificial-development-usb-sd:1"
	MalakSDHostname = "malak"
	MalakSDSelector = "/dev/disk/by-path/pci-0000:0e:00.3-usb-0:4:1.0-scsi-0:0:0:0"

	PiLocalNVMeConfigID = "hardware-configuration:rpi5-sacrificial-development-pi-local-nvme:1"
	PiLocalNVMeHostname = "kaiba-rpi5-provisioner"
	PiLocalNVMeSelector = "/dev/nvme0n1"

	ESPTypeGUID             = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
	ARM64RootTypeGUID       = "b921b045-1df0-41c3-af44-4c6f280d3fae"
	ARM64VerityTypeGUID     = "df3300ce-d69f-4c92-978c-9bfb0f38d820"
	LinuxFilesystemTypeGUID = "0fc63daf-8483-4772-8e79-3d69d8477de4"
)

const artifactSetDigestDomain = "kaiba.provisioning.rpi5-stable-verifier-campaign-artifact-set.v1alpha1"

const (
	MalakSDBootStartBytes        = uint64(1_048_576)
	MalakSDBootCapacityBytes     = uint64(134_217_728)
	MalakSDRootDataStartBytes    = uint64(135_266_304)
	MalakSDRootDataCapacityBytes = uint64(2_418_016_256)
	MalakSDRootHashStartBytes    = uint64(2_553_282_560)
	MalakSDRootHashCapacityBytes = uint64(19_922_944)

	PiLocalNVMeReleaseStartBytes    = uint64(1_048_576)
	PiLocalNVMeReleaseCapacityBytes = uint64(8_589_934_592)
)

const maximumContractBytes = 1024 * 1024
const maximumJSONDepth = 64

// Leg is one fixed execution-host/device pairing. It is not a caller-selected
// runtime mode.
type Leg string

const (
	LegMalakSD     Leg = "malak-sd"
	LegPiLocalNVMe Leg = "pi-local-nvme"
)

// PartitionRole is the closed vocabulary of the four campaign partitions.
type PartitionRole string

const (
	PartitionBootFilesystem    PartitionRole = "boot-filesystem"
	PartitionRootData          PartitionRole = "root-data"
	PartitionRootHash          PartitionRole = "root-hash"
	PartitionReleaseFilesystem PartitionRole = "release-filesystem"
)

// GPTRegionRole identifies one exact final-layout GPT byte range. Primary and
// backup entry arrays are separate roles even when their bytes are expected to
// be equal.
type GPTRegionRole string

const (
	GPTProtectiveMBR     GPTRegionRole = "protective-mbr"
	GPTPrimaryHeader     GPTRegionRole = "primary-header"
	GPTPrimaryEntryArray GPTRegionRole = "primary-entry-array"
	GPTBackupEntryArray  GPTRegionRole = "backup-entry-array"
	GPTBackupHeader      GPTRegionRole = "backup-header"
)

// RecoveryStepKind distinguishes a partition payload from GPT metadata. It
// prevents an executor from interpreting a metadata offset as a partition.
type RecoveryStepKind string

const (
	RecoveryStepPartition RecoveryStepKind = "partition"
	RecoveryStepGPT       RecoveryStepKind = "gpt-metadata"
)

// CampaignBinding prevents either physical leg from being detached from the
// exact logical campaign plan and its independently parsed payload artifact
// set. It does not itself prove the nature of those payload bytes.
type CampaignBinding struct {
	CampaignID                       string        `json:"campaign_id"`
	StableCampaignPlanDigest         bundle.Digest `json:"stable_campaign_plan_digest"`
	CampaignArtifactSetContentDigest bundle.Digest `json:"campaign_artifact_set_content_digest"`
}

// DeviceIdentity is the declarative reviewed configuration for one leg. It is
// not proof of a live attachment or a protected-device check; any future
// executor must independently pin and revalidate an opened block device. The
// only absolute path admitted here is one of the two fixed selectors below.
type DeviceIdentity struct {
	Leg                    Leg    `json:"leg"`
	ConfigID               string `json:"config_id"`
	Hostname               string `json:"hostname"`
	Selector               string `json:"selector"`
	CapacityBytes          uint64 `json:"capacity_bytes"`
	LogicalSectorSizeBytes uint64 `json:"logical_sector_size_bytes"`
	DiskGUID               string `json:"disk_guid"`
}

// ByteRangeDigest binds one unambiguous device byte range. It does not assert
// that the bytes have been read, parsed, written, or durably synchronized.
type ByteRangeDigest struct {
	OffsetBytes uint64        `json:"offset_bytes"`
	SizeBytes   uint64        `json:"size_bytes"`
	SHA256      bundle.Digest `json:"sha256"`
}

// GPTMetadata binds canonical full-device GPT placement and the exact ranges
// a later parser and read-only verifier must inspect. These hashes alone do not
// prove that the bytes decode to the adjacent typed fields; destructive
// staging therefore remains ineligible in this schema.
type GPTMetadata struct {
	ProtectiveMBRLastLBA    uint64          `json:"protective_mbr_last_lba"`
	PrimaryHeaderLBA        uint64          `json:"primary_header_lba"`
	PrimaryEntryArrayLBA    uint64          `json:"primary_entry_array_lba"`
	FirstUsableLBA          uint64          `json:"first_usable_lba"`
	LastUsableLBA           uint64          `json:"last_usable_lba"`
	BackupEntryArrayLBA     uint64          `json:"backup_entry_array_lba"`
	BackupHeaderLBA         uint64          `json:"backup_header_lba"`
	PartitionEntryCount     uint32          `json:"partition_entry_count"`
	PartitionEntrySizeBytes uint32          `json:"partition_entry_size_bytes"`
	ProtectiveMBR           ByteRangeDigest `json:"protective_mbr"`
	PrimaryHeader           ByteRangeDigest `json:"primary_header"`
	PrimaryEntryArray       ByteRangeDigest `json:"primary_entry_array"`
	BackupEntryArray        ByteRangeDigest `json:"backup_entry_array"`
	BackupHeader            ByteRangeDigest `json:"backup_header"`
}

// Partition binds an immutable public source and the exact complete partition
// bytes expected after staging. ExpectedWholePartitionSHA256 covers the source
// followed by exactly ZeroTailBytes zero bytes.
type Partition struct {
	Role                         PartitionRole `json:"role"`
	Number                       uint32        `json:"number"`
	TypeGUID                     string        `json:"type_guid"`
	UniqueGUID                   string        `json:"unique_guid"`
	GPTName                      string        `json:"gpt_name"`
	GPTAttributes                uint64        `json:"gpt_attributes"`
	ByteStart                    uint64        `json:"byte_start"`
	CapacityBytes                uint64        `json:"capacity_bytes"`
	SourceSizeBytes              uint64        `json:"source_size_bytes"`
	SourceSHA256                 bundle.Digest `json:"source_sha256"`
	ZeroTailBytes                uint64        `json:"zero_tail_bytes"`
	ExpectedWholePartitionSHA256 bundle.Digest `json:"expected_whole_partition_sha256"`
}

// DevicePlan lists every and only GPT entry allowed on one fixed device.
type DevicePlan struct {
	Campaign   CampaignBinding `json:"campaign"`
	Identity   DeviceIdentity  `json:"identity"`
	GPT        GPTMetadata     `json:"gpt"`
	Partitions []Partition     `json:"partitions"`
}

// StagingPlan is descriptive input to a future capability-separated writer.
// This package itself cannot open or mutate either device.
type StagingPlan struct {
	SchemaVersion           string          `json:"schema_version"`
	Campaign                CampaignBinding `json:"campaign"`
	Devices                 []DevicePlan    `json:"devices"`
	RecoveryScope           string          `json:"recovery_scope"`
	InitialGPTRecoveryBound bool            `json:"initial_gpt_recovery_bound"`
	DestructiveStagingReady bool            `json:"destructive_staging_ready"`
	PlanDigest              bundle.Digest   `json:"plan_digest"`
}

// PartitionPreimage binds a complete pre-staging partition backup. SizeBytes
// is the full partition capacity, never merely its used prefix.
type PartitionPreimage struct {
	Role           PartitionRole `json:"role"`
	Number         uint32        `json:"number"`
	UniqueGUID     string        `json:"unique_guid"`
	ByteStart      uint64        `json:"byte_start"`
	SizeBytes      uint64        `json:"size_bytes"`
	PreimageSHA256 bundle.Digest `json:"preimage_sha256"`
}

// GPTPreimage binds bytes initially observed at one of the intended final GPT
// locations. This is not an initial-GPT discovery record: an old backup table
// located elsewhere (as on the current truncated SD) is outside its scope.
type GPTPreimage struct {
	Role           GPTRegionRole `json:"role"`
	OffsetBytes    uint64        `json:"offset_bytes"`
	SizeBytes      uint64        `json:"size_bytes"`
	PreimageSHA256 bundle.Digest `json:"preimage_sha256"`
}

// BackupDevice repeats the exact station identity and binds it to the digest
// of the corresponding DevicePlan. This makes a backup useful only with the
// independently supplied sealed staging plan.
type BackupDevice struct {
	Campaign            CampaignBinding     `json:"campaign"`
	StagingPlanDigest   bundle.Digest       `json:"staging_plan_digest"`
	StagingDeviceDigest bundle.Digest       `json:"staging_device_digest"`
	Identity            DeviceIdentity      `json:"identity"`
	Partitions          []PartitionPreimage `json:"partitions"`
	GPTPreimages        []GPTPreimage       `json:"gpt_preimages"`
}

// BackupManifest binds byte-exact preimages of all four full partitions and
// the listed final-layout GPT ranges. It does not bind an initial backup GPT
// discovered at another LBA, so it is not a complete device-recovery record.
type BackupManifest struct {
	SchemaVersion        string          `json:"schema_version"`
	Campaign             CampaignBinding `json:"campaign"`
	StagingPlanDigest    bundle.Digest   `json:"staging_plan_digest"`
	Devices              []BackupDevice  `json:"devices"`
	BackupManifestDigest bundle.Digest   `json:"backup_manifest_digest"`
}

// RollbackStep is an ordered description of one exact preimage range. Role is
// a PartitionRole string for partition steps and a GPTRegionRole string for
// GPT metadata steps. PartitionNumber is zero for metadata. The boot payload
// is necessarily last, so interrupted recovery does not expose it before its
// dependencies and listed GPT ranges have been restored.
type RollbackStep struct {
	StepNumber          uint8            `json:"step_number"`
	Leg                 Leg              `json:"leg"`
	StagingDeviceDigest bundle.Digest    `json:"staging_device_digest"`
	Kind                RecoveryStepKind `json:"kind"`
	Role                string           `json:"role"`
	PartitionNumber     uint32           `json:"partition_number"`
	ByteStart           uint64           `json:"byte_start"`
	SizeBytes           uint64           `json:"size_bytes"`
	PreimageSHA256      bundle.Digest    `json:"preimage_sha256"`
}

// RollbackPlan is only a sealed recovery description. There is intentionally
// no executable, automatic behavior, approval, authorization, or action field.
type RollbackPlan struct {
	SchemaVersion        string          `json:"schema_version"`
	Campaign             CampaignBinding `json:"campaign"`
	StagingPlanDigest    bundle.Digest   `json:"staging_plan_digest"`
	BackupManifestDigest bundle.Digest   `json:"backup_manifest_digest"`
	Steps                []RollbackStep  `json:"steps"`
	RollbackPlanDigest   bundle.Digest   `json:"rollback_plan_digest"`
}

// ArtifactSet is the strict, digest-sealed payload contract emitted by
// mkRpi5StableVerifierCampaignMedia. Its bounded PEM-marker scan is not proof
// that arbitrary private bytes are absent. It intentionally binds no physical
// layout; StagingPlan.ValidateAgainst supplies that separate cross-binding.
type ArtifactSet struct {
	ArtifactSetContentDigest bundle.Digest                 `json:"artifact_set_content_digest"`
	Artifacts                []ArtifactSetEntry            `json:"artifacts"`
	CampaignID               string                        `json:"campaign_id"`
	CampaignPlanResolution   CampaignPlanResolution        `json:"campaign_plan_resolution"`
	Capabilities             ArtifactSetCapabilities       `json:"capabilities"`
	PhysicalLayoutBound      bool                          `json:"physical_layout_bound"`
	PlanDigest               bundle.Digest                 `json:"plan_digest"`
	Provenance               ArtifactSetProvenance         `json:"provenance"`
	RecipeID                 *string                       `json:"recipe_id"`
	RunID                    string                        `json:"run_id"`
	SchemaVersion            string                        `json:"schema_version"`
	SemanticResolution       ArtifactSetSemanticResolution `json:"semantic_resolution"`
	StorageFormat            string                        `json:"storage_format"`
	Verity                   ArtifactSetVerity             `json:"verity"`
}

// CampaignPlanResolution reports deterministic build-time validation of all
// fixed campaign public inputs and mutation recipes. It is not execution,
// hardware-observation, or pass/fail evidence from a device.
type CampaignPlanResolution struct {
	BoundReplacementCount uint32        `json:"bound_replacement_count"`
	ByteXORMutationCount  uint32        `json:"byte_xor_mutation_count"`
	PlanDigest            bundle.Digest `json:"plan_digest"`
	PublicInputCount      uint32        `json:"public_input_count"`
	Status                string        `json:"status"`
}

type ArtifactSetEntry struct {
	Digest    bundle.Digest `json:"digest"`
	Name      string        `json:"name"`
	Role      PartitionRole `json:"role"`
	SizeBytes uint64        `json:"size_bytes"`
}

type ArtifactSetCapabilities struct {
	DelegatedReleasePrivateKeyPEMMarkerScan string `json:"delegated_release_private_key_pem_marker_scan"`
	DeviceWritesPerformed                   bool   `json:"device_writes_performed"`
	HardwareObserved                        bool   `json:"hardware_observed"`
	MutationPerformed                       bool   `json:"mutation_performed"`
	PrivateKeyOperationPerformed            bool   `json:"private_key_operation_performed"`
	ProductionReady                         bool   `json:"production_ready"`
	SigningPerformed                        bool   `json:"signing_performed"`
}

type ArtifactSetVerity struct {
	Algorithm         string        `json:"algorithm"`
	DataBlockSize     uint32        `json:"data_block_size"`
	DataDevice        string        `json:"data_device"`
	DataPartitionGUID string        `json:"data_partition_guid"`
	HashBlockSize     uint32        `json:"hash_block_size"`
	HashDevice        string        `json:"hash_device"`
	HashPartitionGUID string        `json:"hash_partition_guid"`
	NoSuperblock      bool          `json:"no_superblock"`
	RootHash          bundle.Digest `json:"root_hash"`
}

type ArtifactFileBinding struct {
	SHA256    bundle.Digest `json:"sha256"`
	SizeBytes uint64        `json:"size_bytes"`
}

// ArtifactSemanticBinding distinguishes an ordinary file SHA-256 from the
// domain-separated digest produced by its strict semantic parser.
type ArtifactSemanticBinding struct {
	File           ArtifactFileBinding `json:"file"`
	SemanticDigest bundle.Digest       `json:"semantic_digest"`
}

// ArtifactCommandLineBinding binds both the positive command-line file and
// its canonical parser-normalized value. Value excludes the optional file LF.
type ArtifactCommandLineBinding struct {
	File  ArtifactFileBinding `json:"file"`
	Value string              `json:"value"`
}

// ArtifactSetSemanticResolution contains only values derived from the exact
// public campaign bytes. It is descriptive and grants no execution, staging,
// signing, or claim-closure authority.
type ArtifactSetSemanticResolution struct {
	KernelCommandLine          ArtifactCommandLineBinding `json:"kernel_command_line"`
	PositiveReleaseManifest    ArtifactSemanticBinding    `json:"positive_release_manifest"`
	PositiveReleaseTree        ArtifactFileBinding        `json:"positive_release_tree"`
	ReplacementReleaseManifest ArtifactSemanticBinding    `json:"replacement_release_manifest"`
	StableVerifierPolicy       ArtifactSemanticBinding    `json:"stable_verifier_policy"`
}

type ArtifactPublicKeyBinding struct {
	Fingerprint bundle.Digest `json:"fingerprint"`
	SHA256      bundle.Digest `json:"sha256"`
	SizeBytes   uint64        `json:"size_bytes"`
}

type ArtifactSetProvenance struct {
	CampaignPlan       ArtifactFileBinding             `json:"campaign_plan"`
	DelegatedRelease   ArtifactDelegatedReleaseBinding `json:"delegated_release"`
	VerifiedSignedBoot ArtifactVerifiedBootBinding     `json:"verified_signed_boot"`
}

type ArtifactDelegatedReleaseBinding struct {
	ReleaseManifest       ArtifactFileBinding `json:"release_manifest"`
	ReleaseTreeDigest     bundle.Digest       `json:"release_tree_digest"`
	ReleaseTreeSizeBytes  uint64              `json:"release_tree_size_bytes"`
	SignatureVerification string              `json:"signature_verification"`
	WrapperManifest       ArtifactFileBinding `json:"wrapper_manifest"`
}

type ArtifactVerifiedBootBinding struct {
	BootImage               ArtifactFileBinding      `json:"boot_image"`
	BootSignature           ArtifactFileBinding      `json:"boot_signature"`
	PublicKey               ArtifactPublicKeyBinding `json:"public_key"`
	SignatureVerification   string                   `json:"signature_verification"`
	SignerIndependentReview ArtifactFileBinding      `json:"signer_independent_review"`
}
