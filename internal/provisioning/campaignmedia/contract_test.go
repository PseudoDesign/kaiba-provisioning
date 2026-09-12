package campaignmedia

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	testSDDiskGUID      = "5625eee2-0c8a-402f-8c2f-5a1347652bb2"
	testSDBootGUID      = "59d06b61-bf85-4d77-89c3-9e5395934ff8"
	testSDRootDataGUID  = "bdd5be20-f7ea-56e7-ae90-4465ae950596"
	testSDRootHashGUID  = "62616022-71fb-5036-8cc4-b7949cc6e52c"
	testNVMeDiskGUID    = "bb5289ea-2c0b-424f-a4c7-23c8fdf1ebae"
	testNVMeReleaseGUID = "d8361116-a296-43d4-8f9e-65c35d00955b"
)

func testDigest(label string) bundle.Digest { return bundle.Sum([]byte(label)) }

func testCampaignBinding() CampaignBinding {
	return CampaignBinding{
		CampaignID:                       "rpi5-stable-verifier-physical-20260911",
		StableCampaignPlanDigest:         testDigest("stable campaign plan"),
		CampaignArtifactSetContentDigest: testDigest("campaign artifact set"),
	}
}

func testGPT(capacity uint64, label string) GPTMetadata {
	totalLBAs := capacity / LogicalSectorSizeBytes
	rangeBinding := func(role GPTRegionRole, offset, size uint64) ByteRangeDigest {
		return ByteRangeDigest{OffsetBytes: offset, SizeBytes: size, SHA256: testDigest(label + " " + string(role))}
	}
	primaryEntries := rangeBinding(GPTPrimaryEntryArray, 2*LogicalSectorSizeBytes, 128*128)
	backupEntries := rangeBinding(GPTBackupEntryArray, (totalLBAs-33)*LogicalSectorSizeBytes, 128*128)
	backupEntries.SHA256 = primaryEntries.SHA256
	return GPTMetadata{
		ProtectiveMBRLastLBA:    totalLBAs - 1,
		PrimaryHeaderLBA:        1,
		PrimaryEntryArrayLBA:    2,
		FirstUsableLBA:          34,
		LastUsableLBA:           totalLBAs - 34,
		BackupEntryArrayLBA:     totalLBAs - 33,
		BackupHeaderLBA:         totalLBAs - 1,
		PartitionEntryCount:     128,
		PartitionEntrySizeBytes: 128,
		ProtectiveMBR:           rangeBinding(GPTProtectiveMBR, 0, LogicalSectorSizeBytes),
		PrimaryHeader:           rangeBinding(GPTPrimaryHeader, LogicalSectorSizeBytes, LogicalSectorSizeBytes),
		PrimaryEntryArray:       primaryEntries,
		BackupEntryArray:        backupEntries,
		BackupHeader:            rangeBinding(GPTBackupHeader, (totalLBAs-1)*LogicalSectorSizeBytes, LogicalSectorSizeBytes),
	}
}

func testPartition(role PartitionRole, number uint32, typeGUID, guid, name string, start, capacity, sourceSize uint64, label string) Partition {
	sourceDigest := testDigest(label + " source")
	wholeDigest := sourceDigest
	if sourceSize != capacity {
		wholeDigest = testDigest(label + " source followed by zero tail")
	}
	return Partition{
		Role:                         role,
		Number:                       number,
		TypeGUID:                     typeGUID,
		UniqueGUID:                   guid,
		GPTName:                      name,
		GPTAttributes:                0,
		ByteStart:                    start,
		CapacityBytes:                capacity,
		SourceSizeBytes:              sourceSize,
		SourceSHA256:                 sourceDigest,
		ZeroTailBytes:                capacity - sourceSize,
		ExpectedWholePartitionSHA256: wholeDigest,
	}
}

func mustTestPlan(t *testing.T) StagingPlan {
	t.Helper()
	campaign := testCampaignBinding()
	sd := DevicePlan{
		Campaign: campaign,
		Identity: DeviceIdentity{
			Leg: LegMalakSD, ConfigID: MalakSDConfigID, Hostname: MalakSDHostname,
			Selector: MalakSDSelector, CapacityBytes: MalakSDCapacityBytes,
			LogicalSectorSizeBytes: LogicalSectorSizeBytes, DiskGUID: testSDDiskGUID,
		},
		GPT: testGPT(MalakSDCapacityBytes, "sd"),
		Partitions: []Partition{
			testPartition(PartitionBootFilesystem, 1, ESPTypeGUID, testSDBootGUID, "kaiba-boot", MalakSDBootStartBytes, MalakSDBootCapacityBytes, MalakSDBootCapacityBytes, "boot"),
			testPartition(PartitionRootData, 2, ARM64RootTypeGUID, testSDRootDataGUID, "kaiba-root", MalakSDRootDataStartBytes, MalakSDRootDataCapacityBytes, MalakSDRootDataCapacityBytes, "root data"),
			testPartition(PartitionRootHash, 3, ARM64VerityTypeGUID, testSDRootHashGUID, "kaiba-root-verity", MalakSDRootHashStartBytes, MalakSDRootHashCapacityBytes, MalakSDRootHashCapacityBytes, "root hash"),
		},
	}
	nvme := DevicePlan{
		Campaign: campaign,
		Identity: DeviceIdentity{
			Leg: LegPiLocalNVMe, ConfigID: PiLocalNVMeConfigID, Hostname: PiLocalNVMeHostname,
			Selector: PiLocalNVMeSelector, CapacityBytes: PiLocalNVMeCapacityBytes,
			LogicalSectorSizeBytes: LogicalSectorSizeBytes, DiskGUID: testNVMeDiskGUID,
		},
		GPT: testGPT(PiLocalNVMeCapacityBytes, "nvme"),
		Partitions: []Partition{
			testPartition(PartitionReleaseFilesystem, 1, LinuxFilesystemTypeGUID, testNVMeReleaseGUID, "KAIBA_RELEASE", PiLocalNVMeReleaseStartBytes, PiLocalNVMeReleaseCapacityBytes, 64*AlignmentBytes, "release"),
		},
	}
	plan, err := NewStagingPlan(campaign, []DevicePlan{sd, nvme})
	if err != nil {
		t.Fatalf("NewStagingPlan: %v", err)
	}
	return plan
}

func testBackupDevices(t *testing.T, plan StagingPlan) []BackupDevice {
	t.Helper()
	result := make([]BackupDevice, len(plan.Devices))
	for deviceIndex, device := range plan.Devices {
		deviceDigest, err := device.DerivedDigest()
		if err != nil {
			t.Fatalf("device digest: %v", err)
		}
		partitions := make([]PartitionPreimage, len(device.Partitions))
		for partitionIndex, partition := range device.Partitions {
			partitions[partitionIndex] = PartitionPreimage{
				Role: partition.Role, Number: partition.Number, UniqueGUID: partition.UniqueGUID,
				ByteStart: partition.ByteStart, SizeBytes: partition.CapacityBytes,
				PreimageSHA256: testDigest(string(device.Identity.Leg) + ":" + string(partition.Role) + " preimage"),
			}
		}
		gptPreimages := make([]GPTPreimage, len(expectedGPTRanges(device.Identity)))
		for rangeIndex, rangeBinding := range expectedGPTRanges(device.Identity) {
			gptPreimages[rangeIndex] = GPTPreimage{
				Role: rangeBinding.role, OffsetBytes: rangeBinding.offsetBytes, SizeBytes: rangeBinding.sizeBytes,
				PreimageSHA256: testDigest(string(device.Identity.Leg) + ":" + string(rangeBinding.role) + " preimage"),
			}
		}
		result[deviceIndex] = BackupDevice{
			Campaign: plan.Campaign, StagingPlanDigest: plan.PlanDigest,
			StagingDeviceDigest: deviceDigest, Identity: device.Identity, Partitions: partitions, GPTPreimages: gptPreimages,
		}
	}
	return result
}

func mustTestBackup(t *testing.T, plan StagingPlan) BackupManifest {
	t.Helper()
	manifest, err := NewBackupManifest(plan, testBackupDevices(t, plan))
	if err != nil {
		t.Fatalf("NewBackupManifest: %v", err)
	}
	return manifest
}

func TestStagingPlanCanonicalRoundTripAndBindings(t *testing.T) {
	plan := mustTestPlan(t)
	if err := plan.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	derived, err := plan.DerivedDigest()
	if err != nil || derived != plan.PlanDigest {
		t.Fatalf("DerivedDigest = %q, %v; want %q", derived, err, plan.PlanDigest)
	}
	encoded, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	parsed, err := ParseStagingPlan(encoded)
	if err != nil {
		t.Fatalf("ParseStagingPlan: %v", err)
	}
	if parsed.PlanDigest != plan.PlanDigest {
		t.Fatalf("parsed plan digest = %q; want %q", parsed.PlanDigest, plan.PlanDigest)
	}
	if _, err := ParseStagingPlan(append(append([]byte(nil), encoded...), '\n')); err != nil {
		t.Fatalf("ParseStagingPlan with LF: %v", err)
	}
	if got := bytes.Count(encoded, []byte("/dev/")); got != 2 {
		t.Fatalf("canonical plan contains %d absolute device paths; want exactly two reviewed selectors", got)
	}
	if plan.DestructiveStagingReady || plan.InitialGPTRecoveryBound || plan.RecoveryScope != RecoveryScopeFinalLayoutRanges {
		t.Fatal("v1alpha1 staging plan overstates destructive readiness or recovery coverage")
	}
	if err := plan.ValidateForDestructiveStaging(); err == nil {
		t.Fatal("incomplete recovery contract was accepted for destructive staging")
	}
	for _, forbidden := range []string{"private_key", "private_material", "authorized", "authorization", "command", "executable"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("canonical plan contains forbidden field vocabulary %q", forbidden)
		}
	}
}

func TestStagingPlanRejectsFixedIdentityGeometryAndPayloadTampering(t *testing.T) {
	tests := map[string]func(*StagingPlan){
		"device order":                 func(plan *StagingPlan) { plan.Devices[0], plan.Devices[1] = plan.Devices[1], plan.Devices[0] },
		"configuration ID":             func(plan *StagingPlan) { plan.Devices[0].Identity.ConfigID += "-other" },
		"hostname":                     func(plan *StagingPlan) { plan.Devices[1].Identity.Hostname = "kaiba-rpi5-secure-target" },
		"selector":                     func(plan *StagingPlan) { plan.Devices[0].Identity.Selector = "/dev/sda" },
		"capacity":                     func(plan *StagingPlan) { plan.Devices[0].Identity.CapacityBytes -= LogicalSectorSizeBytes },
		"sector size":                  func(plan *StagingPlan) { plan.Devices[1].Identity.LogicalSectorSizeBytes = 4096 },
		"disk GUID":                    func(plan *StagingPlan) { plan.Devices[0].Identity.DiskGUID = strings.ToUpper(testSDDiskGUID) },
		"truncated PMBR":               func(plan *StagingPlan) { plan.Devices[0].GPT.ProtectiveMBRLastLBA = 6_291_455 },
		"image-sized backup GPT":       func(plan *StagingPlan) { plan.Devices[0].GPT.BackupHeaderLBA = 6_291_455 },
		"backup entry array placement": func(plan *StagingPlan) { plan.Devices[0].GPT.BackupEntryArrayLBA-- },
		"GPT entry count":              func(plan *StagingPlan) { plan.Devices[0].GPT.PartitionEntryCount = 127 },
		"GPT metadata digest":          func(plan *StagingPlan) { plan.Devices[0].GPT.BackupHeader.SHA256 = "sha256:no" },
		"GPT metadata range":           func(plan *StagingPlan) { plan.Devices[0].GPT.BackupEntryArray.OffsetBytes-- },
		"missing backup array digest":  func(plan *StagingPlan) { plan.Devices[0].GPT.BackupEntryArray = ByteRangeDigest{} },
		"divergent GPT entry arrays": func(plan *StagingPlan) {
			plan.Devices[0].GPT.BackupEntryArray.SHA256 = testDigest("divergent backup GPT entries")
		},
		"missing partition": func(plan *StagingPlan) { plan.Devices[0].Partitions = plan.Devices[0].Partitions[:2] },
		"partition order": func(plan *StagingPlan) {
			plan.Devices[0].Partitions[0], plan.Devices[0].Partitions[1] = plan.Devices[0].Partitions[1], plan.Devices[0].Partitions[0]
		},
		"partition role":       func(plan *StagingPlan) { plan.Devices[0].Partitions[0].Role = PartitionRootData },
		"partition number":     func(plan *StagingPlan) { plan.Devices[0].Partitions[0].Number = 4 },
		"partition type":       func(plan *StagingPlan) { plan.Devices[0].Partitions[0].TypeGUID = LinuxFilesystemTypeGUID },
		"partition name":       func(plan *StagingPlan) { plan.Devices[0].Partitions[0].GPTName = "KAIBA_BOOT" },
		"partition attributes": func(plan *StagingPlan) { plan.Devices[0].Partitions[0].GPTAttributes = 1 },
		"partition start":      func(plan *StagingPlan) { plan.Devices[0].Partitions[0].ByteStart += AlignmentBytes },
		"partition capacity":   func(plan *StagingPlan) { plan.Devices[0].Partitions[0].CapacityBytes -= AlignmentBytes },
		"duplicate partition GUID": func(plan *StagingPlan) {
			plan.Devices[0].Partitions[1].UniqueGUID = plan.Devices[0].Partitions[0].UniqueGUID
		},
		"cross-device GUID": func(plan *StagingPlan) {
			plan.Devices[1].Partitions[0].UniqueGUID = plan.Devices[0].Partitions[0].UniqueGUID
		},
		"zero source":              func(plan *StagingPlan) { plan.Devices[0].Partitions[0].SourceSizeBytes = 0 },
		"unaligned source":         func(plan *StagingPlan) { plan.Devices[1].Partitions[0].SourceSizeBytes++ },
		"source exceeds partition": func(plan *StagingPlan) { plan.Devices[0].Partitions[0].SourceSizeBytes++ },
		"wrong zero tail":          func(plan *StagingPlan) { plan.Devices[1].Partitions[0].ZeroTailBytes-- },
		"source digest":            func(plan *StagingPlan) { plan.Devices[0].Partitions[0].SourceSHA256 = "sha256:no" },
		"whole digest": func(plan *StagingPlan) {
			plan.Devices[0].Partitions[0].ExpectedWholePartitionSHA256 = testDigest("different")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			plan := mustTestPlan(t)
			mutate(&plan)
			plan.PlanDigest = ""
			if _, err := plan.Seal(); err == nil {
				t.Fatal("tampered staging plan was accepted")
			}
		})
	}
}

func TestStagingPlanDigestDetectsBindingTampering(t *testing.T) {
	plan := mustTestPlan(t)
	plan.Campaign.CampaignArtifactSetContentDigest = testDigest("another artifact set")
	plan.Devices[0].Campaign = plan.Campaign
	plan.Devices[1].Campaign = plan.Campaign
	if err := plan.Validate(); err == nil {
		t.Fatal("stale plan digest accepted changed campaign artifact set")
	}

	plan = mustTestPlan(t)
	plan.Devices[0].GPT.PrimaryHeader.SHA256 = testDigest("changed GPT header")
	if err := plan.Validate(); err == nil {
		t.Fatal("stale plan digest accepted changed GPT bytes")
	}
}

func TestStrictCanonicalParsersRejectAmbiguity(t *testing.T) {
	plan := mustTestPlan(t)
	encoded, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, encoded, "", "  "); err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"empty":           {},
		"pretty":          pretty.Bytes(),
		"unknown field":   bytes.Replace(encoded, []byte(`{"schema_version":`), []byte(`{"unknown":1,"schema_version":`), 1),
		"duplicate field": bytes.Replace(encoded, []byte(`{"schema_version":`), []byte(`{"schema_version":"duplicate","schema_version":`), 1),
		"null":            bytes.Replace(encoded, []byte(`"devices":[`), []byte(`"devices":null,"unused":[`), 1),
		"trailing value":  append(append([]byte(nil), encoded...), []byte(`{}`)...),
		"two newlines":    append(append([]byte(nil), encoded...), '\n', '\n'),
		"oversized":       bytes.Repeat([]byte{' '}, maximumContractBytes+1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseStagingPlan(input); err == nil {
				t.Fatal("ambiguous or non-canonical JSON was accepted")
			}
		})
	}
}

func TestBackupManifestBindsAllFourFullPreimages(t *testing.T) {
	plan := mustTestPlan(t)
	backup := mustTestBackup(t, plan)
	if err := backup.ValidateAgainst(plan); err != nil {
		t.Fatalf("ValidateAgainst: %v", err)
	}
	count := 0
	gptCount := 0
	for _, device := range backup.Devices {
		count += len(device.Partitions)
		gptCount += len(device.GPTPreimages)
		for _, preimage := range device.Partitions {
			if preimage.SizeBytes == 0 {
				t.Fatal("backup contains an empty preimage range")
			}
		}
	}
	if count != 4 {
		t.Fatalf("backup contains %d partition preimages; want 4", count)
	}
	if gptCount != 10 {
		t.Fatalf("backup contains %d final-layout GPT preimages; want 10", gptCount)
	}
	encoded, err := backup.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseBackupManifest(encoded)
	if err != nil {
		t.Fatalf("ParseBackupManifest: %v", err)
	}
	if err := parsed.ValidateAgainst(plan); err != nil {
		t.Fatalf("parsed ValidateAgainst: %v", err)
	}
}

func TestBackupManifestRejectsTamperingAndCrossPlanUse(t *testing.T) {
	plan := mustTestPlan(t)

	backup := mustTestBackup(t, plan)
	backup.Devices[0].Partitions[0].PreimageSHA256 = testDigest("changed preimage")
	if err := backup.Validate(); err == nil {
		t.Fatal("stale backup digest accepted changed preimage")
	}

	backup = mustTestBackup(t, plan)
	backup.Devices[0].StagingDeviceDigest = testDigest("wrong device plan")
	resealed, err := backup.Seal()
	if err != nil {
		t.Fatalf("reseal structurally valid detached backup: %v", err)
	}
	if err := resealed.ValidateAgainst(plan); err == nil {
		t.Fatal("backup accepted wrong staging device digest")
	}

	backup = mustTestBackup(t, plan)
	backup.Devices[0].Partitions[0].SizeBytes--
	backup.BackupManifestDigest = ""
	if _, err := backup.Seal(); err == nil {
		t.Fatal("backup accepted a partial partition preimage")
	}

	backup = mustTestBackup(t, plan)
	backup.Devices[0].Partitions[1].UniqueGUID = testSDBootGUID
	backup.BackupManifestDigest = ""
	if _, err := backup.Seal(); err == nil {
		t.Fatal("backup accepted duplicate partition identity")
	}

	backup = mustTestBackup(t, plan)
	backup.Devices[0].GPTPreimages = backup.Devices[0].GPTPreimages[:4]
	backup.BackupManifestDigest = ""
	if _, err := backup.Seal(); err == nil {
		t.Fatal("backup accepted a missing final-layout GPT preimage")
	}

	backup = mustTestBackup(t, plan)
	backup.Devices[0].GPTPreimages[3].OffsetBytes--
	backup.BackupManifestDigest = ""
	if _, err := backup.Seal(); err == nil {
		t.Fatal("backup accepted a GPT preimage at the wrong byte range")
	}

	otherPlan := plan
	otherPlan.Campaign.CampaignArtifactSetContentDigest = testDigest("other artifact set")
	otherPlan.Devices = cloneDevicePlans(plan.Devices)
	otherPlan.Devices[0].Campaign = otherPlan.Campaign
	otherPlan.Devices[1].Campaign = otherPlan.Campaign
	otherPlan.PlanDigest = ""
	otherPlan, err = otherPlan.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := mustTestBackup(t, plan).ValidateAgainst(otherPlan); err == nil {
		t.Fatal("backup manifest was reusable with another sealed plan")
	}
}

func TestRollbackPlanIsCompleteBootLastAndDescriptiveOnly(t *testing.T) {
	plan := mustTestPlan(t)
	backup := mustTestBackup(t, plan)
	rollback, err := NewRollbackPlan(plan, backup)
	if err != nil {
		t.Fatalf("NewRollbackPlan: %v", err)
	}
	if err := rollback.ValidateAgainst(plan, backup); err != nil {
		t.Fatalf("ValidateAgainst: %v", err)
	}
	wantRoles := []string{
		string(PartitionReleaseFilesystem), string(PartitionRootData), string(PartitionRootHash),
		string(GPTBackupEntryArray), string(GPTBackupHeader), string(GPTPrimaryEntryArray), string(GPTPrimaryHeader), string(GPTProtectiveMBR),
		string(GPTBackupEntryArray), string(GPTBackupHeader), string(GPTPrimaryEntryArray), string(GPTPrimaryHeader), string(GPTProtectiveMBR),
		string(PartitionBootFilesystem),
	}
	for index, role := range wantRoles {
		if rollback.Steps[index].StepNumber != uint8(index+1) || rollback.Steps[index].Role != role {
			t.Fatalf("rollback step %d = %#v; want role %q", index+1, rollback.Steps[index], role)
		}
	}
	encoded, err := rollback.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"authorized", "authorization", "automatic", "execute", "command", "path", "private"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("rollback contract contains action or private-material vocabulary %q", forbidden)
		}
	}
	parsed, err := ParseRollbackPlan(encoded)
	if err != nil {
		t.Fatalf("ParseRollbackPlan: %v", err)
	}
	if err := parsed.ValidateAgainst(plan, backup); err != nil {
		t.Fatalf("parsed ValidateAgainst: %v", err)
	}
}

func TestRollbackPlanRejectsTamperingAndDetachedPreimages(t *testing.T) {
	plan := mustTestPlan(t)
	backup := mustTestBackup(t, plan)
	rollback, err := NewRollbackPlan(plan, backup)
	if err != nil {
		t.Fatal(err)
	}
	rollback.Steps[0], rollback.Steps[1] = rollback.Steps[1], rollback.Steps[0]
	rollback.RollbackPlanDigest = ""
	if _, err := rollback.Seal(); err == nil {
		t.Fatal("rollback accepted reordered steps")
	}

	rollback, err = NewRollbackPlan(plan, backup)
	if err != nil {
		t.Fatal(err)
	}
	rollback.Steps[0].PreimageSHA256 = testDigest("detached preimage")
	rollback.RollbackPlanDigest = ""
	rollback, err = rollback.Seal()
	if err != nil {
		t.Fatalf("reseal structurally valid detached rollback: %v", err)
	}
	if err := rollback.ValidateAgainst(plan, backup); err == nil {
		t.Fatal("rollback accepted a preimage absent from its backup manifest")
	}

	rollback, err = NewRollbackPlan(plan, backup)
	if err != nil {
		t.Fatal(err)
	}
	rollback.Steps[3].PreimageSHA256 = testDigest("detached GPT preimage")
	rollback.RollbackPlanDigest = ""
	rollback, err = rollback.Seal()
	if err != nil {
		t.Fatalf("reseal structurally valid detached GPT rollback: %v", err)
	}
	if err := rollback.ValidateAgainst(plan, backup); err == nil {
		t.Fatal("rollback accepted a GPT preimage absent from its backup manifest")
	}
}
