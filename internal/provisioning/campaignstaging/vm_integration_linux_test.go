//go:build linux

package campaignstaging

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediadevice"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediainventory"
)

// This test is enabled only by tests/campaign-staging-vm.nix. It creates
// disposable loop devices inside that guest and uses the production Linux
// adapter, including its fixed host and selector policy, without overrides.
func vmDevices(t *testing.T) (string, campaignmedia.StagingPlan, []string) {
	t.Helper()
	if os.Getenv("KAIBA_CAMPAIGN_STAGING_VM") != "1" {
		t.Skip("requires the dedicated disposable NixOS VM")
	}
	marker, err := os.ReadFile("/etc/kaiba-campaign-staging-vm")
	if err != nil || string(marker) != "disposable-campaign-staging-test\n" {
		t.Fatal("dedicated VM marker is missing")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile("/etc/kaiba-campaign-staging-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := campaignmedia.ParseStagingPlan(encoded)
	if err != nil {
		t.Fatal(err)
	}
	plan.Campaign.CampaignID = "synthetic-block-device-vm"
	plan.Campaign.StableCampaignPlanDigest = bundle.Sum([]byte("synthetic VM campaign"))
	plan.Campaign.CampaignArtifactSetContentDigest = bundle.Sum([]byte("synthetic VM artifacts"))
	var paths []string
	for i, device := range plan.Devices {
		path := filepath.Join(root, fmt.Sprintf("device-%d.img", i))
		file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(int64(device.Identity.CapacityBytes)); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		loop := vmCommand(t, "losetup", "--find", "--show", path)
		t.Cleanup(func() { vmCommand(t, "losetup", "--detach", loop) })
		paths = append(paths, loop)
	}
	if err := os.MkdirAll(filepath.Dir(campaignmedia.MalakSDSelector), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(paths[0], campaignmedia.MalakSDSelector); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(paths[1])
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if err := syscall.Mknod(campaignmedia.PiLocalNVMeSelector, syscall.S_IFBLK|0600, int(stat.Rdev)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(campaignmedia.MalakSDSelector); _ = os.Remove(campaignmedia.PiLocalNVMeSelector) })
	// udev briefly holds a shared flock while probing a newly attached loop.
	// Wait for fixture initialization; the production opener still refuses
	// any busy attachment immediately and never retries a staging operation.
	vmCommand(t, "udevadm", "settle")
	vmHostname(t, campaignmedia.MalakSDHostname)
	return root, plan, paths
}

func TestCampaignStagingVM(t *testing.T) {
	root, plan, paths := vmDevices(t)
	ctx := context.Background()
	var err error
	t.Log("Checking real Linux inventory, locks, mounted/held rejection, and selector replacement")
	vmAdapterChecks(t, plan.Devices[0].Identity, paths)

	var envelopes []campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2
	payloads := make([]map[campaignmedia.PartitionRole]string, 2)
	for i := range plan.Devices {
		device := &plan.Devices[i]
		device.Campaign = plan.Campaign
		payloads[i] = map[campaignmedia.PartitionRole]string{}
		for j := range device.Partitions {
			p := &device.Partitions[j]
			path := filepath.Join(root, fmt.Sprintf("payload-%d-%d.img", i, j))
			file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Truncate(int64(p.CapacityBytes)); err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteAt([]byte(fmt.Sprintf("SYNTHETIC-VM-PAYLOAD-%d-%d", i, j)), 0); err != nil {
				t.Fatal(err)
			}
			sourceHash, err := mediadevice.HashRange(ctx, file, 0, p.SourceSizeBytes)
			if err != nil {
				t.Fatal(err)
			}
			wholeHash, err := mediadevice.HashRange(ctx, file, 0, p.CapacityBytes)
			if err != nil {
				t.Fatal(err)
			}
			p.SourceSHA256 = bundle.Digest(sourceHash)
			p.ExpectedWholePartitionSHA256 = bundle.Digest(wholeHash)
			if err := file.Truncate(int64(p.SourceSizeBytes)); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			payloads[i][p.Role] = path
		}
		for _, item := range vmGPTItems(t, *device) {
			hash := bundle.Sum(item.data)
			switch item.role {
			case campaignmedia.GPTProtectiveMBR:
				device.GPT.ProtectiveMBR.SHA256 = hash
			case campaignmedia.GPTPrimaryHeader:
				device.GPT.PrimaryHeader.SHA256 = hash
			case campaignmedia.GPTPrimaryEntryArray:
				device.GPT.PrimaryEntryArray.SHA256 = hash
			case campaignmedia.GPTBackupHeader:
				device.GPT.BackupHeader.SHA256 = hash
			case campaignmedia.GPTBackupEntryArray:
				device.GPT.BackupEntryArray.SHA256 = hash
			}
		}
		// Fixture construction is separate from the candidate writer. Only the
		// loop devices allocated above are seeded; the real adapter later has
		// no access to these path arguments.
		file, err := os.OpenFile(paths[i], os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range vmInitialGPTItems(t, *device) {
			if _, err := file.WriteAt(item.data, int64(item.offset)); err != nil {
				t.Fatal(err)
			}
		}
		for _, p := range device.Partitions {
			if _, err := file.WriteAt([]byte("OLD-VM-PARTITION-DATA"), int64(p.ByteStart+2*1024*1024+512)); err != nil {
				t.Fatal(err)
			}
		}
		if err := file.Sync(); err != nil {
			t.Fatal(err)
		}
		planned, err := campaignmedia.PlannedPayloadRangesFromDevicePlan(*device)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := campaignmedia.InspectInitialGPTRecoveryV1Alpha2(file, device.Identity, "capture:"+strings.Repeat(fmt.Sprint(i+1), 64), planned)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if i == 0 && (envelope.PhysicalEndBackupLineage == nil || envelope.PhysicalEndState != campaignmedia.InitialGPTPhysicalEndDistinctBackupLineage) {
			t.Fatal("VM SD fixture lacks both GPT lineages")
		}
		if i == 1 && envelope.SelectedLineage.FirstUsableLBA != 2048 {
			t.Fatal("VM NVMe fixture lacks initial aligned geometry")
		}
		envelopes = append(envelopes, envelope)
	}
	plan, err = plan.Seal()
	if err != nil {
		t.Fatal(err)
	}
	requirements, err := campaignmedia.NewRecoveryBackupRequirementsV1Alpha2(plan, envelopes)
	if err != nil {
		t.Fatal(err)
	}
	for i, device := range plan.Devices {
		vmHostname(t, device.Identity.Hostname)
		config := Config{Plan: plan, Requirements: requirements, Envelopes: envelopes, Leg: device.Identity.Leg, Payloads: payloads[i]}
		opener := FixedDeviceOpener{Identity: device.Identity, ProtectedDevicePaths: []string{"/dev/vda"}}
		vmStagingChecks(t, ctx, root, config, opener)
	}
}

// Reproduce the descriptor transition using the real udev watcher and the
// fixed adapter without hashing full partitions. Every iteration starts
// quiescent, writes one byte, synchronizes, closes, and independently opens
// a read-only descriptor with the previous attachment facts.
func TestCampaignStagingVMOpenTransitions(t *testing.T) {
	_, plan, paths := vmDevices(t)
	ctx := context.Background()
	d := plan.Devices[0]
	file, err := os.OpenFile(paths[0], os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range vmInitialGPTItems(t, d) {
		if _, err := file.WriteAt(item.data, int64(item.offset)); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	vmCommand(t, "udevadm", "settle")
	opener := FixedDeviceOpener{Identity: d.Identity, ProtectedDevicePaths: []string{"/dev/vda"}}
	for i := 0; i < 50; i++ {
		target, err := opener.Open(ctx, true, nil)
		if err != nil {
			t.Fatalf("iteration %d initial writable open: %v", i, err)
		}
		facts := target.Facts()
		if _, err := target.WriteAt([]byte{byte(i)}, int64(d.Partitions[0].ByteStart)); err != nil {
			t.Fatal(err)
		}
		if err := target.Sync(); err != nil {
			t.Fatal(err)
		}
		if err := target.Close(); err != nil {
			t.Fatal(err)
		}
		reader, err := openExecutionReadbackTarget(ctx, recipe{identity: d.Identity}, opener, facts, func() error { return ctx.Err() })
		if err != nil {
			t.Log(vmCommand(t, "cat", "/proc/locks"))
			t.Log(vmCommand(t, "ps", "-eo", "pid,comm"))
			t.Fatalf("iteration %d writable-close to independent readonly-open: %v", i, err)
		}
		var readback [1]byte
		if _, err := reader.ReadAt(readback[:], int64(d.Partitions[0].ByteStart)); err != nil {
			t.Fatal(err)
		}
		if readback[0] != byte(i) {
			t.Fatal("independent descriptor readback differs from the synchronized byte")
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		vmCommand(t, "udevadm", "settle")
	}
}

func vmCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %q: %v: %s", name, args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func vmHostname(t *testing.T, hostname string) {
	t.Helper()
	if err := syscall.Sethostname([]byte(hostname)); err != nil {
		t.Fatal(err)
	}
}

func vmAdapterChecks(t *testing.T, identity campaignmedia.DeviceIdentity, paths []string) {
	t.Helper()
	ctx := context.Background()
	opener := FixedDeviceOpener{Identity: identity, ProtectedDevicePaths: []string{"/dev/vda"}}
	target, err := opener.Open(ctx, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	facts := target.Facts()
	if facts.Kind != mediainventory.TargetBlockDevice || facts.DiskSequence == 0 || !strings.Contains(facts.SysfsPath, "/block/loop") {
		t.Fatalf("unexpected real loop facts: %#v", facts)
	}
	if _, err := target.WriteAt([]byte("forbidden"), 0); err == nil {
		t.Fatal("read-only target accepted a write")
	}
	if competing, err := opener.Open(ctx, true, nil); err == nil {
		competing.Close()
		t.Fatal("second opener obtained an exclusively held target")
	}
	if err := os.Remove(identity.Selector); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(paths[1], identity.Selector); err != nil {
		t.Fatal(err)
	}
	if err := target.Revalidate(ctx); err == nil {
		t.Fatal("revalidation accepted a replaced selector")
	}
	if _, err := opener.Open(ctx, true, nil); err == nil {
		t.Fatal("opener accepted wrong-size replacement")
	}
	if err := os.Remove(identity.Selector); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(paths[0], identity.Selector); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	changed := facts
	changed.DiskSequence++
	if _, err := opener.Open(ctx, true, &changed); err == nil {
		t.Fatal("opener accepted a changed attachment sequence")
	}
	changed = facts
	changed.BootID = "00000000-0000-0000-0000-000000000000"
	if _, err := opener.Open(ctx, true, &changed); err == nil {
		t.Fatal("opener accepted a changed boot ID")
	}
	for _, protected := range []string{paths[0], "/dev/missing-protected-device"} {
		if _, err := (FixedDeviceOpener{Identity: identity, ProtectedDevicePaths: []string{protected}}).Open(ctx, true, nil); err == nil {
			t.Fatal("opener ignored protected device policy")
		}
	}
	// A live, unmounted device-mapper consumer must be rejected as well as a
	// filesystem mount. Both are real kernel state, not an inventory mock.
	vmCommand(t, "dmsetup", "create", "campaign-held", "--table", "0 65536 linear "+paths[0]+" 0")
	if _, err := opener.Open(ctx, true, nil); err == nil {
		t.Fatal("opener accepted an active holder")
	}
	vmCommand(t, "dmsetup", "remove", "campaign-held")
	vmCommand(t, "udevadm", "settle")
	vmCommand(t, "mkfs.ext4", "-F", "-b", "4096", paths[0], "8192")
	vmCommand(t, "udevadm", "settle")
	mountpoint := t.TempDir()
	vmCommand(t, "mount", paths[0], mountpoint)
	if _, err := opener.Open(ctx, true, nil); err == nil {
		t.Fatal("opener accepted a mounted target")
	}
	vmCommand(t, "umount", mountpoint)
	vmCommand(t, "udevadm", "settle")
	target, err = opener.Open(ctx, true, &facts)
	if err != nil {
		t.Fatal(err)
	}
	vmHostname(t, "wrong-campaign-host")
	if err := target.Revalidate(ctx); err == nil {
		t.Fatal("target ignored changed execution host")
	}
	vmHostname(t, identity.Hostname)
	if err := target.Revalidate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
}

type vmGPTItem struct {
	role   campaignmedia.GPTRegionRole
	offset uint64
	data   []byte
}

// This fixture renderer deliberately accepts initial layouts which are not
// final plans. Strict campaignmedia inspection independently validates its
// bytes before they can enter a staging configuration.
func vmGPTItems(t *testing.T, d campaignmedia.DevicePlan) []vmGPTItem {
	t.Helper()
	guid := func(s string) []byte {
		b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
		if err != nil || len(b) != 16 {
			t.Fatal("invalid fixture GUID")
		}
		return []byte{b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]}
	}
	entries := make([]byte, 128*128)
	for _, p := range d.Partitions {
		e := entries[(p.Number-1)*128 : p.Number*128]
		copy(e[:16], guid(p.TypeGUID))
		copy(e[16:32], guid(p.UniqueGUID))
		binary.LittleEndian.PutUint64(e[32:40], p.ByteStart/512)
		binary.LittleEndian.PutUint64(e[40:48], (p.ByteStart+p.CapacityBytes)/512-1)
		binary.LittleEndian.PutUint64(e[48:56], p.GPTAttributes)
		for i, c := range utf16.Encode([]rune(p.GPTName)) {
			binary.LittleEndian.PutUint16(e[56+i*2:58+i*2], c)
		}
	}
	header := func(current, alternate, array uint64) []byte {
		b := make([]byte, 512)
		copy(b, "EFI PART")
		binary.LittleEndian.PutUint32(b[8:12], 0x10000)
		binary.LittleEndian.PutUint32(b[12:16], 92)
		binary.LittleEndian.PutUint64(b[24:32], current)
		binary.LittleEndian.PutUint64(b[32:40], alternate)
		binary.LittleEndian.PutUint64(b[40:48], d.GPT.FirstUsableLBA)
		binary.LittleEndian.PutUint64(b[48:56], d.GPT.LastUsableLBA)
		copy(b[56:72], guid(d.Identity.DiskGUID))
		binary.LittleEndian.PutUint64(b[72:80], array)
		binary.LittleEndian.PutUint32(b[80:84], 128)
		binary.LittleEndian.PutUint32(b[84:88], 128)
		binary.LittleEndian.PutUint32(b[88:92], crc32.ChecksumIEEE(entries))
		binary.LittleEndian.PutUint32(b[16:20], crc32.ChecksumIEEE(b[:92]))
		return b
	}
	mbr := make([]byte, 512)
	mbr[450] = 0xee
	mbr[510] = 0x55
	mbr[511] = 0xaa
	binary.LittleEndian.PutUint32(mbr[454:458], 1)
	binary.LittleEndian.PutUint32(mbr[458:462], uint32(d.GPT.ProtectiveMBRLastLBA))
	return []vmGPTItem{
		{campaignmedia.GPTProtectiveMBR, 0, mbr},
		{campaignmedia.GPTPrimaryHeader, 512, header(1, d.GPT.BackupHeaderLBA, 2)},
		{campaignmedia.GPTPrimaryEntryArray, 1024, entries},
		{campaignmedia.GPTBackupEntryArray, d.GPT.BackupEntryArray.OffsetBytes, entries},
		{campaignmedia.GPTBackupHeader, d.GPT.BackupHeader.OffsetBytes, header(d.GPT.BackupHeaderLBA, 1, d.GPT.BackupEntryArrayLBA)},
	}
}

func vmInitialGPTItems(t *testing.T, d campaignmedia.DevicePlan) []vmGPTItem {
	t.Helper()
	initial := d
	if d.Identity.Leg == campaignmedia.LegPiLocalNVMe {
		initial.GPT.FirstUsableLBA = 2048
		return vmGPTItems(t, initial)
	}
	const embeddedLBAs = uint64(6_291_456)
	initial.GPT.ProtectiveMBRLastLBA = embeddedLBAs - 1
	initial.GPT.LastUsableLBA = embeddedLBAs - 34
	initial.GPT.BackupHeaderLBA = embeddedLBAs - 1
	initial.GPT.BackupEntryArrayLBA = embeddedLBAs - 33
	initial.GPT.BackupHeader.OffsetBytes = (embeddedLBAs - 1) * 512
	initial.GPT.BackupEntryArray.OffsetBytes = (embeddedLBAs - 33) * 512
	items := vmGPTItems(t, initial)
	legacy := d
	legacy.Identity.DiskGUID = "c9a1ecae-6d32-46b2-8d9b-9257424f50e2"
	legacy.Partitions = append([]campaignmedia.Partition(nil), d.Partitions...)
	legacy.Partitions[0].UniqueGUID = "6dd777cd-1675-4468-8894-24fdad0bf6cf"
	legacy.Partitions[1].ByteStart = 135_266_304
	legacy.Partitions[1].CapacityBytes = 2_360_344_576
	legacy.Partitions[2].ByteStart = 2_495_610_880
	legacy.Partitions[2].CapacityBytes = 18_874_368
	for _, item := range vmGPTItems(t, legacy) {
		if item.role == campaignmedia.GPTBackupHeader || item.role == campaignmedia.GPTBackupEntryArray {
			items = append(items, item)
		}
	}
	return items
}

func vmStagingChecks(t *testing.T, ctx context.Context, root string, config Config, opener FixedDeviceOpener) {
	t.Helper()
	if config.Leg == campaignmedia.LegMalakSD {
		t.Log("Preparing an SD attempt and interrupting it after an actual block write")
		directory := filepath.Join(root, "interrupted-sd")
		preview, err := Prepare(ctx, directory, config, opener)
		if err != nil {
			t.Fatal("interrupted Prepare:", err)
		}
		approval, err := Approve(preview, preview.PreviewDigest, "synthetic-vm-reviewer")
		if err != nil {
			t.Fatal(err)
		}
		interrupted, cancel := context.WithCancel(ctx)
		injector := &vmInterruptOpener{base: opener, cancel: cancel}
		_, err = Execute(interrupted, directory, config, approval, injector)
		cancel()
		if err == nil || injector.written == 0 {
			t.Fatalf("attempt did not fail after an actual write: %v", err)
		}
		if _, err := os.Stat(filepath.Join(directory, "execution-started.json")); err != nil {
			t.Fatal("interrupted attempt lost its durable journal:", err)
		}
		if _, err := Execute(ctx, directory, config, approval, opener); err == nil {
			t.Fatal("interrupted attempt allowed a retry")
		}
		if _, err := os.Stat(filepath.Join(directory, "execution-complete.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("interrupted attempt produced a completion record")
		}
		// Exercise a bounded manual recovery from the durable preimage. This
		// restoration exists only in the VM test; execution never auto-resumes
		// or silently restores an interrupted physical attempt.
		var original []byte
		for _, backup := range preview.Backups {
			if injector.offset >= int64(backup.Offset) && uint64(injector.offset)+uint64(injector.written) <= backup.Offset+backup.Size {
				file, err := os.Open(filepath.Join(directory, backup.Name))
				if err != nil {
					t.Fatal(err)
				}
				original = make([]byte, injector.written)
				if _, err := file.ReadAt(original, injector.offset-int64(backup.Offset)); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				break
			}
		}
		if len(original) == 0 {
			t.Fatal("durable backup does not cover the interrupted write")
		}
		target, err := opener.Open(ctx, true, &preview.Attachment)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := target.WriteAt(original, injector.offset); err != nil {
			t.Fatal(err)
		}
		if err := target.Sync(); err != nil {
			t.Fatal(err)
		}
		if err := target.Close(); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("Preparing, acknowledging, and staging full %s geometry through the fixed Linux adapter", config.Leg)
	directory := filepath.Join(root, string(config.Leg))
	preview, err := Prepare(ctx, directory, config, opener)
	if err != nil {
		t.Fatal("positive Prepare:", err)
	}
	approval, err := Approve(preview, preview.PreviewDigest, "synthetic-vm-reviewer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Approve(preview, bundle.Sum([]byte("different preview")), "synthetic-vm-reviewer"); err == nil {
		t.Fatal("acknowledgement accepted the wrong preview digest")
	}
	report, err := Execute(ctx, directory, config, approval, opener)
	if err != nil {
		t.Fatal("positive Execute:", err)
	}
	if !report.BackupReadbackVerified || !report.Readback.CompleteRangesVerified || report.HardwareQualified || report.CampaignClaimsClosed {
		t.Fatal("VM report violated the mechanical evidence boundary")
	}
	if _, err := Execute(ctx, directory, config, approval, opener); err == nil {
		t.Fatal("completed attempt allowed a retry")
	}
	// Reattach the same backing bytes at the same device node. The boot-local
	// disk sequence must change even though path, size, and contents do not.
	// Prepared write authority stays bound to the old attachment; independent
	// readback is deliberately allowed to inspect the newly attached device.
	loop := filepath.Join("/dev", filepath.Base(preview.Attachment.SysfsPath))
	backing := vmCommand(t, "losetup", "--noheadings", "--output", "BACK-FILE", loop)
	vmCommand(t, "losetup", "--detach", loop)
	vmCommand(t, "losetup", loop, backing)
	vmCommand(t, "udevadm", "settle")
	if stale, err := opener.Open(ctx, false, &preview.Attachment); err == nil {
		stale.Close()
		t.Fatal("opener accepted the previous attachment after actual loop reattachment")
	}
	t.Logf("Independently reopening and verifying every planned %s range", config.Leg)
	readback, err := Verify(ctx, config, opener)
	if err != nil {
		t.Fatal(err)
	}
	if !readback.CompleteRangesVerified || readback.HardwareQualified || readback.CampaignClaimsClosed {
		t.Fatal("separate readback changed the evidence boundary")
	}
	if readback.Attachment.DiskSequence == preview.Attachment.DiskSequence {
		t.Fatal("independent readback did not observe the new attachment sequence")
	}
	encoded, err := report.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseReport(encoded); err != nil {
		t.Fatal(err)
	}
	target, err := opener.Open(ctx, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range config.Plan.Devices {
		if device.Identity.Leg != config.Leg {
			continue
		}
		for _, p := range device.Partitions {
			marker := make([]byte, len("OLD-VM-PARTITION-DATA"))
			if _, err := target.ReadAt(marker, int64(p.ByteStart+2*1024*1024+512)); err != nil {
				t.Fatal(err)
			}
			for _, b := range marker {
				if b != 0 {
					t.Fatal("staging left old nonzero partition bytes")
				}
			}
		}
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
}

type vmInterruptOpener struct {
	base    FixedDeviceOpener
	cancel  context.CancelFunc
	offset  int64
	written int
}

func (opener *vmInterruptOpener) Open(ctx context.Context, writable bool, expected *mediainventory.TargetFacts) (Target, error) {
	target, err := opener.base.Open(ctx, writable, expected)
	if err != nil || !writable {
		return target, err
	}
	return &vmInterruptTarget{Target: target, opener: opener}, nil
}

type vmInterruptTarget struct {
	Target
	opener *vmInterruptOpener
}

func (target *vmInterruptTarget) WriteAt(data []byte, offset int64) (int, error) {
	n, err := target.Target.WriteAt(data, offset)
	if n > 0 && target.opener.written == 0 {
		target.opener.offset = offset
		target.opener.written = n
		target.opener.cancel()
	}
	return n, err
}
