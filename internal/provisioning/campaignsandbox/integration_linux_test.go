//go:build linux

package campaignsandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
)

// This separate CI check hashes full fixed campaign ranges (~11 GiB per
// complete pass) while allocating only sparse regular-file fixtures. Default
// unit tests cover the same I/O engine with small actual-byte fixtures.
func TestPublicCampaignSandboxIntegration(t *testing.T) {
	if os.Getenv("KAIBA_CAMPAIGN_SANDBOX_INTEGRATION") != "1" {
		t.Skip("enabled by the named full-geometry sandbox integration check")
	}
	ctx := context.Background()
	root := t.TempDir()
	encoded, err := os.ReadFile("../campaignmedia/testdata/recovery-v1alpha2/staging-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := campaignmedia.ParseStagingPlan(encoded)
	if err != nil {
		t.Fatal(err)
	}
	// Retain only the reviewed geometry from the public fixture. Every digest
	// below is derived afresh from these synthetic bytes, never hardware data.
	plan.Campaign.CampaignID = "synthetic-sandbox-integration"
	plan.Campaign.StableCampaignPlanDigest = bundle.Sum([]byte("synthetic fixed campaign fixture"))
	plan.Campaign.CampaignArtifactSetContentDigest = bundle.Sum([]byte("synthetic fixed artifact fixture"))
	input := Input{}
	for i := range plan.Devices {
		d := &plan.Devices[i]
		d.Campaign = plan.Campaign
		for j := range d.Partitions {
			p := &d.Partitions[j]
			path := filepath.Join(root, fmt.Sprintf("payload-%d-%d.img", i, j))
			f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(int64(p.CapacityBytes)); err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteAt([]byte(fmt.Sprintf("SYNTHETIC-PAYLOAD-%d-%d", i, j)), 0); err != nil {
				t.Fatal(err)
			}
			p.SourceSHA256, err = hashRange(ctx, f, 0, p.SourceSizeBytes)
			if err != nil {
				t.Fatal(err)
			}
			p.ExpectedWholePartitionSHA256, err = hashRange(ctx, f, 0, p.CapacityBytes)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(int64(p.SourceSizeBytes)); err != nil {
				t.Fatal(err)
			}
			f.Close()
			input.Payloads = append(input.Payloads, PayloadInput{Leg: d.Identity.Leg, Role: p.Role, Path: path})
		}
		items, err := canonicalGPT(*d)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range items {
			hash := bundle.Sum(item.data)
			switch campaignmedia.GPTRegionRole(item.role) {
			case campaignmedia.GPTProtectiveMBR:
				d.GPT.ProtectiveMBR.SHA256 = hash
			case campaignmedia.GPTPrimaryHeader:
				d.GPT.PrimaryHeader.SHA256 = hash
			case campaignmedia.GPTPrimaryEntryArray:
				d.GPT.PrimaryEntryArray.SHA256 = hash
			case campaignmedia.GPTBackupHeader:
				d.GPT.BackupHeader.SHA256 = hash
			case campaignmedia.GPTBackupEntryArray:
				d.GPT.BackupEntryArray.SHA256 = hash
			}
		}
		path := filepath.Join(root, fmt.Sprintf("initial-%d.img", i))
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(int64(d.Identity.CapacityBytes)); err != nil {
			t.Fatal(err)
		}
		for _, item := range initialGPTFixtureItems(t, *d) {
			if _, err := f.WriteAt(item.data, int64(item.offset)); err != nil {
				t.Fatal(err)
			}
		}
		for _, p := range d.Partitions {
			if _, err := f.WriteAt([]byte("OLD-NONZERO-DATA"), int64(p.ByteStart+2*1024*1024+512)); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
		planned, err := campaignmedia.PlannedPayloadRangesFromDevicePlan(*d)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := campaignmedia.InspectInitialGPTRecoveryV1Alpha2(f, d.Identity, "capture:"+strings.Repeat(fmt.Sprint(i+1), 64), planned)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 && (envelope.SelectedLineage.Placement != campaignmedia.InitialGPTPlacementImageSized || envelope.PhysicalEndState != campaignmedia.InitialGPTPhysicalEndDistinctBackupLineage || envelope.PhysicalEndBackupLineage == nil) {
			t.Fatal("integration did not capture both actual SD GPT lineages")
		}
		if i == 1 && envelope.SelectedLineage.FirstUsableLBA != 2048 {
			t.Fatal("integration did not capture aligned initial NVMe geometry")
		}
		input.Envelopes = append(input.Envelopes, envelope)
		input.Disks = append(input.Disks, DiskInput{Leg: d.Identity.Leg, Path: path})
	}
	input.Plan, err = plan.Seal()
	if err != nil {
		t.Fatal(err)
	}
	input.Requirements, err = campaignmedia.NewRecoveryBackupRequirementsV1Alpha2(input.Plan, input.Envelopes)
	if err != nil {
		t.Fatal(err)
	}
	bad := input
	bad.Plan.PlanDigest = bundle.Sum([]byte("tampered plan"))
	if _, err := Prepare(ctx, filepath.Join(root, "rejected-plan"), bad); err == nil {
		t.Fatal("public adapter accepted changed plan")
	}
	if _, err := os.Stat(filepath.Join(root, "rejected-plan")); !os.IsNotExist(err) {
		t.Fatal("invalid plan created a sandbox")
	}
	t.Log("Preparing full fixed geometry using synthetic sparse regular files")
	sandbox := filepath.Join(root, "sandbox")
	preview, err := Prepare(ctx, sandbox, input)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := Approve(preview, "synthetic-integration-reviewer")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Executing public adapter, including reopened backup and final partition/GPT readback")
	report, err := Execute(ctx, sandbox, approval)
	if err != nil {
		t.Fatal(err)
	}
	if report.PhysicalStagingReady || report.HardwareObserved || !report.FinalReadbackVerified {
		t.Fatal("synthetic execution changed physical readiness")
	}
	if _, err := Execute(ctx, sandbox, approval); err == nil || !strings.Contains(err.Error(), "already started") {
		t.Fatalf("public restart failed to reject retry: %v", err)
	}
	for i, d := range preview.Disks {
		f, err := os.Open(filepath.Join(sandbox, d.Name))
		if err != nil {
			t.Fatal(err)
		}
		device := input.Plan.Devices[i]
		planned, err := campaignmedia.PlannedPayloadRangesFromDevicePlan(device)
		if err != nil {
			t.Fatal(err)
		}
		final, err := campaignmedia.InspectInitialGPTRecoveryV1Alpha2(f, device.Identity, "capture:"+strings.Repeat(fmt.Sprint(i+3), 64), planned)
		if err != nil {
			t.Fatal(err)
		}
		if final.PhysicalEndState != campaignmedia.InitialGPTPhysicalEndSelectedLineageBackup || final.SelectedLineage.Placement != campaignmedia.InitialGPTPlacementCanonicalPhysical || final.SelectedLineage.FirstUsableLBA != 34 {
			t.Fatal("independent final parser did not observe canonical final GPT")
		}
		for _, w := range d.Writes {
			found := false
			for _, span := range final.RecoveryRanges {
				if span.OffsetBytes == w.Offset && span.SizeBytes == w.Size {
					found = true
					if span.PreimageSHA256 != w.SHA256 {
						t.Fatal("independent final range digest differs from intended bytes")
					}
				}
			}
			if !found {
				t.Fatal("independent final parser omitted a staged range")
			}
		}
		for _, p := range device.Partitions {
			marker := make([]byte, len("OLD-NONZERO-DATA"))
			if _, err := f.ReadAt(marker, int64(p.ByteStart+2*1024*1024+512)); err != nil {
				t.Fatal(err)
			}
			for _, b := range marker {
				if b != 0 {
					t.Fatal("zero-hole write left old partition data")
				}
			}
		}
		f.Close()
	}
}

// Use the exact reviewed *initial* layout differences, independent of the
// final plan: image-sized selected SD, a distinct physical-end legacy backup,
// and NVMe first-usable LBA 2048. Strict campaignmedia inspection below must
// accept all generated bytes before any sandbox preparation begins.
func initialGPTFixtureItems(t *testing.T, d campaignmedia.DevicePlan) []writeRecipe {
	t.Helper()
	initial := d
	if d.Identity.Leg == campaignmedia.LegPiLocalNVMe {
		initial.GPT.FirstUsableLBA = 2048
		items, err := canonicalGPT(initial)
		if err != nil {
			t.Fatal(err)
		}
		return items
	}
	const embeddedLBAs = uint64(6_291_456)
	initial.GPT.ProtectiveMBRLastLBA = embeddedLBAs - 1
	initial.GPT.LastUsableLBA = embeddedLBAs - 34
	initial.GPT.BackupHeaderLBA = embeddedLBAs - 1
	initial.GPT.BackupEntryArrayLBA = embeddedLBAs - 33
	initial.GPT.BackupHeader.OffsetBytes = (embeddedLBAs - 1) * 512
	initial.GPT.BackupEntryArray.OffsetBytes = (embeddedLBAs - 33) * 512
	items, err := canonicalGPT(initial)
	if err != nil {
		t.Fatal(err)
	}
	legacy := d
	legacy.Identity.DiskGUID = "c9a1ecae-6d32-46b2-8d9b-9257424f50e2"
	legacy.Partitions = append([]campaignmedia.Partition(nil), d.Partitions...)
	legacy.Partitions[0].UniqueGUID = "6dd777cd-1675-4468-8894-24fdad0bf6cf"
	legacy.Partitions[1].ByteStart = 135_266_304
	legacy.Partitions[1].CapacityBytes = 2_360_344_576
	legacy.Partitions[2].ByteStart = 2_495_610_880
	legacy.Partitions[2].CapacityBytes = 18_874_368
	legacyItems, err := canonicalGPT(legacy)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range legacyItems {
		if item.role == string(campaignmedia.GPTBackupHeader) || item.role == string(campaignmedia.GPTBackupEntryArray) {
			items = append(items, item)
		}
	}
	return items
}
