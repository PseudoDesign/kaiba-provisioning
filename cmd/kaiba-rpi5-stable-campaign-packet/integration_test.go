//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignpacket"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

// The named Nix integration check supplies real, independently constructed
// baseline artifacts, materializations and public recipe bytes. Recovery
// envelopes below are explicitly synthetic test declarations; this test does
// not pretend to observe a board or an initial disk. Full planned zero tails
// are hashed, including the fixed multi-gigabyte NVMe partition.
func TestPublicCampaignPacketIntegration(t *testing.T) {
	if os.Getenv("KAIBA_PACKET_INTEGRATION") != "1" {
		t.Skip("enabled by the named native Nix packet integration check")
	}
	root := t.TempDir()
	read := func(path string) []byte {
		t.Helper()
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	write := func(path string, encoded []byte) {
		t.Helper()
		if err := os.WriteFile(path, encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	copyInput := func(source, name string) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		from, err := os.Open(source)
		if err != nil {
			t.Fatal(err)
		}
		defer from.Close()
		to, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(to, from); err != nil {
			to.Close()
			t.Fatal(err)
		}
		if err := to.Close(); err != nil {
			t.Fatal(err)
		}
		return path
	}
	planPath := copyInput(os.Getenv("KAIBA_PACKET_PLAN"), "campaign-plan.json")
	plan, err := stablecampaign.ParsePlan(read(planPath))
	if err != nil {
		t.Fatal(err)
	}
	baseline := os.Getenv("KAIBA_PACKET_BASELINE")
	artifactPath := copyInput(filepath.Join(baseline, "artifact-set.json"), "artifact-set.json")
	artifacts, err := campaignmedia.ParseArtifactSet(read(artifactPath))
	if err != nil {
		t.Fatal(err)
	}
	run1 := copyInput(os.Getenv("KAIBA_PACKET_RUN1"), "run-1.json")
	run2 := copyInput(os.Getenv("KAIBA_PACKET_RUN2"), "run-2.json")
	payloads := make(map[campaignmedia.PartitionRole]string)
	for _, artifact := range artifacts.Artifacts {
		payloads[artifact.Role] = copyInput(filepath.Join(baseline, artifact.Name), "payloads/"+string(artifact.Role))
	}
	staging, err := campaignmedia.ParseStagingPlan(read("../../internal/provisioning/campaignmedia/testdata/recovery-v1alpha2/staging-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	staging.Campaign = campaignmedia.CampaignBinding{CampaignID: plan.CampaignID, StableCampaignPlanDigest: plan.PlanDigest, CampaignArtifactSetContentDigest: artifacts.ArtifactSetContentDigest}
	for i := range staging.Devices {
		device := &staging.Devices[i]
		device.Campaign = staging.Campaign
		for j := range device.Partitions {
			partition := &device.Partitions[j]
			for _, artifact := range artifacts.Artifacts {
				if artifact.Role == partition.Role {
					partition.SourceSizeBytes = artifact.SizeBytes
					partition.SourceSHA256 = artifact.Digest
				}
			}
			partition.ZeroTailBytes = partition.CapacityBytes - partition.SourceSizeBytes
			partition.ExpectedWholePartitionSHA256 = packetFixturePaddedDigest(t, payloads[partition.Role], partition.ZeroTailBytes)
			if partition.Role == campaignmedia.PartitionRootData {
				partition.UniqueGUID = artifacts.Verity.DataPartitionGUID
			}
			if partition.Role == campaignmedia.PartitionRootHash {
				partition.UniqueGUID = artifacts.Verity.HashPartitionGUID
			}
		}
		packetFixtureBindGPT(t, device)
		if _, err := campaignmedia.FinalGPTWrites(*device); err != nil {
			t.Fatalf("independent GPT fixture: %v", err)
		}
	}
	staging, err = staging.Seal()
	if err != nil {
		t.Fatal(err)
	}
	stagingJSON, err := staging.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	stagingPath := filepath.Join(root, "staging-plan.json")
	write(stagingPath, stagingJSON)
	var envelopes []campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2
	var envelopePaths []string
	for _, name := range []string{"sd-envelope.json", "nvme-envelope.json"} {
		path := copyInput("../../internal/provisioning/campaignmedia/testdata/recovery-v1alpha2/"+name, name)
		envelope, err := campaignmedia.ParseInitialGPTRecoveryEnvelopeV1Alpha2(read(path))
		if err != nil {
			t.Fatal(err)
		}
		envelopes = append(envelopes, envelope)
		envelopePaths = append(envelopePaths, path)
	}
	requirements, err := campaignmedia.NewRecoveryBackupRequirementsV1Alpha2(staging, envelopes)
	if err != nil {
		t.Fatal(err)
	}
	requirementsJSON, err := requirements.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	requirementsPath := filepath.Join(root, "requirements.json")
	write(requirementsPath, requirementsJSON)
	arguments := []string{"--source-revision", strings.Repeat("1", 40), "--campaign-plan", planPath, "--artifact-set", artifactPath,
		"--run-1-materialization", run1, "--run-2-materialization", run2, "--staging-plan", stagingPath,
		"--requirements", requirementsPath, "--sd-envelope", envelopePaths[0], "--nvme-envelope", envelopePaths[1]}
	for _, name := range payloadNames {
		arguments = append(arguments, "--"+name, payloads[campaignmedia.PartitionRole(name)])
	}
	publicPaths := make(map[string]string)
	for _, binding := range plan.PublicInputs {
		path := copyInput(filepath.Join(os.Getenv("KAIBA_PACKET_PUBLIC_INPUTS"), binding.Name), "public/"+binding.Name)
		publicPaths[binding.Name] = path
		arguments = append(arguments, "--public-input", binding.Name+"="+path)
	}
	for _, recipe := range plan.ByteXORMutations {
		path := copyInput(filepath.Join(os.Getenv("KAIBA_PACKET_TARGETS"), recipe.Target), "targets/"+recipe.Target)
		arguments = append(arguments, "--byte-mutation-target", recipe.Target+"="+path)
	}
	t.Log("Verifying both real materializations, all public recipe bytes, complete payloads and planned zero tails")
	var stdout, stderr bytes.Buffer
	if code := run(arguments, &stdout, &stderr); code != 0 {
		t.Fatalf("valid CLI returned %d: %s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("successful packet produced diagnostics: %s", stderr.String())
	}
	encoded := stdout.Bytes()
	if len(encoded) == 0 || encoded[len(encoded)-1] != '\n' || bytes.Contains(encoded[:len(encoded)-1], []byte{'\n'}) {
		t.Fatal("packet is not one canonical JSON line")
	}
	var report struct {
		SchemaVersion string            `json:"schema_version"`
		Assurance     string            `json:"assurance"`
		PlanDigest    bundle.Digest     `json:"plan_digest"`
		PacketDigest  bundle.Digest     `json:"packet_digest"`
		Partitions    []json.RawMessage `json:"partitions"`
		Runs          []struct {
			RunIndex            uint16 `json:"run_index"`
			RunID               string `json:"run_id"`
			WitnessRequirements []struct {
				ClaimClosed bool `json:"claim_closed"`
				Collected   bool `json:"authenticated_witnesses_collected"`
			} `json:"witness_requirements"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(encoded, &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != campaignpacket.SchemaVersion || report.Assurance != "public-byte-and-contract-consistency-only" || report.PlanDigest != plan.PlanDigest || len(report.Partitions) != 4 || len(report.Runs) != 2 {
		t.Fatal("packet omitted independently validated bindings")
	}
	if report.Runs[0].RunIndex != 1 || report.Runs[0].RunID != "positive-baseline" || len(report.Runs[0].WitnessRequirements) != 5 || report.Runs[1].RunIndex != 2 || report.Runs[1].RunID != "authorization-offline-rejected:authority-offline" || len(report.Runs[1].WitnessRequirements) != 1 {
		t.Fatalf("wrong first-run requirements: %+v", report.Runs)
	}
	for _, run := range report.Runs {
		for _, w := range run.WitnessRequirements {
			if w.ClaimClosed || w.Collected {
				t.Fatal("prepared packet claimed collected witnesses")
			}
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"source_revision_verified", "ci_status_verified", "backup_capture_performed", "backup_readback_verified", "live_attachments_verified", "operator_approval_bound", "destructive_staging_ready", "hardware_observed", "claim_closure_available", "signature_verification_performed"} {
		if string(fields[field]) != "false" {
			t.Fatalf("%s did not remain false", field)
		}
	}
	end := bytes.LastIndex(encoded, []byte(`,"packet_digest":`))
	if end < 0 {
		t.Fatal("packet digest not present")
	}
	material := append(append([]byte(nil), encoded[:end]...), '}')
	if want := bundle.Sum(append([]byte("kaiba.provisioning.rpi5-stable-verifier-preparation-packet.v1alpha1\x00"), material...)); want != report.PacketDigest {
		t.Fatal("packet digest did not bind complete report")
	}
	reject := func(name string, args []string) {
		t.Helper()
		var out, diagnostics bytes.Buffer
		if code := run(args, &out, &diagnostics); code == 0 || out.Len() != 0 {
			t.Fatalf("%s produced a packet: code=%d stderr=%s", name, code, diagnostics.String())
		}
	}
	swapped := append([]string(nil), arguments...)
	for index, value := range swapped {
		if value == "--run-2-materialization" {
			swapped[index+1] = run1
		}
	}
	reject("baseline substituted for run 2", swapped)
	for _, test := range []struct{ name, path string }{
		{"substituted partition payload", payloads[campaignmedia.PartitionBootFilesystem]},
		{"substituted public trust bytes", publicPaths["authorization-trust-anchor"]},
	} {
		file, err := os.OpenFile(test.path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		var original [1]byte
		if _, err := file.ReadAt(original[:], 0); err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteAt([]byte{original[0] ^ 1}, 0); err != nil {
			t.Fatal(err)
		}
		file.Close()
		reject(test.name, arguments)
		file, err = os.OpenFile(test.path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteAt(original[:], 0); err != nil {
			t.Fatal(err)
		}
		file.Close()
	}
	changed := staging
	changed.Devices = append([]campaignmedia.DevicePlan(nil), staging.Devices...)
	changed.Devices[0].GPT.PrimaryHeader.SHA256 = bundle.Sum([]byte("forged GPT"))
	changed, err = changed.Seal()
	if err != nil {
		t.Fatal(err)
	}
	changedJSON, err := changed.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	write(stagingPath, changedJSON)
	reject("resealed invented GPT bytes", arguments)
	write(stagingPath, stagingJSON)
	write(requirementsPath, bytes.Replace(requirementsJSON, []byte(`"backup_capture_performed":false`), []byte(`"backup_capture_performed":true`), 1))
	reject("fabricated durable recovery capture", arguments)
	write(requirementsPath, requirementsJSON)
}

func packetFixturePaddedDigest(t *testing.T, path string, zeroTail uint64) bundle.Digest {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		t.Fatal(err)
	}
	zero := make([]byte, 1024*1024)
	for zeroTail > 0 {
		count := min(uint64(len(zero)), zeroTail)
		hash.Write(zero[:int(count)])
		zeroTail -= count
	}
	return bundle.Digest(fmt.Sprintf("sha256:%x", hash.Sum(nil)))
}

// This independent fixture encoder is intentionally test-local: production
// FinalGPTWrites must verify the expected hashes rather than derive a plan's
// expected hashes from itself. It does not create or write a device.
func packetFixtureBindGPT(t *testing.T, device *campaignmedia.DevicePlan) {
	t.Helper()
	guid := func(text string) []byte {
		encoded, err := hex.DecodeString(strings.ReplaceAll(text, "-", ""))
		if err != nil || len(encoded) != 16 {
			t.Fatal("invalid fixture GUID")
		}
		for _, pair := range [][2]int{{0, 3}, {1, 2}, {4, 5}, {6, 7}} {
			encoded[pair[0]], encoded[pair[1]] = encoded[pair[1]], encoded[pair[0]]
		}
		return encoded
	}
	entries := make([]byte, 128*128)
	for _, partition := range device.Partitions {
		entry := entries[(partition.Number-1)*128 : partition.Number*128]
		copy(entry, guid(partition.TypeGUID))
		copy(entry[16:], guid(partition.UniqueGUID))
		for _, field := range []struct {
			offset int
			value  uint64
		}{{32, partition.ByteStart / 512}, {40, (partition.ByteStart+partition.CapacityBytes)/512 - 1}, {48, partition.GPTAttributes}} {
			binary.LittleEndian.PutUint64(entry[field.offset:], field.value)
		}
		for index, value := range utf16.Encode([]rune(partition.GPTName)) {
			binary.LittleEndian.PutUint16(entry[56+index*2:], value)
		}
	}
	makeHeader := func(lba, alternate, array uint64) []byte {
		header := make([]byte, 512)
		copy(header, "EFI PART")
		binary.LittleEndian.PutUint32(header[8:], 0x10000)
		binary.LittleEndian.PutUint32(header[12:], 92)
		for _, field := range []struct {
			offset int
			value  uint64
		}{{24, lba}, {32, alternate}, {40, 34}, {48, device.GPT.LastUsableLBA}, {72, array}} {
			binary.LittleEndian.PutUint64(header[field.offset:], field.value)
		}
		copy(header[56:], guid(device.Identity.DiskGUID))
		binary.LittleEndian.PutUint32(header[80:], 128)
		binary.LittleEndian.PutUint32(header[84:], 128)
		binary.LittleEndian.PutUint32(header[88:], crc32.ChecksumIEEE(entries))
		binary.LittleEndian.PutUint32(header[16:], crc32.ChecksumIEEE(header[:92]))
		return header
	}
	pmbr := make([]byte, 512)
	pmbr[450] = 0xee
	pmbr[510] = 0x55
	pmbr[511] = 0xaa
	binary.LittleEndian.PutUint32(pmbr[454:], 1)
	binary.LittleEndian.PutUint32(pmbr[458:], uint32(device.Identity.CapacityBytes/512-1))
	device.GPT.ProtectiveMBR.SHA256 = bundle.Sum(pmbr)
	device.GPT.PrimaryEntryArray.SHA256 = bundle.Sum(entries)
	device.GPT.BackupEntryArray.SHA256 = bundle.Sum(entries)
	device.GPT.PrimaryHeader.SHA256 = bundle.Sum(makeHeader(1, device.GPT.BackupHeaderLBA, 2))
	device.GPT.BackupHeader.SHA256 = bundle.Sum(makeHeader(device.GPT.BackupHeaderLBA, 1, device.GPT.BackupEntryArrayLBA))
}
