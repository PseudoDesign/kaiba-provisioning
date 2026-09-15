package campaignmedia

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

func preparationFixture(t *testing.T) (stablecampaign.Plan, ArtifactSet, StagingGUIDs, map[PartitionRole]PayloadSource) {
	t.Helper()
	plan := mustStableCampaignPlan(t)
	artifacts := mustArtifactSet(t, plan)
	guids := StagingGUIDs{SDDisk: testSDDiskGUID, NVMeDisk: testNVMeDiskGUID,
		Boot: testSDBootGUID, RootData: testSDRootDataGUID, RootHash: testSDRootHashGUID, Release: testNVMeReleaseGUID}
	sources := make(map[PartitionRole]PayloadSource)
	for _, entry := range artifacts.Artifacts {
		// Reader injection avoids repeatedly hashing multi-GiB geometry in the
		// orchestration tests. Exact bytes and zero-tail hashing are tested below.
		sources[entry.Role] = PayloadSource{Reader: bytes.NewReader([]byte(entry.Role)), SizeBytes: entry.SizeBytes}
	}
	return plan, artifacts, guids, sources
}

func fixturePayloadHasher(t *testing.T, artifacts ArtifactSet, called *[]PartitionRole) payloadHasher {
	t.Helper()
	return func(source PayloadSource, capacity uint64) (bundle.Digest, bundle.Digest, error) {
		name, err := io.ReadAll(io.NewSectionReader(source.Reader, 0, 100))
		if err != nil {
			t.Fatal(err)
		}
		role := PartitionRole(name)
		entry, ok := artifactForRole(artifacts, role)
		if !ok || source.SizeBytes != entry.SizeBytes {
			t.Fatal("wrong source reached payload hasher")
		}
		capacities := map[PartitionRole]uint64{
			PartitionBootFilesystem: MalakSDBootCapacityBytes, PartitionRootData: MalakSDRootDataCapacityBytes,
			PartitionRootHash: MalakSDRootHashCapacityBytes, PartitionReleaseFilesystem: PiLocalNVMeReleaseCapacityBytes,
		}
		if capacity != capacities[role] {
			t.Fatalf("%s hashed with capacity %d", role, capacity)
		}
		*called = append(*called, role)
		whole := entry.Digest
		if capacity > source.SizeBytes {
			whole = bundle.Sum([]byte("independently measured zero tail for " + role))
		}
		return entry.Digest, whole, nil
	}
}

func TestPrepareStagingPlanBindsAllSourcesAndCanonicalGPT(t *testing.T) {
	campaign, artifacts, guids, sources := preparationFixture(t)
	var called []PartitionRole
	plan, err := prepareStagingPlan(campaign, artifacts, guids, sources, fixturePayloadHasher(t, artifacts, &called))
	if err != nil {
		t.Fatal(err)
	}
	if len(called) != 4 {
		t.Fatalf("hashed %d sources, want four", len(called))
	}
	if err := plan.ValidateAgainst(campaign, artifacts); err != nil {
		t.Fatal(err)
	}
	if plan.DestructiveStagingReady || plan.InitialGPTRecoveryBound || plan.ValidateForDestructiveStaging() == nil {
		t.Fatal("public preparation raised readiness")
	}
	for _, device := range plan.Devices {
		writes, err := FinalGPTWrites(device)
		if err != nil || len(writes) != 5 {
			t.Fatalf("GPT bytes not independently bound: %d writes, %v", len(writes), err)
		}
		for _, write := range writes {
			if write.Range.SHA256 != bundle.Sum(write.Data) || write.Range.SizeBytes != uint64(len(write.Data)) {
				t.Fatal("GPT retained a placeholder digest")
			}
		}
		altered := device
		altered.GPT.PrimaryHeader.SHA256 = bundle.Sum([]byte("wrong header"))
		if _, err := FinalGPTWrites(altered); err == nil {
			t.Fatal("public GPT verifier accepted a substituted digest")
		}
	}
	encoded, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseStagingPlan(append(bytes.Clone(encoded), '\n'))
	if err != nil || parsed.PlanDigest != plan.PlanDigest {
		t.Fatalf("canonical staging roundtrip: %v", err)
	}
	second, err := prepareStagingPlan(campaign, artifacts, guids, sources, fixturePayloadHasher(t, artifacts, &called))
	if err != nil || second.PlanDigest != plan.PlanDigest {
		t.Fatalf("preparation was not deterministic: %v", err)
	}
	guids.Boot = "f2222222-2222-4222-8222-222222222222"
	changed, err := prepareStagingPlan(campaign, artifacts, guids, sources, fixturePayloadHasher(t, artifacts, &called))
	if err != nil || changed.PlanDigest == plan.PlanDigest || changed.Devices[0].GPT.PrimaryEntryArray.SHA256 == plan.Devices[0].GPT.PrimaryEntryArray.SHA256 {
		t.Fatalf("changed GUID did not change real GPT and plan digest: %v", err)
	}
}

func TestPrepareStagingPlanRejectsInvalidMetadataBeforePayloadReads(t *testing.T) {
	for name, alter := range map[string]func(*stablecampaign.Plan, *ArtifactSet, *StagingGUIDs, map[PartitionRole]PayloadSource){
		"detached campaign": func(p *stablecampaign.Plan, _ *ArtifactSet, _ *StagingGUIDs, _ map[PartitionRole]PayloadSource) {
			p.PlanDigest = testDigest("other plan")
		},
		"bad artifact digest": func(_ *stablecampaign.Plan, a *ArtifactSet, _ *StagingGUIDs, _ map[PartitionRole]PayloadSource) {
			a.ArtifactSetContentDigest = testDigest("other set")
		},
		"duplicate GUID": func(_ *stablecampaign.Plan, _ *ArtifactSet, g *StagingGUIDs, _ map[PartitionRole]PayloadSource) {
			g.Release = g.SDDisk
		},
		"invalid GUID": func(_ *stablecampaign.Plan, _ *ArtifactSet, g *StagingGUIDs, _ map[PartitionRole]PayloadSource) {
			g.Boot = "not-a-guid"
		},
		"wrong verity GUID": func(_ *stablecampaign.Plan, _ *ArtifactSet, g *StagingGUIDs, _ map[PartitionRole]PayloadSource) {
			g.RootHash = "f2222222-2222-4222-8222-222222222222"
		},
		"missing source": func(_ *stablecampaign.Plan, _ *ArtifactSet, _ *StagingGUIDs, s map[PartitionRole]PayloadSource) {
			delete(s, PartitionRootHash)
		},
		"unknown role": func(_ *stablecampaign.Plan, _ *ArtifactSet, _ *StagingGUIDs, s map[PartitionRole]PayloadSource) {
			s["unknown"] = s[PartitionRootHash]
			delete(s, PartitionRootHash)
		},
		"nil reader": func(_ *stablecampaign.Plan, _ *ArtifactSet, _ *StagingGUIDs, s map[PartitionRole]PayloadSource) {
			v := s[PartitionRootHash]
			v.Reader = nil
			s[PartitionRootHash] = v
		},
		"typed nil reader": func(_ *stablecampaign.Plan, _ *ArtifactSet, _ *StagingGUIDs, s map[PartitionRole]PayloadSource) {
			v := s[PartitionRootHash]
			v.Reader = (*bytes.Reader)(nil)
			s[PartitionRootHash] = v
		},
		"wrong last source size": func(_ *stablecampaign.Plan, _ *ArtifactSet, _ *StagingGUIDs, s map[PartitionRole]PayloadSource) {
			v := s[PartitionReleaseFilesystem]
			v.SizeBytes--
			s[PartitionReleaseFilesystem] = v
		},
	} {
		t.Run(name, func(t *testing.T) {
			plan, artifacts, guids, sources := preparationFixture(t)
			alter(&plan, &artifacts, &guids, sources)
			_, err := prepareStagingPlan(plan, artifacts, guids, sources, func(PayloadSource, uint64) (bundle.Digest, bundle.Digest, error) {
				t.Fatal("invalid metadata caused payload reads")
				return "", "", nil
			})
			if err == nil {
				t.Fatal("accepted invalid metadata")
			}
		})
	}
}

func TestPrepareStagingPlanRejectsUnreadableOrSubstitutedSource(t *testing.T) {
	for _, failure := range []bool{false, true} {
		plan, artifacts, guids, sources := preparationFixture(t)
		prepared, err := prepareStagingPlan(plan, artifacts, guids, sources, func(PayloadSource, uint64) (bundle.Digest, bundle.Digest, error) {
			if failure {
				return "", "", errors.New("read failure")
			}
			return testDigest("wrong bytes"), testDigest("wrong partition"), nil
		})
		if err == nil || prepared.PlanDigest != "" {
			t.Fatal("failed preparation returned a sealed plan")
		}
	}
}

func TestHashPayloadCoversExactSourceAndEntireZeroTail(t *testing.T) {
	data := bytes.Repeat([]byte{0x5a}, 512)
	for _, capacity := range []uint64{512, 4096, 2*1024*1024 + 512} {
		source, whole, err := hashPayload(PayloadSource{Reader: bytes.NewReader(data), SizeBytes: uint64(len(data))}, capacity)
		if err != nil {
			t.Fatal(err)
		}
		wantWhole := make([]byte, capacity)
		copy(wantWhole, data)
		if source != bundle.Sum(data) || whole != bundle.Sum(wantWhole) {
			t.Fatal("source or complete zero-tail hash is wrong")
		}
	}
	changed := bytes.Clone(data)
	changed[len(changed)-1] ^= 1
	original, _, _ := hashPayload(PayloadSource{Reader: bytes.NewReader(data), SizeBytes: 512}, 4096)
	altered, _, _ := hashPayload(PayloadSource{Reader: bytes.NewReader(changed), SizeBytes: 512}, 4096)
	if original == altered {
		t.Fatal("last source byte was omitted")
	}
	for name, source := range map[string]PayloadSource{
		"short":        {Reader: bytes.NewReader(data[:511]), SizeBytes: 512},
		"trailing":     {Reader: bytes.NewReader(append(bytes.Clone(data), 0)), SizeBytes: 512},
		"empty":        {Reader: bytes.NewReader(nil)},
		"too large":    {Reader: bytes.NewReader(data), SizeBytes: 8192},
		"reader error": {Reader: failingPayloadReader{}, SizeBytes: 512},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := hashPayload(source, 4096); err == nil {
				t.Fatal("accepted malformed source")
			}
		})
	}
}

type failingPayloadReader struct{}

func (failingPayloadReader) ReadAt([]byte, int64) (int, error) { return 0, errors.New("read failed") }
