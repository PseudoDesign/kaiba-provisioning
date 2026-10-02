// Package campaignqualification validates independently reviewed, signed
// witnesses for the development campaign. It never opens devices, signs,
// dispatches operations, or grants provisioning/enrollment authority.
package campaignqualification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

const ExpectationSchema = "kaiba.provisioning.rpi5-campaign-qualification-expectation/v1alpha1"

// Input must come from the independently reviewed candidate, not the run's
// claimed readback. Layout is the baseline geometry; Payloads are this run's
// actual materialized bytes. DeviceFingerprint and ProfileDigest are reviewed
// inventory bindings, not inferred from a hostname or a block-device path.
type Input struct {
	Plan              stablecampaign.Plan
	Baseline          campaignmedia.ArtifactSet
	Materialization   campaignmedia.RunArtifactMaterialization
	Layout            campaignmedia.StagingPlan
	PublicSources     stablecampaign.PublicArtifactSources
	Payloads          map[campaignmedia.PartitionRole]stablecampaign.PublicArtifactSource
	DeviceFingerprint bundle.Digest
	ProfileDigest     bundle.Digest
}

type expectationRecord struct {
	SchemaVersion            string                                 `json:"schema_version"`
	DeviceFingerprint        bundle.Digest                          `json:"device_fingerprint"`
	ProfileDigest            bundle.Digest                          `json:"profile_digest"`
	CampaignID               string                                 `json:"campaign_id"`
	PlanDigest               bundle.Digest                          `json:"plan_digest"`
	RunIndex                 uint16                                 `json:"run_index"`
	RunID                    string                                 `json:"run_id"`
	ArtifactSetContentDigest bundle.Digest                          `json:"artifact_set_content_digest"`
	MaterializationDigest    bundle.Digest                          `json:"materialization_digest"`
	LayoutDigest             bundle.Digest                          `json:"layout_digest"`
	MediaPartitions          []stablecampaign.MediaPartitionBinding `json:"media_partitions"`
	PolicyDigest             bundle.Digest                          `json:"policy_digest"`
	ManifestDigest           bundle.Digest                          `json:"manifest_digest"`
	KernelCommandLine        string                                 `json:"kernel_command_line"`
	ExpectationDigest        bundle.Digest                          `json:"expectation_digest,omitempty"`
}

// Expectation has no public constructor from declarations or JSON. Only
// Prepare can create one after resolving the plan and rehashing actual payloads.
type Expectation struct {
	value expectationRecord
	plan  stablecampaign.Plan
}

func (expectation Expectation) CanonicalJSON() ([]byte, error) {
	if expectation.value.ExpectationDigest == "" {
		return nil, errors.New("uninitialized qualification expectation")
	}
	return json.Marshal(expectation.value)
}

func (expectation Expectation) Digest() bundle.Digest { return expectation.value.ExpectationDigest }

// Prepare derives all expected media hashes from independent public sources.
// Metadata seals prove byte consistency; the artifact witness must separately
// attest reviewed build, signing, and release provenance.
func Prepare(input Input) (Expectation, error) {
	for _, binding := range []bundle.Digest{input.DeviceFingerprint, input.ProfileDigest} {
		if err := binding.Validate(); err != nil {
			return Expectation{}, fmt.Errorf("inventory binding: %w", err)
		}
	}
	if err := input.Layout.ValidateAgainst(input.Plan, input.Baseline); err != nil {
		return Expectation{}, fmt.Errorf("baseline layout: %w", err)
	}
	for _, device := range input.Layout.Devices {
		if _, err := campaignmedia.FinalGPTWrites(device); err != nil {
			return Expectation{}, fmt.Errorf("independent final GPT rendering: %w", err)
		}
	}
	resolved, err := stablecampaign.ResolvePublicArtifactSources(input.Plan, input.PublicSources)
	if err != nil {
		return Expectation{}, fmt.Errorf("resolve independent public bytes: %w", err)
	}
	if err := input.Materialization.ValidateAgainst(input.Plan, input.Baseline, resolved); err != nil {
		return Expectation{}, fmt.Errorf("run materialization: %w", err)
	}
	if len(input.Payloads) != 4 {
		return Expectation{}, errors.New("exactly four actual run payloads are required")
	}
	runs, err := stablecampaign.ExpectedRuns(input.Plan)
	if err != nil {
		return Expectation{}, err
	}
	run := runs[input.Materialization.RunIndex-1]
	value := expectationRecord{
		SchemaVersion: ExpectationSchema, DeviceFingerprint: input.DeviceFingerprint, ProfileDigest: input.ProfileDigest,
		CampaignID: input.Plan.CampaignID, PlanDigest: input.Plan.PlanDigest, RunIndex: run.Index, RunID: run.RunID,
		ArtifactSetContentDigest: input.Baseline.ArtifactSetContentDigest,
		MaterializationDigest:    input.Materialization.MaterializationDigest, LayoutDigest: input.Layout.PlanDigest,
		PolicyDigest:      resolved.Semantics.StableVerifierPolicy.SemanticDigest,
		ManifestDigest:    resolved.Semantics.PositiveReleaseManifest.SemanticDigest,
		KernelCommandLine: resolved.Semantics.KernelCommandLine.Value,
	}
	if run.RunID == "delegated-key-replacement-boots:replacement-manifest" {
		value.ManifestDigest = resolved.Semantics.ReplacementReleaseManifest.SemanticDigest
	}
	// The materialization's canonical order is also the semantic readback order.
	for _, artifact := range input.Materialization.MaterializedArtifacts {
		var partition *campaignmedia.Partition
		for _, device := range input.Layout.Devices {
			for _, candidate := range device.Partitions {
				if candidate.Role == artifact.Role {
					copy := candidate
					partition = &copy
				}
			}
		}
		if partition == nil {
			return Expectation{}, fmt.Errorf("missing geometry for %s", artifact.Role)
		}
		whole, err := hashPayload(input.Payloads[artifact.Role], artifact, partition.CapacityBytes)
		if err != nil {
			return Expectation{}, fmt.Errorf("payload %s: %w", artifact.Role, err)
		}
		value.MediaPartitions = append(value.MediaPartitions, stablecampaign.MediaPartitionBinding{
			Role: stablecampaign.MediaPartitionRole(artifact.Role), Digest: whole, SizeBytes: partition.CapacityBytes,
		})
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return Expectation{}, err
	}
	value.ExpectationDigest = domainDigest("kaiba.provisioning.rpi5-campaign-qualification-expectation.v1alpha1", encoded)
	// Deep-copy the plan so later caller mutations cannot alter a sealed expectation.
	planBytes, err := input.Plan.CanonicalJSON()
	if err != nil {
		return Expectation{}, err
	}
	plan, err := stablecampaign.ParsePlan(planBytes)
	if err != nil {
		return Expectation{}, err
	}
	return Expectation{value: value, plan: plan}, nil
}

func domainDigest(domain string, encoded []byte) bundle.Digest {
	return bundle.Sum(append([]byte(domain+"\x00"), encoded...))
}

func hashPayload(source stablecampaign.PublicArtifactSource, artifact campaignmedia.ArtifactSetEntry, capacity uint64) (bundle.Digest, error) {
	if source.ReaderAt == nil || (reflect.ValueOf(source.ReaderAt).Kind() == reflect.Pointer && reflect.ValueOf(source.ReaderAt).IsNil()) ||
		source.SizeBytes != artifact.SizeBytes || source.SizeBytes == 0 || source.SizeBytes > capacity || capacity > campaignmedia.PiLocalNVMeReleaseCapacityBytes {
		return "", errors.New("missing source, wrong measured size, or invalid capacity")
	}
	hash := sha256.New()
	buffer := make([]byte, 128*1024)
	for offset := uint64(0); offset < source.SizeBytes; {
		count := min(uint64(len(buffer)), source.SizeBytes-offset)
		n, err := source.ReaderAt.ReadAt(buffer[:int(count)], int64(offset))
		if n != int(count) || (err != nil && !errors.Is(err, io.EOF)) {
			return "", fmt.Errorf("incomplete payload read at %d", offset)
		}
		hash.Write(buffer[:int(count)])
		offset += count
	}
	if bundle.Digest("sha256:"+hex.EncodeToString(hash.Sum(nil))) != artifact.Digest {
		return "", errors.New("actual bytes differ from the materialized artifact")
	}
	clear(buffer)
	for remaining := capacity - source.SizeBytes; remaining > 0; {
		count := min(uint64(len(buffer)), remaining)
		hash.Write(buffer[:int(count)])
		remaining -= count
	}
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}
