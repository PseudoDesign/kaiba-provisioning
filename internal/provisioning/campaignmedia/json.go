package campaignmedia

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

// DerivedDigest returns the domain-separated digest of the staging plan with
// plan_digest empty.
func (plan StagingPlan) DerivedDigest() (bundle.Digest, error) {
	material := plan
	material.PlanDigest = ""
	if err := material.validate(false); err != nil {
		return "", err
	}
	return digestJSON(stagingPlanDigestDomain, material, "staging plan")
}

// Seal returns a copy with its derived plan_digest populated.
func (plan StagingPlan) Seal() (StagingPlan, error) {
	digest, err := plan.DerivedDigest()
	if err != nil {
		return StagingPlan{}, err
	}
	plan.PlanDigest = digest
	if err := plan.Validate(); err != nil {
		return StagingPlan{}, err
	}
	return plan, nil
}

// CanonicalJSON returns the unique whitespace-free staging plan encoding.
func (plan StagingPlan) CanonicalJSON() ([]byte, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	return marshalWithinLimit("staging plan", plan)
}

// ParseStagingPlan accepts only strict canonical JSON, optionally followed by
// one LF.
func ParseStagingPlan(encoded []byte) (StagingPlan, error) {
	var plan StagingPlan
	if err := strictCanonicalDecode(encoded, &plan, func() ([]byte, error) { return plan.CanonicalJSON() }); err != nil {
		return StagingPlan{}, fmt.Errorf("parse staging plan: %w", err)
	}
	return plan, nil
}

// DerivedDigest returns the domain-separated digest of the backup manifest
// with backup_manifest_digest empty.
func (manifest BackupManifest) DerivedDigest() (bundle.Digest, error) {
	material := manifest
	material.BackupManifestDigest = ""
	if err := material.validate(false); err != nil {
		return "", err
	}
	return digestJSON(backupManifestDigestDomain, material, "backup manifest")
}

// Seal returns a copy with its derived backup_manifest_digest populated.
func (manifest BackupManifest) Seal() (BackupManifest, error) {
	digest, err := manifest.DerivedDigest()
	if err != nil {
		return BackupManifest{}, err
	}
	manifest.BackupManifestDigest = digest
	if err := manifest.Validate(); err != nil {
		return BackupManifest{}, err
	}
	return manifest, nil
}

// CanonicalJSON returns the unique whitespace-free backup manifest encoding.
func (manifest BackupManifest) CanonicalJSON() ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return marshalWithinLimit("backup manifest", manifest)
}

// ParseBackupManifest accepts only strict canonical JSON, optionally followed
// by one LF. Call ValidateAgainst to bind it to the independently supplied
// staging plan.
func ParseBackupManifest(encoded []byte) (BackupManifest, error) {
	var manifest BackupManifest
	if err := strictCanonicalDecode(encoded, &manifest, func() ([]byte, error) { return manifest.CanonicalJSON() }); err != nil {
		return BackupManifest{}, fmt.Errorf("parse backup manifest: %w", err)
	}
	return manifest, nil
}

// DerivedDigest returns the domain-separated digest of the rollback plan with
// rollback_plan_digest empty.
func (rollback RollbackPlan) DerivedDigest() (bundle.Digest, error) {
	material := rollback
	material.RollbackPlanDigest = ""
	if err := material.validate(false); err != nil {
		return "", err
	}
	return digestJSON(rollbackPlanDigestDomain, material, "rollback plan")
}

// Seal returns a copy with its derived rollback_plan_digest populated.
func (rollback RollbackPlan) Seal() (RollbackPlan, error) {
	digest, err := rollback.DerivedDigest()
	if err != nil {
		return RollbackPlan{}, err
	}
	rollback.RollbackPlanDigest = digest
	if err := rollback.Validate(); err != nil {
		return RollbackPlan{}, err
	}
	return rollback, nil
}

// CanonicalJSON returns the unique whitespace-free rollback encoding.
func (rollback RollbackPlan) CanonicalJSON() ([]byte, error) {
	if err := rollback.Validate(); err != nil {
		return nil, err
	}
	return marshalWithinLimit("rollback plan", rollback)
}

// ParseRollbackPlan accepts only strict canonical JSON, optionally followed by
// one LF. Call ValidateAgainst to bind it to the staging and backup contracts.
func ParseRollbackPlan(encoded []byte) (RollbackPlan, error) {
	var rollback RollbackPlan
	if err := strictCanonicalDecode(encoded, &rollback, func() ([]byte, error) { return rollback.CanonicalJSON() }); err != nil {
		return RollbackPlan{}, fmt.Errorf("parse rollback plan: %w", err)
	}
	return rollback, nil
}

type artifactSetDigestMaterial struct {
	Artifacts              []ArtifactSetEntry            `json:"artifacts"`
	CampaignID             string                        `json:"campaign_id"`
	CampaignPlanResolution CampaignPlanResolution        `json:"campaign_plan_resolution"`
	Capabilities           ArtifactSetCapabilities       `json:"capabilities"`
	PhysicalLayoutBound    bool                          `json:"physical_layout_bound"`
	PlanDigest             bundle.Digest                 `json:"plan_digest"`
	Provenance             ArtifactSetProvenance         `json:"provenance"`
	RecipeID               *string                       `json:"recipe_id"`
	RunID                  string                        `json:"run_id"`
	SchemaVersion          string                        `json:"schema_version"`
	SemanticResolution     ArtifactSetSemanticResolution `json:"semantic_resolution"`
	StorageFormat          string                        `json:"storage_format"`
	Verity                 ArtifactSetVerity             `json:"verity"`
}

func (set ArtifactSet) digestMaterial() artifactSetDigestMaterial {
	return artifactSetDigestMaterial{
		Artifacts:              append([]ArtifactSetEntry(nil), set.Artifacts...),
		CampaignID:             set.CampaignID,
		CampaignPlanResolution: set.CampaignPlanResolution,
		Capabilities:           set.Capabilities,
		PhysicalLayoutBound:    set.PhysicalLayoutBound,
		PlanDigest:             set.PlanDigest,
		Provenance:             set.Provenance,
		RecipeID:               set.RecipeID,
		RunID:                  set.RunID,
		SchemaVersion:          set.SchemaVersion,
		SemanticResolution:     set.SemanticResolution,
		StorageFormat:          set.StorageFormat,
		Verity:                 set.Verity,
	}
}

// DerivedDigest returns the Nix-compatible, domain-separated artifact-set
// digest over compact lexicographically keyed JSON with
// artifact_set_content_digest absent.
func (set ArtifactSet) DerivedDigest() (bundle.Digest, error) {
	if err := set.validate(false); err != nil {
		return "", err
	}
	return digestJSON(artifactSetDigestDomain, set.digestMaterial(), "artifact set")
}

// CanonicalJSON returns the exact compact, lexicographically keyed encoding
// emitted by jq -cS in the Nix artifact builder.
func (set ArtifactSet) CanonicalJSON() ([]byte, error) {
	if err := set.Validate(); err != nil {
		return nil, err
	}
	return marshalWithinLimit("artifact set", set)
}

// ParseArtifactSet accepts only the Nix artifact-set canonical JSON, optionally
// followed by one LF. recipe_id is the sole field allowed to contain JSON null.
func ParseArtifactSet(encoded []byte) (ArtifactSet, error) {
	var set ArtifactSet
	allowedNulls := map[string]struct{}{"$.recipe_id": {}}
	if err := strictCanonicalDecodeWithNulls(encoded, &set, func() ([]byte, error) { return set.CanonicalJSON() }, allowedNulls); err != nil {
		return ArtifactSet{}, fmt.Errorf("parse artifact set: %w", err)
	}
	return set, nil
}

func digestJSON(domain string, value any, label string) (bundle.Digest, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode %s digest material: %w", label, err)
	}
	return domainDigest(domain, encoded), nil
}

func domainDigest(domain string, value []byte) bundle.Digest {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(value)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil)))
}

func marshalWithinLimit(label string, value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", label, err)
	}
	if len(encoded) > maximumContractBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", label, maximumContractBytes)
	}
	return encoded, nil
}

// strictCanonicalDecode rejects duplicate keys, unknown fields, nulls,
// trailing values, excessive nesting, and every non-canonical representation.
// A single terminal LF is the only transport decoration accepted.
func strictCanonicalDecode(encoded []byte, destination any, canonical func() ([]byte, error)) error {
	return strictCanonicalDecodeWithNulls(encoded, destination, canonical, nil)
}

func strictCanonicalDecodeWithNulls(encoded []byte, destination any, canonical func() ([]byte, error), allowedNulls map[string]struct{}) error {
	if len(encoded) == 0 || len(encoded) > maximumContractBytes {
		return fmt.Errorf("JSON contract size must be between 1 and %d bytes", maximumContractBytes)
	}
	if err := inspectJSON(encoded, allowedNulls); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON contract: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contract contains a trailing value")
		}
		return fmt.Errorf("decode trailing JSON contract: %w", err)
	}
	expected, err := canonical()
	if err != nil {
		return err
	}
	actual := encoded
	if bytes.HasSuffix(actual, []byte{'\n'}) {
		actual = actual[:len(actual)-1]
	}
	if !bytes.Equal(actual, expected) {
		return errors.New("JSON contract is not in canonical form")
	}
	return nil
}

func inspectJSON(encoded []byte, allowedNulls map[string]struct{}) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode JSON contract: %w", err)
	}
	if err := inspectJSONToken(decoder, token, "$", 0, allowedNulls); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON contract contains trailing data")
	}
	return nil
}

func inspectJSONToken(decoder *json.Decoder, token json.Token, location string, depth int, allowedNulls map[string]struct{}) error {
	if depth > maximumJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels at %s", maximumJSONDepth, location)
	}
	if token == nil {
		if _, allowed := allowedNulls[location]; allowed {
			return nil
		}
		return fmt.Errorf("JSON null is not allowed at %s", location)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON object at %s: %w", location, err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key at %s is not a string", location)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q at %s", key, location)
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON value at %s.%s: %w", location, key, err)
			}
			if err := inspectJSONToken(decoder, value, location+"."+key, depth+1, allowedNulls); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("decode JSON object end at %s", location)
		}
	case '[':
		for index := 0; decoder.More(); index++ {
			value, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON array at %s: %w", location, err)
			}
			if err := inspectJSONToken(decoder, value, fmt.Sprintf("%s[%d]", location, index), depth+1, allowedNulls); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("decode JSON array end at %s", location)
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delimiter, location)
	}
	return nil
}
