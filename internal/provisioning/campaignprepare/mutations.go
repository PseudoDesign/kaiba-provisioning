// Package campaignprepare builds public campaign inputs without private keys,
// signing operations, media access, or claims of physical qualification.
package campaignprepare

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/eepromsigning"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stableverifier"
)

const (
	MutationMetadataMaxBytes   = 1024 * 1024
	MutationRootPublicMaxBytes = 16 * 1024
)

var mutationPrivateMarker = regexp.MustCompile(`-----BEGIN [A-Z0-9 -]{0,64}PRIVATE KEY-----`)

// MutationInputs contains only independently supplied public artifacts. Each
// manifest must have exactly one real RSA signature. RootPublicPEM is the
// caller's separately reviewed trust anchor, never inferred from the policy.
type MutationInputs struct {
	PolicyJSON              []byte
	RootPublicPEM           []byte
	PositiveManifestJSON    []byte
	ReplacementManifestJSON []byte
	RevokedManifestJSON     []byte
}

// BuildMutations returns exactly twenty canonical JSON files, including the
// .json suffix in each map key. It authenticates the policy and three supplied
// signatures, then checks every generated recipe through the campaign resolver.
// It verifies metadata signatures, not component bytes, source provenance,
// runtime compatibility, or approval to execute a campaign.
func BuildMutations(input MutationInputs) (map[string][]byte, error) {
	for _, item := range []struct {
		name    string
		data    []byte
		maximum int
	}{
		{"policy", input.PolicyJSON, MutationMetadataMaxBytes},
		{"root public key", input.RootPublicPEM, MutationRootPublicMaxBytes},
		{"positive manifest", input.PositiveManifestJSON, MutationMetadataMaxBytes},
		{"replacement manifest", input.ReplacementManifestJSON, MutationMetadataMaxBytes},
		{"revoked manifest", input.RevokedManifestJSON, MutationMetadataMaxBytes},
	} {
		if len(item.data) == 0 || len(item.data) > item.maximum {
			return nil, fmt.Errorf("%s size must be 1 through %d bytes", item.name, item.maximum)
		}
		if mutationPrivateMarker.Match(item.data) {
			return nil, fmt.Errorf("%s contains private-key material", item.name)
		}
	}
	policy, err := stableverifier.ParsePolicy(input.PolicyJSON)
	if err != nil {
		return nil, err
	}
	if policy.ReleaseSignatureThreshold != 1 {
		return nil, errors.New("campaign mutation preparation requires release_signature_threshold 1")
	}
	keys, err := verifyMutationPolicy(policy, input.RootPublicPEM)
	if err != nil {
		return nil, err
	}
	positive, err := parseAndVerifyMutationManifest(input.PositiveManifestJSON, policy, keys, "active")
	if err != nil {
		return nil, fmt.Errorf("positive manifest: %w", err)
	}
	replacement, err := parseAndVerifyMutationManifest(input.ReplacementManifestJSON, policy, keys, "active")
	if err != nil {
		return nil, fmt.Errorf("replacement manifest: %w", err)
	}
	revoked, err := parseAndVerifyMutationManifest(input.RevokedManifestJSON, policy, keys, "revoked")
	if err != nil {
		return nil, fmt.Errorf("revoked manifest: %w", err)
	}
	primaryID, replacementID, revokedID := positive.Signatures[0].KeyID, replacement.Signatures[0].KeyID, revoked.Signatures[0].KeyID
	if primaryID == replacementID || primaryID == revokedID || replacementID == revokedID {
		return nil, errors.New("primary, replacement and revoked manifests must use distinct delegated keys")
	}
	if len(positive.Overlays) == 0 {
		return nil, errors.New("full campaign mutations require at least one real manifest overlay")
	}
	positivePreimage, err := positive.SigningPreimage()
	if err != nil {
		return nil, err
	}
	for _, manifest := range []stableverifier.Manifest{replacement, revoked} {
		preimage, err := manifest.SigningPreimage()
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(preimage, positivePreimage) {
			return nil, errors.New("replacement and revoked manifests must preserve the exact positive signing preimage")
		}
	}
	outputs := make(map[string][]byte, 20)
	before := stablecampaign.ArtifactBinding{Name: "positive-release-manifest", Digest: bundle.Sum(input.PositiveManifestJSON), SizeBytes: uint64(len(input.PositiveManifestJSON))}
	add := func(testID, subcase string, manifest stableverifier.Manifest) error {
		// Negative mutations may intentionally violate a semantic field. The
		// campaign resolver validates this fixed struct's canonical structure.
		encoded, err := json.Marshal(manifest)
		if err != nil {
			return err
		}
		name := ""
		switch testID {
		case "manifest-field-mutations-rejected":
			name = "manifest-field-" + subcase
		case "delegated-key-replacement-boots":
			name = "replacement-release-manifest"
		case "revoked-delegated-key-rejected":
			name = "revoked-release-manifest"
		case "unsigned-release-rejected":
			name = "unsigned-release-manifest"
		case "wrong-delegated-key-rejected":
			name = "wrong-key-release-manifest"
		default:
			return errors.New("unexpected fixed mutation case")
		}
		after := stablecampaign.ArtifactBinding{Name: name, Digest: bundle.Sum(encoded), SizeBytes: uint64(len(encoded))}
		recipe, err := stablecampaign.NewBoundReplacementMutationRecipe(testID, subcase, before, after)
		if err != nil {
			return err
		}
		if err := stablecampaign.ValidateBoundReplacement(recipe, input.PositiveManifestJSON, encoded); err != nil {
			return err
		}
		if testID != "delegated-key-replacement-boots" {
			if _, err := parseAndVerifyMutationManifest(encoded, policy, keys, "active"); err == nil {
				return fmt.Errorf("negative mutation %s unexpectedly verifies", name)
			}
		}
		for existing, contents := range outputs {
			if bytes.Equal(contents, encoded) {
				return fmt.Errorf("mutation %s duplicates %s", name, existing)
			}
		}
		outputs[name+".json"] = encoded
		return nil
	}
	if err := add("delegated-key-replacement-boots", "replacement-manifest", replacement); err != nil {
		return nil, err
	}
	if err := add("revoked-delegated-key-rejected", "revoked-manifest", revoked); err != nil {
		return nil, err
	}
	unsigned := cloneMutationManifest(positive)
	unsigned.Signatures = []stableverifier.RSASignature{}
	if err := add("unsigned-release-rejected", "unsigned-manifest", unsigned); err != nil {
		return nil, err
	}
	wrongKey := cloneMutationManifest(positive)
	wrongKey.Signatures[0].Value = replacement.Signatures[0].Value
	if err := add("wrong-delegated-key-rejected", "wrong-key-manifest", wrongKey); err != nil {
		return nil, err
	}
	for _, testCase := range stablecampaign.FixedCases() {
		if testCase.TestID != "manifest-field-mutations-rejected" {
			continue
		}
		for _, subcase := range testCase.Subcases {
			mutated := cloneMutationManifest(positive)
			if err := mutateManifestField(&mutated, subcase, replacementID, replacement.Signatures[0].Value); err != nil {
				return nil, err
			}
			if err := add(testCase.TestID, subcase, mutated); err != nil {
				return nil, err
			}
		}
	}
	if len(outputs) != 20 {
		return nil, errors.New("fixed campaign mutation inventory is not twenty files")
	}
	return outputs, nil
}

type mutationDelegatedKey struct {
	public *rsa.PublicKey
	status string
}

func verifyMutationPolicy(policy stableverifier.Policy, rootPEM []byte) (map[string]mutationDelegatedKey, error) {
	root, fingerprint, _, err := eepromsigning.ParsePublicKey(rootPEM)
	if err != nil {
		return nil, err
	}
	if fingerprint != policy.RootKeyFingerprint {
		return nil, errors.New("policy does not bind the separately supplied root public key")
	}
	preimage, err := policy.SigningPreimage()
	if err != nil {
		return nil, err
	}
	signature, err := base64.StdEncoding.DecodeString(policy.RootSignature.Value)
	if err != nil {
		return nil, err
	}
	if err := eepromsigning.VerifySignature(root, preimage, signature); err != nil {
		return nil, fmt.Errorf("policy root signature: %w", err)
	}
	keys := make(map[string]mutationDelegatedKey, len(policy.DelegatedKeys))
	for _, key := range policy.DelegatedKeys {
		public, fingerprint, _, err := eepromsigning.ParsePublicKey([]byte(key.PublicKeyPEM))
		if err != nil {
			return nil, err
		}
		if fingerprint != key.PublicKeyFingerprint {
			return nil, fmt.Errorf("delegated key %s fingerprint does not match public bytes", key.KeyID)
		}
		keys[key.KeyID] = mutationDelegatedKey{public: public, status: key.Status}
	}
	return keys, nil
}

func parseAndVerifyMutationManifest(encoded []byte, policy stableverifier.Policy, keys map[string]mutationDelegatedKey, status string) (stableverifier.Manifest, error) {
	manifest, err := stableverifier.ParseManifest(encoded)
	if err != nil {
		return stableverifier.Manifest{}, err
	}
	if len(manifest.Signatures) != 1 {
		return stableverifier.Manifest{}, errors.New("manifest must contain exactly one delegated signature")
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		return stableverifier.Manifest{}, err
	}
	if manifest.PolicyDigest != policyDigest || manifest.CohortID != policy.CohortID || manifest.DeviceClass != policy.DeviceClass || manifest.SecurityEpoch != policy.SecurityEpoch {
		return stableverifier.Manifest{}, errors.New("manifest target, epoch or policy digest does not match the signed policy")
	}
	allowedSlot := false
	for _, slot := range policy.AllowedSlotIDs {
		if manifest.SlotID == slot {
			allowedSlot = true
		}
	}
	if !allowedSlot {
		return stableverifier.Manifest{}, errors.New("manifest slot is not allowed by policy")
	}
	signed := manifest.Signatures[0]
	key, exists := keys[signed.KeyID]
	if !exists || key.status != status {
		return stableverifier.Manifest{}, fmt.Errorf("signature must identify a known %s delegated key", status)
	}
	preimage, err := manifest.SigningPreimage()
	if err != nil {
		return stableverifier.Manifest{}, err
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Value)
	if err != nil {
		return stableverifier.Manifest{}, err
	}
	if err := eepromsigning.VerifySignature(key.public, preimage, signature); err != nil {
		return stableverifier.Manifest{}, fmt.Errorf("delegated signature %s: %w", signed.KeyID, err)
	}
	return manifest, nil
}

func cloneMutationManifest(value stableverifier.Manifest) stableverifier.Manifest {
	value.Components = append([]stableverifier.Component(nil), value.Components...)
	if value.Overlays != nil {
		value.Overlays = append([]stableverifier.Overlay{}, value.Overlays...)
	}
	value.Signatures = append([]stableverifier.RSASignature(nil), value.Signatures...)
	return value
}

func distinctMutationString(value string) string {
	if value == "campaign-mutation" {
		return "campaign-mutation-alternate"
	}
	return "campaign-mutation"
}
func distinctMutationUint(value uint64) uint64 {
	if value == math.MaxUint64 {
		return value - 1
	}
	return value + 1
}
func distinctMutationDigest(value bundle.Digest) bundle.Digest {
	changed := []byte(value)
	if changed[7] == '0' {
		changed[7] = '1'
	} else {
		changed[7] = '0'
	}
	return bundle.Digest(changed)
}

func mutateManifestField(manifest *stableverifier.Manifest, subcase, replacementID, replacementSignature string) error {
	switch subcase {
	case "schema-version":
		manifest.SchemaVersion = "kaiba.provisioning.rpi5-delegated-release-manifest/v1alpha0"
	case "release-id":
		manifest.ReleaseID = distinctMutationString(manifest.ReleaseID)
	case "device-class":
		manifest.DeviceClass = "raspberry-pi-4-model-b-v1alpha1"
	case "cohort-id":
		manifest.CohortID = distinctMutationString(manifest.CohortID)
	case "policy-digest":
		manifest.PolicyDigest = distinctMutationDigest(manifest.PolicyDigest)
	case "security-epoch":
		manifest.SecurityEpoch = distinctMutationUint(manifest.SecurityEpoch)
	case "slot-id":
		manifest.SlotID = distinctMutationString(manifest.SlotID)
	case "component-role":
		manifest.Components[0].Role = "unknown_component"
	case "component-digest":
		manifest.Components[0].Digest = distinctMutationDigest(manifest.Components[0].Digest)
	case "component-size-bytes":
		manifest.Components[0].SizeBytes = distinctMutationUint(manifest.Components[0].SizeBytes)
	case "overlay-name":
		for index := 0; index <= len(manifest.Overlays); index++ {
			candidate := fmt.Sprintf("campaign-mutation-%d", index)
			exists := false
			for _, overlay := range manifest.Overlays {
				if overlay.Name == candidate {
					exists = true
				}
			}
			if !exists {
				manifest.Overlays[0].Name = candidate
				break
			}
		}
	case "overlay-digest":
		manifest.Overlays[0].Digest = distinctMutationDigest(manifest.Overlays[0].Digest)
	case "overlay-size-bytes":
		manifest.Overlays[0].SizeBytes = distinctMutationUint(manifest.Overlays[0].SizeBytes)
	case "signature-key-id":
		manifest.Signatures[0].KeyID = replacementID
	case "signature-algorithm":
		manifest.Signatures[0].Algorithm = "rsa-2048-sha512-pkcs1v15"
	case "signature-value":
		signature, err := base64.StdEncoding.DecodeString(manifest.Signatures[0].Value)
		if err != nil {
			return err
		}
		signature[0] ^= 1
		candidate := base64.StdEncoding.EncodeToString(signature)
		if candidate == replacementSignature {
			signature[0] ^= 3
			candidate = base64.StdEncoding.EncodeToString(signature)
		}
		manifest.Signatures[0].Value = candidate
	default:
		return fmt.Errorf("unsupported fixed manifest mutation %q", subcase)
	}
	return nil
}
