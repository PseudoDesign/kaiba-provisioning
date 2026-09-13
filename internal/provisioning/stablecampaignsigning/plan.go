package stablecampaignsigning

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signedboot"
)

// ValidateIntentForPlan implements signedboot.IntentValidator for the stable
// one-artifact intent. It returns the canonical JSON without a transport LF.
func ValidateIntentForPlan(encoded []byte, plan signedboot.Plan) ([]byte, error) {
	payload, err := canonicalPayload(encoded, MaxIntentBytes, "stable signing intent")
	if err != nil {
		return nil, err
	}
	intent, err := ParseIntent(payload)
	if err != nil {
		return nil, err
	}
	canonical, err := intent.CanonicalJSON()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(payload, canonical) {
		return nil, errors.New("release-intent.json is not the canonical stable signing intent")
	}
	intentDigest, err := intent.Digest()
	if err != nil {
		return nil, err
	}
	if plan.ReleaseIntentDigest != intentDigest {
		return nil, errors.New("stable signing intent digest does not match the signing plan")
	}
	if intent.SigningInput.Digest != plan.BootImageDigest || intent.SigningInput.SizeBytes != plan.BootImageSizeBytes {
		return nil, errors.New("stable signing intent boot input does not match the signing plan")
	}
	if intent.PublicKeyFingerprint != plan.PublicKeyFingerprint {
		return nil, errors.New("stable signing intent public key does not match the signing plan")
	}
	if intent.SignerPolicyDigest != plan.SignerPolicyDigest {
		return nil, errors.New("stable signing intent signer policy does not match the signing plan")
	}
	if intent.SourceDateEpoch != plan.SourceDateEpoch {
		return nil, errors.New("stable signing intent timestamp does not match the signing plan")
	}
	return canonical, nil
}

// LoadPlanDirectory applies the stable intent validator while retaining every
// filesystem and cryptographic binding enforced by signedboot.
func LoadPlanDirectory(path string) (signedboot.LoadedPlan, error) {
	loaded, err := signedboot.LoadPlanDirectoryWithIntentValidator(path, ValidateIntentForPlan)
	if err != nil {
		return signedboot.LoadedPlan{}, fmt.Errorf("load stable signing plan: %w", err)
	}
	return loaded, nil
}
