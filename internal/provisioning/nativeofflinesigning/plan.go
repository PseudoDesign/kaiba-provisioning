package nativeofflinesigning

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signedboot"
)

// ValidateIntentForPlan implements signedboot.IntentValidator for the stable
// one-artifact intent. It returns the canonical JSON without a transport LF.
func ValidateIntentForPlan(encoded []byte, plan signedboot.Plan) ([]byte, error) {
	payload, err := canonicalPayload(encoded, MaxIntentBytes, "offline signing intent")
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
		return nil, errors.New("release-intent.json is not the canonical offline signing intent")
	}
	intentDigest, err := intent.Digest()
	if err != nil {
		return nil, err
	}
	if plan.ReleaseIntentDigest != intentDigest {
		return nil, errors.New("offline signing intent digest does not match the signing plan")
	}
	if intent.SigningInput.Digest != plan.BootImageDigest || intent.SigningInput.SizeBytes != plan.BootImageSizeBytes {
		return nil, errors.New("offline signing intent boot input does not match the signing plan")
	}
	if intent.PublicKeyFingerprint != plan.PublicKeyFingerprint {
		return nil, errors.New("offline signing intent public key does not match the signing plan")
	}
	if intent.SignerPolicyDigest != plan.SignerPolicyDigest {
		return nil, errors.New("offline signing intent signer policy does not match the signing plan")
	}
	if intent.SourceDateEpoch != plan.SourceDateEpoch {
		return nil, errors.New("offline signing intent timestamp does not match the signing plan")
	}
	return canonical, nil
}

// LoadPlanDirectory applies the stable intent validator while retaining every
// filesystem and cryptographic binding enforced by signedboot. The four-file
// plan binds the unsigned manifest digest; construction and campaign consumption
// separately validate the actual manifest with ValidateUnsignedManifest.
func LoadPlanDirectory(path string) (signedboot.LoadedPlan, error) {
	loaded, err := signedboot.LoadPlanDirectoryWithIntentValidator(path, ValidateIntentForPlan)
	if err != nil {
		return signedboot.LoadedPlan{}, fmt.Errorf("load offline signing plan: %w", err)
	}
	intent, err := ParseIntent(loaded.ReleaseIntentJSON)
	if err != nil {
		return signedboot.LoadedPlan{}, err
	}
	if bundle.Sum(loaded.PublicPEM) != intent.PublicKeyFileDigest {
		return signedboot.LoadedPlan{}, errors.New("public.pem digest does not match the offline signing intent")
	}
	return loaded, nil
}
