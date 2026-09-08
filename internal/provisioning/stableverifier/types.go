// Package stableverifier verifies the complete delegated release closure used
// by the Raspberry Pi 5 stable-verifier development spike. It deliberately
// contains no authorization or handoff implementation: callers must authorize
// the returned manifest digest before consuming the retained component handles.
package stableverifier

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	PolicySchemaV1Alpha1   = "kaiba.provisioning.rpi5-stable-verifier-policy/v1alpha1"
	ManifestSchemaV1Alpha1 = "kaiba.provisioning.rpi5-delegated-release-manifest/v1alpha1"
	DeviceClass            = "raspberry-pi-5-model-b-v1alpha1"

	RSA2048SHA256Algorithm = "rsa-2048-sha256-pkcs1v15"
	Ed25519Algorithm       = "ed25519"

	policySigningDomain   = "kaiba.provisioning.rpi5-stable-verifier-policy-signature.v1alpha1"
	policyDigestDomain    = "kaiba.provisioning.rpi5-stable-verifier-policy.v1alpha1"
	manifestSigningDomain = "kaiba.provisioning.rpi5-delegated-release-manifest-signature.v1alpha1"
	manifestDigestDomain  = "kaiba.provisioning.rpi5-delegated-release-manifest.v1alpha1"

	maxMetadataBytes  = 1024 * 1024
	maxPublicKeyBytes = 16 * 1024
)

// ComponentRole is one mandatory, uniquely named boot input. The declaration
// order is the canonical manifest and on-disk verification order.
type ComponentRole string

const (
	RoleKernel             ComponentRole = "kernel"
	RoleInitramfs          ComponentRole = "initramfs"
	RoleResolvedDeviceTree ComponentRole = "resolved_device_tree"
	RoleKernelCommandLine  ComponentRole = "kernel_command_line"
	RoleRootImage          ComponentRole = "root_image"
	RoleDMVerityMetadata   ComponentRole = "dm_verity_metadata"
	RoleSlotMetadata       ComponentRole = "slot_metadata"
)

var componentRoles = []ComponentRole{
	RoleKernel,
	RoleInitramfs,
	RoleResolvedDeviceTree,
	RoleKernelCommandLine,
	RoleRootImage,
	RoleDMVerityMetadata,
	RoleSlotMetadata,
}

var componentPaths = map[ComponentRole]string{
	RoleKernel:             "kernel",
	RoleInitramfs:          "initramfs",
	RoleResolvedDeviceTree: "device-tree.dtb",
	RoleKernelCommandLine:  "cmdline.txt",
	RoleRootImage:          "root.img",
	RoleDMVerityMetadata:   "dm-verity.json",
	RoleSlotMetadata:       "slot.txt",
}

var componentMaximums = map[ComponentRole]uint64{
	RoleKernel:             256 * 1024 * 1024,
	RoleInitramfs:          512 * 1024 * 1024,
	RoleResolvedDeviceTree: 8 * 1024 * 1024,
	RoleKernelCommandLine:  4096,
	RoleRootImage:          64 * 1024 * 1024 * 1024,
	RoleDMVerityMetadata:   1024 * 1024,
	RoleSlotMetadata:       4096,
}

// ComponentRoles returns the fixed canonical component order.
func ComponentRoles() []ComponentRole {
	return append([]ComponentRole(nil), componentRoles...)
}

// ComponentPath returns the fixed path below a delegated release directory.
func ComponentPath(role ComponentRole) (string, bool) {
	path, ok := componentPaths[role]
	return path, ok
}

// RSASignature is a canonical base64 encoding of a raw RSA-2048 signature.
type RSASignature struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// DelegatedKey describes one release-signing key and its current status.
type DelegatedKey struct {
	KeyID                string        `json:"key_id"`
	Algorithm            string        `json:"algorithm"`
	PublicKeyPEM         string        `json:"public_key_pem"`
	PublicKeyFingerprint bundle.Digest `json:"public_key_fingerprint"`
	Status               string        `json:"status"`
}

// AuthorizationAuthority is an application-signing key trusted by the
// subsequent fresh-authorization stage. The verifier core validates and
// preserves this policy but does not perform the network exchange.
type AuthorizationAuthority struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

// Policy is the root-signed delegated-key and boot-authorization policy.
type Policy struct {
	SchemaVersion             string                   `json:"schema_version"`
	PolicyID                  string                   `json:"policy_id"`
	DeviceClass               string                   `json:"device_class"`
	CohortID                  string                   `json:"cohort_id"`
	SecurityEpoch             uint64                   `json:"security_epoch"`
	MinimumVerifierVersion    uint64                   `json:"minimum_verifier_version"`
	ReleaseSignatureThreshold uint32                   `json:"release_signature_threshold"`
	AllowedSlotIDs            []string                 `json:"allowed_slot_ids"`
	RootKeyID                 string                   `json:"root_key_id"`
	RootKeyFingerprint        bundle.Digest            `json:"root_key_fingerprint"`
	DelegatedKeys             []DelegatedKey           `json:"delegated_keys"`
	AuthorizationAuthorities  []AuthorizationAuthority `json:"authorization_authorities"`
	RootSignature             RSASignature             `json:"root_signature"`
}

type unsignedPolicy struct {
	SchemaVersion             string                   `json:"schema_version"`
	PolicyID                  string                   `json:"policy_id"`
	DeviceClass               string                   `json:"device_class"`
	CohortID                  string                   `json:"cohort_id"`
	SecurityEpoch             uint64                   `json:"security_epoch"`
	MinimumVerifierVersion    uint64                   `json:"minimum_verifier_version"`
	ReleaseSignatureThreshold uint32                   `json:"release_signature_threshold"`
	AllowedSlotIDs            []string                 `json:"allowed_slot_ids"`
	RootKeyID                 string                   `json:"root_key_id"`
	RootKeyFingerprint        bundle.Digest            `json:"root_key_fingerprint"`
	DelegatedKeys             []DelegatedKey           `json:"delegated_keys"`
	AuthorizationAuthorities  []AuthorizationAuthority `json:"authorization_authorities"`
}

func (policy Policy) unsigned() unsignedPolicy {
	return unsignedPolicy{
		SchemaVersion: policy.SchemaVersion, PolicyID: policy.PolicyID,
		DeviceClass: policy.DeviceClass, CohortID: policy.CohortID,
		SecurityEpoch: policy.SecurityEpoch, MinimumVerifierVersion: policy.MinimumVerifierVersion,
		ReleaseSignatureThreshold: policy.ReleaseSignatureThreshold,
		AllowedSlotIDs:            policy.AllowedSlotIDs,
		RootKeyID:                 policy.RootKeyID, RootKeyFingerprint: policy.RootKeyFingerprint,
		DelegatedKeys: policy.DelegatedKeys, AuthorizationAuthorities: policy.AuthorizationAuthorities,
	}
}

// Component binds one fixed release role to its complete contents.
type Component struct {
	Role      ComponentRole `json:"role"`
	Digest    bundle.Digest `json:"digest"`
	SizeBytes uint64        `json:"size_bytes"`
}

// Overlay binds one ordered device-tree overlay. Name maps to
// overlays/<name>.dtbo and cannot contain a path separator or extension.
type Overlay struct {
	Name      string        `json:"name"`
	Digest    bundle.Digest `json:"digest"`
	SizeBytes uint64        `json:"size_bytes"`
}

// Manifest authenticates the exact delegated release closure.
type Manifest struct {
	SchemaVersion string         `json:"schema_version"`
	ReleaseID     string         `json:"release_id"`
	DeviceClass   string         `json:"device_class"`
	CohortID      string         `json:"cohort_id"`
	PolicyDigest  bundle.Digest  `json:"policy_digest"`
	SecurityEpoch uint64         `json:"security_epoch"`
	SlotID        string         `json:"slot_id"`
	Components    []Component    `json:"components"`
	Overlays      []Overlay      `json:"overlays"`
	Signatures    []RSASignature `json:"signatures"`
}

type unsignedManifest struct {
	SchemaVersion string        `json:"schema_version"`
	ReleaseID     string        `json:"release_id"`
	DeviceClass   string        `json:"device_class"`
	CohortID      string        `json:"cohort_id"`
	PolicyDigest  bundle.Digest `json:"policy_digest"`
	SecurityEpoch uint64        `json:"security_epoch"`
	SlotID        string        `json:"slot_id"`
	Components    []Component   `json:"components"`
	Overlays      []Overlay     `json:"overlays"`
}

func (manifest Manifest) unsigned() unsignedManifest {
	return unsignedManifest{
		SchemaVersion: manifest.SchemaVersion, ReleaseID: manifest.ReleaseID,
		DeviceClass: manifest.DeviceClass, CohortID: manifest.CohortID,
		PolicyDigest: manifest.PolicyDigest, SecurityEpoch: manifest.SecurityEpoch,
		SlotID: manifest.SlotID, Components: manifest.Components, Overlays: manifest.Overlays,
	}
}

func (signature RSASignature) validate() error {
	if err := validateIdentifier("signature key_id", signature.KeyID); err != nil {
		return err
	}
	if signature.Algorithm != RSA2048SHA256Algorithm {
		return fmt.Errorf("signature algorithm %q is unsupported", signature.Algorithm)
	}
	decoded, err := base64.StdEncoding.DecodeString(signature.Value)
	if err != nil || len(decoded) != 256 || base64.StdEncoding.EncodeToString(decoded) != signature.Value {
		return errors.New("signature must be the canonical base64 encoding of exactly 256 bytes")
	}
	return nil
}

func (policy Policy) validate() error {
	if err := policy.validateUnsigned(); err != nil {
		return err
	}
	if policy.RootSignature.KeyID != policy.RootKeyID {
		return errors.New("root signature key_id does not match root_key_id")
	}
	if err := policy.RootSignature.validate(); err != nil {
		return fmt.Errorf("root_signature: %w", err)
	}
	return nil
}

func (policy Policy) validateUnsigned() error {
	if policy.SchemaVersion != PolicySchemaV1Alpha1 {
		return fmt.Errorf("unsupported policy schema_version %q", policy.SchemaVersion)
	}
	if err := validateIdentifier("policy_id", policy.PolicyID); err != nil {
		return err
	}
	if policy.DeviceClass != DeviceClass {
		return fmt.Errorf("unsupported policy device_class %q", policy.DeviceClass)
	}
	if err := validateIdentifier("cohort_id", policy.CohortID); err != nil {
		return err
	}
	if policy.SecurityEpoch == 0 || policy.MinimumVerifierVersion == 0 {
		return errors.New("policy security_epoch and minimum_verifier_version must be positive")
	}
	if err := validateIdentifier("root_key_id", policy.RootKeyID); err != nil {
		return err
	}
	if err := policy.RootKeyFingerprint.Validate(); err != nil {
		return fmt.Errorf("root_key_fingerprint: %w", err)
	}
	if len(policy.DelegatedKeys) == 0 || len(policy.DelegatedKeys) > 16 {
		return errors.New("policy must contain between 1 and 16 delegated keys")
	}
	active := uint32(0)
	previous := ""
	keyFingerprints := make(map[bundle.Digest]struct{}, len(policy.DelegatedKeys))
	for _, key := range policy.DelegatedKeys {
		if err := validateIdentifier("delegated key_id", key.KeyID); err != nil {
			return err
		}
		if previous != "" && key.KeyID <= previous {
			return errors.New("delegated keys must be strictly sorted by key_id")
		}
		previous = key.KeyID
		if key.Algorithm != RSA2048SHA256Algorithm {
			return fmt.Errorf("delegated key %q uses unsupported algorithm %q", key.KeyID, key.Algorithm)
		}
		if len(key.PublicKeyPEM) == 0 || len(key.PublicKeyPEM) > maxPublicKeyBytes {
			return fmt.Errorf("delegated key %q public key has an invalid size", key.KeyID)
		}
		if err := key.PublicKeyFingerprint.Validate(); err != nil {
			return fmt.Errorf("delegated key %q public_key_fingerprint: %w", key.KeyID, err)
		}
		if _, exists := keyFingerprints[key.PublicKeyFingerprint]; exists {
			return errors.New("delegated keys must use distinct public keys")
		}
		keyFingerprints[key.PublicKeyFingerprint] = struct{}{}
		switch key.Status {
		case "active":
			active++
		case "revoked":
		default:
			return fmt.Errorf("delegated key %q has unsupported status %q", key.KeyID, key.Status)
		}
	}
	if policy.ReleaseSignatureThreshold == 0 || policy.ReleaseSignatureThreshold > 16 || policy.ReleaseSignatureThreshold > active {
		return errors.New("release_signature_threshold exceeds the number of active delegated keys")
	}
	if len(policy.AllowedSlotIDs) == 0 || len(policy.AllowedSlotIDs) > 8 {
		return errors.New("policy must contain between 1 and 8 allowed slot identifiers")
	}
	previous = ""
	for _, slotID := range policy.AllowedSlotIDs {
		if err := validateIdentifier("allowed slot identifier", slotID); err != nil {
			return err
		}
		if previous != "" && slotID <= previous {
			return errors.New("allowed slot identifiers must be strictly sorted")
		}
		previous = slotID
	}
	if len(policy.AuthorizationAuthorities) == 0 || len(policy.AuthorizationAuthorities) > 8 {
		return errors.New("policy must contain between 1 and 8 authorization authorities")
	}
	previous = ""
	authorityKeys := make(map[string]struct{}, len(policy.AuthorizationAuthorities))
	for _, authority := range policy.AuthorizationAuthorities {
		if err := validateIdentifier("authorization authority key_id", authority.KeyID); err != nil {
			return err
		}
		if previous != "" && authority.KeyID <= previous {
			return errors.New("authorization authorities must be strictly sorted by key_id")
		}
		previous = authority.KeyID
		if authority.Algorithm != Ed25519Algorithm {
			return fmt.Errorf("authorization authority %q uses unsupported algorithm %q", authority.KeyID, authority.Algorithm)
		}
		if len(authority.PublicKey) != len("ed25519:")+64 || !strings.HasPrefix(authority.PublicKey, "ed25519:") {
			return fmt.Errorf("authorization authority %q public key is not canonical Ed25519", authority.KeyID)
		}
		decoded, err := hex.DecodeString(strings.TrimPrefix(authority.PublicKey, "ed25519:"))
		if err != nil || len(decoded) != 32 || "ed25519:"+hex.EncodeToString(decoded) != authority.PublicKey {
			return fmt.Errorf("authorization authority %q public key is not canonical Ed25519", authority.KeyID)
		}
		if _, exists := authorityKeys[authority.PublicKey]; exists {
			return errors.New("authorization authorities must use distinct public keys")
		}
		authorityKeys[authority.PublicKey] = struct{}{}
	}
	return nil
}

func (manifest Manifest) validate() error {
	if err := manifest.validateUnsigned(); err != nil {
		return err
	}
	if len(manifest.Signatures) == 0 || len(manifest.Signatures) > 16 {
		return errors.New("manifest must contain between 1 and 16 signatures")
	}
	previous := ""
	for _, signature := range manifest.Signatures {
		if err := signature.validate(); err != nil {
			return err
		}
		if previous != "" && signature.KeyID <= previous {
			return errors.New("manifest signatures must be strictly sorted by key_id")
		}
		previous = signature.KeyID
	}
	return nil
}

func (manifest Manifest) validateUnsigned() error {
	if manifest.SchemaVersion != ManifestSchemaV1Alpha1 {
		return fmt.Errorf("unsupported manifest schema_version %q", manifest.SchemaVersion)
	}
	if err := validateIdentifier("release_id", manifest.ReleaseID); err != nil {
		return err
	}
	if manifest.DeviceClass != DeviceClass {
		return fmt.Errorf("unsupported manifest device_class %q", manifest.DeviceClass)
	}
	if err := validateIdentifier("cohort_id", manifest.CohortID); err != nil {
		return err
	}
	if err := manifest.PolicyDigest.Validate(); err != nil {
		return fmt.Errorf("policy_digest: %w", err)
	}
	if manifest.SecurityEpoch == 0 {
		return errors.New("manifest security_epoch must be positive")
	}
	if err := validateIdentifier("slot_id", manifest.SlotID); err != nil {
		return err
	}
	if len(manifest.Components) != len(componentRoles) {
		return fmt.Errorf("manifest must contain exactly %d fixed components", len(componentRoles))
	}
	for index, role := range componentRoles {
		component := manifest.Components[index]
		if component.Role != role {
			return fmt.Errorf("manifest component %d has role %q, want %q", index, component.Role, role)
		}
		if err := component.Digest.Validate(); err != nil {
			return fmt.Errorf("component %q digest: %w", role, err)
		}
		if component.SizeBytes == 0 || component.SizeBytes > componentMaximums[role] {
			return fmt.Errorf("component %q size must be between 1 and %d bytes", role, componentMaximums[role])
		}
	}
	if manifest.Overlays == nil {
		return errors.New("manifest overlays must be an array, not null")
	}
	if len(manifest.Overlays) > 64 {
		return errors.New("manifest contains more than 64 overlays")
	}
	seenOverlays := make(map[string]struct{}, len(manifest.Overlays))
	for _, overlay := range manifest.Overlays {
		if err := validateOverlayName(overlay.Name); err != nil {
			return err
		}
		if _, exists := seenOverlays[overlay.Name]; exists {
			return fmt.Errorf("overlay name %q is duplicated", overlay.Name)
		}
		seenOverlays[overlay.Name] = struct{}{}
		if err := overlay.Digest.Validate(); err != nil {
			return fmt.Errorf("overlay %q digest: %w", overlay.Name, err)
		}
		if overlay.SizeBytes == 0 || overlay.SizeBytes > 8*1024*1024 {
			return fmt.Errorf("overlay %q size must be between 1 and %d bytes", overlay.Name, 8*1024*1024)
		}
	}
	return nil
}

func validateIdentifier(label, value string) error {
	if len(value) == 0 || len(value) > 128 || !lowerAlphaNumeric(value[0]) {
		return fmt.Errorf("%s is not a canonical identifier", label)
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !lowerAlphaNumeric(character) && !strings.ContainsRune("._:-", rune(character)) {
			return fmt.Errorf("%s is not a canonical identifier", label)
		}
	}
	return nil
}

func validateOverlayName(value string) error {
	if len(value) == 0 || len(value) > 64 || !lowerAlphaNumeric(value[0]) {
		return errors.New("overlay name is not canonical")
	}
	for index := 1; index < len(value); index++ {
		if !lowerAlphaNumeric(value[index]) && value[index] != '_' && value[index] != '-' {
			return errors.New("overlay name is not canonical")
		}
	}
	return nil
}

func lowerAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}
