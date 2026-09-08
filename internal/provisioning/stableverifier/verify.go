package stableverifier

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/eepromsigning"
)

const (
	manifestFileName = "release-manifest.json"
	overlayDirectory = "overlays"
)

// Inputs names the independently supplied root of trust, signed policy, and
// delegated release. All paths must be clean absolute paths without symlinks.
type Inputs struct {
	RootPublicKeyPath string
	PolicyPath        string
	ReleaseDirectory  string
}

// Requirements contains values fixed by the running verifier and the selected
// boot target rather than values supplied by the delegated release.
type Requirements struct {
	VerifierVersion      uint64
	MinimumSecurityEpoch uint64
	CohortID             string
	SlotID               string
}

// VerifiedComponent is immutable metadata for one retained release input.
type VerifiedComponent struct {
	Role      ComponentRole
	Name      string
	Digest    bundle.Digest
	SizeBytes uint64
}

type retainedFile struct {
	metadata          VerifiedComponent
	file              *os.File
	identity          fileIdentity
	immutableSnapshot bool
}

// VerifiedRelease owns open handles to the exact files whose sizes and hashes
// were checked. It must be closed after authorization and handoff complete.
// Callers obtain duplicates of these handles; paths are never reopened.
type VerifiedRelease struct {
	mu             sync.Mutex
	closed         bool
	policy         Policy
	manifest       Manifest
	policyDigest   bundle.Digest
	manifestDigest bundle.Digest
	commandLine    string
	components     map[ComponentRole]retainedFile
	overlays       []VerifiedComponent
}

// VerifyRelease verifies root policy authority, delegated signatures, epoch,
// target bindings, exact directory contents, and all component bytes.
func VerifyRelease(ctx context.Context, inputs Inputs, requirements Requirements) (*VerifiedRelease, error) {
	if ctx == nil {
		return nil, errors.New("stable-verifier verification requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if requirements.VerifierVersion == 0 {
		return nil, errors.New("verifier version must be positive")
	}
	if err := validateIdentifier("required cohort_id", requirements.CohortID); err != nil {
		return nil, err
	}
	if err := validateIdentifier("required slot_id", requirements.SlotID); err != nil {
		return nil, err
	}

	rootPEM, err := readAbsoluteRegular(inputs.RootPublicKeyPath, maxPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("read root public key: %w", err)
	}
	rootKey, rootFingerprint, _, err := eepromsigning.ParsePublicKey(rootPEM)
	if err != nil {
		return nil, fmt.Errorf("parse root public key: %w", err)
	}
	policyBytes, err := readAbsoluteRegular(inputs.PolicyPath, maxMetadataBytes)
	if err != nil {
		return nil, fmt.Errorf("read stable-verifier policy: %w", err)
	}
	policy, err := ParsePolicy(policyBytes)
	if err != nil {
		return nil, err
	}
	delegatedKeys, err := verifyPolicy(policy, rootKey, rootFingerprint)
	if err != nil {
		return nil, err
	}
	if policy.MinimumVerifierVersion > requirements.VerifierVersion {
		return nil, fmt.Errorf("policy requires verifier version %d, running version is %d", policy.MinimumVerifierVersion, requirements.VerifierVersion)
	}
	if policy.SecurityEpoch < requirements.MinimumSecurityEpoch {
		return nil, fmt.Errorf("policy security epoch %d is below required floor %d", policy.SecurityEpoch, requirements.MinimumSecurityEpoch)
	}
	if policy.CohortID != requirements.CohortID {
		return nil, errors.New("policy cohort does not match the verifier configuration")
	}
	if !containsString(policy.AllowedSlotIDs, requirements.SlotID) {
		return nil, errors.New("required slot is not authorized by policy")
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		return nil, err
	}

	directory, directoryIdentity, err := openAbsolute(inputs.ReleaseDirectory, true)
	if err != nil {
		return nil, fmt.Errorf("open delegated release directory: %w", err)
	}
	defer directory.Close()
	rootNames := []string{manifestFileName, overlayDirectory}
	for _, role := range componentRoles {
		rootNames = append(rootNames, componentPaths[role])
	}
	if err := requireExactNames(directory, rootNames); err != nil {
		return nil, fmt.Errorf("delegated release directory: %w", err)
	}
	manifestBytes, err := readRegularAt(directory, manifestFileName, maxMetadataBytes)
	if err != nil {
		return nil, fmt.Errorf("read delegated release manifest: %w", err)
	}
	manifest, err := ParseManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	if manifest.PolicyDigest != policyDigest {
		return nil, errors.New("manifest policy_digest does not bind the verified policy")
	}
	if manifest.DeviceClass != policy.DeviceClass || manifest.CohortID != policy.CohortID {
		return nil, errors.New("manifest target does not match the verified policy")
	}
	if manifest.SecurityEpoch != policy.SecurityEpoch {
		return nil, errors.New("manifest security_epoch does not equal the verified policy epoch")
	}
	if manifest.SlotID != requirements.SlotID {
		return nil, errors.New("manifest slot does not match the verifier-selected slot")
	}
	if err := verifyManifestSignatures(manifest, policy, delegatedKeys); err != nil {
		return nil, err
	}

	retained := make(map[ComponentRole]retainedFile, len(componentRoles))
	overlays := make([]VerifiedComponent, 0, len(manifest.Overlays))
	closeRetained := func() {
		for _, source := range retained {
			_ = source.file.Close()
		}
	}
	for index, expected := range manifest.Components {
		if err := ctx.Err(); err != nil {
			closeRetained()
			return nil, err
		}
		path := componentPaths[expected.Role]
		// Freeze every component consumed after verification. Retaining the
		// original descriptor is sufficient for root.img because the signed
		// dm-verity metadata is the second-stage integrity boundary for that
		// potentially large object.
		snapshot := expected.Role != RoleRootImage
		source, err := verifyAndRetainAt(
			ctx, directory, path, expected.Digest, expected.SizeBytes,
			componentMaximums[expected.Role], snapshot,
		)
		if err != nil {
			closeRetained()
			return nil, fmt.Errorf("verify component %q: %w", expected.Role, err)
		}
		source.metadata = VerifiedComponent{
			Role: expected.Role, Name: path, Digest: expected.Digest, SizeBytes: expected.SizeBytes,
		}
		retained[manifest.Components[index].Role] = source
	}
	if err := verifySlotMetadata(retained[RoleSlotMetadata].file, manifest.SlotID); err != nil {
		closeRetained()
		return nil, err
	}
	commandLine, err := readKernelCommandLine(retained[RoleKernelCommandLine].file)
	if err != nil {
		closeRetained()
		return nil, err
	}

	overlayDir, overlayIdentity, err := openDirectoryAt(directory, overlayDirectory)
	if err != nil {
		closeRetained()
		return nil, fmt.Errorf("open overlay directory: %w", err)
	}
	overlayNames := make([]string, 0, len(manifest.Overlays))
	for _, overlay := range manifest.Overlays {
		overlayNames = append(overlayNames, overlay.Name+".dtbo")
	}
	if err := requireExactNames(overlayDir, overlayNames); err != nil {
		overlayDir.Close()
		closeRetained()
		return nil, fmt.Errorf("overlay directory: %w", err)
	}
	for _, expected := range manifest.Overlays {
		path := expected.Name + ".dtbo"
		source, err := verifyAndRetainAt(
			ctx, overlayDir, path, expected.Digest, expected.SizeBytes, 8*1024*1024, false,
		)
		if err != nil {
			overlayDir.Close()
			closeRetained()
			return nil, fmt.Errorf("verify overlay %q: %w", expected.Name, err)
		}
		metadata := VerifiedComponent{Name: expected.Name, Digest: expected.Digest, SizeBytes: expected.SizeBytes}
		if err := source.file.Close(); err != nil {
			overlayDir.Close()
			closeRetained()
			return nil, fmt.Errorf("close verified overlay %q: %w", expected.Name, err)
		}
		overlays = append(overlays, metadata)
	}
	if err := requireExactNames(overlayDir, overlayNames); err != nil {
		overlayDir.Close()
		closeRetained()
		return nil, fmt.Errorf("overlay directory changed while verifying: %w", err)
	}
	if err := requireSameOpenIdentity(overlayDir, overlayIdentity); err != nil {
		overlayDir.Close()
		closeRetained()
		return nil, fmt.Errorf("overlay directory changed while verifying: %w", err)
	}
	if err := overlayDir.Close(); err != nil {
		closeRetained()
		return nil, fmt.Errorf("close overlay directory: %w", err)
	}
	if err := requireExactNames(directory, rootNames); err != nil {
		closeRetained()
		return nil, fmt.Errorf("delegated release directory changed while verifying: %w", err)
	}
	if err := requireSameOpenIdentity(directory, directoryIdentity); err != nil {
		closeRetained()
		return nil, fmt.Errorf("delegated release directory changed while verifying: %w", err)
	}
	manifestDigest, err := manifest.Digest()
	if err != nil {
		closeRetained()
		return nil, err
	}
	return &VerifiedRelease{
		policy: policy, manifest: manifest, policyDigest: policyDigest, manifestDigest: manifestDigest,
		commandLine: commandLine, components: retained, overlays: overlays,
	}, nil
}

func verifyPolicy(policy Policy, rootKey *rsa.PublicKey, rootFingerprint bundle.Digest) (map[string]*rsa.PublicKey, error) {
	if policy.RootKeyFingerprint != rootFingerprint {
		return nil, errors.New("policy root_key_fingerprint does not match the configured root public key")
	}
	preimage, err := policy.SigningPreimage()
	if err != nil {
		return nil, err
	}
	signature, err := decodeRSASignature(policy.RootSignature)
	if err != nil {
		return nil, fmt.Errorf("decode root signature: %w", err)
	}
	if err := eepromsigning.VerifySignature(rootKey, preimage, signature); err != nil {
		return nil, fmt.Errorf("verify root policy signature: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(policy.DelegatedKeys))
	for _, key := range policy.DelegatedKeys {
		publicKey, fingerprint, _, err := eepromsigning.ParsePublicKey([]byte(key.PublicKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("parse delegated key %q: %w", key.KeyID, err)
		}
		if fingerprint != key.PublicKeyFingerprint {
			return nil, fmt.Errorf("delegated key %q fingerprint does not match its public key", key.KeyID)
		}
		keys[key.KeyID] = publicKey
	}
	return keys, nil
}

func verifyManifestSignatures(manifest Manifest, policy Policy, keys map[string]*rsa.PublicKey) error {
	preimage, err := manifest.SigningPreimage()
	if err != nil {
		return err
	}
	statuses := make(map[string]string, len(policy.DelegatedKeys))
	for _, key := range policy.DelegatedKeys {
		statuses[key.KeyID] = key.Status
	}
	valid := uint32(0)
	for _, signed := range manifest.Signatures {
		status, exists := statuses[signed.KeyID]
		if !exists {
			return fmt.Errorf("manifest signature uses unknown delegated key %q", signed.KeyID)
		}
		if status == "revoked" {
			return fmt.Errorf("manifest signature uses revoked delegated key %q", signed.KeyID)
		}
		signature, err := decodeRSASignature(signed)
		if err != nil {
			return fmt.Errorf("decode delegated signature %q: %w", signed.KeyID, err)
		}
		if err := eepromsigning.VerifySignature(keys[signed.KeyID], preimage, signature); err != nil {
			return fmt.Errorf("verify delegated signature %q: %w", signed.KeyID, err)
		}
		valid++
	}
	if valid < policy.ReleaseSignatureThreshold {
		return fmt.Errorf("manifest has %d valid active signatures, policy requires %d", valid, policy.ReleaseSignatureThreshold)
	}
	return nil
}

func decodeRSASignature(signature RSASignature) ([]byte, error) {
	if err := signature.validate(); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(signature.Value)
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// Policy returns a defensive copy of the verified root-signed policy.
func (release *VerifiedRelease) Policy() Policy {
	release.mu.Lock()
	defer release.mu.Unlock()
	return clonePolicy(release.policy)
}

// Manifest returns a defensive copy of the verified delegated manifest.
func (release *VerifiedRelease) Manifest() Manifest {
	release.mu.Lock()
	defer release.mu.Unlock()
	return cloneManifest(release.manifest)
}

// PolicyDigest returns the digest bound by the delegated manifest.
func (release *VerifiedRelease) PolicyDigest() bundle.Digest {
	return release.policyDigest
}

// ManifestDigest returns the digest that fresh authorization must bind.
func (release *VerifiedRelease) ManifestDigest() bundle.Digest {
	return release.manifestDigest
}

// KernelCommandLine returns the authenticated command line without the one
// canonical trailing LF used by its on-disk representation.
func (release *VerifiedRelease) KernelCommandLine() string {
	return release.commandLine
}

// Components returns immutable metadata in canonical handoff order.
func (release *VerifiedRelease) Components() []VerifiedComponent {
	release.mu.Lock()
	defer release.mu.Unlock()
	result := make([]VerifiedComponent, 0, len(componentRoles))
	for _, role := range componentRoles {
		result = append(result, release.components[role].metadata)
	}
	return result
}

// Overlays returns immutable metadata in the signed overlay application order.
func (release *VerifiedRelease) Overlays() []VerifiedComponent {
	release.mu.Lock()
	defer release.mu.Unlock()
	return append([]VerifiedComponent(nil), release.overlays...)
}

// OpenComponent duplicates the already-verified open file description. The
// returned descriptor is close-on-exec and positioned at byte zero.
func (release *VerifiedRelease) OpenComponent(role ComponentRole) (*os.File, error) {
	release.mu.Lock()
	defer release.mu.Unlock()
	if release.closed {
		return nil, errors.New("verified release is closed")
	}
	source, exists := release.components[role]
	if !exists {
		return nil, fmt.Errorf("component role %q is not present", role)
	}
	return duplicateRetained(source)
}

// Close releases all retained source handles. It is safe to call repeatedly.
func (release *VerifiedRelease) Close() error {
	if release == nil {
		return nil
	}
	release.mu.Lock()
	defer release.mu.Unlock()
	if release.closed {
		return nil
	}
	release.closed = true
	var joined error
	for _, source := range release.components {
		joined = errors.Join(joined, source.file.Close())
	}
	return joined
}

func clonePolicy(policy Policy) Policy {
	policy.DelegatedKeys = append([]DelegatedKey(nil), policy.DelegatedKeys...)
	policy.AuthorizationAuthorities = append([]AuthorizationAuthority(nil), policy.AuthorizationAuthorities...)
	policy.AllowedSlotIDs = append([]string(nil), policy.AllowedSlotIDs...)
	return policy
}

func cloneManifest(manifest Manifest) Manifest {
	manifest.Components = append([]Component(nil), manifest.Components...)
	manifest.Overlays = append([]Overlay(nil), manifest.Overlays...)
	manifest.Signatures = append([]RSASignature(nil), manifest.Signatures...)
	return manifest
}
