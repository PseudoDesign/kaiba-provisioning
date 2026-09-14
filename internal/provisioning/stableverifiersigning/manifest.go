package stableverifiersigning

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	UnsignedManifestSchemaV1Alpha1 = "kaiba.provisioning.rpi5-stable-verifier-boot-artifact/v1alpha1"
	MaxUnsignedManifestBytes       = 64 * 1024
)

var manifestPathPattern = regexp.MustCompile(`^[A-Za-z0-9_+.-][A-Za-z0-9_+./-]{0,254}$`)

var verifierOwnedPaths = map[string]bool{
	"kaiba/authority-ca.pem":            true,
	"kaiba/provenance.json":             true,
	"kaiba/root-public.pem":             true,
	"kaiba/stable-verifier":             true,
	"kaiba/stable-verifier-policy.json": true,
}

type unsignedManifest struct {
	SchemaVersion    string `json:"schema_version"`
	SourceRevision   string `json:"source_revision"`
	PiPlatformSource struct {
		Revision string `json:"revision"`
		NARHash  string `json:"nar_hash"`
	} `json:"pi_platform_source"`
	BootImage struct {
		Path      string        `json:"path"`
		SHA256    bundle.Digest `json:"sha256"`
		SizeBytes uint64        `json:"size_bytes"`
	} `json:"boot_image"`
	Files            []string `json:"files"`
	HardwareObserved *bool    `json:"hardware_observed"`
	ProductionReady  *bool    `json:"production_ready"`
	SigningStatus    string   `json:"signing_status"`
}

// ValidateUnsignedManifest checks the actual existing verifier-artifact
// descriptor, including its exact file digest, source and sole boot artifact
// binding. The existing producer emits pretty JSON; the exact original bytes
// are hashed, with no canonicalization or newline removal. This descriptor
// records a source assertion, not authenticated provenance. Callers additionally
// check their pinned Pi platform identity and exact expected firmware allowlist.
func ValidateUnsignedManifest(encoded []byte, intent Intent) error {
	if err := intent.Validate(); err != nil {
		return fmt.Errorf("verifier signing intent: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > MaxUnsignedManifestBytes {
		return fmt.Errorf("unsigned verifier manifest size must be between 1 and %d bytes", MaxUnsignedManifestBytes)
	}
	if bundle.Sum(encoded) != intent.UnsignedManifestDigest {
		return fmt.Errorf("unsigned verifier manifest digest does not match the signing intent")
	}
	var manifest unsignedManifest
	if err := strictDecode(encoded, &manifest); err != nil {
		return fmt.Errorf("decode unsigned verifier manifest: %w", err)
	}
	if err := validateManifestFieldNames(encoded); err != nil {
		return err
	}
	if manifest.SchemaVersion != UnsignedManifestSchemaV1Alpha1 {
		return fmt.Errorf("unsupported unsigned verifier manifest schema_version %q", manifest.SchemaVersion)
	}
	if manifest.SourceRevision != intent.SourceRevision {
		return fmt.Errorf("unsigned verifier manifest source_revision does not match the signing intent")
	}
	if !sourceRevisionPattern.MatchString(manifest.PiPlatformSource.Revision) {
		return fmt.Errorf("unsigned verifier manifest Pi platform revision is not canonical")
	}
	narText := strings.TrimPrefix(manifest.PiPlatformSource.NARHash, "sha256-")
	narBytes, err := base64.StdEncoding.Strict().DecodeString(narText)
	if err != nil || len(narBytes) != 32 || "sha256-"+base64.StdEncoding.EncodeToString(narBytes) != manifest.PiPlatformSource.NARHash {
		return fmt.Errorf("unsigned verifier manifest Pi platform nar_hash is not canonical SHA-256 SRI")
	}
	if manifest.BootImage.Path != "boot.img" || manifest.BootImage.SHA256 != intent.SigningInput.Digest || manifest.BootImage.SizeBytes != intent.SigningInput.SizeBytes {
		return fmt.Errorf("unsigned verifier manifest boot_image does not match the signing intent")
	}
	const mib = 1024 * 1024
	if manifest.BootImage.SizeBytes < 32*mib || manifest.BootImage.SizeBytes > 96*mib || manifest.BootImage.SizeBytes%mib != 0 {
		return fmt.Errorf("unsigned verifier manifest boot_image size must be 32 through 96 whole MiB")
	}
	if manifest.HardwareObserved == nil || *manifest.HardwareObserved || manifest.ProductionReady == nil || *manifest.ProductionReady {
		return fmt.Errorf("unsigned verifier manifest hardware_observed and production_ready must be explicitly false")
	}
	if manifest.SigningStatus != "unsigned_requires_external_root_signature" {
		return fmt.Errorf("unsigned verifier manifest signing_status must be unsigned_requires_external_root_signature")
	}
	if len(manifest.Files) < 6 || len(manifest.Files) > 133 {
		return fmt.Errorf("unsigned verifier manifest files must contain 6 through 133 paths")
	}
	seenOwned := make(map[string]bool)
	for index, name := range manifest.Files {
		if !manifestPathPattern.MatchString(name) || path.Clean(name) != name ||
			strings.HasPrefix(name, ".") || strings.Contains(name, "/.") || strings.Contains(name, "..") {
			return fmt.Errorf("unsigned verifier manifest files[%d] is not a canonical relative file path", index)
		}
		if index > 0 && manifest.Files[index-1] >= name {
			return fmt.Errorf("unsigned verifier manifest files must be sorted and unique")
		}
		if name == "kaiba" || strings.HasPrefix(name, "kaiba/") {
			if !verifierOwnedPaths[name] {
				return fmt.Errorf("unsigned verifier manifest files contains an unknown verifier-owned path %q", name)
			}
			seenOwned[name] = true
		}
	}
	if len(seenOwned) != len(verifierOwnedPaths) {
		return fmt.Errorf("unsigned verifier manifest files omits a required verifier-owned path")
	}
	return nil
}

// The producer's pretty JSON cannot be compared with a canonical struct
// encoding. Check exact, case-sensitive field names separately: encoding/json
// otherwise accepts case-folded aliases such as HARDWARE_OBSERVED alongside
// hardware_observed, and its last-value behavior could disagree with jq.
// strictDecode has already rejected literal duplicate keys, nulls and trailing
// values throughout the document before this check runs.
func validateManifestFieldNames(encoded []byte) error {
	root, err := exactManifestObjectFields(encoded, "unsigned verifier manifest",
		"schema_version", "source_revision", "pi_platform_source", "boot_image",
		"files", "hardware_observed", "production_ready", "signing_status")
	if err != nil {
		return err
	}
	if _, err := exactManifestObjectFields(root["pi_platform_source"], "Pi platform source", "revision", "nar_hash"); err != nil {
		return err
	}
	if _, err := exactManifestObjectFields(root["boot_image"], "boot image", "path", "sha256", "size_bytes"); err != nil {
		return err
	}
	return nil
}

func exactManifestObjectFields(encoded []byte, label string, expected ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return nil, fmt.Errorf("decode %s object: %w", label, err)
	}
	if len(fields) != len(expected) {
		return nil, fmt.Errorf("%s must contain exactly the defined case-sensitive field names", label)
	}
	for _, name := range expected {
		if _, present := fields[name]; !present {
			return nil, fmt.Errorf("%s is missing exact field name %q", label, name)
		}
	}
	return fields, nil
}
