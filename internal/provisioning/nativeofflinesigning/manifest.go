package nativeofflinesigning

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	UnsignedManifestSchemaV1Alpha1 = "kaiba.provisioning.rpi5-native-offline-signing-input/v1alpha1"
	MaxUnsignedManifestBytes       = 64 * 1024
	RootDataPARTUUID               = "b1a02b6c-8ec1-4ca9-9b8a-348211271de0"
	RootHashPARTUUID               = "66d98f80-4260-4de0-98b5-232bcac98e29"
)

type InputFile struct {
	Digest    bundle.Digest `json:"digest"`
	SizeBytes uint64        `json:"size_bytes"`
}

// UnsignedManifest binds the candidate and public review bytes. It is not an
// observation of hardware or an approval. The Nix constructor verifies the
// referenced bytes, verity tree and boot arguments before creating this file.
type UnsignedManifest struct {
	SchemaVersion           string        `json:"schema_version"`
	SourceRevision          string        `json:"source_revision"`
	UnsignedArtifactsDigest bundle.Digest `json:"unsigned_artifacts_digest"`
	ReviewDigest            bundle.Digest `json:"review_digest"`
	BootImage               InputFile     `json:"boot_image"`
	RootData                InputFile     `json:"root_data"`
	RootHashTree            InputFile     `json:"root_hash_tree"`
	RootIntegrityDigest     bundle.Digest `json:"root_integrity_digest"`
	RootDataPARTUUID        string        `json:"root_data_partuuid"`
	RootHashPARTUUID        string        `json:"root_hash_partuuid"`
	HardwareObserved        bool          `json:"hardware_observed"`
	FleetAdmission          string        `json:"fleet_admission"`
}

func ValidateUnsignedManifest(encoded []byte, intent Intent) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	if len(encoded) == 0 || len(encoded) > MaxUnsignedManifestBytes || bundle.Sum(encoded) != intent.UnsignedManifestDigest {
		return errors.New("unsigned manifest size or exact byte digest mismatch")
	}
	var m UnsignedManifest
	if err := strictDecode(encoded, &m); err != nil {
		return err
	}
	canonical, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var fields map[string]any
	if err := json.Unmarshal(canonical, &fields); err != nil {
		return err
	}
	canonical, err = json.Marshal(fields)
	if err != nil {
		return err
	}
	// Sorted field names and one transport LF also reject aliases and omissions.
	if !bytes.Equal(encoded, append(canonical, '\n')) {
		return errors.New("unsigned manifest must use canonical JSON plus one LF")
	}
	if m.SchemaVersion != UnsignedManifestSchemaV1Alpha1 || m.SourceRevision != intent.SourceRevision {
		return errors.New("unsigned manifest scope or source mismatch")
	}
	if m.BootImage.Digest != intent.SigningInput.Digest || m.BootImage.SizeBytes != intent.SigningInput.SizeBytes {
		return errors.New("unsigned manifest boot input mismatch")
	}
	if m.RootDataPARTUUID != RootDataPARTUUID || m.RootHashPARTUUID != RootHashPARTUUID || m.HardwareObserved || m.FleetAdmission != "unevaluated" {
		return errors.New("unsigned manifest is not the unqualified native NVMe candidate")
	}
	for _, d := range []bundle.Digest{m.UnsignedArtifactsDigest, m.ReviewDigest, m.RootIntegrityDigest, m.RootData.Digest, m.RootHashTree.Digest} {
		if err := d.Validate(); err != nil {
			return err
		}
	}
	for _, f := range []InputFile{m.RootData, m.RootHashTree} {
		if f.SizeBytes == 0 || f.SizeBytes%4096 != 0 {
			return fmt.Errorf("root input must contain whole 4096-byte blocks")
		}
	}
	return nil
}
