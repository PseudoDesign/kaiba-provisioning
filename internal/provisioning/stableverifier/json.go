package stableverifier

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

// ParsePolicy accepts only strict, canonical policy JSON, optionally followed
// by one LF. Unknown or duplicate fields and JSON null are rejected.
func ParsePolicy(encoded []byte) (Policy, error) {
	var policy Policy
	if err := strictDecode(encoded, &policy); err != nil {
		return Policy{}, fmt.Errorf("parse stable-verifier policy: %w", err)
	}
	if err := policy.validate(); err != nil {
		return Policy{}, err
	}
	canonical, err := policy.CanonicalJSON()
	if err != nil {
		return Policy{}, err
	}
	if !canonicalJSONFile(encoded, canonical) {
		return Policy{}, errors.New("stable-verifier policy is not canonical JSON")
	}
	return policy, nil
}

// ParseManifest accepts only strict, canonical manifest JSON, optionally
// followed by one LF. Unknown or duplicate fields and JSON null are rejected.
func ParseManifest(encoded []byte) (Manifest, error) {
	var manifest Manifest
	if err := strictDecode(encoded, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse delegated release manifest: %w", err)
	}
	if err := manifest.validate(); err != nil {
		return Manifest{}, err
	}
	canonical, err := manifest.CanonicalJSON()
	if err != nil {
		return Manifest{}, err
	}
	if !canonicalJSONFile(encoded, canonical) {
		return Manifest{}, errors.New("delegated release manifest is not canonical JSON")
	}
	return manifest, nil
}

// CanonicalJSON returns the unique complete policy representation.
func (policy Policy) CanonicalJSON() ([]byte, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(policy)
}

// SigningPreimage returns the domain-separated canonical bytes covered by the
// root signature. RootSignature is intentionally excluded.
func (policy Policy) SigningPreimage() ([]byte, error) {
	if err := policy.validateUnsigned(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(policy.unsigned())
	if err != nil {
		return nil, fmt.Errorf("encode unsigned policy: %w", err)
	}
	return domainPreimage(policySigningDomain, encoded), nil
}

// Digest returns the domain-separated digest of the complete root-signed
// policy artifact. Delegated manifests bind this value.
func (policy Policy) Digest() (bundle.Digest, error) {
	encoded, err := policy.CanonicalJSON()
	if err != nil {
		return "", err
	}
	return domainDigest(policyDigestDomain, encoded), nil
}

// CanonicalJSON returns the unique complete signed manifest representation.
func (manifest Manifest) CanonicalJSON() ([]byte, error) {
	if err := manifest.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(manifest)
}

// SigningPreimage returns the domain-separated canonical bytes covered by
// every delegated signature. Signatures are intentionally excluded.
func (manifest Manifest) SigningPreimage() ([]byte, error) {
	if err := manifest.validateUnsigned(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(manifest.unsigned())
	if err != nil {
		return nil, fmt.Errorf("encode unsigned manifest: %w", err)
	}
	return domainPreimage(manifestSigningDomain, encoded), nil
}

// Digest returns the domain-separated digest of the complete delegated-signed
// manifest. Fresh boot authorization must bind this value.
func (manifest Manifest) Digest() (bundle.Digest, error) {
	encoded, err := manifest.CanonicalJSON()
	if err != nil {
		return "", err
	}
	return domainDigest(manifestDigestDomain, encoded), nil
}

func domainPreimage(domain string, encoded []byte) []byte {
	result := make([]byte, 0, len(domain)+1+len(encoded))
	result = append(result, domain...)
	result = append(result, 0)
	return append(result, encoded...)
}

func domainDigest(domain string, encoded []byte) bundle.Digest {
	digest := sha256.Sum256(domainPreimage(domain, encoded))
	return bundle.Digest("sha256:" + hex.EncodeToString(digest[:]))
}

func strictDecode(encoded []byte, destination any) error {
	if len(encoded) == 0 || len(encoded) > maxMetadataBytes {
		return fmt.Errorf("JSON size must be between 1 and %d bytes", maxMetadataBytes)
	}
	if err := rejectDuplicateKeysAndNulls(encoded); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("trailing JSON value %v", token)
	}
	return nil
}

func rejectDuplicateKeysAndNulls(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if _, err := decodeUniqueValue(decoder, nil); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("trailing JSON value %v", token)
	}
	return nil
}

func decodeUniqueValue(decoder *json.Decoder, first json.Token) (any, error) {
	token := first
	var err error
	if token == nil {
		token, err = decoder.Token()
		if err != nil {
			return nil, err
		}
	}
	if token == nil {
		return nil, errors.New("JSON null is not permitted")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON object key is not a string")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("JSON object key %q is duplicated", key)
			}
			value, err := decodeUniqueValue(decoder, nil)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
			return nil, errors.New("JSON object is not closed")
		}
		return object, nil
	case '[':
		values := make([]any, 0)
		for decoder.More() {
			value, err := decodeUniqueValue(decoder, nil)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim(']') {
			return nil, errors.New("JSON array is not closed")
		}
		return values, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func canonicalJSONFile(encoded, canonical []byte) bool {
	return bytes.Equal(encoded, canonical) ||
		(len(encoded) == len(canonical)+1 && encoded[len(encoded)-1] == '\n' && bytes.Equal(encoded[:len(canonical)], canonical))
}
