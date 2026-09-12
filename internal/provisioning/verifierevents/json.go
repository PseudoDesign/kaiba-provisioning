package verifierevents

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

// Parse accepts one bounded canonical UART event record. A single trailing LF
// is the only transport decoration accepted outside the canonical JSON bytes.
func Parse(encoded []byte) (Record, error) {
	if len(encoded) == 0 || len(encoded) > MaxRecordBytes+1 {
		return Record{}, fmt.Errorf(
			"verifier event size must be between 1 and %d bytes plus an optional trailing LF",
			MaxRecordBytes,
		)
	}
	payload := encoded
	if encoded[len(encoded)-1] == '\n' {
		payload = encoded[:len(encoded)-1]
	}
	if len(payload) == 0 || len(payload) > MaxRecordBytes {
		return Record{}, fmt.Errorf("verifier event size must be between 1 and %d bytes", MaxRecordBytes)
	}
	if err := inspectJSON(payload); err != nil {
		return Record{}, fmt.Errorf("decode verifier event: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var record Record
	if err := decoder.Decode(&record); err != nil {
		return Record{}, fmt.Errorf("decode verifier event: %w", err)
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return Record{}, fmt.Errorf("decode verifier event: %w", err)
		}
		return Record{}, fmt.Errorf("decode verifier event: trailing JSON value %v", token)
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	canonical, err := record.canonicalJSON()
	if err != nil {
		return Record{}, err
	}
	if !bytes.Equal(payload, canonical) {
		return Record{}, errors.New("verifier event is not canonical JSON")
	}
	return record, nil
}

func (record Record) canonicalJSON() ([]byte, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode verifier event: %w", err)
	}
	if len(encoded) > MaxRecordBytes {
		return nil, fmt.Errorf("verifier event exceeds %d bytes", MaxRecordBytes)
	}
	return encoded, nil
}

// Digest returns the domain-separated digest of the record's canonical JSON.
// Transport newlines are deliberately excluded from the digest.
func (record Record) Digest() (bundle.Digest, error) {
	canonical, err := record.canonicalJSON()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(eventDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(canonical)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

// inspectJSON rejects duplicate object keys and JSON nulls before decoding
// into a Go struct can erase either ambiguity.
func inspectJSON(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := inspectJSONValue(decoder, token, "$", 0); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return fmt.Errorf("trailing JSON value %v", token)
	}
	return nil
}

func inspectJSONValue(decoder *json.Decoder, token json.Token, location string, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON nesting exceeds 64 levels at %s", location)
	}
	if token == nil {
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
				return err
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
				return err
			}
			if err := inspectJSONValue(decoder, value, location+"."+key, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("JSON object at %s has an invalid terminator", location)
		}
	case '[':
		for index := 0; decoder.More(); index++ {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := inspectJSONValue(decoder, value, fmt.Sprintf("%s[%d]", location, index), depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("JSON array at %s has an invalid terminator", location)
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delimiter, location)
	}
	return nil
}
