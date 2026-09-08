package releaseauthorization

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

func ParseChallenge(data []byte) (Challenge, error) {
	var challenge Challenge
	if err := parseCanonical(data, &challenge, func() ([]byte, error) { return challenge.CanonicalJSON() }); err != nil {
		return Challenge{}, err
	}
	return challenge, nil
}

func ParseAuthorizationRequest(data []byte) (AuthorizationRequest, error) {
	var request AuthorizationRequest
	if err := parseCanonical(data, &request, func() ([]byte, error) { return request.CanonicalJSON() }); err != nil {
		return AuthorizationRequest{}, err
	}
	return request, nil
}

func ParseAuthorization(data []byte) (Authorization, error) {
	var authorization Authorization
	if err := parseCanonical(data, &authorization, func() ([]byte, error) { return authorization.CanonicalJSON() }); err != nil {
		return Authorization{}, err
	}
	return authorization, nil
}

func ParseBootstrapRegistration(data []byte) (BootstrapRegistration, error) {
	var registration BootstrapRegistration
	if err := parseCanonical(data, &registration, func() ([]byte, error) { return registration.CanonicalJSON() }); err != nil {
		return BootstrapRegistration{}, err
	}
	return registration, nil
}

func ParseOneBootProof(data []byte) (OneBootProof, error) {
	var proof OneBootProof
	if err := parseCanonical(data, &proof, func() ([]byte, error) { return proof.CanonicalJSON() }); err != nil {
		return OneBootProof{}, err
	}
	return proof, nil
}

func parseCanonical(data []byte, destination any, canonical func() ([]byte, error)) error {
	if len(data) == 0 || len(data) > MaxDocumentBytes {
		return invalid(fmt.Sprintf("JSON size must be between 1 and %d bytes", MaxDocumentBytes))
	}
	if err := rejectDuplicateKeysAndNulls(data); err != nil {
		return invalid(err.Error())
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return invalid(err.Error())
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return invalid(err.Error())
		}
		return invalid(fmt.Sprintf("trailing JSON value %v", token))
	}
	expected, err := canonical()
	if err != nil {
		return err
	}
	if !bytes.Equal(data, expected) {
		return invalid("JSON is not the canonical fixed-order encoding")
	}
	return nil
}

func rejectDuplicateKeysAndNulls(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
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
			if _, duplicate := object[key]; duplicate {
				return nil, fmt.Errorf("JSON object key %q is duplicated", key)
			}
			value, err := decodeUniqueValue(decoder, nil)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
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
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return nil, errors.New("JSON array is not closed")
		}
		return values, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}
