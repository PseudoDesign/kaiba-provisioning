package stablecampaign

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

const planDigestDomain = "kaiba.provisioning.rpi5-stable-verifier-campaign-plan.v1alpha1"

// DerivedDigest returns the domain-separated digest of the plan with its
// plan_digest field empty.
func (plan Plan) DerivedDigest() (bundle.Digest, error) {
	material := plan
	material.PlanDigest = ""
	if err := material.validate(false); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", fmt.Errorf("encode campaign plan digest material: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(planDigestDomain + "\x00"))
	_, _ = hash.Write(encoded)
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

// Seal returns a copy with its derived PlanDigest populated.
func (plan Plan) Seal() (Plan, error) {
	digest, err := plan.DerivedDigest()
	if err != nil {
		return Plan{}, err
	}
	plan.PlanDigest = digest
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

// CanonicalJSON returns the unique whitespace-free campaign plan encoding.
func (plan Plan) CanonicalJSON() ([]byte, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	return marshalWithinLimit("campaign plan", plan)
}

// ParsePlan accepts only strict canonical JSON, optionally followed by one LF.
func ParsePlan(encoded []byte) (Plan, error) {
	var plan Plan
	if err := strictCanonicalDecode(encoded, &plan, func() ([]byte, error) { return plan.CanonicalJSON() }); err != nil {
		return Plan{}, fmt.Errorf("parse campaign plan: %w", err)
	}
	return plan, nil
}

func (recipe ByteXORMutationRecipe) CanonicalJSON() ([]byte, error) {
	if err := recipe.Validate(); err != nil {
		return nil, err
	}
	return marshalWithinLimit("byte-XOR recipe", recipe)
}

func ParseByteXORMutationRecipe(encoded []byte) (ByteXORMutationRecipe, error) {
	var recipe ByteXORMutationRecipe
	if err := strictCanonicalDecode(encoded, &recipe, func() ([]byte, error) { return recipe.CanonicalJSON() }); err != nil {
		return ByteXORMutationRecipe{}, fmt.Errorf("parse byte-XOR recipe: %w", err)
	}
	return recipe, nil
}

func (recipe BoundReplacementMutationRecipe) CanonicalJSON() ([]byte, error) {
	if err := recipe.Validate(); err != nil {
		return nil, err
	}
	return marshalWithinLimit("bound replacement recipe", recipe)
}

func ParseBoundReplacementMutationRecipe(encoded []byte) (BoundReplacementMutationRecipe, error) {
	var recipe BoundReplacementMutationRecipe
	if err := strictCanonicalDecode(encoded, &recipe, func() ([]byte, error) { return recipe.CanonicalJSON() }); err != nil {
		return BoundReplacementMutationRecipe{}, fmt.Errorf("parse bound replacement recipe: %w", err)
	}
	return recipe, nil
}

func marshalWithinLimit(label string, value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", label, err)
	}
	if len(encoded) > maximumContractBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", label, maximumContractBytes)
	}
	return encoded, nil
}

func strictCanonicalDecode(encoded []byte, destination any, canonical func() ([]byte, error)) error {
	if len(encoded) == 0 || len(encoded) > maximumContractBytes {
		return fmt.Errorf("JSON contract size must be between 1 and %d bytes", maximumContractBytes)
	}
	if err := inspectJSON(encoded); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON contract: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contract contains a trailing value")
		}
		return fmt.Errorf("decode trailing JSON contract: %w", err)
	}
	expected, err := canonical()
	if err != nil {
		return err
	}
	actual := encoded
	if bytes.HasSuffix(actual, []byte{'\n'}) {
		actual = actual[:len(actual)-1]
	}
	if !bytes.Equal(actual, expected) {
		return errors.New("JSON contract is not in canonical form")
	}
	return nil
}

func inspectJSON(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode JSON contract: %w", err)
	}
	if err := inspectJSONToken(decoder, token, "$", 0); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON contract contains trailing data")
	}
	return nil
}

func inspectJSONToken(decoder *json.Decoder, token json.Token, location string, depth int) error {
	if depth > maximumJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels at %s", maximumJSONDepth, location)
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
				return fmt.Errorf("decode JSON object at %s: %w", location, err)
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
				return fmt.Errorf("decode JSON value at %s.%s: %w", location, key, err)
			}
			if err := inspectJSONToken(decoder, value, location+"."+key, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("decode JSON object end at %s", location)
		}
	case '[':
		for index := 0; decoder.More(); index++ {
			value, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON array at %s: %w", location, err)
			}
			if err := inspectJSONToken(decoder, value, fmt.Sprintf("%s[%d]", location, index), depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("decode JSON array end at %s", location)
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delimiter, location)
	}
	return nil
}
