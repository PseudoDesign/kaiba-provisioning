package stablecampaign

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5kexecinput"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stableverifier"
)

const resolverReadChunkBytes = 128 * 1024

// PublicArtifactBytes supplies the public bytes needed to resolve a campaign
// plan. PublicInputs is keyed by ArtifactBinding.Name. ByteMutationTargets is
// keyed by ByteXORMutationRecipe.Target and contains each positive target
// before mutation. Neither map may contain undeclared entries.
//
// The caller remains responsible for obtaining ByteMutationTargets from the
// reviewed positive release tree. This API binds their bytes to the recipes;
// it does not infer provenance from a directory, archive, or block device.
type PublicArtifactBytes struct {
	PublicInputs        map[string][]byte
	ByteMutationTargets map[string][]byte
}

// PublicArtifactSource is one exact public artifact extent. SizeBytes must be
// the independently measured length of the supplied object, not a value copied
// from the plan binding; ReaderAt must serve every byte in [0, SizeBytes).
// Bytes outside that declared object extent are not inspected.
// ResolvePublicArtifactSources never closes ReaderAt, changes a seek offset,
// or retains it after returning. The caller owns its lifetime and must not
// modify the underlying bytes concurrently with resolution.
type PublicArtifactSource struct {
	SizeBytes uint64
	ReaderAt  io.ReaderAt
}

// PublicArtifactSources is the streaming form of PublicArtifactBytes. It is
// suitable for release trees and root images that must not be materialized in
// memory. Map keys have the same meaning as in PublicArtifactBytes.
type PublicArtifactSources struct {
	PublicInputs        map[string]PublicArtifactSource
	ByteMutationTargets map[string]PublicArtifactSource
}

// ResolvedByteXORMutation records a recipe whose supplied positive bytes and
// deterministically recomputed one-byte mutation matched both bindings.
type ResolvedByteXORMutation struct {
	RecipeID string
	Target   string
	Before   ArtifactBinding
	After    ArtifactBinding
}

// ResolvedBoundReplacement records a recipe whose positive and replacement
// manifest bytes matched their bindings and canonical structural constraint.
type ResolvedBoundReplacement struct {
	RecipeID           string
	ReplacementInput   string
	DifferenceSelector string
	Before             ArtifactBinding
	After              ArtifactBinding
}

// ResolvedSemanticArtifact binds an ordinary file digest and size to the
// domain-separated digest derived by the corresponding strict parser. The
// File binding always comes from the independently validated campaign plan.
type ResolvedSemanticArtifact struct {
	File           ArtifactBinding `json:"file"`
	SemanticDigest bundle.Digest   `json:"semantic_digest"`
}

// ResolvedKernelCommandLine binds the exact positive command-line file and
// its parser-normalized value. Value excludes the optional transport LF.
type ResolvedKernelCommandLine struct {
	File  ArtifactBinding `json:"file"`
	Value string          `json:"value"`
}

// ResolvedCampaignSemantics is the public semantic projection independently
// derived while all campaign bytes are resolved. It contains no path, private
// material, mutation authority, hardware observation, or execution result.
type ResolvedCampaignSemantics struct {
	StableVerifierPolicy       ResolvedSemanticArtifact  `json:"stable_verifier_policy"`
	PositiveReleaseManifest    ResolvedSemanticArtifact  `json:"positive_release_manifest"`
	ReplacementReleaseManifest ResolvedSemanticArtifact  `json:"replacement_release_manifest"`
	PositiveReleaseTree        ArtifactBinding           `json:"positive_release_tree"`
	KernelCommandLine          ResolvedKernelCommandLine `json:"kernel_command_line"`
}

// ResolvedPublicArtifacts reports the public metadata checked by
// ResolvePublicArtifacts. It is a convenience result, not a signed proof, and
// deliberately does not retain caller-owned byte slices.
type ResolvedPublicArtifacts struct {
	PlanDigest        bundle.Digest
	PublicInputs      []ArtifactBinding
	ByteXORMutations  []ResolvedByteXORMutation
	BoundReplacements []ResolvedBoundReplacement
	Semantics         ResolvedCampaignSemantics
}

// ResolvePublicArtifacts independently checks all public input bindings and
// mutation recipes against exact bytes without reading paths or devices.
//
// For a "$" negative replacement, resolution proves only that the replacement
// is a different, separately bound, canonical manifest. The one successful
// delegated-key replacement is additionally required to preserve the positive
// manifest signing preimage, so only its delegated signatures may change.
// Revocation status, delegated-key identity, and signature validity still
// require the stable verifier and its independently trusted policy.
func ResolvePublicArtifacts(plan Plan, supplied PublicArtifactBytes) (ResolvedPublicArtifacts, error) {
	return ResolvePublicArtifactSources(plan, sourcesFromBytes(supplied))
}

// ResolvePublicArtifactSources is the streaming resolver. Each public input
// is read once. Each byte-mutation target is also read once while independent
// before and XOR-after SHA-256 states are updated in parallel. Individual
// ReaderAt calls are capped at resolverReadChunkBytes.
func ResolvePublicArtifactSources(plan Plan, supplied PublicArtifactSources) (ResolvedPublicArtifacts, error) {
	if err := plan.Validate(); err != nil {
		return ResolvedPublicArtifacts{}, fmt.Errorf("resolve public artifacts: campaign plan: %w", err)
	}

	expectedInputNames := make([]string, len(plan.PublicInputs))
	for index, binding := range plan.PublicInputs {
		expectedInputNames[index] = binding.Name
	}
	if err := requireExactSourceEntries("public inputs", supplied.PublicInputs, expectedInputNames); err != nil {
		return ResolvedPublicArtifacts{}, err
	}
	boundedInputs := map[string]struct{}{
		"positive-release-manifest": {},
		"stable-verifier-policy":    {},
	}
	for _, recipe := range plan.BoundReplacements {
		boundedInputs[recipe.ReplacementInput] = struct{}{}
	}
	boundedBytes := make(map[string][]byte, len(boundedInputs))
	for _, binding := range plan.PublicInputs {
		source := supplied.PublicInputs[binding.Name]
		if _, bounded := boundedInputs[binding.Name]; bounded {
			contents, err := readBoundedSource(source, maximumContractBytes)
			if err != nil {
				return ResolvedPublicArtifacts{}, fmt.Errorf("public input %q: %w", binding.Name, err)
			}
			if err := verifyArtifactBytes(binding, contents); err != nil {
				return ResolvedPublicArtifacts{}, fmt.Errorf("public input %q: %w", binding.Name, err)
			}
			boundedBytes[binding.Name] = contents
			continue
		}
		if err := verifyArtifactSource(binding, source); err != nil {
			return ResolvedPublicArtifacts{}, fmt.Errorf("public input %q: %w", binding.Name, err)
		}
	}

	policy, err := stableverifier.ParsePolicy(boundedBytes["stable-verifier-policy"])
	if err != nil {
		return ResolvedPublicArtifacts{}, fmt.Errorf("stable-verifier policy must be valid canonical policy JSON: %w", err)
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		return ResolvedPublicArtifacts{}, fmt.Errorf("derive stable-verifier policy digest: %w", err)
	}

	positiveBytes := boundedBytes["positive-release-manifest"]
	positiveManifest, err := stableverifier.ParseManifest(positiveBytes)
	if err != nil {
		return ResolvedPublicArtifacts{}, fmt.Errorf("positive release manifest must be a valid canonical stable-verifier manifest: %w", err)
	}
	positiveManifestDigest, err := positiveManifest.Digest()
	if err != nil {
		return ResolvedPublicArtifacts{}, fmt.Errorf("derive positive release manifest digest: %w", err)
	}
	if positiveManifest.PolicyDigest != policyDigest {
		return ResolvedPublicArtifacts{}, errors.New("positive release manifest policy_digest does not bind the resolved stable-verifier policy")
	}

	expectedTargets := make([]string, len(plan.ByteXORMutations))
	for index, recipe := range plan.ByteXORMutations {
		expectedTargets[index] = recipe.Target
	}
	if err := requireExactSourceEntries("byte mutation targets", supplied.ByteMutationTargets, expectedTargets); err != nil {
		return ResolvedPublicArtifacts{}, err
	}

	resolution := ResolvedPublicArtifacts{
		PlanDigest:        plan.PlanDigest,
		PublicInputs:      append([]ArtifactBinding(nil), plan.PublicInputs...),
		ByteXORMutations:  make([]ResolvedByteXORMutation, 0, len(plan.ByteXORMutations)),
		BoundReplacements: make([]ResolvedBoundReplacement, 0, len(plan.BoundReplacements)),
		Semantics: ResolvedCampaignSemantics{
			StableVerifierPolicy: ResolvedSemanticArtifact{
				File: planPublicInput(plan, "stable-verifier-policy"), SemanticDigest: policyDigest,
			},
			PositiveReleaseManifest: ResolvedSemanticArtifact{
				File: planPublicInput(plan, "positive-release-manifest"), SemanticDigest: positiveManifestDigest,
			},
			PositiveReleaseTree: planPublicInput(plan, "positive-release-tree"),
		},
	}
	for _, recipe := range plan.ByteXORMutations {
		target := supplied.ByteMutationTargets[recipe.Target]
		if target.SizeBytes != recipe.Before.SizeBytes || target.SizeBytes != recipe.After.SizeBytes {
			return ResolvedPublicArtifacts{}, fmt.Errorf("byte-XOR recipe %q target size is %d bytes, bindings require %d", recipe.RecipeID, target.SizeBytes, recipe.Before.SizeBytes)
		}
		var commandLineValue string
		var beforeDigest, mutatedDigest bundle.Digest
		if recipe.Target == "release/cmdline.txt" {
			contents, readErr := readBoundedSource(target, uint64(rpi5kexecinput.MaxCommandLineBytes+1))
			if readErr != nil {
				return ResolvedPublicArtifacts{}, fmt.Errorf("byte-XOR recipe %q: %w", recipe.RecipeID, readErr)
			}
			beforeDigest = bundle.Sum(contents)
			mutated := append([]byte(nil), contents...)
			mutated[recipe.OffsetBytes] ^= recipe.XORMask
			mutatedDigest = bundle.Sum(mutated)
			commandLineValue, err = rpi5kexecinput.ParseCommandLineFile(contents)
		} else {
			beforeDigest, mutatedDigest, err = digestSourceWithXOR(target, recipe.OffsetBytes, recipe.XORMask)
		}
		if err != nil {
			return ResolvedPublicArtifacts{}, fmt.Errorf("byte-XOR recipe %q: %w", recipe.RecipeID, err)
		}
		if beforeDigest != recipe.Before.Digest {
			return ResolvedPublicArtifacts{}, fmt.Errorf("byte-XOR recipe %q before target digest is %q, binding requires %q", recipe.RecipeID, beforeDigest, recipe.Before.Digest)
		}
		if mutatedDigest != recipe.After.Digest {
			return ResolvedPublicArtifacts{}, fmt.Errorf("byte-XOR recipe %q recomputed after bytes do not match after binding", recipe.RecipeID)
		}
		if err := verifyRecipeAgainstManifest(recipe, positiveManifest); err != nil {
			return ResolvedPublicArtifacts{}, err
		}
		if recipe.Target == "release/cmdline.txt" {
			resolution.Semantics.KernelCommandLine = ResolvedKernelCommandLine{
				File: recipe.Before, Value: commandLineValue,
			}
		}
		resolution.ByteXORMutations = append(resolution.ByteXORMutations, ResolvedByteXORMutation{
			RecipeID: recipe.RecipeID,
			Target:   recipe.Target,
			Before:   recipe.Before,
			After:    recipe.After,
		})
	}

	for _, recipe := range plan.BoundReplacements {
		replacementBytes := boundedBytes[recipe.ReplacementInput]
		replacementManifest, err := parseCanonicalManifestStructure(replacementBytes)
		if err != nil {
			return ResolvedPublicArtifacts{}, fmt.Errorf("replacement recipe %q: %w", recipe.RecipeID, err)
		}
		differences := manifestDifferenceSelectors(positiveManifest, replacementManifest)
		if recipe.DifferenceSelector == "$" {
			if len(differences) == 0 {
				return ResolvedPublicArtifacts{}, fmt.Errorf(
					"replacement recipe %q changes transport bytes but not manifest structure",
					recipe.RecipeID,
				)
			}
		} else {
			if len(differences) != 1 || differences[0] != recipe.DifferenceSelector {
				return ResolvedPublicArtifacts{}, fmt.Errorf(
					"replacement recipe %q differs at %v, want exactly [%s]",
					recipe.RecipeID, differences, recipe.DifferenceSelector,
				)
			}
		}
		if recipe.RecipeID == "delegated-key-replacement-boots:replacement-manifest" {
			validatedReplacement, parseErr := stableverifier.ParseManifest(replacementBytes)
			if parseErr != nil {
				return ResolvedPublicArtifacts{}, fmt.Errorf("replacement recipe %q must contain a valid canonical manifest: %w", recipe.RecipeID, parseErr)
			}
			positivePreimage, preimageErr := positiveManifest.SigningPreimage()
			if preimageErr != nil {
				return ResolvedPublicArtifacts{}, preimageErr
			}
			replacementPreimage, preimageErr := validatedReplacement.SigningPreimage()
			if preimageErr != nil {
				return ResolvedPublicArtifacts{}, preimageErr
			}
			if !bytes.Equal(positivePreimage, replacementPreimage) {
				return ResolvedPublicArtifacts{}, fmt.Errorf("replacement recipe %q changes signed release content rather than only delegated signatures", recipe.RecipeID)
			}
			replacementDigest, digestErr := validatedReplacement.Digest()
			if digestErr != nil {
				return ResolvedPublicArtifacts{}, digestErr
			}
			resolution.Semantics.ReplacementReleaseManifest = ResolvedSemanticArtifact{
				File: recipe.After, SemanticDigest: replacementDigest,
			}
		}
		resolution.BoundReplacements = append(resolution.BoundReplacements, ResolvedBoundReplacement{
			RecipeID:           recipe.RecipeID,
			ReplacementInput:   recipe.ReplacementInput,
			DifferenceSelector: recipe.DifferenceSelector,
			Before:             recipe.Before,
			After:              recipe.After,
		})
	}

	return resolution, nil
}

func planPublicInput(plan Plan, name string) ArtifactBinding {
	for _, binding := range plan.PublicInputs {
		if binding.Name == name {
			return binding
		}
	}
	return ArtifactBinding{}
}

func verifyRecipeAgainstManifest(recipe ByteXORMutationRecipe, manifest stableverifier.Manifest) error {
	if recipe.TestID != "component-byte-mutations-rejected" {
		return nil
	}
	target := recipe.Target
	if recipe.SubcaseID == "overlay" {
		for _, overlay := range manifest.Overlays {
			if target == "release/overlays/"+overlay.Name+".dtbo" {
				if recipe.Before.Digest != overlay.Digest || recipe.Before.SizeBytes != overlay.SizeBytes {
					return fmt.Errorf("byte-XOR recipe %q before binding differs from the positive manifest overlay", recipe.RecipeID)
				}
				return nil
			}
		}
		return fmt.Errorf("byte-XOR recipe %q target is absent from the positive manifest overlays", recipe.RecipeID)
	}
	for _, component := range manifest.Components {
		path, ok := stableverifier.ComponentPath(component.Role)
		if ok && target == "release/"+path {
			if recipe.Before.Digest != component.Digest || recipe.Before.SizeBytes != component.SizeBytes {
				return fmt.Errorf("byte-XOR recipe %q before binding differs from the positive manifest component", recipe.RecipeID)
			}
			return nil
		}
	}
	return fmt.Errorf("byte-XOR recipe %q target is absent from the positive manifest components", recipe.RecipeID)
}

func sourcesFromBytes(supplied PublicArtifactBytes) PublicArtifactSources {
	result := PublicArtifactSources{
		PublicInputs:        make(map[string]PublicArtifactSource, len(supplied.PublicInputs)),
		ByteMutationTargets: make(map[string]PublicArtifactSource, len(supplied.ByteMutationTargets)),
	}
	for name, contents := range supplied.PublicInputs {
		result.PublicInputs[name] = PublicArtifactSource{SizeBytes: uint64(len(contents)), ReaderAt: bytes.NewReader(contents)}
	}
	for name, contents := range supplied.ByteMutationTargets {
		result.ByteMutationTargets[name] = PublicArtifactSource{SizeBytes: uint64(len(contents)), ReaderAt: bytes.NewReader(contents)}
	}
	return result
}

func requireExactSourceEntries(label string, supplied map[string]PublicArtifactSource, expected []string) error {
	if len(supplied) != len(expected) {
		return fmt.Errorf("%s must contain exactly %d declared entries", label, len(expected))
	}
	expectedSet := make(map[string]struct{}, len(expected))
	for _, name := range expected {
		if _, duplicate := expectedSet[name]; duplicate {
			return fmt.Errorf("campaign plan declares duplicate %s entry %q", label, name)
		}
		expectedSet[name] = struct{}{}
		if _, ok := supplied[name]; !ok {
			return fmt.Errorf("%s is missing declared entry %q", label, name)
		}
	}
	for name := range supplied {
		if _, ok := expectedSet[name]; !ok {
			return fmt.Errorf("%s contains undeclared entry %q", label, name)
		}
	}
	return nil
}

func verifyArtifactSource(binding ArtifactBinding, source PublicArtifactSource) error {
	if source.SizeBytes != binding.SizeBytes {
		return fmt.Errorf("size is %d bytes, binding requires %d", source.SizeBytes, binding.SizeBytes)
	}
	actual, err := digestSource(source)
	if err != nil {
		return err
	}
	if actual != binding.Digest {
		return fmt.Errorf("digest is %q, binding requires %q", actual, binding.Digest)
	}
	return nil
}

func verifyArtifactBytes(binding ArtifactBinding, contents []byte) error {
	if uint64(len(contents)) != binding.SizeBytes {
		return fmt.Errorf("size is %d bytes, binding requires %d", len(contents), binding.SizeBytes)
	}
	actual := bundle.Sum(contents)
	if actual != binding.Digest {
		return fmt.Errorf("digest is %q, binding requires %q", actual, binding.Digest)
	}
	return nil
}

func digestSource(source PublicArtifactSource) (bundle.Digest, error) {
	if err := validateSource(source); err != nil {
		return "", err
	}
	hash := sha256.New()
	if err := streamSource(source, func(_ uint64, chunk []byte) {
		_, _ = hash.Write(chunk)
	}); err != nil {
		return "", err
	}
	return digestFromHash(hash.Sum(nil)), nil
}

func digestSourceWithXOR(source PublicArtifactSource, offset uint64, mask uint8) (bundle.Digest, bundle.Digest, error) {
	if err := validateSource(source); err != nil {
		return "", "", err
	}
	if offset >= source.SizeBytes {
		return "", "", errors.New("XOR offset is outside supplied target")
	}
	beforeHash := sha256.New()
	afterHash := sha256.New()
	err := streamSource(source, func(chunkOffset uint64, chunk []byte) {
		_, _ = beforeHash.Write(chunk)
		if offset < chunkOffset || offset >= chunkOffset+uint64(len(chunk)) {
			_, _ = afterHash.Write(chunk)
			return
		}
		mutationIndex := offset - chunkOffset
		_, _ = afterHash.Write(chunk[:mutationIndex])
		_, _ = afterHash.Write([]byte{chunk[mutationIndex] ^ mask})
		_, _ = afterHash.Write(chunk[mutationIndex+1:])
	})
	if err != nil {
		return "", "", err
	}
	return digestFromHash(beforeHash.Sum(nil)), digestFromHash(afterHash.Sum(nil)), nil
}

func validateSource(source PublicArtifactSource) error {
	if source.SizeBytes == 0 || source.SizeBytes > math.MaxInt64 {
		return fmt.Errorf("source size must be between 1 and %d bytes", int64(math.MaxInt64))
	}
	if nilReaderAt(source.ReaderAt) {
		return errors.New("source ReaderAt is nil")
	}
	return nil
}

func nilReaderAt(reader io.ReaderAt) bool {
	if reader == nil {
		return true
	}
	value := reflect.ValueOf(reader)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func streamSource(source PublicArtifactSource, consume func(offset uint64, chunk []byte)) error {
	buffer := make([]byte, resolverReadChunkBytes)
	for offset := uint64(0); offset < source.SizeBytes; {
		remaining := source.SizeBytes - offset
		readSize := uint64(len(buffer))
		if remaining < readSize {
			readSize = remaining
		}
		chunk := buffer[:int(readSize)]
		count, err := source.ReaderAt.ReadAt(chunk, int64(offset))
		if count < 0 || count > len(chunk) {
			return fmt.Errorf("ReaderAt returned invalid byte count %d for %d-byte request at offset %d", count, len(chunk), offset)
		}
		if count != len(chunk) {
			return fmt.Errorf("ReaderAt returned %d of %d bytes at offset %d: %w", count, len(chunk), offset, err)
		}
		if err != nil {
			return fmt.Errorf("ReaderAt returned an error after a complete read at offset %d: %w", offset, err)
		}
		consume(offset, chunk)
		offset += uint64(count)
	}
	return nil
}

func readBoundedSource(source PublicArtifactSource, maximum uint64) ([]byte, error) {
	if err := validateSource(source); err != nil {
		return nil, err
	}
	if source.SizeBytes > maximum {
		return nil, fmt.Errorf("source is %d bytes, maximum is %d", source.SizeBytes, maximum)
	}
	contents := make([]byte, int(source.SizeBytes))
	if err := streamSource(source, func(offset uint64, chunk []byte) {
		copy(contents[int(offset):], chunk)
	}); err != nil {
		return nil, err
	}
	return contents, nil
}

func digestFromHash(sum []byte) bundle.Digest {
	return bundle.Digest("sha256:" + hex.EncodeToString(sum))
}

// parseCanonicalManifestStructure checks the stable-verifier manifest's exact
// JSON shape and canonical encoding without enforcing semantic values. This is
// necessary for negative cases whose one selected value is intentionally an
// unsupported schema, role, digest, algorithm, or signature.
func parseCanonicalManifestStructure(encoded []byte) (stableverifier.Manifest, error) {
	if len(encoded) == 0 || len(encoded) > maximumContractBytes {
		return stableverifier.Manifest{}, fmt.Errorf("manifest size must be between 1 and %d bytes", maximumContractBytes)
	}
	if err := inspectJSON(encoded); err != nil {
		return stableverifier.Manifest{}, fmt.Errorf("manifest JSON structure: %w", err)
	}

	var manifest stableverifier.Manifest
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return stableverifier.Manifest{}, fmt.Errorf("decode manifest structure: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return stableverifier.Manifest{}, errors.New("manifest contains a trailing JSON value")
		}
		return stableverifier.Manifest{}, fmt.Errorf("decode trailing manifest JSON: %w", err)
	}

	canonical, err := json.Marshal(manifest)
	if err != nil {
		return stableverifier.Manifest{}, fmt.Errorf("encode canonical manifest structure: %w", err)
	}
	actual := encoded
	if bytes.HasSuffix(actual, []byte{'\n'}) {
		actual = actual[:len(actual)-1]
	}
	if !bytes.Equal(actual, canonical) {
		return stableverifier.Manifest{}, errors.New("manifest is not canonical structural JSON")
	}
	return manifest, nil
}

func manifestDifferenceSelectors(before, after stableverifier.Manifest) []string {
	differences := make([]string, 0, 2)
	appendStringDifference(&differences, "/schema_version", before.SchemaVersion, after.SchemaVersion)
	appendStringDifference(&differences, "/release_id", before.ReleaseID, after.ReleaseID)
	appendStringDifference(&differences, "/device_class", before.DeviceClass, after.DeviceClass)
	appendStringDifference(&differences, "/cohort_id", before.CohortID, after.CohortID)
	appendStringDifference(&differences, "/policy_digest", string(before.PolicyDigest), string(after.PolicyDigest))
	appendUint64Difference(&differences, "/security_epoch", before.SecurityEpoch, after.SecurityEpoch)
	appendStringDifference(&differences, "/slot_id", before.SlotID, after.SlotID)

	if len(before.Components) != len(after.Components) {
		differences = append(differences, "/components")
	} else {
		for index := range before.Components {
			prefix := fmt.Sprintf("/components/%d", index)
			appendStringDifference(&differences, prefix+"/role", string(before.Components[index].Role), string(after.Components[index].Role))
			appendStringDifference(&differences, prefix+"/digest", string(before.Components[index].Digest), string(after.Components[index].Digest))
			appendUint64Difference(&differences, prefix+"/size_bytes", before.Components[index].SizeBytes, after.Components[index].SizeBytes)
		}
	}

	if len(before.Overlays) != len(after.Overlays) {
		differences = append(differences, "/overlays")
	} else {
		for index := range before.Overlays {
			prefix := fmt.Sprintf("/overlays/%d", index)
			appendStringDifference(&differences, prefix+"/name", before.Overlays[index].Name, after.Overlays[index].Name)
			appendStringDifference(&differences, prefix+"/digest", string(before.Overlays[index].Digest), string(after.Overlays[index].Digest))
			appendUint64Difference(&differences, prefix+"/size_bytes", before.Overlays[index].SizeBytes, after.Overlays[index].SizeBytes)
		}
	}

	if len(before.Signatures) != len(after.Signatures) {
		differences = append(differences, "/signatures")
	} else {
		for index := range before.Signatures {
			prefix := fmt.Sprintf("/signatures/%d", index)
			appendStringDifference(&differences, prefix+"/key_id", before.Signatures[index].KeyID, after.Signatures[index].KeyID)
			appendStringDifference(&differences, prefix+"/algorithm", before.Signatures[index].Algorithm, after.Signatures[index].Algorithm)
			appendStringDifference(&differences, prefix+"/value", before.Signatures[index].Value, after.Signatures[index].Value)
		}
	}
	return differences
}

func appendStringDifference(differences *[]string, selector, before, after string) {
	if before != after {
		*differences = append(*differences, selector)
	}
}

func appendUint64Difference(differences *[]string, selector string, before, after uint64) {
	if before != after {
		*differences = append(*differences, selector)
	}
}
