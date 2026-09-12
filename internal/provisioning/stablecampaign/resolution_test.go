package stablecampaign

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stableverifier"
)

func TestResolvePublicArtifactsChecksEveryBindingAndMutation(t *testing.T) {
	fixture := resolvedPlanFixture(t)
	targetSnapshots := cloneByteMap(fixture.supplied.ByteMutationTargets)

	resolved, err := ResolvePublicArtifacts(fixture.plan, fixture.supplied)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.PlanDigest != fixture.plan.PlanDigest ||
		len(resolved.PublicInputs) != len(fixture.plan.PublicInputs) ||
		len(resolved.ByteXORMutations) != len(fixture.plan.ByteXORMutations) ||
		len(resolved.BoundReplacements) != len(fixture.plan.BoundReplacements) {
		t.Fatalf("incomplete resolution: %#v", resolved)
	}
	policy, err := stableverifier.ParsePolicy(fixture.supplied.PublicInputs["stable-verifier-policy"])
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	positiveDigest, err := fixture.positive.Digest()
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := stableverifier.ParseManifest(fixture.supplied.PublicInputs["replacement-release-manifest"])
	if err != nil {
		t.Fatal(err)
	}
	replacementDigest, err := replacement.Digest()
	if err != nil {
		t.Fatal(err)
	}
	wantSemantics := ResolvedCampaignSemantics{
		StableVerifierPolicy: ResolvedSemanticArtifact{
			File: planPublicInput(fixture.plan, "stable-verifier-policy"), SemanticDigest: policyDigest,
		},
		PositiveReleaseManifest: ResolvedSemanticArtifact{
			File: planPublicInput(fixture.plan, "positive-release-manifest"), SemanticDigest: positiveDigest,
		},
		ReplacementReleaseManifest: ResolvedSemanticArtifact{
			File: planPublicInput(fixture.plan, "replacement-release-manifest"), SemanticDigest: replacementDigest,
		},
		PositiveReleaseTree: planPublicInput(fixture.plan, "positive-release-tree"),
		KernelCommandLine: ResolvedKernelCommandLine{
			File:  byteRecipeForID(t, fixture.plan, "component-byte-mutations-rejected:kernel-command-line").Before,
			Value: "console=ttyAMA10,115200n8 ro",
		},
	}
	if resolved.Semantics != wantSemantics {
		t.Fatalf("semantic resolution = %#v, want %#v", resolved.Semantics, wantSemantics)
	}
	for target, before := range targetSnapshots {
		if !bytes.Equal(fixture.supplied.ByteMutationTargets[target], before) {
			t.Fatalf("resolver modified caller-owned target %q", target)
		}
	}
}

func TestResolvePublicArtifactSourcesStreamsLargeTargetOnceWithBoundedReads(t *testing.T) {
	fixture := resolvedPlanFixture(t)
	sources := sourcesFromBytes(fixture.supplied)
	recipeIndex := -1
	for index, candidate := range fixture.plan.ByteXORMutations {
		if candidate.TestID == "dm-verity-corruption-rejected" && candidate.SubcaseID == "root-data" {
			recipeIndex = index
			break
		}
	}
	if recipeIndex < 0 {
		t.Fatal("missing root-data streaming fixture recipe")
	}
	recipe := fixture.plan.ByteXORMutations[recipeIndex]

	const size = uint64(32*1024*1024 + 17)
	const value = byte(0xa5)
	reader := &guardRepeatedReaderAt{size: size, value: value, maximumRequest: resolverReadChunkBytes}
	sources.ByteMutationTargets[recipe.Target] = PublicArtifactSource{SizeBytes: size, ReaderAt: reader}
	recipe.Before = ArtifactBinding{
		Name: recipe.Before.Name, Digest: digestRepeatedByte(size, value, false), SizeBytes: size,
	}
	recipe.After = ArtifactBinding{
		Name: recipe.After.Name, Digest: digestRepeatedByte(size, value, true), SizeBytes: size,
	}
	fixture.plan.ByteXORMutations[recipeIndex] = recipe
	fixture.plan = resealPlan(t, fixture.plan)

	if _, err := ResolvePublicArtifactSources(fixture.plan, sources); err != nil {
		t.Fatal(err)
	}
	if reader.violation != "" {
		t.Fatal(reader.violation)
	}
	if reader.totalBytes != size {
		t.Fatalf("large target was read %d bytes, want exactly one %d-byte pass", reader.totalBytes, size)
	}
	if reader.maximumObserved > resolverReadChunkBytes {
		t.Fatalf("largest ReaderAt request was %d bytes, cap is %d", reader.maximumObserved, resolverReadChunkBytes)
	}
}

func TestResolvePublicArtifactSourcesReadsManifestExtentOnce(t *testing.T) {
	fixture := resolvedPlanFixture(t)
	sources := sourcesFromBytes(fixture.supplied)
	manifestBytes := fixture.supplied.PublicInputs["positive-release-manifest"]
	reader := &noRereadReaderAt{contents: manifestBytes, seen: make([]bool, len(manifestBytes))}
	sources.PublicInputs["positive-release-manifest"] = PublicArtifactSource{
		SizeBytes: uint64(len(manifestBytes)), ReaderAt: reader,
	}

	if _, err := ResolvePublicArtifactSources(fixture.plan, sources); err != nil {
		t.Fatal(err)
	}
	if reader.totalBytes != uint64(len(manifestBytes)) {
		t.Fatalf("positive manifest was read %d bytes, want exactly one %d-byte pass", reader.totalBytes, len(manifestBytes))
	}
}

func TestResolvePublicArtifactsRejectsMissingAndExtraEntries(t *testing.T) {
	tests := map[string]func(*resolvedPlanTestFixture){
		"missing public input": func(fixture *resolvedPlanTestFixture) {
			delete(fixture.supplied.PublicInputs, "stable-verifier-policy")
		},
		"extra public input": func(fixture *resolvedPlanTestFixture) {
			fixture.supplied.PublicInputs["undeclared"] = []byte("not reviewed")
		},
		"missing mutation target": func(fixture *resolvedPlanTestFixture) {
			delete(fixture.supplied.ByteMutationTargets, fixture.plan.ByteXORMutations[0].Target)
		},
		"extra mutation target": func(fixture *resolvedPlanTestFixture) {
			fixture.supplied.ByteMutationTargets["release/undeclared"] = []byte("not reviewed")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := resolvedPlanFixture(t)
			mutate(&fixture)
			if _, err := ResolvePublicArtifacts(fixture.plan, fixture.supplied); err == nil {
				t.Fatal("inexact supplied byte set was accepted")
			}
		})
	}
}

func TestResolvePublicArtifactsRejectsPublicInputAndXORMismatch(t *testing.T) {
	t.Run("public input digest", func(t *testing.T) {
		fixture := resolvedPlanFixture(t)
		fixture.supplied.PublicInputs["stable-verifier-policy"][0] ^= 1
		if _, err := ResolvePublicArtifacts(fixture.plan, fixture.supplied); err == nil || !strings.Contains(err.Error(), "digest") {
			t.Fatalf("mutated public input accepted: %v", err)
		}
	})

	t.Run("byte target before", func(t *testing.T) {
		fixture := resolvedPlanFixture(t)
		target := fixture.plan.ByteXORMutations[0].Target
		fixture.supplied.ByteMutationTargets[target][1] ^= 1
		if _, err := ResolvePublicArtifacts(fixture.plan, fixture.supplied); err == nil || !strings.Contains(err.Error(), "before target") {
			t.Fatalf("wrong before target accepted: %v", err)
		}
	})

	t.Run("forged after binding", func(t *testing.T) {
		fixture := resolvedPlanFixture(t)
		fixture.plan.ByteXORMutations[0].After.Digest = bundle.Sum([]byte("not the deterministic mutation"))
		fixture.plan = resealPlan(t, fixture.plan)
		if _, err := ResolvePublicArtifacts(fixture.plan, fixture.supplied); err == nil || !strings.Contains(err.Error(), "recomputed after bytes") {
			t.Fatalf("forged XOR after binding accepted: %v", err)
		}
	})
}

func TestResolvePublicArtifactsRequiresValidPositiveManifest(t *testing.T) {
	fixture := resolvedPlanFixture(t)
	invalid := cloneManifest(fixture.positive)
	invalid.SchemaVersion = "unsupported-positive-schema"
	encoded, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	rebindPositiveManifest(t, &fixture, encoded)
	if _, err := ResolvePublicArtifacts(fixture.plan, fixture.supplied); err == nil || !strings.Contains(err.Error(), "positive release manifest") {
		t.Fatalf("semantically invalid positive manifest accepted: %v", err)
	}
}

func TestResolvePublicArtifactsCrossBindsPositiveManifestSemantics(t *testing.T) {
	t.Run("policy digest", func(t *testing.T) {
		fixture := resolvedPlanFixture(t)
		detached := cloneManifest(fixture.positive)
		detached.PolicyDigest = bundle.Sum([]byte("different stable-verifier policy"))
		encoded, err := detached.CanonicalJSON()
		if err != nil {
			t.Fatal(err)
		}
		rebindPositiveManifest(t, &fixture, encoded)
		if _, err := ResolvePublicArtifacts(fixture.plan, fixture.supplied); err == nil ||
			!strings.Contains(err.Error(), "policy_digest") {
			t.Fatalf("positive manifest detached from policy accepted: %v", err)
		}
	})

	t.Run("component bytes", func(t *testing.T) {
		fixture := resolvedPlanFixture(t)
		const recipeID = "component-byte-mutations-rejected:kernel"
		for index, recipe := range fixture.plan.ByteXORMutations {
			if recipe.RecipeID != recipeID {
				continue
			}
			target := append([]byte(nil), fixture.supplied.ByteMutationTargets[recipe.Target]...)
			target[len(target)-1] ^= 0x40
			fixture.supplied.ByteMutationTargets[recipe.Target] = target
			mutated := append([]byte(nil), target...)
			mutated[recipe.OffsetBytes] ^= recipe.XORMask
			recipe.Before = bindingForBytes(recipe.Before.Name, target)
			recipe.After = bindingForBytes(recipe.After.Name, mutated)
			fixture.plan.ByteXORMutations[index] = recipe
			fixture.plan = resealPlan(t, fixture.plan)
			if _, err := ResolvePublicArtifacts(fixture.plan, fixture.supplied); err == nil ||
				!strings.Contains(err.Error(), "positive manifest component") {
				t.Fatalf("component target detached from positive manifest accepted: %v", err)
			}
			return
		}
		t.Fatal("kernel mutation recipe absent")
	})
}

func TestResolvePublicArtifactsRequiresSuccessfulReplacementToPreserveSigningPreimage(t *testing.T) {
	fixture := resolvedPlanFixture(t)
	detached := cloneManifest(fixture.positive)
	detached.ReleaseID = "release-2"
	encoded, err := detached.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	rebindReplacementInput(t, &fixture, "replacement-release-manifest", encoded)
	if _, err := ResolvePublicArtifacts(fixture.plan, fixture.supplied); err == nil ||
		!strings.Contains(err.Error(), "changes signed release content") {
		t.Fatalf("successful replacement with a different signing preimage accepted: %v", err)
	}
}

func TestResolvePublicArtifactsRejectsWrongManifestFieldDifference(t *testing.T) {
	tests := map[string]func(stableverifier.Manifest) []byte{
		"two fields": func(manifest stableverifier.Manifest) []byte {
			manifest.SchemaVersion = "wrong-schema"
			manifest.ReleaseID = "wrong-release"
			return marshalManifestStructure(t, manifest)
		},
		"array length": func(manifest stableverifier.Manifest) []byte {
			manifest.Components = manifest.Components[:len(manifest.Components)-1]
			return marshalManifestStructure(t, manifest)
		},
		"no difference": func(manifest stableverifier.Manifest) []byte {
			return append(marshalManifestStructure(t, manifest), '\n')
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := resolvedPlanFixture(t)
			inputName := "manifest-field-schema-version"
			rebindReplacementInput(t, &fixture, inputName, mutate(cloneManifest(fixture.positive)))
			if _, err := ResolvePublicArtifacts(fixture.plan, fixture.supplied); err == nil || !strings.Contains(err.Error(), "differs at") {
				t.Fatalf("wrong field difference accepted: %v", err)
			}
		})
	}
}

func TestResolvePublicArtifactsRejectsAmbiguousReplacementManifestJSON(t *testing.T) {
	tests := map[string]func([]byte) []byte{
		"duplicate key": func(encoded []byte) []byte {
			return bytes.Replace(encoded, []byte(`"schema_version":`), []byte(`"schema_version":"duplicate","schema_version":`), 1)
		},
		"null": func(encoded []byte) []byte {
			return bytes.Replace(encoded, []byte(`"schema_version":"unsupported-schema"`), []byte(`"schema_version":null`), 1)
		},
		"unknown": func(encoded []byte) []byte {
			return bytes.Replace(encoded, []byte(`{"schema_version":`), []byte(`{"unknown":false,"schema_version":`), 1)
		},
		"noncanonical whitespace": func(encoded []byte) []byte {
			return append([]byte(" "), encoded...)
		},
		"wrong type": func(encoded []byte) []byte {
			return bytes.Replace(encoded, []byte(`"security_epoch":1`), []byte(`"security_epoch":"1"`), 1)
		},
		"trailing value": func(encoded []byte) []byte {
			return append(encoded, []byte(`{}`)...)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := resolvedPlanFixture(t)
			inputName := "manifest-field-schema-version"
			original := fixture.supplied.PublicInputs[inputName]
			rebindReplacementInput(t, &fixture, inputName, mutate(append([]byte(nil), original...)))
			if _, err := ResolvePublicArtifacts(fixture.plan, fixture.supplied); err == nil {
				t.Fatal("ambiguous replacement manifest JSON was accepted")
			}
		})
	}
}

func TestResolvePublicArtifactsRejectsNoncanonicalWholeManifestReplacement(t *testing.T) {
	fixture := resolvedPlanFixture(t)
	inputName := "unsigned-release-manifest"
	encoded := append([]byte(" "), fixture.supplied.PublicInputs[inputName]...)
	rebindReplacementInput(t, &fixture, inputName, encoded)
	if _, err := ResolvePublicArtifacts(fixture.plan, fixture.supplied); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("noncanonical whole-manifest replacement accepted: %v", err)
	}
}

func TestResolvePublicArtifactsRejectsWholeReplacementWithOnlyTransportDifference(t *testing.T) {
	fixture := resolvedPlanFixture(t)
	inputName := "wrong-key-release-manifest"
	encoded := append(append([]byte(nil), fixture.supplied.PublicInputs["positive-release-manifest"]...), '\n')
	rebindReplacementInput(t, &fixture, inputName, encoded)
	if _, err := ResolvePublicArtifacts(fixture.plan, fixture.supplied); err == nil || !strings.Contains(err.Error(), "not manifest structure") {
		t.Fatalf("same-semantics whole-manifest replacement accepted: %v", err)
	}
}

type resolvedPlanTestFixture struct {
	plan     Plan
	supplied PublicArtifactBytes
	positive stableverifier.Manifest
}

func resolvedPlanFixture(t *testing.T) resolvedPlanTestFixture {
	t.Helper()
	policy := validResolvedPolicy(t)
	policyBytes, err := policy.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}

	targets := make(map[string][]byte, len(expectedByteRecipeKeys()))
	for _, pair := range expectedByteRecipeKeys() {
		target, _ := expectedByteTarget(pair[0], pair[1])
		if pair[1] == "overlay" {
			target = "release/overlays/campaign.dtbo"
		}
		contents := []byte("positive mutation target: " + target)
		if target == "release/cmdline.txt" {
			contents = []byte("console=ttyAMA10,115200n8 ro\n")
		}
		targets[target] = contents
	}

	positive := validPositiveManifest(t, policyDigest, targets)
	positiveBytes, err := positive.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}

	inputBytes := make(map[string][]byte, len(expectedPublicInputNames()))
	for _, name := range expectedPublicInputNames() {
		inputBytes[name] = []byte("public campaign input: " + name)
	}
	inputBytes["stable-verifier-policy"] = policyBytes
	inputBytes["positive-release-manifest"] = positiveBytes
	for _, pair := range expectedReplacementRecipeKeys() {
		name := replacementInputName(pair[0], pair[1])
		variant := cloneManifest(positive)
		if pair[0] == "manifest-field-mutations-rejected" {
			mutateManifestField(&variant, pair[1])
		} else {
			mutateWholeManifest(&variant, pair[0])
		}
		inputBytes[name] = marshalManifestStructure(t, variant)
	}

	bindings := make([]ArtifactBinding, 0, len(inputBytes))
	byName := make(map[string]ArtifactBinding, len(inputBytes))
	for _, name := range expectedPublicInputNames() {
		binding := bindingForBytes(name, inputBytes[name])
		bindings = append(bindings, binding)
		byName[name] = binding
	}

	byteRecipes := make([]ByteXORMutationRecipe, 0, len(expectedByteRecipeKeys()))
	for _, pair := range expectedByteRecipeKeys() {
		target, _ := expectedByteTarget(pair[0], pair[1])
		if pair[1] == "overlay" {
			target = "release/overlays/campaign.dtbo"
		}
		beforeBytes := targets[target]
		afterBytes := append([]byte(nil), beforeBytes...)
		afterBytes[0] ^= 1
		targets[target] = beforeBytes
		name := byteBindingName(pair[0], pair[1])
		recipe, err := NewByteXORMutationRecipe(
			pair[0], pair[1], target,
			bindingForBytes(name, beforeBytes), bindingForBytes(name, afterBytes),
		)
		if err != nil {
			t.Fatalf("construct byte recipe %q: %v", recipeID(pair[0], pair[1]), err)
		}
		byteRecipes = append(byteRecipes, recipe)
	}

	replacements := make([]BoundReplacementMutationRecipe, 0, len(expectedReplacementRecipeKeys()))
	for _, pair := range expectedReplacementRecipeKeys() {
		inputName := replacementInputName(pair[0], pair[1])
		recipe, err := NewBoundReplacementMutationRecipe(pair[0], pair[1], byName["positive-release-manifest"], byName[inputName])
		if err != nil {
			t.Fatalf("construct replacement recipe %q: %v", recipeID(pair[0], pair[1]), err)
		}
		replacements = append(replacements, recipe)
	}

	plan, err := NewPlan("resolved-campaign", bindings, byteRecipes, replacements)
	if err != nil {
		t.Fatal(err)
	}
	return resolvedPlanTestFixture{
		plan: plan,
		supplied: PublicArtifactBytes{
			PublicInputs:        inputBytes,
			ByteMutationTargets: targets,
		},
		positive: positive,
	}
}

func validResolvedPolicy(t *testing.T) stableverifier.Policy {
	t.Helper()
	policy := stableverifier.Policy{
		SchemaVersion:             stableverifier.PolicySchemaV1Alpha1,
		PolicyID:                  "policy-1",
		DeviceClass:               stableverifier.DeviceClass,
		CohortID:                  "cohort-1",
		SecurityEpoch:             1,
		MinimumVerifierVersion:    1,
		ReleaseSignatureThreshold: 1,
		AllowedSlotIDs:            []string{"a"},
		RootKeyID:                 "root-1",
		RootKeyFingerprint:        bundle.Sum([]byte("root-key")),
		DelegatedKeys: []stableverifier.DelegatedKey{{
			KeyID: "key-1", Algorithm: stableverifier.RSA2048SHA256Algorithm,
			PublicKeyPEM: "public-key", PublicKeyFingerprint: bundle.Sum([]byte("delegated-key")),
			Status: "active",
		}},
		AuthorizationAuthorities: []stableverifier.AuthorizationAuthority{{
			KeyID: "authority-1", Algorithm: stableverifier.Ed25519Algorithm,
			PublicKey: "ed25519:" + strings.Repeat("a", 64),
		}},
		RootSignature: stableverifier.RSASignature{
			KeyID: "root-1", Algorithm: stableverifier.RSA2048SHA256Algorithm,
			Value: base64.StdEncoding.EncodeToString(make([]byte, 256)),
		},
	}
	if _, err := policy.CanonicalJSON(); err != nil {
		t.Fatalf("construct valid policy: %v", err)
	}
	return policy
}

func validPositiveManifest(
	t *testing.T,
	policyDigest bundle.Digest,
	targets map[string][]byte,
) stableverifier.Manifest {
	t.Helper()
	components := make([]stableverifier.Component, 0, len(stableverifier.ComponentRoles()))
	for _, role := range stableverifier.ComponentRoles() {
		componentPath, ok := stableverifier.ComponentPath(role)
		if !ok {
			t.Fatalf("missing path for component role %q", role)
		}
		contents := targets["release/"+componentPath]
		components = append(components, stableverifier.Component{
			Role: role, Digest: bundle.Sum(contents), SizeBytes: uint64(len(contents)),
		})
	}
	overlayBytes := targets["release/overlays/campaign.dtbo"]
	manifest := stableverifier.Manifest{
		SchemaVersion: stableverifier.ManifestSchemaV1Alpha1,
		ReleaseID:     "release-1",
		DeviceClass:   stableverifier.DeviceClass,
		CohortID:      "cohort-1",
		PolicyDigest:  policyDigest,
		SecurityEpoch: 1,
		SlotID:        "a",
		Components:    components,
		Overlays: []stableverifier.Overlay{{
			Name: "campaign", Digest: bundle.Sum(overlayBytes), SizeBytes: uint64(len(overlayBytes)),
		}},
		Signatures: []stableverifier.RSASignature{{
			KeyID:     "key-1",
			Algorithm: stableverifier.RSA2048SHA256Algorithm,
			Value:     base64.StdEncoding.EncodeToString(make([]byte, 256)),
		}},
	}
	if _, err := manifest.CanonicalJSON(); err != nil {
		t.Fatalf("construct valid positive manifest: %v", err)
	}
	return manifest
}

func mutateManifestField(manifest *stableverifier.Manifest, subcase string) {
	switch subcase {
	case "schema-version":
		manifest.SchemaVersion = "unsupported-schema"
	case "release-id":
		manifest.ReleaseID = "other-release"
	case "device-class":
		manifest.DeviceClass = "other-device"
	case "cohort-id":
		manifest.CohortID = "other-cohort"
	case "policy-digest":
		manifest.PolicyDigest = "not-a-canonical-digest"
	case "security-epoch":
		manifest.SecurityEpoch++
	case "slot-id":
		manifest.SlotID = "b"
	case "component-role":
		manifest.Components[0].Role = "other-role"
	case "component-digest":
		manifest.Components[0].Digest = "not-a-canonical-digest"
	case "component-size-bytes":
		manifest.Components[0].SizeBytes++
	case "overlay-name":
		manifest.Overlays[0].Name = "other-overlay"
	case "overlay-digest":
		manifest.Overlays[0].Digest = "not-a-canonical-digest"
	case "overlay-size-bytes":
		manifest.Overlays[0].SizeBytes++
	case "signature-key-id":
		manifest.Signatures[0].KeyID = "other-key"
	case "signature-algorithm":
		manifest.Signatures[0].Algorithm = "unsupported-algorithm"
	case "signature-value":
		manifest.Signatures[0].Value = "not-a-signature"
	default:
		panic("unhandled manifest mutation subcase " + subcase)
	}
}

func mutateWholeManifest(manifest *stableverifier.Manifest, testID string) {
	switch testID {
	case "delegated-key-replacement-boots":
		manifest.Signatures[0].KeyID = "key-2"
	case "revoked-delegated-key-rejected":
		manifest.Signatures[0].KeyID = "revoked-key"
	case "unsigned-release-rejected":
		manifest.Signatures = make([]stableverifier.RSASignature, 0)
	case "wrong-delegated-key-rejected":
		manifest.Signatures[0].KeyID = "wrong-key"
	default:
		panic("unhandled whole-manifest mutation test " + testID)
	}
}

func cloneManifest(source stableverifier.Manifest) stableverifier.Manifest {
	clone := source
	clone.Components = append([]stableverifier.Component(nil), source.Components...)
	clone.Overlays = append([]stableverifier.Overlay(nil), source.Overlays...)
	clone.Signatures = append([]stableverifier.RSASignature(nil), source.Signatures...)
	return clone
}

func marshalManifestStructure(t *testing.T, manifest stableverifier.Manifest) []byte {
	t.Helper()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func bindingForBytes(name string, contents []byte) ArtifactBinding {
	return ArtifactBinding{Name: name, Digest: bundle.Sum(contents), SizeBytes: uint64(len(contents))}
}

func byteRecipeForID(t *testing.T, plan Plan, recipeID string) ByteXORMutationRecipe {
	t.Helper()
	for _, recipe := range plan.ByteXORMutations {
		if recipe.RecipeID == recipeID {
			return recipe
		}
	}
	t.Fatalf("byte mutation recipe %q absent", recipeID)
	return ByteXORMutationRecipe{}
}

func cloneByteMap(source map[string][]byte) map[string][]byte {
	clone := make(map[string][]byte, len(source))
	for name, contents := range source {
		clone[name] = append([]byte(nil), contents...)
	}
	return clone
}

func rebindReplacementInput(t *testing.T, fixture *resolvedPlanTestFixture, name string, contents []byte) {
	t.Helper()
	fixture.supplied.PublicInputs[name] = contents
	binding := bindingForBytes(name, contents)
	foundInput := false
	for index := range fixture.plan.PublicInputs {
		if fixture.plan.PublicInputs[index].Name == name {
			fixture.plan.PublicInputs[index] = binding
			foundInput = true
		}
	}
	if !foundInput {
		t.Fatalf("public input %q not found", name)
	}
	foundRecipe := false
	for index := range fixture.plan.BoundReplacements {
		if fixture.plan.BoundReplacements[index].ReplacementInput == name {
			fixture.plan.BoundReplacements[index].After = binding
			foundRecipe = true
		}
	}
	if !foundRecipe {
		t.Fatalf("replacement input %q has no recipe", name)
	}
	fixture.plan = resealPlan(t, fixture.plan)
}

func rebindPositiveManifest(t *testing.T, fixture *resolvedPlanTestFixture, contents []byte) {
	t.Helper()
	name := "positive-release-manifest"
	fixture.supplied.PublicInputs[name] = contents
	binding := bindingForBytes(name, contents)
	for index := range fixture.plan.PublicInputs {
		if fixture.plan.PublicInputs[index].Name == name {
			fixture.plan.PublicInputs[index] = binding
		}
	}
	for index := range fixture.plan.BoundReplacements {
		fixture.plan.BoundReplacements[index].Before = binding
	}
	fixture.plan = resealPlan(t, fixture.plan)
}

func resealPlan(t *testing.T, plan Plan) Plan {
	t.Helper()
	sealed, err := plan.Seal()
	if err != nil {
		t.Fatalf("reseal plan: %v", err)
	}
	return sealed
}

func TestResolvedFixtureHasUniquePublicDigests(t *testing.T) {
	fixture := resolvedPlanFixture(t)
	seen := make(map[bundle.Digest]string, len(fixture.plan.PublicInputs))
	for _, input := range fixture.plan.PublicInputs {
		if previous, duplicate := seen[input.Digest]; duplicate {
			t.Fatalf("fixture inputs %q and %q duplicate digest %s", previous, input.Name, input.Digest)
		}
		seen[input.Digest] = input.Name
	}
	if got, want := len(fixture.plan.PublicInputs), len(expectedPublicInputNames()); got != want {
		t.Fatalf("fixture has %d inputs, want %d", got, want)
	}
}

type guardRepeatedReaderAt struct {
	size            uint64
	value           byte
	maximumRequest  int
	maximumObserved int
	totalBytes      uint64
	violation       string
}

func (reader *guardRepeatedReaderAt) ReadAt(destination []byte, offset int64) (int, error) {
	if len(destination) > reader.maximumObserved {
		reader.maximumObserved = len(destination)
	}
	if len(destination) > reader.maximumRequest {
		reader.violation = fmt.Sprintf("ReaderAt request was %d bytes, limit is %d", len(destination), reader.maximumRequest)
		return 0, errors.New(reader.violation)
	}
	if offset < 0 || uint64(offset) > reader.size || uint64(len(destination)) > reader.size-uint64(offset) {
		reader.violation = fmt.Sprintf("ReaderAt request [%d,%d) exceeds extent %d", offset, offset+int64(len(destination)), reader.size)
		return 0, errors.New(reader.violation)
	}
	for index := range destination {
		destination[index] = reader.value
	}
	reader.totalBytes += uint64(len(destination))
	return len(destination), nil
}

type noRereadReaderAt struct {
	contents   []byte
	seen       []bool
	totalBytes uint64
}

func (reader *noRereadReaderAt) ReadAt(destination []byte, offset int64) (int, error) {
	if offset < 0 || int64(len(destination)) > int64(len(reader.contents))-offset {
		return 0, errors.New("read is outside manifest extent")
	}
	for index := range destination {
		position := int(offset) + index
		if reader.seen[position] {
			return 0, fmt.Errorf("manifest byte %d was read more than once", position)
		}
	}
	copy(destination, reader.contents[int(offset):int(offset)+len(destination)])
	for index := range destination {
		reader.seen[int(offset)+index] = true
	}
	reader.totalBytes += uint64(len(destination))
	return len(destination), nil
}

func digestRepeatedByte(size uint64, value byte, mutateFirst bool) bundle.Digest {
	hash := sha256.New()
	if mutateFirst {
		_, _ = hash.Write([]byte{value ^ 1})
		size--
	}
	buffer := bytes.Repeat([]byte{value}, 64*1024)
	for size > 0 {
		writeSize := uint64(len(buffer))
		if size < writeSize {
			writeSize = size
		}
		_, _ = hash.Write(buffer[:int(writeSize)])
		size -= writeSize
	}
	return bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil)))
}

func ExampleResolvePublicArtifacts() {
	// Callers populate exact bytes from an already reviewed public handoff.
	_, _ = ResolvePublicArtifacts(Plan{}, PublicArtifactBytes{
		PublicInputs:        map[string][]byte{},
		ByteMutationTargets: map[string][]byte{},
	})
	fmt.Println("resolution performs no filesystem or device I/O")
	// Output: resolution performs no filesystem or device I/O
}
