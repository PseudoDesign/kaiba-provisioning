package stablecampaign

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stableevidence"
)

func TestPlanCanonicalRoundTripAndDigest(t *testing.T) {
	plan := validPlan(t)
	encoded, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePlan(append(append([]byte(nil), encoded...), '\n'))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.PlanDigest != plan.PlanDigest {
		t.Fatalf("parsed digest %q, want %q", parsed.PlanDigest, plan.PlanDigest)
	}
	derived, err := parsed.DerivedDigest()
	if err != nil {
		t.Fatal(err)
	}
	if derived != plan.PlanDigest {
		t.Fatalf("derived digest %q, want %q", derived, plan.PlanDigest)
	}
	if len(parsed.Cases) != 14 {
		t.Fatalf("got %d logical cases, want 14", len(parsed.Cases))
	}
	if len(parsed.ByteXORMutations) != 10 || len(parsed.BoundReplacements) != 20 {
		t.Fatalf("unexpected mutation coverage: %d byte-XOR, %d replacements", len(parsed.ByteXORMutations), len(parsed.BoundReplacements))
	}
}

func TestPlanRejectsNoncanonicalOrdering(t *testing.T) {
	tests := map[string]func(*Plan){
		"public inputs": func(plan *Plan) {
			plan.PublicInputs[0], plan.PublicInputs[1] = plan.PublicInputs[1], plan.PublicInputs[0]
		},
		"logical cases": func(plan *Plan) {
			plan.Cases[0], plan.Cases[1] = plan.Cases[1], plan.Cases[0]
		},
		"subcases": func(plan *Plan) {
			plan.Cases[3].Subcases[0], plan.Cases[3].Subcases[1] = plan.Cases[3].Subcases[1], plan.Cases[3].Subcases[0]
		},
		"byte recipes": func(plan *Plan) {
			plan.ByteXORMutations[0], plan.ByteXORMutations[1] = plan.ByteXORMutations[1], plan.ByteXORMutations[0]
		},
		"replacement recipes": func(plan *Plan) {
			plan.BoundReplacements[0], plan.BoundReplacements[1] = plan.BoundReplacements[1], plan.BoundReplacements[0]
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			plan := validPlan(t)
			mutate(&plan)
			if err := plan.Validate(); err == nil {
				t.Fatal("noncanonical ordering was accepted")
			}
		})
	}
}

func TestPlanRejectsMissingAndDuplicateSubcases(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		plan := validPlan(t)
		plan.Cases[3].Subcases = plan.Cases[3].Subcases[:len(plan.Cases[3].Subcases)-1]
		if err := plan.Validate(); err == nil || !strings.Contains(err.Error(), "exact 8 subcases") {
			t.Fatalf("missing subcase accepted: %v", err)
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		plan := validPlan(t)
		plan.Cases[3].Subcases[1] = plan.Cases[3].Subcases[0]
		if err := plan.Validate(); err == nil || !strings.Contains(err.Error(), "subcases[1]") {
			t.Fatalf("duplicate subcase accepted: %v", err)
		}
	})
	t.Run("duplicate recipe", func(t *testing.T) {
		plan := validPlan(t)
		plan.ByteXORMutations[1] = plan.ByteXORMutations[0]
		if err := plan.Validate(); err == nil || !strings.Contains(err.Error(), "byte_xor_mutations[1]") {
			t.Fatalf("duplicate mutation recipe accepted: %v", err)
		}
	})
	t.Run("missing replacement recipe", func(t *testing.T) {
		plan := validPlan(t)
		plan.BoundReplacements = plan.BoundReplacements[:len(plan.BoundReplacements)-1]
		if err := plan.Validate(); err == nil || !strings.Contains(err.Error(), "exact 20") {
			t.Fatalf("missing replacement recipe accepted: %v", err)
		}
	})
}

func TestStrictPlanParsingRejectsAmbiguity(t *testing.T) {
	plan := validPlan(t)
	encoded, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"duplicate": bytes.Replace(encoded, []byte(`"campaign_id":"campaign-1"`), []byte(`"campaign_id":"campaign-1","campaign_id":"campaign-2"`), 1),
		"null":      bytes.Replace(encoded, []byte(`"classification":"development-only"`), []byte(`"classification":null`), 1),
		"unknown":   bytes.Replace(encoded, []byte(`"campaign_id":"campaign-1"`), []byte(`"campaign_id":"campaign-1","unexpected":false`), 1),
		"field order": bytes.Replace(
			encoded,
			[]byte(`{"schema_version":"`+PlanSchemaV1Alpha1+`","campaign_id":"campaign-1"`),
			[]byte(`{"campaign_id":"campaign-1","schema_version":"`+PlanSchemaV1Alpha1+`"`),
			1,
		),
		"whitespace":   append([]byte(" "), encoded...),
		"two newlines": append(append(append([]byte(nil), encoded...), '\n'), '\n'),
		"trailing":     append(append([]byte(nil), encoded...), []byte(`{}`)...),
		"excessive nesting": []byte(
			`{"schema_version":` + strings.Repeat(`[`, maximumJSONDepth+1) + `false` + strings.Repeat(`]`, maximumJSONDepth+1) + `}`,
		),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePlan(input); err == nil {
				t.Fatal("ambiguous or noncanonical JSON was accepted")
			}
		})
	}
}

func TestStrictRecipeParsingRejectsDuplicateNullAndUnknown(t *testing.T) {
	plan := validPlan(t)
	byteEncoded, err := plan.ByteXORMutations[0].CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	replacementEncoded, err := plan.BoundReplacements[0].CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		input []byte
		parse func([]byte) error
	}{
		{
			name:  "byte duplicate",
			input: bytes.Replace(byteEncoded, []byte(`"recipe_id":"`), []byte(`"recipe_id":"duplicate","recipe_id":"`), 1),
			parse: func(input []byte) error { _, err := ParseByteXORMutationRecipe(input); return err },
		},
		{
			name:  "byte null",
			input: bytes.Replace(byteEncoded, []byte(`"target":"`), []byte(`"discarded":null,"target":"`), 1),
			parse: func(input []byte) error { _, err := ParseByteXORMutationRecipe(input); return err },
		},
		{
			name:  "replacement unknown",
			input: bytes.Replace(replacementEncoded, []byte(`"target":"`), []byte(`"unexpected":false,"target":"`), 1),
			parse: func(input []byte) error { _, err := ParseBoundReplacementMutationRecipe(input); return err },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.parse(test.input); err == nil {
				t.Fatal("invalid recipe JSON was accepted")
			}
		})
	}
}

func TestRecipeCanonicalRoundTrips(t *testing.T) {
	plan := validPlan(t)
	byteEncoded, err := plan.ByteXORMutations[0].CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsedByte, err := ParseByteXORMutationRecipe(append(append([]byte(nil), byteEncoded...), '\n'))
	if err != nil {
		t.Fatal(err)
	}
	if parsedByte.RecipeID != plan.ByteXORMutations[0].RecipeID {
		t.Fatalf("parsed byte recipe %q, want %q", parsedByte.RecipeID, plan.ByteXORMutations[0].RecipeID)
	}

	replacementEncoded, err := plan.BoundReplacements[0].CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsedReplacement, err := ParseBoundReplacementMutationRecipe(append(append([]byte(nil), replacementEncoded...), '\n'))
	if err != nil {
		t.Fatal(err)
	}
	if parsedReplacement.RecipeID != plan.BoundReplacements[0].RecipeID {
		t.Fatalf("parsed replacement recipe %q, want %q", parsedReplacement.RecipeID, plan.BoundReplacements[0].RecipeID)
	}
}

func TestByteXORRecipeRejectsInvalidBindingsPathsAndMutations(t *testing.T) {
	base := validPlan(t).ByteXORMutations[0]
	tests := map[string]func(*ByteXORMutationRecipe){
		"bad digest":     func(recipe *ByteXORMutationRecipe) { recipe.Before.Digest = "SHA256:not-canonical" },
		"absolute path":  func(recipe *ByteXORMutationRecipe) { recipe.Target = "/release/kernel" },
		"traversal path": func(recipe *ByteXORMutationRecipe) { recipe.Target = "release/../kernel" },
		"wrong target":   func(recipe *ByteXORMutationRecipe) { recipe.Target = "release/initramfs" },
		"same digest":    func(recipe *ByteXORMutationRecipe) { recipe.After.Digest = recipe.Before.Digest },
		"different size": func(recipe *ByteXORMutationRecipe) { recipe.After.SizeBytes++ },
		"wrong binding name": func(recipe *ByteXORMutationRecipe) {
			recipe.After.Name = "different-public-target"
		},
		"outside offset":   func(recipe *ByteXORMutationRecipe) { recipe.OffsetBytes = recipe.Before.SizeBytes },
		"different offset": func(recipe *ByteXORMutationRecipe) { recipe.OffsetBytes = 1 },
		"zero mask":        func(recipe *ByteXORMutationRecipe) { recipe.XORMask = 0 },
		"multi-bit mask":   func(recipe *ByteXORMutationRecipe) { recipe.XORMask = 3 },
		"unknown subcase": func(recipe *ByteXORMutationRecipe) {
			recipe.SubcaseID = "invented"
			recipe.RecipeID = recipeID(recipe.TestID, recipe.SubcaseID)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			recipe := base
			mutate(&recipe)
			if err := recipe.Validate(); err == nil {
				t.Fatal("invalid byte-XOR recipe was accepted")
			}
		})
	}
}

func TestReplacementRecipeRejectsInvalidBindingsPathsAndMutations(t *testing.T) {
	base := validPlan(t).BoundReplacements[0]
	tests := map[string]func(*BoundReplacementMutationRecipe){
		"bad digest":     func(recipe *BoundReplacementMutationRecipe) { recipe.After.Digest = "sha256:ABC" },
		"absolute path":  func(recipe *BoundReplacementMutationRecipe) { recipe.Target = "/release/release-manifest.json" },
		"wrong path":     func(recipe *BoundReplacementMutationRecipe) { recipe.Target = "release/kernel" },
		"same digest":    func(recipe *BoundReplacementMutationRecipe) { recipe.After.Digest = recipe.Before.Digest },
		"wrong input":    func(recipe *BoundReplacementMutationRecipe) { recipe.ReplacementInput = "root-public-key" },
		"wrong selector": func(recipe *BoundReplacementMutationRecipe) { recipe.DifferenceSelector = "/release_id" },
		"unknown subcase": func(recipe *BoundReplacementMutationRecipe) {
			recipe.SubcaseID = "invented"
			recipe.RecipeID = recipeID(recipe.TestID, recipe.SubcaseID)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			recipe := base
			mutate(&recipe)
			if err := recipe.Validate(); err == nil {
				t.Fatal("invalid replacement recipe was accepted")
			}
		})
	}
}

func TestPlanRequiresPublicOnlyNonProductionBoundary(t *testing.T) {
	tests := map[string]func(*SafetyBoundary){
		"classification": func(boundary *SafetyBoundary) { boundary.Classification = "production" },
		"private material": func(boundary *SafetyBoundary) {
			boundary.PrivateMaterialEmbeddedInContract = true
		},
		"production ready":           func(boundary *SafetyBoundary) { boundary.ProductionReady = true },
		"signing authorization":      func(boundary *SafetyBoundary) { boundary.SigningAuthorized = true },
		"device-write authorization": func(boundary *SafetyBoundary) { boundary.DeviceWritesAuthorized = true },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			plan := validPlan(t)
			mutate(&plan.SafetyBoundary)
			if err := plan.Validate(); err == nil {
				t.Fatal("expanded safety claim was accepted")
			}
		})
	}

	t.Run("recipe safety boundary", func(t *testing.T) {
		plan := validPlan(t)
		plan.ByteXORMutations[0].SafetyBoundary.PrivateMaterialEmbeddedInContract = true
		if err := plan.Validate(); err == nil {
			t.Fatal("private-material mutation recipe was accepted")
		}
	})

	plan := validPlan(t)
	encoded, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"BEGIN PRIVATE KEY", "private_key", `"production_ready":true`, `"signing_authorized":true`, `"device_writes_authorized":true`, "/tmp/", "/dev/"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("public plan contains forbidden material %q", forbidden)
		}
	}
}

func TestPlanRejectsInvalidPublicInputsAndDigest(t *testing.T) {
	t.Run("invalid input digest", func(t *testing.T) {
		plan := validPlan(t)
		plan.PublicInputs[0].Digest = "sha256:ABC"
		if err := plan.Validate(); err == nil {
			t.Fatal("invalid public digest was accepted")
		}
	})
	t.Run("zero input size", func(t *testing.T) {
		plan := validPlan(t)
		plan.PublicInputs[0].SizeBytes = 0
		if err := plan.Validate(); err == nil {
			t.Fatal("zero-sized public input was accepted")
		}
	})
	t.Run("private input", func(t *testing.T) {
		plan := validPlan(t)
		plan.PublicInputs[0].Name = "delegated-private-key"
		if err := plan.Validate(); err == nil {
			t.Fatal("noncanonical private input was accepted")
		}
	})
	t.Run("duplicate input digest", func(t *testing.T) {
		plan := validPlan(t)
		plan.PublicInputs[1].Digest = plan.PublicInputs[0].Digest
		if err := plan.Validate(); err == nil || !strings.Contains(err.Error(), "same digest") {
			t.Fatalf("duplicate public digest accepted: %v", err)
		}
	})
	t.Run("tampered plan digest", func(t *testing.T) {
		plan := validPlan(t)
		plan.PlanDigest = testDigest(999)
		if err := plan.Validate(); err == nil || !strings.Contains(err.Error(), "does not bind") {
			t.Fatalf("tampered plan digest accepted: %v", err)
		}
	})
}

func TestFixedCasesReturnsDefensiveCopy(t *testing.T) {
	first := FixedCases()
	first[0].TestID = "changed"
	first[3].Subcases[0] = "changed"
	second := FixedCases()
	if second[0].TestID != "approved-release-boots" || second[3].Subcases[0] != "kernel" {
		t.Fatal("FixedCases exposed mutable package state")
	}
}

func TestRequiredPublicInputNamesReturnsDefensiveCopy(t *testing.T) {
	first := RequiredPublicInputNames()
	first[0] = "changed"
	second := RequiredPublicInputNames()
	if second[0] == "changed" {
		t.Fatal("RequiredPublicInputNames exposed mutable package state")
	}
}

func TestConstructorsProduceValidatedContracts(t *testing.T) {
	plan := validPlan(t)
	byteRecipe := plan.ByteXORMutations[0]
	constructedByte, err := NewByteXORMutationRecipe(
		byteRecipe.TestID, byteRecipe.SubcaseID, byteRecipe.Target,
		byteRecipe.Before, byteRecipe.After,
	)
	if err != nil {
		t.Fatal(err)
	}
	if constructedByte != byteRecipe {
		t.Fatalf("constructed byte recipe differs: %#v", constructedByte)
	}

	replacement := plan.BoundReplacements[0]
	constructedReplacement, err := NewBoundReplacementMutationRecipe(
		replacement.TestID, replacement.SubcaseID, replacement.Before, replacement.After,
	)
	if err != nil {
		t.Fatal(err)
	}
	if constructedReplacement != replacement {
		t.Fatalf("constructed replacement differs: %#v", constructedReplacement)
	}

	constructedPlan, err := NewPlan(
		plan.CampaignID, plan.PublicInputs, plan.ByteXORMutations, plan.BoundReplacements,
	)
	if err != nil {
		t.Fatal(err)
	}
	if constructedPlan.PlanDigest != plan.PlanDigest {
		t.Fatalf("constructed plan digest %q, want %q", constructedPlan.PlanDigest, plan.PlanDigest)
	}
}

func TestFixedCasesMatchEvidenceProfile(t *testing.T) {
	evidenceIDs := stableevidence.MandatoryTestIDs()
	cases := FixedCases()
	if len(cases) != len(evidenceIDs) {
		t.Fatalf("contract has %d cases, evidence requires %d", len(cases), len(evidenceIDs))
	}
	for index, testID := range evidenceIDs {
		if cases[index].TestID != testID {
			t.Fatalf("contract case %d is %q, evidence requires %q", index, cases[index].TestID, testID)
		}
	}
}

func validPlan(t *testing.T) Plan {
	t.Helper()
	names := expectedPublicInputNames()
	inputs := make([]ArtifactBinding, len(names))
	byName := make(map[string]ArtifactBinding, len(names))
	for index, name := range names {
		binding := ArtifactBinding{Name: name, Digest: testDigest(index + 1), SizeBytes: uint64(index + 1)}
		inputs[index] = binding
		byName[name] = binding
	}

	byteRecipes := make([]ByteXORMutationRecipe, 0, len(expectedByteRecipeKeys()))
	for index, pair := range expectedByteRecipeKeys() {
		target, _ := expectedByteTarget(pair[0], pair[1])
		if pair[1] == "overlay" {
			target = "release/overlays/campaign.dtbo"
		}
		name := byteBindingName(pair[0], pair[1])
		byteRecipes = append(byteRecipes, ByteXORMutationRecipe{
			SchemaVersion: ByteXORSchemaV1Alpha1, RecipeID: recipeID(pair[0], pair[1]),
			TestID: pair[0], SubcaseID: pair[1], SafetyBoundary: PublicSafetyBoundary(),
			Target:      target,
			Before:      ArtifactBinding{Name: name, Digest: testDigest(100 + index), SizeBytes: 4096},
			After:       ArtifactBinding{Name: name, Digest: testDigest(200 + index), SizeBytes: 4096},
			OffsetBytes: 0, XORMask: 1,
		})
	}

	positive := byName["positive-release-manifest"]
	replacements := make([]BoundReplacementMutationRecipe, 0, len(expectedReplacementRecipeKeys()))
	for _, pair := range expectedReplacementRecipeKeys() {
		inputName := replacementInputName(pair[0], pair[1])
		selector := "$"
		if pair[0] == "manifest-field-mutations-rejected" {
			selector = manifestSelectors[pair[1]]
		}
		replacements = append(replacements, BoundReplacementMutationRecipe{
			SchemaVersion: ReplacementSchemaV1Alpha1, RecipeID: recipeID(pair[0], pair[1]),
			TestID: pair[0], SubcaseID: pair[1], SafetyBoundary: PublicSafetyBoundary(),
			Target: "release/release-manifest.json", Before: positive, After: byName[inputName],
			ReplacementInput: inputName, DifferenceSelector: selector,
		})
	}

	plan := Plan{
		SchemaVersion: PlanSchemaV1Alpha1, CampaignID: "campaign-1", CampaignProfile: CampaignProfile,
		DeviceClass: DeviceClass, SafetyBoundary: PublicSafetyBoundary(), PublicInputs: inputs,
		Cases: FixedCases(), ByteXORMutations: byteRecipes, BoundReplacements: replacements,
	}
	sealed, err := plan.Seal()
	if err != nil {
		t.Fatalf("seal valid plan: %v", err)
	}
	return sealed
}

func testDigest(value int) bundle.Digest {
	return bundle.Digest(fmt.Sprintf("sha256:%064x", value))
}
