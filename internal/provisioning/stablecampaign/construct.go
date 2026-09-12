package stablecampaign

// NewByteXORMutationRecipe constructs the sole byte mutation accepted by this
// campaign: bit zero of byte zero in one fixed target. Before and after remain
// public bindings; no target bytes cross this API.
func NewByteXORMutationRecipe(
	testID, subcaseID, target string,
	before, after ArtifactBinding,
) (ByteXORMutationRecipe, error) {
	recipe := ByteXORMutationRecipe{
		SchemaVersion:  ByteXORSchemaV1Alpha1,
		RecipeID:       recipeID(testID, subcaseID),
		TestID:         testID,
		SubcaseID:      subcaseID,
		SafetyBoundary: PublicSafetyBoundary(),
		Target:         target,
		Before:         before,
		After:          after,
		OffsetBytes:    0,
		XORMask:        1,
	}
	if err := recipe.Validate(); err != nil {
		return ByteXORMutationRecipe{}, err
	}
	return recipe, nil
}

// NewBoundReplacementMutationRecipe constructs the one manifest-file
// replacement assigned to a fixed replacement subcase. Its public input name
// and semantic difference selector are derived rather than caller-selected.
func NewBoundReplacementMutationRecipe(
	testID, subcaseID string,
	before, after ArtifactBinding,
) (BoundReplacementMutationRecipe, error) {
	selector := "$"
	if testID == "manifest-field-mutations-rejected" {
		selector = manifestSelectors[subcaseID]
	}
	recipe := BoundReplacementMutationRecipe{
		SchemaVersion:      ReplacementSchemaV1Alpha1,
		RecipeID:           recipeID(testID, subcaseID),
		TestID:             testID,
		SubcaseID:          subcaseID,
		SafetyBoundary:     PublicSafetyBoundary(),
		Target:             "release/release-manifest.json",
		Before:             before,
		After:              after,
		ReplacementInput:   replacementInputName(testID, subcaseID),
		DifferenceSelector: selector,
	}
	if err := recipe.Validate(); err != nil {
		return BoundReplacementMutationRecipe{}, err
	}
	return recipe, nil
}

// NewPlan fills every invariant campaign field and seals the canonical plan.
// Inputs and recipes must already be in the package's declared canonical
// order; silent sorting could conceal an accidentally duplicated subcase.
func NewPlan(
	campaignID string,
	publicInputs []ArtifactBinding,
	byteXORMutations []ByteXORMutationRecipe,
	boundReplacements []BoundReplacementMutationRecipe,
) (Plan, error) {
	plan := Plan{
		SchemaVersion:     PlanSchemaV1Alpha1,
		CampaignID:        campaignID,
		CampaignProfile:   CampaignProfile,
		DeviceClass:       DeviceClass,
		SafetyBoundary:    PublicSafetyBoundary(),
		PublicInputs:      append([]ArtifactBinding(nil), publicInputs...),
		Cases:             FixedCases(),
		ByteXORMutations:  append([]ByteXORMutationRecipe(nil), byteXORMutations...),
		BoundReplacements: append([]BoundReplacementMutationRecipe(nil), boundReplacements...),
	}
	return plan.Seal()
}
