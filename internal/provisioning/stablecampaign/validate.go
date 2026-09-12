package stablecampaign

import (
	"errors"
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
)

var (
	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,127}$`)
	overlayTarget     = regexp.MustCompile(`^release/overlays/[a-z0-9][a-z0-9_-]{0,63}\.dtbo$`)

	fixedCases = []LogicalCase{
		{TestID: "approved-release-boots", Subcases: []string{"positive-baseline"}},
		{TestID: "authorization-offline-rejected", Subcases: []string{"authority-offline"}},
		{TestID: "authorization-replay-rejected", Subcases: []string{"stale-authorization"}},
		{TestID: "component-byte-mutations-rejected", Subcases: []string{
			"kernel", "initramfs", "resolved-device-tree", "kernel-command-line",
			"root-image", "dm-verity-metadata", "slot-metadata", "overlay",
		}},
		{TestID: "delegated-key-replacement-boots", Subcases: []string{"replacement-manifest"}},
		{TestID: "dm-verity-corruption-rejected", Subcases: []string{"root-data", "root-hash"}},
		{TestID: "kernel-command-line-observed", Subcases: []string{"positive-baseline"}},
		{TestID: "manifest-field-mutations-rejected", Subcases: []string{
			"schema-version", "release-id", "device-class", "cohort-id", "policy-digest",
			"security-epoch", "slot-id", "component-role", "component-digest",
			"component-size-bytes", "overlay-name", "overlay-digest", "overlay-size-bytes",
			"signature-key-id", "signature-algorithm", "signature-value",
		}},
		{TestID: "one-boot-key-bound", Subcases: []string{"positive-baseline"}},
		{TestID: "released-os-bootstrap-reuse-rejected", Subcases: []string{"positive-baseline"}},
		{TestID: "resolved-device-tree-observed", Subcases: []string{"positive-baseline"}},
		{TestID: "revoked-delegated-key-rejected", Subcases: []string{"revoked-manifest"}},
		{TestID: "unsigned-release-rejected", Subcases: []string{"unsigned-manifest"}},
		{TestID: "wrong-delegated-key-rejected", Subcases: []string{"wrong-key-manifest"}},
	}

	componentTargets = map[string]string{
		"kernel":               "release/kernel",
		"initramfs":            "release/initramfs",
		"resolved-device-tree": "release/device-tree.dtb",
		"kernel-command-line":  "release/cmdline.txt",
		"root-image":           "release/root.img",
		"dm-verity-metadata":   "release/dm-verity.json",
		"slot-metadata":        "release/slot.txt",
	}

	manifestSelectors = map[string]string{
		"schema-version":       "/schema_version",
		"release-id":           "/release_id",
		"device-class":         "/device_class",
		"cohort-id":            "/cohort_id",
		"policy-digest":        "/policy_digest",
		"security-epoch":       "/security_epoch",
		"slot-id":              "/slot_id",
		"component-role":       "/components/0/role",
		"component-digest":     "/components/0/digest",
		"component-size-bytes": "/components/0/size_bytes",
		"overlay-name":         "/overlays/0/name",
		"overlay-digest":       "/overlays/0/digest",
		"overlay-size-bytes":   "/overlays/0/size_bytes",
		"signature-key-id":     "/signatures/0/key_id",
		"signature-algorithm":  "/signatures/0/algorithm",
		"signature-value":      "/signatures/0/value",
	}
)

var basePublicInputNames = []string{
	"authorization-trust-anchor",
	"customer-boot-public-key",
	"positive-release-manifest",
	"positive-release-tree",
	"release-policy-root-public-key",
	"stable-verifier-policy",
	"unsigned-verifier-boot",
}

// RequiredPublicInputNames returns the exact sorted public artifact vocabulary
// for the fixed campaign. It includes one separately bound manifest artifact
// for every whole-file replacement recipe.
func RequiredPublicInputNames() []string { return expectedPublicInputNames() }

// FixedCases returns a defensive copy of the exact logical result and subcase
// matrix. Callers cannot weaken the campaign by mutating the returned value.
func FixedCases() []LogicalCase {
	result := make([]LogicalCase, len(fixedCases))
	for index, testCase := range fixedCases {
		result[index] = LogicalCase{
			TestID:   testCase.TestID,
			Subcases: append([]string(nil), testCase.Subcases...),
		}
	}
	return result
}

func (boundary SafetyBoundary) validate() error {
	if boundary != publicSafetyBoundary() {
		return errors.New("safety_boundary must remain development-only, private-material-free, non-production, non-signing, and non-writing")
	}
	return nil
}

func (binding ArtifactBinding) validate(label string) error {
	if !identifierPattern.MatchString(binding.Name) || strings.Contains(binding.Name, "..") {
		return fmt.Errorf("%s.name must be a canonical public input identifier", label)
	}
	if err := binding.Digest.Validate(); err != nil {
		return fmt.Errorf("%s.digest: %w", label, err)
	}
	if binding.SizeBytes == 0 || binding.SizeBytes > math.MaxInt64 {
		return fmt.Errorf("%s.size_bytes must be between 1 and %d", label, int64(math.MaxInt64))
	}
	return nil
}

func validateTarget(target string) error {
	if target == "" || len(target) > 255 || strings.Contains(target, `\`) || strings.ContainsRune(target, '\x00') ||
		strings.HasPrefix(target, "/") || path.Clean(target) != target ||
		strings.HasPrefix(target, "../") || strings.Contains(target, "/../") {
		return errors.New("target must be a clean canonical relative campaign target")
	}
	return nil
}

func recipeID(testID, subcaseID string) string { return testID + ":" + subcaseID }

func byteBindingName(testID, subcaseID string) string { return testID + "-" + subcaseID }

func replacementInputName(testID, subcaseID string) string {
	if testID == "manifest-field-mutations-rejected" {
		return "manifest-field-" + subcaseID
	}
	switch testID {
	case "delegated-key-replacement-boots":
		return "replacement-release-manifest"
	case "revoked-delegated-key-rejected":
		return "revoked-release-manifest"
	case "unsigned-release-rejected":
		return "unsigned-release-manifest"
	case "wrong-delegated-key-rejected":
		return "wrong-key-release-manifest"
	default:
		return ""
	}
}

func expectedByteRecipeKeys() [][2]string {
	result := make([][2]string, 0, 10)
	for _, subcase := range fixedCases[3].Subcases {
		result = append(result, [2]string{fixedCases[3].TestID, subcase})
	}
	for _, subcase := range fixedCases[5].Subcases {
		result = append(result, [2]string{fixedCases[5].TestID, subcase})
	}
	sort.Slice(result, func(i, j int) bool {
		return recipeID(result[i][0], result[i][1]) < recipeID(result[j][0], result[j][1])
	})
	return result
}

func containsRecipePair(pairs [][2]string, testID, subcaseID string) bool {
	for _, pair := range pairs {
		if pair[0] == testID && pair[1] == subcaseID {
			return true
		}
	}
	return false
}

func expectedByteTarget(testID, subcaseID string) (string, bool) {
	if testID == "component-byte-mutations-rejected" {
		if subcaseID == "overlay" {
			return "", true
		}
		target, ok := componentTargets[subcaseID]
		return target, ok
	}
	if testID == "dm-verity-corruption-rejected" {
		switch subcaseID {
		case "root-data":
			return "media/root-data", true
		case "root-hash":
			return "media/root-hash", true
		}
	}
	return "", false
}

func expectedReplacementRecipeKeys() [][2]string {
	result := make([][2]string, 0, 20)
	for _, testCase := range fixedCases {
		switch testCase.TestID {
		case "delegated-key-replacement-boots", "manifest-field-mutations-rejected",
			"revoked-delegated-key-rejected", "unsigned-release-rejected", "wrong-delegated-key-rejected":
			for _, subcase := range testCase.Subcases {
				result = append(result, [2]string{testCase.TestID, subcase})
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return recipeID(result[i][0], result[i][1]) < recipeID(result[j][0], result[j][1])
	})
	return result
}

func expectedPublicInputNames() []string {
	names := append([]string(nil), basePublicInputNames...)
	for _, pair := range expectedReplacementRecipeKeys() {
		names = append(names, replacementInputName(pair[0], pair[1]))
	}
	sort.Strings(names)
	return names
}

func (recipe ByteXORMutationRecipe) Validate() error {
	if recipe.SchemaVersion != ByteXORSchemaV1Alpha1 {
		return fmt.Errorf("unsupported byte-XOR recipe schema_version %q", recipe.SchemaVersion)
	}
	if recipe.RecipeID != recipeID(recipe.TestID, recipe.SubcaseID) {
		return errors.New("byte-XOR recipe_id must bind test_id and subcase_id")
	}
	if !containsRecipePair(expectedByteRecipeKeys(), recipe.TestID, recipe.SubcaseID) {
		return errors.New("byte-XOR recipe does not identify a fixed mutation subcase")
	}
	if err := recipe.SafetyBoundary.validate(); err != nil {
		return err
	}
	if err := validateTarget(recipe.Target); err != nil {
		return err
	}
	if err := recipe.Before.validate("before"); err != nil {
		return err
	}
	if err := recipe.After.validate("after"); err != nil {
		return err
	}
	expectedName := byteBindingName(recipe.TestID, recipe.SubcaseID)
	if recipe.Before.Name != expectedName || recipe.After.Name != expectedName || recipe.Before.SizeBytes != recipe.After.SizeBytes {
		return errors.New("byte-XOR before and after bindings must name the same equal-sized target")
	}
	if recipe.Before.Digest == recipe.After.Digest {
		return errors.New("byte-XOR after digest must differ from before digest")
	}
	if recipe.OffsetBytes >= recipe.Before.SizeBytes {
		return errors.New("byte-XOR offset_bytes must identify one byte within the target")
	}
	if recipe.OffsetBytes != 0 || recipe.XORMask != 1 {
		return errors.New("campaign byte-XOR mutation must flip bit zero of byte zero")
	}
	expectedTarget, _ := expectedByteTarget(recipe.TestID, recipe.SubcaseID)
	if recipe.SubcaseID == "overlay" {
		if !overlayTarget.MatchString(recipe.Target) {
			return errors.New("overlay mutation must target one canonical release overlay")
		}
	} else if recipe.Target != expectedTarget {
		return fmt.Errorf("byte-XOR recipe must target %q", expectedTarget)
	}
	return nil
}

func (recipe BoundReplacementMutationRecipe) Validate() error {
	if recipe.SchemaVersion != ReplacementSchemaV1Alpha1 {
		return fmt.Errorf("unsupported replacement recipe schema_version %q", recipe.SchemaVersion)
	}
	if recipe.RecipeID != recipeID(recipe.TestID, recipe.SubcaseID) {
		return errors.New("replacement recipe_id must bind test_id and subcase_id")
	}
	if !containsRecipePair(expectedReplacementRecipeKeys(), recipe.TestID, recipe.SubcaseID) {
		return errors.New("replacement recipe does not identify a fixed mutation subcase")
	}
	if err := recipe.SafetyBoundary.validate(); err != nil {
		return err
	}
	if err := validateTarget(recipe.Target); err != nil {
		return err
	}
	if err := recipe.Before.validate("before"); err != nil {
		return err
	}
	if err := recipe.After.validate("after"); err != nil {
		return err
	}
	if recipe.Before.Digest == recipe.After.Digest {
		return errors.New("replacement after digest must differ from before digest")
	}
	expectedInput := replacementInputName(recipe.TestID, recipe.SubcaseID)
	if recipe.Before.Name != "positive-release-manifest" || recipe.After.Name != expectedInput ||
		recipe.ReplacementInput != expectedInput {
		return errors.New("replacement_input must name the bound public after artifact")
	}
	if recipe.Target != "release/release-manifest.json" {
		return errors.New("replacement recipe must target the delegated release manifest")
	}
	expectedSelector := "$"
	if recipe.TestID == "manifest-field-mutations-rejected" {
		expectedSelector = manifestSelectors[recipe.SubcaseID]
	}
	if recipe.DifferenceSelector != expectedSelector {
		return fmt.Errorf("difference_selector must be %q", expectedSelector)
	}
	return nil
}

func (plan Plan) validate(includeDigest bool) error {
	if plan.SchemaVersion != PlanSchemaV1Alpha1 {
		return fmt.Errorf("unsupported campaign plan schema_version %q", plan.SchemaVersion)
	}
	if !identifierPattern.MatchString(plan.CampaignID) {
		return errors.New("campaign_id must be a canonical identifier")
	}
	if plan.CampaignProfile != CampaignProfile || plan.DeviceClass != DeviceClass {
		return errors.New("campaign_profile and device_class must identify the fixed Raspberry Pi 5 campaign")
	}
	if err := plan.SafetyBoundary.validate(); err != nil {
		return err
	}
	if err := plan.validatePublicInputs(); err != nil {
		return err
	}
	if err := validateCases(plan.Cases); err != nil {
		return err
	}
	if err := plan.validateByteRecipes(); err != nil {
		return err
	}
	if err := plan.validateReplacementRecipes(); err != nil {
		return err
	}
	if includeDigest {
		if err := plan.PlanDigest.Validate(); err != nil {
			return fmt.Errorf("plan_digest: %w", err)
		}
		derived, err := plan.DerivedDigest()
		if err != nil {
			return err
		}
		if plan.PlanDigest != derived {
			return errors.New("plan_digest does not bind the canonical campaign plan")
		}
	}
	return nil
}

// Validate requires the fixed campaign matrix, exact recipe coverage, public-
// only safety boundary, canonical ordering, and a matching plan digest.
func (plan Plan) Validate() error { return plan.validate(true) }

func (plan Plan) validatePublicInputs() error {
	expected := expectedPublicInputNames()
	if len(plan.PublicInputs) != len(expected) {
		return fmt.Errorf("public_inputs must contain the exact %d public artifacts", len(expected))
	}
	digests := make(map[string]string, len(plan.PublicInputs))
	for index, binding := range plan.PublicInputs {
		if binding.Name != expected[index] {
			return fmt.Errorf("public_inputs[%d].name must be %q", index, expected[index])
		}
		if err := binding.validate(fmt.Sprintf("public_inputs[%d]", index)); err != nil {
			return err
		}
		if previous, duplicate := digests[string(binding.Digest)]; duplicate {
			return fmt.Errorf("public_inputs %q and %q must not bind the same digest", previous, binding.Name)
		}
		digests[string(binding.Digest)] = binding.Name
	}
	return nil
}

func validateCases(cases []LogicalCase) error {
	if len(cases) != len(fixedCases) {
		return fmt.Errorf("cases must contain the exact %d logical results", len(fixedCases))
	}
	for caseIndex, expected := range fixedCases {
		actual := cases[caseIndex]
		if actual.TestID != expected.TestID {
			return fmt.Errorf("cases[%d].test_id must be %q", caseIndex, expected.TestID)
		}
		if len(actual.Subcases) != len(expected.Subcases) {
			return fmt.Errorf("case %q must contain the exact %d subcases", expected.TestID, len(expected.Subcases))
		}
		for subcaseIndex, expectedSubcase := range expected.Subcases {
			if actual.Subcases[subcaseIndex] != expectedSubcase {
				return fmt.Errorf("case %q subcases[%d] must be %q", expected.TestID, subcaseIndex, expectedSubcase)
			}
		}
	}
	return nil
}

func (plan Plan) validateByteRecipes() error {
	expected := expectedByteRecipeKeys()
	if len(plan.ByteXORMutations) != len(expected) {
		return fmt.Errorf("byte_xor_mutations must contain the exact %d mutation subcases", len(expected))
	}
	for index, pair := range expected {
		recipe := plan.ByteXORMutations[index]
		if recipe.TestID != pair[0] || recipe.SubcaseID != pair[1] || recipe.RecipeID != recipeID(pair[0], pair[1]) {
			return fmt.Errorf("byte_xor_mutations[%d] must be recipe %q", index, recipeID(pair[0], pair[1]))
		}
		if err := recipe.Validate(); err != nil {
			return fmt.Errorf("byte_xor_mutations[%d]: %w", index, err)
		}
	}
	return nil
}

func (plan Plan) validateReplacementRecipes() error {
	expected := expectedReplacementRecipeKeys()
	if len(plan.BoundReplacements) != len(expected) {
		return fmt.Errorf("bound_replacements must contain the exact %d mutation subcases", len(expected))
	}
	inputs := make(map[string]ArtifactBinding, len(plan.PublicInputs))
	for _, input := range plan.PublicInputs {
		inputs[input.Name] = input
	}
	positive := inputs["positive-release-manifest"]
	for index, pair := range expected {
		recipe := plan.BoundReplacements[index]
		if recipe.TestID != pair[0] || recipe.SubcaseID != pair[1] || recipe.RecipeID != recipeID(pair[0], pair[1]) {
			return fmt.Errorf("bound_replacements[%d] must be recipe %q", index, recipeID(pair[0], pair[1]))
		}
		if err := recipe.Validate(); err != nil {
			return fmt.Errorf("bound_replacements[%d]: %w", index, err)
		}
		if recipe.Target != "release/release-manifest.json" || recipe.Before != positive {
			return fmt.Errorf("replacement recipe %q must replace the bound positive manifest", recipe.RecipeID)
		}
		expectedInput := replacementInputName(pair[0], pair[1])
		if recipe.ReplacementInput != expectedInput || recipe.After != inputs[expectedInput] {
			return fmt.Errorf("replacement recipe %q does not bind public input %q", recipe.RecipeID, expectedInput)
		}
		expectedSelector := "$"
		if pair[0] == "manifest-field-mutations-rejected" {
			expectedSelector = manifestSelectors[pair[1]]
		}
		if recipe.DifferenceSelector != expectedSelector {
			return fmt.Errorf("replacement recipe %q difference_selector must be %q", recipe.RecipeID, expectedSelector)
		}
	}
	return nil
}
