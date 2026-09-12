package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stableverifier"
)

func TestRunConstructsDeterministicResolvedPublicPlan(t *testing.T) {
	fixture := newCLIFixture(t)
	var first, firstError bytes.Buffer
	if exit := run(fixture.arguments(false), &first, &firstError); exit != exitOK {
		t.Fatalf("first run exit = %d, stderr = %s", exit, firstError.String())
	}
	if !bytes.HasSuffix(first.Bytes(), []byte{'\n'}) || bytes.HasSuffix(first.Bytes(), []byte("\n\n")) {
		t.Fatalf("output does not have exactly one transport LF: %q", first.Bytes())
	}
	plan, err := stablecampaign.ParsePlan(first.Bytes())
	if err != nil {
		t.Fatalf("parse generated plan: %v", err)
	}
	if plan.CampaignID != "campaign-plan-test" || len(plan.PublicInputs) != 27 ||
		len(plan.ByteXORMutations) != 10 || len(plan.BoundReplacements) != 20 {
		t.Fatalf("generated plan is incomplete: %#v", plan)
	}
	for _, path := range fixture.publicPaths {
		if bytes.Contains(first.Bytes(), []byte(path)) {
			t.Fatalf("generated plan retained host path %q", path)
		}
	}

	var second, secondError bytes.Buffer
	if exit := run(fixture.arguments(true), &second, &secondError); exit != exitOK {
		t.Fatalf("reordered run exit = %d, stderr = %s", exit, secondError.String())
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("flag order changed deterministic campaign plan")
	}
}

func TestRunHelpListsTheExactNamedInterface(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if exit := run([]string{"--help"}, &stdout, &stderr); exit != exitOK {
		t.Fatalf("help exit = %d", exit)
	}
	if stdout.Len() != 0 {
		t.Fatalf("help wrote stdout: %q", stdout.String())
	}
	for _, required := range []string{
		"authorization-trust-anchor",
		"manifest-field-signature-value",
		"wrong-key-release-manifest",
		"media/root-data",
		"release/kernel",
		"release/overlays/<canonical-name>.dtbo (exactly one)",
	} {
		if !strings.Contains(stderr.String(), required) {
			t.Fatalf("help omitted %q: %s", required, stderr.String())
		}
	}
}

func TestRunWritesCreateOnlyOutputWithCanonicalTransport(t *testing.T) {
	fixture := newCLIFixture(t)
	output := filepath.Join(fixture.root, "campaign-plan.json")
	arguments := append(fixture.arguments(false), "--output", output)
	var stdout, stderr bytes.Buffer
	if exit := run(arguments, &stdout, &stderr); exit != exitOK {
		t.Fatalf("run exit = %d, stderr = %s", exit, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("file output also wrote stdout: %q", stdout.String())
	}
	encoded, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(output)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 {
		t.Fatalf("published output mode = %v, want regular 0444", info.Mode())
	}
	if !bytes.HasSuffix(encoded, []byte{'\n'}) {
		t.Fatal("file output lacks transport LF")
	}
	if _, err := stablecampaign.ParsePlan(encoded); err != nil {
		t.Fatalf("file output is not a canonical plan: %v", err)
	}

	original := append([]byte(nil), encoded...)
	stdout.Reset()
	stderr.Reset()
	if exit := run(arguments, &stdout, &stderr); exit != exitInvalid {
		t.Fatalf("overwrite exit = %d, want %d", exit, exitInvalid)
	}
	after, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("existing output was changed")
	}
}

func TestRunLeavesNoNamedOutputWhenPublicationFails(t *testing.T) {
	fixture := newCLIFixture(t)
	output := filepath.Join(fixture.root, "campaign-plan-publication-failure.json")
	previous := publishCanonicalNew
	publishCanonicalNew = func(path string, contents []byte) error {
		if path != output || len(contents) == 0 || contents[len(contents)-1] != '\n' {
			t.Fatalf("publication received path %q and %d bytes", path, len(contents))
		}
		return errors.New("injected publication failure")
	}
	t.Cleanup(func() { publishCanonicalNew = previous })

	arguments := append(fixture.arguments(false), "--output", output)
	assertInvalidFailureContains(t, arguments, "injected publication failure")
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed publication left a named output: %v", err)
	}
}

func TestRunRejectsInexactAndAmbiguousOptions(t *testing.T) {
	fixture := newCLIFixture(t)
	valid := fixture.arguments(false)
	tests := map[string][]string{
		"missing campaign id":       valid[2:],
		"duplicate campaign id":     append(append([]string(nil), valid...), "--campaign-id", "second"),
		"positional argument":       append(append([]string(nil), valid...), "unexpected"),
		"unknown option":            append(append([]string(nil), valid...), "--not-an-option"),
		"relative output":           append(append([]string(nil), valid...), "--output", "relative.json"),
		"noncanonical output":       append(append([]string(nil), valid...), "--output", fixture.root+"/sub/../plan"),
		"duplicate output":          append(append(append([]string(nil), valid...), "--output", filepath.Join(fixture.root, "one")), "--output", filepath.Join(fixture.root, "two")),
		"malformed named input":     append(append([]string(nil), valid...), "--public-input", "not-a-pair"),
		"relative named input":      append(append([]string(nil), valid...), "--public-input", "extra=relative"),
		"device named input":        append(append([]string(nil), valid...), "--public-input", "extra=/dev/null"),
		"duplicate named input":     append(append([]string(nil), valid...), "--public-input", "stable-verifier-policy="+fixture.publicPaths["stable-verifier-policy"]),
		"duplicate mutation target": append(append([]string(nil), valid...), "--byte-mutation-target", "release/kernel="+fixture.targetPaths["release/kernel"]),
		"invalid campaign id":       append([]string{"--campaign-id", "INVALID"}, valid[2:]...),
	}
	for name, arguments := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if exit := run(arguments, &stdout, &stderr); exit != exitUsage {
				t.Fatalf("exit = %d, want %d; stderr = %s", exit, exitUsage, stderr.String())
			}
			if stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunRejectsMissingAndExtraDeclaredNames(t *testing.T) {
	fixture := newCLIFixture(t)
	t.Run("public input", func(t *testing.T) {
		arguments := fixture.argumentsWithout("--public-input", "stable-verifier-policy", "")
		arguments = append(arguments, "--public-input", "undeclared="+fixture.publicPaths["stable-verifier-policy"])
		assertUsageFailure(t, arguments)
	})
	t.Run("fixed target", func(t *testing.T) {
		arguments := fixture.argumentsWithout("--byte-mutation-target", "release/kernel", "")
		arguments = append(arguments, "--byte-mutation-target", "release/undeclared="+fixture.targetPaths["release/kernel"])
		assertUsageFailure(t, arguments)
	})
	t.Run("second nonfixed target", func(t *testing.T) {
		arguments := fixture.argumentsWithout("--byte-mutation-target", fixture.overlayTarget, "")
		arguments = append(arguments,
			"--byte-mutation-target", "release/overlays/first.dtbo="+fixture.targetPaths[fixture.overlayTarget],
			"--byte-mutation-target", "release/overlays/second.dtbo="+fixture.targetPaths[fixture.overlayTarget],
		)
		assertUsageFailure(t, arguments)
	})
}

func TestRunRejectsNoncanonicalOverlayThroughStableCampaignConstructor(t *testing.T) {
	fixture := newCLIFixture(t)
	arguments := fixture.argumentsWithout("--byte-mutation-target", fixture.overlayTarget, "")
	arguments = append(arguments, "--byte-mutation-target", "release/overlays/Bad.dtbo="+fixture.targetPaths[fixture.overlayTarget])
	var stdout, stderr bytes.Buffer
	if exit := run(arguments, &stdout, &stderr); exit != exitInvalid {
		t.Fatalf("exit = %d, want %d; stderr = %s", exit, exitInvalid, stderr.String())
	}
	if !strings.Contains(stderr.String(), "canonical release overlay") {
		t.Fatalf("unexpected error: %s", stderr.String())
	}
}

func TestRunRejectsSymlinksSpecialFilesEmptyFilesAndSymlinkAncestors(t *testing.T) {
	t.Run("final symlink", func(t *testing.T) {
		fixture := newCLIFixture(t)
		link := filepath.Join(fixture.root, "public-link")
		if err := os.Symlink(fixture.publicPaths["stable-verifier-policy"], link); err != nil {
			t.Fatal(err)
		}
		fixture.publicPaths["stable-verifier-policy"] = link
		assertInvalidFailureContains(t, fixture.arguments(false), "symlink")
	})
	t.Run("symlink ancestor", func(t *testing.T) {
		fixture := newCLIFixture(t)
		realDirectory := filepath.Dir(fixture.publicPaths["stable-verifier-policy"])
		linkDirectory := filepath.Join(fixture.root, "linked-directory")
		if err := os.Symlink(realDirectory, linkDirectory); err != nil {
			t.Fatal(err)
		}
		fixture.publicPaths["stable-verifier-policy"] = filepath.Join(linkDirectory, "stable-verifier-policy")
		assertInvalidFailureContains(t, fixture.arguments(false), "symlink")
	})
	t.Run("directory", func(t *testing.T) {
		fixture := newCLIFixture(t)
		fixture.publicPaths["stable-verifier-policy"] = fixture.root
		assertInvalidFailureContains(t, fixture.arguments(false), "regular non-symlink")
	})
	t.Run("empty", func(t *testing.T) {
		fixture := newCLIFixture(t)
		empty := filepath.Join(fixture.root, "empty")
		if err := os.WriteFile(empty, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		fixture.publicPaths["stable-verifier-policy"] = empty
		assertInvalidFailureContains(t, fixture.arguments(false), "nonempty")
	})
	t.Run("named pipe", func(t *testing.T) {
		fixture := newCLIFixture(t)
		pipe := filepath.Join(fixture.root, "pipe")
		if err := syscall.Mkfifo(pipe, 0o600); err != nil {
			t.Skipf("mkfifo unavailable: %v", err)
		}
		fixture.publicPaths["stable-verifier-policy"] = pipe
		assertInvalidFailureContains(t, fixture.arguments(false), "regular non-symlink")
	})
}

func TestRunRejectsReusedOpenedFileIdentityAcrossRoles(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *cliFixture)
	}{
		{
			name: "same path across public inputs",
			mutate: func(_ *testing.T, fixture *cliFixture) {
				fixture.publicPaths["customer-boot-public-key"] = fixture.publicPaths["authorization-trust-anchor"]
			},
		},
		{
			name: "hard link across public inputs",
			mutate: func(t *testing.T, fixture *cliFixture) {
				link := filepath.Join(fixture.root, "hard-linked-public-input")
				if err := os.Link(fixture.publicPaths["authorization-trust-anchor"], link); err != nil {
					t.Fatal(err)
				}
				fixture.publicPaths["customer-boot-public-key"] = link
			},
		},
		{
			name: "public input and byte target",
			mutate: func(_ *testing.T, fixture *cliFixture) {
				fixture.targetPaths["release/kernel"] = fixture.publicPaths["authorization-trust-anchor"]
			},
		},
		{
			name: "two byte targets",
			mutate: func(_ *testing.T, fixture *cliFixture) {
				fixture.targetPaths["release/initramfs"] = fixture.targetPaths["release/kernel"]
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCLIFixture(t)
			test.mutate(t, &fixture)
			assertInvalidFailureContains(t, fixture.arguments(false), "reuses the same opened file identity")
		})
	}
}

func TestRunAllowsDistinctFilesWithIdenticalContents(t *testing.T) {
	fixture := newCLIFixture(t)
	rootDataPath := fixture.targetPaths["media/root-data"]
	rootHashPath := fixture.targetPaths["media/root-hash"]
	contents, err := os.ReadFile(rootDataPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootHashPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	rootDataInfo, err := os.Stat(rootDataPath)
	if err != nil {
		t.Fatal(err)
	}
	rootHashInfo, err := os.Stat(rootHashPath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(rootDataInfo, rootHashInfo) {
		t.Fatal("test fixture unexpectedly reused one file identity")
	}

	var stdout, stderr bytes.Buffer
	if exit := run(fixture.arguments(false), &stdout, &stderr); exit != exitOK {
		t.Fatalf("run exit = %d, stderr = %s", exit, stderr.String())
	}
	if _, err := stablecampaign.ParsePlan(stdout.Bytes()); err != nil {
		t.Fatalf("parse generated plan: %v", err)
	}
}

func TestInspectSourceStreamsBoundedReadsAndComputesXORWithoutMutation(t *testing.T) {
	contents := bytes.Repeat([]byte{0xa5}, 3*readChunkSize+17)
	original := append([]byte(nil), contents...)
	reader := &guardReaderAt{contents: contents}
	before, after, err := inspectSource(stablecampaign.PublicArtifactSource{
		SizeBytes: uint64(len(contents)), ReaderAt: reader,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), contents...)
	mutated[0] ^= 1
	if before != bundle.Sum(contents) || after != bundle.Sum(mutated) {
		t.Fatalf("digests = (%q, %q), want (%q, %q)", before, after, bundle.Sum(contents), bundle.Sum(mutated))
	}
	if reader.maximum > readChunkSize || reader.total != len(contents) {
		t.Fatalf("read maximum = %d, total = %d", reader.maximum, reader.total)
	}
	if !bytes.Equal(contents, original) {
		t.Fatal("XOR digest computation modified source bytes")
	}
}

func TestInspectSourceRejectsPrivateKeyPEMMarkersAcrossChunkBoundaries(t *testing.T) {
	markers := append([][]byte(nil), privateKeyPEMMarkers...)
	markers = append(markers, []byte("-----BEGIN ML-DSA PRIVATE KEY-----"))
	for _, marker := range markers {
		t.Run(string(marker), func(t *testing.T) {
			prefix := bytes.Repeat([]byte{'x'}, readChunkSize-len(marker)/2)
			contents := append(prefix, marker...)
			contents = append(contents, 'x')
			_, _, err := inspectSource(stablecampaign.PublicArtifactSource{
				SizeBytes: uint64(len(contents)), ReaderAt: bytes.NewReader(contents),
			}, false)
			if err == nil || !strings.Contains(err.Error(), "scoped defense in depth") {
				t.Fatalf("marker was accepted: %v", err)
			}
		})
	}
}

func TestRunRejectsPrivateKeyPEMMarkerInAnySuppliedFileClass(t *testing.T) {
	for _, testCase := range []struct {
		name string
		set  func(*cliFixture, string)
	}{
		{
			name: "public input",
			set: func(fixture *cliFixture, path string) {
				fixture.publicPaths["unsigned-verifier-boot"] = path
			},
		},
		{
			name: "byte mutation target",
			set: func(fixture *cliFixture, path string) {
				fixture.targetPaths["release/kernel"] = path
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newCLIFixture(t)
			path := filepath.Join(fixture.root, "private-marker")
			if err := os.WriteFile(path, []byte("-----BEGIN PRIVATE KEY-----\npublic-test-fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			testCase.set(&fixture, path)
			assertInvalidFailureContains(t, fixture.arguments(false), "scoped defense in depth")
		})
	}
}

func TestRunRejectsSemanticallyWrongReplacement(t *testing.T) {
	fixture := newCLIFixture(t)
	positive, err := os.ReadFile(fixture.publicPaths["positive-release-manifest"])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.publicPaths["manifest-field-schema-version"], positive, 0o600); err != nil {
		t.Fatal(err)
	}
	assertInvalidFailureContains(t, fixture.arguments(false), "must differ from before digest")
}

func TestRunReportsOutputWriterFailure(t *testing.T) {
	fixture := newCLIFixture(t)
	var stderr bytes.Buffer
	exit := run(fixture.arguments(false), errorWriter{}, &stderr)
	if exit != exitInvalid || !strings.Contains(stderr.String(), "write stdout") {
		t.Fatalf("exit = %d, stderr = %s", exit, stderr.String())
	}
}

type cliFixture struct {
	root          string
	publicPaths   map[string]string
	targetPaths   map[string]string
	overlayTarget string
}

func newCLIFixture(t *testing.T) cliFixture {
	t.Helper()
	root := t.TempDir()
	publicDirectory := filepath.Join(root, "public")
	targetDirectory := filepath.Join(root, "targets")
	if err := os.Mkdir(publicDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(targetDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	overlayTarget := "release/overlays/campaign.dtbo"
	targetNames := []string{
		"release/kernel", "release/initramfs", "release/device-tree.dtb", "release/cmdline.txt",
		"release/root.img", "release/dm-verity.json", "release/slot.txt", overlayTarget,
		"media/root-data", "media/root-hash",
	}
	targetBytes := make(map[string][]byte, len(targetNames))
	for index, target := range targetNames {
		contents := []byte{byte(index + 1), 'p', 'u', 'b', 'l', 'i', 'c'}
		if target == "release/cmdline.txt" {
			contents = []byte("console=ttyAMA10,115200n8 ro\n")
		}
		targetBytes[target] = contents
	}
	policy := validPolicy(t)
	policyBytes, err := policy.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	positive := validManifest(t, policyDigest, targetBytes)
	positiveBytes, err := positive.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	publicPaths := make(map[string]string, len(stablecampaign.RequiredPublicInputNames()))
	for _, name := range stablecampaign.RequiredPublicInputNames() {
		contents := []byte("public campaign input: " + name)
		switch {
		case name == "stable-verifier-policy":
			contents = policyBytes
		case name == "positive-release-manifest":
			contents = positiveBytes
		case strings.HasPrefix(name, "manifest-field-"):
			variant := cloneManifest(positive)
			mutateManifestField(&variant, strings.TrimPrefix(name, "manifest-field-"))
			contents = marshalManifest(t, variant)
		case name == "replacement-release-manifest":
			variant := cloneManifest(positive)
			variant.Signatures[0].KeyID = "key-2"
			contents = marshalManifest(t, variant)
		case name == "revoked-release-manifest":
			variant := cloneManifest(positive)
			variant.Signatures[0].KeyID = "revoked-key"
			contents = marshalManifest(t, variant)
		case name == "unsigned-release-manifest":
			variant := cloneManifest(positive)
			variant.Signatures = []stableverifier.RSASignature{}
			contents = marshalManifest(t, variant)
		case name == "wrong-key-release-manifest":
			variant := cloneManifest(positive)
			variant.Signatures[0].KeyID = "wrong-key"
			contents = marshalManifest(t, variant)
		}
		path := filepath.Join(publicDirectory, name)
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
		publicPaths[name] = path
	}
	targetPaths := make(map[string]string, len(targetNames))
	for _, target := range targetNames {
		path := filepath.Join(targetDirectory, "target-"+strings.ReplaceAll(target, "/", "-"))
		if err := os.WriteFile(path, targetBytes[target], 0o600); err != nil {
			t.Fatal(err)
		}
		targetPaths[target] = path
	}
	return cliFixture{root: root, publicPaths: publicPaths, targetPaths: targetPaths, overlayTarget: overlayTarget}
}

func (fixture cliFixture) arguments(reverse bool) []string {
	arguments := []string{"--campaign-id", "campaign-plan-test"}
	publicNames := stablecampaign.RequiredPublicInputNames()
	targetNames := sortedKeys(fixture.targetPaths)
	if reverse {
		reverseStrings(publicNames)
		reverseStrings(targetNames)
	}
	for _, name := range publicNames {
		arguments = append(arguments, "--public-input", name+"="+fixture.publicPaths[name])
	}
	for _, target := range targetNames {
		arguments = append(arguments, "--byte-mutation-target", target+"="+fixture.targetPaths[target])
	}
	return arguments
}

func (fixture cliFixture) argumentsWithout(option, name, replacement string) []string {
	arguments := fixture.arguments(false)
	result := make([]string, 0, len(arguments))
	for index := 0; index < len(arguments); index++ {
		if arguments[index] == option && index+1 < len(arguments) && strings.HasPrefix(arguments[index+1], name+"=") {
			index++
			if replacement != "" {
				result = append(result, option, replacement)
			}
			continue
		}
		result = append(result, arguments[index])
	}
	return result
}

func validPolicy(t *testing.T) stableverifier.Policy {
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

func validManifest(
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
		ReleaseID:     "release-1", DeviceClass: stableverifier.DeviceClass,
		CohortID: "cohort-1", PolicyDigest: policyDigest,
		SecurityEpoch: 1, SlotID: "a", Components: components,
		Overlays: []stableverifier.Overlay{{
			Name: "campaign", Digest: bundle.Sum(overlayBytes), SizeBytes: uint64(len(overlayBytes)),
		}},
		Signatures: []stableverifier.RSASignature{{
			KeyID: "key-1", Algorithm: stableverifier.RSA2048SHA256Algorithm,
			Value: base64.StdEncoding.EncodeToString(make([]byte, 256)),
		}},
	}
	if _, err := manifest.CanonicalJSON(); err != nil {
		t.Fatalf("construct valid manifest: %v", err)
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
		panic("unhandled manifest field " + subcase)
	}
}

func cloneManifest(source stableverifier.Manifest) stableverifier.Manifest {
	clone := source
	clone.Components = append([]stableverifier.Component(nil), source.Components...)
	clone.Overlays = append([]stableverifier.Overlay(nil), source.Overlays...)
	clone.Signatures = append([]stableverifier.RSASignature(nil), source.Signatures...)
	return clone
}

func marshalManifest(t *testing.T, manifest stableverifier.Manifest) []byte {
	t.Helper()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type guardReaderAt struct {
	contents []byte
	maximum  int
	total    int
}

func (reader *guardReaderAt) ReadAt(destination []byte, offset int64) (int, error) {
	if len(destination) > reader.maximum {
		reader.maximum = len(destination)
	}
	if len(destination) > readChunkSize {
		return 0, errors.New("unbounded read")
	}
	if offset < 0 || offset >= int64(len(reader.contents)) {
		return 0, io.EOF
	}
	n := copy(destination, reader.contents[offset:])
	reader.total += n
	if n < len(destination) {
		return n, io.EOF
	}
	return n, nil
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("injected write failure") }

func sortedKeys(values map[string]string) []string {
	result := make([]string, 0, len(values))
	for name := range values {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func reverseStrings(values []string) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func assertUsageFailure(t *testing.T, arguments []string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if exit := run(arguments, &stdout, &stderr); exit != exitUsage {
		t.Fatalf("exit = %d, want %d; stderr = %s", exit, exitUsage, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func assertInvalidFailureContains(t *testing.T, arguments []string, expected string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if exit := run(arguments, &stdout, &stderr); exit != exitInvalid {
		t.Fatalf("exit = %d, want %d; stderr = %s", exit, exitInvalid, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), expected) {
		t.Fatalf("stdout = %q, stderr = %q; want %q", stdout.String(), stderr.String(), expected)
	}
}
