{
  lib,
  pkgs,
  signerIndependentReview ? ../signers/development-prototype/independent-review-2026-08-27.json,
  expectedCustomerKeyHash ? "sha256:b8818acea4e71173903ee003e33ed37e969def7d2ea67bec15c0b73cb36c3895",
  expectedPublicKeyFileSHA256 ? "93923fb1b289c39e8b336b90defb881f5d15ce3832c74655b295e1a35bfdab80",
  expectedPublicKeyFingerprint ? "sha256:0e68e7196fedc382ca435b995598e92d0fe36e4b1a1f949f85f5f2e6e2920fb9",
}:

let
  canonicalRelativePath =
    value:
    builtins.isString value
    && builtins.match "[A-Za-z0-9_+.-][A-Za-z0-9_+./-]{0,254}" value != null
    && !(lib.hasPrefix "/" value)
    && !(lib.hasPrefix "." value)
    && !(lib.hasInfix "/." value)
    && !(lib.hasInfix ".." value)
    && !(lib.hasInfix "//" value);
  cleanAbsolute =
    value:
    builtins.isString value
    && lib.hasPrefix "/" value
    && value != "/"
    && !(lib.hasInfix "//" value)
    && !(lib.hasInfix "/./" value)
    && !(lib.hasInfix "/../" value)
    && !(lib.hasSuffix "/." value)
    && !(lib.hasSuffix "/.." value);
  storeBacked =
    value: cleanAbsolute (toString value) && lib.hasPrefix "${builtins.storeDir}/" (toString value);
  canonicalDigest =
    value: builtins.isString value && builtins.match "sha256:[0-9a-f]{64}" value != null;
  canonicalPartitionGUID =
    value:
    builtins.isString value
    && builtins.match "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" value != null
    && value != "00000000-0000-0000-0000-000000000000";
  exactAllowlist =
    values:
    builtins.isList values
    && values != [ ]
    && builtins.length values <= 128
    && lib.all canonicalRelativePath values
    && builtins.length values == builtins.length (lib.unique values)
    && values == lib.sort builtins.lessThan values;
  delegatedReleaseFixedPaths = [
    "cmdline.txt"
    "device-tree.dtb"
    "dm-verity.json"
    "initramfs"
    "kernel"
    "release-manifest.json"
    "root.img"
    "slot.txt"
  ];
  delegatedReleasePath =
    path:
    builtins.elem path delegatedReleaseFixedPaths
    || builtins.match "overlays/[a-z0-9][a-z0-9_-]{0,63}\\.dtbo" path != null;
  campaignMutationInputNames = [
    "manifest-field-cohort-id"
    "manifest-field-component-digest"
    "manifest-field-component-role"
    "manifest-field-component-size-bytes"
    "manifest-field-device-class"
    "manifest-field-overlay-digest"
    "manifest-field-overlay-name"
    "manifest-field-overlay-size-bytes"
    "manifest-field-policy-digest"
    "manifest-field-release-id"
    "manifest-field-schema-version"
    "manifest-field-security-epoch"
    "manifest-field-signature-algorithm"
    "manifest-field-signature-key-id"
    "manifest-field-signature-value"
    "manifest-field-slot-id"
    "replacement-release-manifest"
    "revoked-release-manifest"
    "unsigned-release-manifest"
    "wrong-key-release-manifest"
  ];
  verifiedSignedBootContractValid =
    artifact:
    let
      contract =
        if builtins.isAttrs artifact && artifact ? kaibaVerifiedSignedBoot then
          artifact.kaibaVerifiedSignedBoot
        else
          { };
    in
    (contract.verificationMode or null) == "pure_offline"
    && (contract.signatureVerificationRequired or false)
    && !(contract.blockDeviceWriteCapable or true)
    && !(contract.directHardwareAccess or true)
    && !(contract.mutationCapable or true)
    && !(contract.privateKeyAccess or true)
    && !(contract.signingAuthorityConfigured or true);
  delegatedReleaseContractValid =
    artifact:
    let
      contract =
        if builtins.isAttrs artifact && artifact ? kaibaRpi5DelegatedReleaseSpike then
          artifact.kaibaRpi5DelegatedReleaseSpike
        else
          { };
    in
    (contract.artifactSchemaVersion or null)
    == "kaiba.provisioning.rpi5-delegated-release-spike/v1alpha1"
    && (contract.storageFormat or null) == "nvme-directory-payload"
    && exactAllowlist (contract.releaseAllowlist or [ ])
    && !(contract.blockDeviceWriteCapable or true)
    && !(contract.hardwareObserved or true)
    && !(contract.privateKeyAccess or true)
    && !(contract.productionReady or true)
    && !(contract.signingAuthorityConfigured or true);
  campaignMutationInputsContractValid =
    artifact:
    let
      contract =
        if builtins.isAttrs artifact && artifact ? kaibaRpi5StableVerifierCampaignMutationInputs then
          artifact.kaibaRpi5StableVerifierCampaignMutationInputs
        else
          { };
    in
    (contract.artifactSchemaVersion or null)
    == "kaiba.provisioning.rpi5-stable-verifier-campaign-mutation-inputs/v1alpha1"
    && (contract.storageFormat or null) == "named-public-file-set"
    && (contract.inputNames or [ ]) == campaignMutationInputNames
    && !(contract.blockDeviceWriteCapable or true)
    && !(contract.directHardwareAccess or true)
    && !(contract.hardwareObserved or true)
    && !(contract.privateKeyAccess or true)
    && !(contract.productionReady or true)
    && !(contract.signingAuthorityConfigured or true);

  campaignContractSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../internal/provisioning/bundle
      ../internal/provisioning/campaignmedia
      ../internal/provisioning/eepromsigning
      ../internal/provisioning/releaseintent
      ../internal/provisioning/rpi5kexecinput
      ../internal/provisioning/rpi5bootsig
      ../internal/provisioning/signedboot
      ../internal/provisioning/signing
      ../internal/provisioning/signinggate
      ../internal/provisioning/stablecampaign
      ../internal/provisioning/stableverifier
      ../internal/provisioning/verifierevents
    ];
  };
  campaignContractMain = pkgs.writeText "kaiba-stable-campaign-contract-main.go" ''
    package main

    import (
      "bytes"
      "encoding/json"
      "errors"
      "fmt"
      "io"
      "os"
      "path/filepath"
      "sort"
      "strconv"

      "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
      "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signedboot"
      "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
      "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stableverifier"
    )

    func fail(err error) {
      fmt.Fprintln(os.Stderr, err)
      os.Exit(1)
    }

    func main() {
      if len(os.Args) == 8 && os.Args[1] == "run-artifact-materialization" {
        constructRunArtifactMaterialization(
          os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6], os.Args[7],
        )
        return
      }
      if len(os.Args) == 6 && os.Args[1] == "artifact-set" {
        validateArtifactSet(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
        return
      }
      if len(os.Args) == 5 && os.Args[1] == "resolve" {
        resolveCampaign(os.Args[2], os.Args[3], os.Args[4])
        return
      }
      if len(os.Args) != 3 {
        fail(fmt.Errorf("usage: %s plan|policy|release-manifest|delegated-wrapper|signed-boot PATH; artifact-set PLAN ARTIFACT_SET PUBLIC_INPUTS TARGETS; resolve PLAN PUBLIC_INPUTS TARGETS; or run-artifact-materialization PLAN ARTIFACT_SET PUBLIC_INPUTS TARGETS RUN_INDEX MATERIALIZED_ARTIFACTS", os.Args[0]))
      }
      if os.Args[1] == "signed-boot" {
        validateSignedBoot(os.Args[2])
        return
      }
      encoded, err := os.ReadFile(os.Args[2])
      if err != nil {
        fail(err)
      }
      switch os.Args[1] {
      case "plan":
        plan, err := stablecampaign.ParsePlan(encoded)
        if err != nil {
          fail(err)
        }
        derived, err := plan.DerivedDigest()
        if err != nil {
          fail(err)
        }
        if derived != plan.PlanDigest {
          fail(fmt.Errorf("campaign plan digest does not bind its canonical contents"))
        }
        fmt.Printf("%s\n%s\n", plan.CampaignID, plan.PlanDigest)
      case "policy":
        if _, err := stableverifier.ParsePolicy(encoded); err != nil {
          fail(err)
        }
      case "release-manifest":
        manifest, err := stableverifier.ParseManifest(encoded)
        if err != nil {
          fail(err)
        }
        fmt.Printf("%s\n", manifest.ReleaseID)
      case "delegated-wrapper":
        wrapper, err := parseDelegatedWrapper(encoded)
        if err != nil {
          fail(err)
        }
        fmt.Printf("%s\n", wrapper.ReleaseID)
      default:
        fail(fmt.Errorf("unsupported contract kind %q", os.Args[1]))
      }
    }

    func constructRunArtifactMaterialization(
      planPath, artifactSetPath, publicInputDirectory, targetDirectory,
      runIndexValue, materializedArtifactsPath string,
    ) {
      planBytes, err := os.ReadFile(planPath)
      if err != nil {
        fail(err)
      }
      plan, err := stablecampaign.ParsePlan(planBytes)
      if err != nil {
        fail(err)
      }
      artifactSetBytes, err := os.ReadFile(artifactSetPath)
      if err != nil {
        fail(err)
      }
      artifactSet, err := campaignmedia.ParseArtifactSet(artifactSetBytes)
      if err != nil {
        fail(err)
      }
      resolved := resolveCampaignArtifacts(plan, publicInputDirectory, targetDirectory)

      parsedIndex, err := strconv.ParseUint(runIndexValue, 10, 16)
      if err != nil || parsedIndex == 0 {
        fail(fmt.Errorf("run_index must be a canonical positive uint16"))
      }
      materializedBytes, err := os.ReadFile(materializedArtifactsPath)
      if err != nil {
        fail(err)
      }
      if len(materializedBytes) == 0 || len(materializedBytes) > 1024*1024 {
        fail(fmt.Errorf("materialized artifact bindings must contain between 1 and 1048576 bytes"))
      }
      if err := inspectJSON(materializedBytes); err != nil {
        fail(fmt.Errorf("inspect materialized artifact bindings: %w", err))
      }
      decoder := json.NewDecoder(bytes.NewReader(materializedBytes))
      decoder.DisallowUnknownFields()
      var materialized []campaignmedia.ArtifactSetEntry
      if err := decoder.Decode(&materialized); err != nil {
        fail(fmt.Errorf("decode materialized artifact bindings: %w", err))
      }
      var trailing any
      if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
        fail(fmt.Errorf("materialized artifact bindings contain trailing data"))
      }

      result, err := campaignmedia.NewRunArtifactMaterialization(
        plan, artifactSet, resolved, uint16(parsedIndex), materialized,
      )
      if err != nil {
        fail(err)
      }
      canonical, err := result.CanonicalJSON()
      if err != nil {
        fail(err)
      }
      if _, err := os.Stdout.Write(append(canonical, '\n')); err != nil {
        fail(err)
      }
    }

    func validateArtifactSet(planPath, artifactSetPath, publicInputDirectory, targetDirectory string) {
      planBytes, err := os.ReadFile(planPath)
      if err != nil {
        fail(err)
      }
      plan, err := stablecampaign.ParsePlan(planBytes)
      if err != nil {
        fail(err)
      }
      artifactSetBytes, err := os.ReadFile(artifactSetPath)
      if err != nil {
        fail(err)
      }
      artifactSet, err := campaignmedia.ParseArtifactSet(artifactSetBytes)
      if err != nil {
        fail(err)
      }
      resolved := resolveCampaignArtifacts(plan, publicInputDirectory, targetDirectory)
      if err := artifactSet.ValidateAgainstResolved(plan, resolved); err != nil {
        fail(err)
      }
      fmt.Printf("%s\n", artifactSet.ArtifactSetContentDigest)
    }

    func resolveCampaign(planPath, publicInputDirectory, targetDirectory string) {
      encoded, err := os.ReadFile(planPath)
      if err != nil {
        fail(err)
      }
      plan, err := stablecampaign.ParsePlan(encoded)
      if err != nil {
        fail(err)
      }
      resolved := resolveCampaignArtifacts(plan, publicInputDirectory, targetDirectory)
      fmt.Printf("%s\n%d\n%d\n%d\n%s\n%s\n%s\n%s\n%d\n%s\n",
        resolved.PlanDigest,
        len(resolved.PublicInputs),
        len(resolved.ByteXORMutations),
        len(resolved.BoundReplacements),
        resolved.Semantics.StableVerifierPolicy.SemanticDigest,
        resolved.Semantics.PositiveReleaseManifest.SemanticDigest,
        resolved.Semantics.ReplacementReleaseManifest.SemanticDigest,
        resolved.Semantics.PositiveReleaseTree.Digest,
        resolved.Semantics.PositiveReleaseTree.SizeBytes,
        resolved.Semantics.KernelCommandLine.Value,
      )
    }

    func resolveCampaignArtifacts(plan stablecampaign.Plan, publicInputDirectory, targetDirectory string) stablecampaign.ResolvedPublicArtifacts {
      opened := make([]*os.File, 0, len(plan.PublicInputs)+len(plan.ByteXORMutations))
      defer func() {
        for _, file := range opened {
          _ = file.Close()
        }
      }()
      openSource := func(path string) stablecampaign.PublicArtifactSource {
        before, err := os.Lstat(path)
        if err != nil {
          fail(err)
        }
        if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() <= 0 {
          fail(fmt.Errorf("resolver input %q must be a nonempty regular non-symlink file", path))
        }
        file, err := os.Open(path)
        if err != nil {
          fail(err)
        }
        after, err := file.Stat()
        if err != nil || !os.SameFile(before, after) {
          _ = file.Close()
          fail(fmt.Errorf("resolver input %q changed while opening", path))
        }
        opened = append(opened, file)
        return stablecampaign.PublicArtifactSource{SizeBytes: uint64(after.Size()), ReaderAt: file}
      }
      publicInputs := make(map[string]stablecampaign.PublicArtifactSource, len(plan.PublicInputs))
      for _, binding := range plan.PublicInputs {
        publicInputs[binding.Name] = openSource(filepath.Join(publicInputDirectory, binding.Name))
      }
      targets := make(map[string]stablecampaign.PublicArtifactSource, len(plan.ByteXORMutations))
      for _, recipe := range plan.ByteXORMutations {
        targets[recipe.Target] = openSource(filepath.Join(targetDirectory, recipe.Target))
      }
      resolved, err := stablecampaign.ResolvePublicArtifactSources(plan, stablecampaign.PublicArtifactSources{
        PublicInputs: publicInputs, ByteMutationTargets: targets,
      })
      if err != nil {
        fail(err)
      }
      return resolved
    }

    type delegatedFile struct {
      Path string `json:"path"`
      SHA256 string `json:"sha256"`
      SizeBytes uint64 `json:"size_bytes"`
    }

    type delegatedWrapper struct {
      BundleDigest string `json:"bundle_digest"`
      Files []delegatedFile `json:"files"`
      HardwareObserved bool `json:"hardware_observed"`
      ProductionReady bool `json:"production_ready"`
      ReleaseID string `json:"release_id"`
      SchemaVersion string `json:"schema_version"`
      SignatureVerification string `json:"signature_verification"`
      SourceRevision string `json:"source_revision"`
      StorageFormat string `json:"storage_format"`
    }

    func parseDelegatedWrapper(encoded []byte) (delegatedWrapper, error) {
      if len(encoded) == 0 || len(encoded) > 1024*1024 {
        return delegatedWrapper{}, fmt.Errorf("delegated wrapper size must be between 1 and 1048576 bytes")
      }
      if err := inspectJSON(encoded); err != nil {
        return delegatedWrapper{}, fmt.Errorf("inspect delegated wrapper: %w", err)
      }
      decoder := json.NewDecoder(bytes.NewReader(encoded))
      decoder.DisallowUnknownFields()
      var wrapper delegatedWrapper
      if err := decoder.Decode(&wrapper); err != nil {
        return delegatedWrapper{}, fmt.Errorf("decode delegated wrapper: %w", err)
      }
      var trailing any
      if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
        return delegatedWrapper{}, fmt.Errorf("delegated wrapper contains trailing data")
      }
      return wrapper, nil
    }

    func inspectJSON(encoded []byte) error {
      decoder := json.NewDecoder(bytes.NewReader(encoded))
      decoder.UseNumber()
      if err := inspectJSONValue(decoder, "$", 0); err != nil {
        return err
      }
      var trailing any
      if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
        return errors.New("JSON contains trailing data")
      }
      return nil
    }

    func inspectJSONValue(decoder *json.Decoder, location string, depth int) error {
      if depth > 32 {
        return fmt.Errorf("JSON nesting exceeds 32 levels at %s", location)
      }
      token, err := decoder.Token()
      if err != nil {
        return err
      }
      delimiter, isDelimiter := token.(json.Delim)
      if !isDelimiter {
        if token == nil {
          return fmt.Errorf("JSON null is forbidden at %s", location)
        }
        return nil
      }
      switch delimiter {
      case '{':
        names := map[string]struct{}{}
        for decoder.More() {
          keyToken, err := decoder.Token()
          if err != nil {
            return err
          }
          key, ok := keyToken.(string)
          if !ok {
            return fmt.Errorf("non-string object key at %s", location)
          }
          if _, exists := names[key]; exists {
            return fmt.Errorf("duplicate JSON key %q at %s", key, location)
          }
          names[key] = struct{}{}
          if err := inspectJSONValue(decoder, location+"."+key, depth+1); err != nil {
            return err
          }
        }
        closing, err := decoder.Token()
        if err != nil || closing != json.Delim('}') {
          return fmt.Errorf("unterminated JSON object at %s", location)
        }
      case '[':
        index := 0
        for decoder.More() {
          if err := inspectJSONValue(decoder, fmt.Sprintf("%s[%d]", location, index), depth+1); err != nil {
            return err
          }
          index++
        }
        closing, err := decoder.Token()
        if err != nil || closing != json.Delim(']') {
          return fmt.Errorf("unterminated JSON array at %s", location)
        }
      default:
        return fmt.Errorf("unexpected JSON delimiter %q at %s", delimiter, location)
      }
      return nil
    }

    func validateSignedBoot(bundlePath string) {
      expected := []string{
        "boot.img", "boot.sig", "manifest.json", "public.pem", "release-intent.json",
        "signing-plan.json", "signing-result.json",
      }
      entries, err := os.ReadDir(bundlePath)
      if err != nil {
        fail(err)
      }
      names := make([]string, 0, len(entries))
      for _, entry := range entries {
        info, err := entry.Info()
        if err != nil {
          fail(err)
        }
        if entry.Type()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
          fail(fmt.Errorf("signed-boot input %q is not a regular non-symlink file", entry.Name()))
        }
        names = append(names, entry.Name())
      }
      sort.Strings(names)
      if len(names) != len(expected) {
        fail(fmt.Errorf("signed-boot input has files %q, want %q", names, expected))
      }
      for index := range expected {
        if names[index] != expected[index] {
          fail(fmt.Errorf("signed-boot input has files %q, want %q", names, expected))
        }
      }

      temporary, err := os.MkdirTemp("", "kaiba-campaign-signed-boot-")
      if err != nil {
        fail(err)
      }
      defer os.RemoveAll(temporary)
      planDirectory := filepath.Join(temporary, "plan")
      resultDirectory := filepath.Join(temporary, "result")
      finalDirectory := filepath.Join(temporary, "final")
      if err := os.Mkdir(planDirectory, 0o700); err != nil {
        fail(err)
      }
      if err := os.Mkdir(resultDirectory, 0o700); err != nil {
        fail(err)
      }
      mappings := map[string]string{
        "boot.img": "plan/boot.img",
        "public.pem": "plan/public.pem",
        "release-intent.json": "plan/release-intent.json",
        "signing-plan.json": "plan/plan.json",
        "boot.sig": "result/boot.sig",
        "signing-result.json": "result/signing-result.json",
      }
      for sourceName, targetName := range mappings {
        source := filepath.Join(bundlePath, sourceName)
        before, err := os.Lstat(source)
        if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
          fail(fmt.Errorf("signed-boot source %q changed or is not regular", sourceName))
        }
        payload, err := os.ReadFile(source)
        if err != nil {
          fail(err)
        }
        after, err := os.Lstat(source)
        if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() {
          fail(fmt.Errorf("signed-boot source %q changed while reading", sourceName))
        }
        if err := os.WriteFile(filepath.Join(temporary, targetName), payload, 0o600); err != nil {
          fail(err)
        }
      }
      if err := signedboot.Finalize(planDirectory, resultDirectory, finalDirectory); err != nil {
        fail(fmt.Errorf("re-finalize signed-boot input: %w", err))
      }
      for _, name := range expected {
        supplied, err := os.ReadFile(filepath.Join(bundlePath, name))
        if err != nil {
          fail(err)
        }
        finalized, err := os.ReadFile(filepath.Join(finalDirectory, name))
        if err != nil {
          fail(err)
        }
        if !bytes.Equal(supplied, finalized) {
          fail(fmt.Errorf("signed-boot file %q differs from production re-finalization", name))
        }
      }
    }
  '';
  campaignContractToolSource = pkgs.runCommand "kaiba-stable-campaign-contract-source" { } ''
    cp -R --no-preserve=ownership ${campaignContractSource}/. "$out/"
    chmod -R u+w "$out"
    mkdir -p "$out/cmd/kaiba-stable-campaign-contract"
    install -m 0444 ${campaignContractMain} \
      "$out/cmd/kaiba-stable-campaign-contract/main.go"
  '';
  campaignContractTool = pkgs.buildGoModule {
    pname = "kaiba-stable-campaign-contract";
    version = "0.1.0";
    src = campaignContractToolSource;
    subPackages = [ "cmd/kaiba-stable-campaign-contract" ];
    vendorHash = null;
    doCheck = false;
    meta.mainProgram = "kaiba-stable-campaign-contract";
  };
  inputValidatorRuntimeInputs = [
    campaignContractTool
    pkgs.coreutils
    pkgs.diffutils
    pkgs.findutils
    pkgs.gnugrep
    pkgs.gnused
    pkgs.jq
    pkgs.mtools
    pkgs.openssl
    pkgs.xxd
  ];
  campaignInputValidator = pkgs.writeShellScriptBin "kaiba-stable-verifier-campaign-input-validate" ''
    set -euo pipefail
    export LC_ALL=C
    export PATH=${lib.makeBinPath inputValidatorRuntimeInputs}

    verified_signed_boot=
    campaign_plan=
    campaign_mutation_inputs=
    delegated_release=
    release_allowlist=
    metadata_out=

    while test "$#" -gt 0; do
      test "$#" -ge 2 || {
        echo 'campaign input validator received an option without a value' >&2
        exit 64
      }
      case "$1" in
        --verified-signed-boot) verified_signed_boot="$2" ;;
        --campaign-plan) campaign_plan="$2" ;;
        --campaign-mutation-inputs) campaign_mutation_inputs="$2" ;;
        --delegated-release) delegated_release="$2" ;;
        --release-allowlist) release_allowlist="$2" ;;
        --metadata-out) metadata_out="$2" ;;
        *)
          echo "campaign input validator received an unknown option: $1" >&2
          exit 64
          ;;
      esac
      shift 2
    done

    for value in \
      "$verified_signed_boot" \
      "$campaign_plan" \
      "$campaign_mutation_inputs" \
      "$delegated_release" \
      "$release_allowlist" \
      "$metadata_out"
    do
      test -n "$value" || {
        echo 'campaign input validator is missing a required argument' >&2
        exit 64
      }
    done
    test ! -e "$metadata_out"

    validation_tmp="$(mktemp -d)"
    trap 'rm -rf -- "$validation_tmp"' EXIT

    # A kaibaVerifiedSignedBoot value is treated as an untrusted public byte
    # container here. Re-open all seven finalizer outputs and re-establish the
    # cryptographic and manifest bindings rather than trusting passthru flags.
    test -d "$verified_signed_boot"
    test ! -L "$verified_signed_boot"
    find "$verified_signed_boot" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
      > "$validation_tmp/actual-signed-boot-files"
    printf '%s\n' \
      boot.img \
      boot.sig \
      manifest.json \
      public.pem \
      release-intent.json \
      signing-plan.json \
      signing-result.json \
      > "$validation_tmp/expected-signed-boot-files"
    cmp "$validation_tmp/expected-signed-boot-files" \
      "$validation_tmp/actual-signed-boot-files"
    while IFS= read -r file_name; do
      input="$verified_signed_boot/$file_name"
      test -f "$input"
      test ! -L "$input"
      test -s "$input"
    done < "$validation_tmp/expected-signed-boot-files"
    kaiba-stable-campaign-contract signed-boot "$verified_signed_boot"

    readonly boot_image="$verified_signed_boot/boot.img"
    readonly boot_signature="$verified_signed_boot/boot.sig"
    readonly public_key="$verified_signed_boot/public.pem"
    readonly signed_boot_manifest="$verified_signed_boot/manifest.json"
    boot_image_digest="sha256:$(sha256sum "$boot_image" | cut -d ' ' -f 1)"
    boot_image_size="$(stat --format=%s "$boot_image")"
    test "$boot_image_size" -gt 0
    test "$boot_image_size" -le 100663296
    public_key_digest="sha256:$(sha256sum "$public_key" | cut -d ' ' -f 1)"
    public_key_size="$(stat --format=%s "$public_key")"
    test "$public_key_size" -gt 0
    test "$public_key_size" -le 16384

    openssl rsa -pubin -in "$public_key" -pubout \
      -out "$validation_tmp/canonical-public.pem"
    cmp "$public_key" "$validation_tmp/canonical-public.pem"
    test "$(openssl pkey -pubin -in "$public_key" -text -noout | sed -n '1p')" = \
      'Public-Key: (2048 bit)'
    openssl pkey -pubin -in "$public_key" -text -noout \
      | grep -Fx 'Exponent: 65537 (0x10001)' > /dev/null
    public_key_fingerprint="sha256:$(
      openssl pkey -pubin -in "$public_key" -outform DER \
        | sha256sum | cut -d ' ' -f 1
    )"
    test "$public_key_digest" = 'sha256:${expectedPublicKeyFileSHA256}'
    test "$public_key_fingerprint" = '${expectedPublicKeyFingerprint}'

    readonly signer_review=${lib.escapeShellArg (toString signerIndependentReview)}
    test -f "$signer_review"
    test ! -L "$signer_review"
    test -s "$signer_review"
    jq -e \
      --arg public_key_file_sha256 '${expectedPublicKeyFileSHA256}' \
      --arg public_key_fingerprint '${expectedPublicKeyFingerprint}' \
      --arg customer_key_hash '${expectedCustomerKeyHash}' \
      '
        .schema_version == "kaiba.provisioning.signer-independent-review/v1alpha1"
        and .status == "passed"
        and .scope == "development-sacrificial-signer"
        and .public_bindings.public_key_file_sha256 == $public_key_file_sha256
        and .public_bindings.public_key_fingerprint == $public_key_fingerprint
        and .public_bindings.customer_key_hash == $customer_key_hash
        and (.public_bindings.signer_policy_digest | test("^sha256:[0-9a-f]{64}$"))
        and .signing_authorized == false
        and .production_approved == false
      ' "$signer_review" > /dev/null
    signer_review_digest="sha256:$(sha256sum "$signer_review" | cut -d ' ' -f 1)"
    signer_review_size="$(stat --format=%s "$signer_review")"
    signer_policy_digest="$(jq -er .public_bindings.signer_policy_digest "$signer_review")"

    test "$(wc -l < "$boot_signature")" -eq 3
    signature_image_digest="$(sed -n '1p' "$boot_signature")"
    signature_timestamp="$(sed -n '2p' "$boot_signature")"
    signature_line="$(sed -n '3p' "$boot_signature")"
    printf '%s\n' "$signature_image_digest" | grep -Ex '[0-9a-f]{64}' > /dev/null
    printf '%s\n' "$signature_timestamp" | grep -Ex 'ts: (0|[1-9][0-9]{0,19})' > /dev/null
    printf '%s\n' "$signature_line" | grep -Ex 'rsa2048: [0-9a-f]{512}' > /dev/null
    test "sha256:$signature_image_digest" = "$boot_image_digest"
    printf '%s' "''${signature_line#rsa2048: }" \
      | xxd -r -p > "$validation_tmp/boot-signature.bin"
    test "$(stat --format=%s "$validation_tmp/boot-signature.bin")" -eq 256
    openssl dgst -sha256 \
      -verify "$public_key" \
      -signature "$validation_tmp/boot-signature.bin" \
      "$boot_image" > "$validation_tmp/signature-verification.txt"
    grep -Fx 'Verified OK' "$validation_tmp/signature-verification.txt" > /dev/null
    boot_signature_digest="sha256:$(sha256sum "$boot_signature" | cut -d ' ' -f 1)"
    boot_signature_size="$(stat --format=%s "$boot_signature")"

    jq -e \
      --arg boot_digest "$boot_image_digest" \
      --argjson boot_size "$boot_image_size" \
      --arg key_digest "$public_key_digest" \
      --argjson key_size "$public_key_size" \
      --arg signature_digest "$boot_signature_digest" \
      --argjson signature_size "$boot_signature_size" \
      --arg signer_policy_digest "$signer_policy_digest" \
      '
        keys == ["artifacts", "device_class", "manifest_id", "schema_version", "signing_policy_digest"]
        and .schema_version == "kaiba.provisioning.secure-boot-bundle/v1alpha1"
        and .device_class == "raspberry-pi-5"
        and [.artifacts[].role] == ["boot_public_key", "rpi5.boot_image", "rpi5.boot_signature"]
        and .artifacts == [
          {role: "boot_public_key", digest: $key_digest, size_bytes: $key_size},
          {role: "rpi5.boot_image", digest: $boot_digest, size_bytes: $boot_size},
          {role: "rpi5.boot_signature", digest: $signature_digest, size_bytes: $signature_size}
        ]
        and .signing_policy_digest == $signer_policy_digest
      ' "$signed_boot_manifest" > /dev/null
    jq -e \
      --arg boot_digest "$boot_image_digest" \
      --argjson boot_size "$boot_image_size" \
      --arg public_key_fingerprint "$public_key_fingerprint" \
      --arg signer_policy_digest "$signer_policy_digest" \
      '
        .schema_version == "kaiba.provisioning.rpi5-boot-signing-plan/v1alpha2"
        and .boot_image_digest == $boot_digest
        and .boot_image_size_bytes == $boot_size
        and .public_key_fingerprint == $public_key_fingerprint
        and .signer_policy_digest == $signer_policy_digest
      ' "$verified_signed_boot/signing-plan.json" > /dev/null
    jq -e \
      --arg public_key_fingerprint "$public_key_fingerprint" \
      --arg signer_policy_digest "$signer_policy_digest" \
      --arg expected_customer_key_hash '${expectedCustomerKeyHash}' \
      '
        .schema_version == "kaiba.provisioning.rpi5-release-intent/v1alpha1"
        and .public_key_fingerprint == $public_key_fingerprint
        and .signing_policy_digest == $signer_policy_digest
        and .expected_customer_key_hash == $expected_customer_key_hash
      ' "$verified_signed_boot/release-intent.json" > /dev/null

    test -f "$campaign_plan"
    test ! -L "$campaign_plan"
    test -s "$campaign_plan"
    test "$(stat --format=%s "$campaign_plan")" -le 1048576
    kaiba-stable-campaign-contract plan "$campaign_plan" \
      > "$validation_tmp/validated-plan"
    campaign_id="$(sed -n '1p' "$validation_tmp/validated-plan")"
    plan_digest="$(sed -n '2p' "$validation_tmp/validated-plan")"
    test "$(wc -l < "$validation_tmp/validated-plan")" -eq 2
    printf '%s\n' "$plan_digest" | grep -Ex 'sha256:[0-9a-f]{64}' > /dev/null
    campaign_plan_digest="sha256:$(sha256sum "$campaign_plan" | cut -d ' ' -f 1)"
    campaign_plan_size="$(stat --format=%s "$campaign_plan")"

    require_plan_binding() {
      binding_name="$1"
      binding_digest="$2"
      binding_size="$3"
      jq -e \
        --arg name "$binding_name" \
        --arg digest "$binding_digest" \
        --argjson size_bytes "$binding_size" \
        '[.public_inputs[] | select(.name == $name)]
         == [{name: $name, digest: $digest, size_bytes: $size_bytes}]' \
        "$campaign_plan" > /dev/null
    }
    require_plan_binding unsigned-verifier-boot "$boot_image_digest" "$boot_image_size"
    require_plan_binding customer-boot-public-key "$public_key_digest" "$public_key_size"

    # Re-open the stable verifier's own public policy inputs from the exact
    # root-signed FAT boot image. These bytes, rather than caller-side paths or
    # passthru metadata, are the campaign's three trust-policy bindings. The
    # authorization-trust-anchor is specifically the embedded TLS CA; the
    # authorization signing keys remain fields of the signed verifier policy.
    readonly extracted_boot_inputs="$validation_tmp/extracted-boot-inputs"
    mkdir "$extracted_boot_inputs"
    mcopy -i "$boot_image" '::/kaiba/stable-verifier-policy.json' \
      "$extracted_boot_inputs/stable-verifier-policy.json"
    mcopy -i "$boot_image" '::/kaiba/root-public.pem' \
      "$extracted_boot_inputs/root-public.pem"
    mcopy -i "$boot_image" '::/kaiba/authority-ca.pem' \
      "$extracted_boot_inputs/authority-ca.pem"
    while IFS=$'\t' read -r binding_name extracted_name; do
      extracted="$extracted_boot_inputs/$extracted_name"
      test -f "$extracted"
      test ! -L "$extracted"
      test -s "$extracted"
      test "$(stat --format=%s "$extracted")" -le 1048576
      require_plan_binding \
        "$binding_name" \
        "sha256:$(sha256sum "$extracted" | cut -d ' ' -f 1)" \
        "$(stat --format=%s "$extracted")"
    done <<'EOF'
    authorization-trust-anchor	authority-ca.pem
    release-policy-root-public-key	root-public.pem
    stable-verifier-policy	stable-verifier-policy.json
    EOF
    kaiba-stable-campaign-contract policy \
      "$extracted_boot_inputs/stable-verifier-policy.json"
    openssl rsa -pubin -in "$extracted_boot_inputs/root-public.pem" -noout
    openssl x509 -in "$extracted_boot_inputs/authority-ca.pem" -noout

    # Every replacement recipe is backed by one explicit, typed, immutable
    # public file. The plan parser has already cross-bound each recipe to its
    # named input; this closes the remaining byte-level binding.
    test -d "$campaign_mutation_inputs"
    test ! -L "$campaign_mutation_inputs"
    find "$campaign_mutation_inputs" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
      > "$validation_tmp/actual-mutation-input-files"
    sed 's/$/.json/' ${
      pkgs.writeText "kaiba-stable-campaign-mutation-input-names" (
        lib.concatStringsSep "\n" campaignMutationInputNames + "\n"
      )
    } \
      > "$validation_tmp/expected-mutation-input-files"
    cmp "$validation_tmp/expected-mutation-input-files" \
      "$validation_tmp/actual-mutation-input-files"
    : > "$validation_tmp/mutation-inputs.ndjson"
    while IFS= read -r binding_name; do
      input="$campaign_mutation_inputs/$binding_name.json"
      test -f "$input"
      test ! -L "$input"
      test -s "$input"
      test "$(stat --format=%s "$input")" -le 1048576
      jq -e 'type == "object"' "$input" > /dev/null
      input_digest="sha256:$(sha256sum "$input" | cut -d ' ' -f 1)"
      input_size="$(stat --format=%s "$input")"
      require_plan_binding "$binding_name" "$input_digest" "$input_size"
      jq -cnS \
        --arg name "$binding_name" \
        --arg sha256 "$input_digest" \
        --argjson size_bytes "$input_size" \
        '{name: $name, sha256: $sha256, size_bytes: $size_bytes}' \
        >> "$validation_tmp/mutation-inputs.ndjson"
    done < ${
      pkgs.writeText "kaiba-stable-campaign-mutation-input-binding-names" (
        lib.concatStringsSep "\n" campaignMutationInputNames + "\n"
      )
    }
    jq -csS . "$validation_tmp/mutation-inputs.ndjson" \
      > "$validation_tmp/mutation-inputs.json"
    mutation_inputs_json="$(< "$validation_tmp/mutation-inputs.json")"
    mutation_input_set_content_digest="sha256:$({
      printf '%s\0' 'kaiba.provisioning.rpi5-stable-verifier-campaign-mutation-inputs.v1alpha1'
      printf '%s' "$mutation_inputs_json"
    } | sha256sum | cut -d ' ' -f 1)"

    # The delegated-release wrapper is likewise reopened as untrusted bytes.
    # Its exact tree is compared with the typed allowlist and its wrapper
    # bundle digest is recomputed before any payload is copied.
    test -d "$delegated_release"
    test ! -L "$delegated_release"
    find "$delegated_release" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
      > "$validation_tmp/actual-delegated-release-files"
    printf '%s\n' manifest.json nvme-release \
      > "$validation_tmp/expected-delegated-release-files"
    cmp "$validation_tmp/expected-delegated-release-files" \
      "$validation_tmp/actual-delegated-release-files"
    readonly delegated_manifest="$delegated_release/manifest.json"
    readonly release_tree="$delegated_release/nvme-release"
    test -f "$delegated_manifest"
    test ! -L "$delegated_manifest"
    test -s "$delegated_manifest"
    test -d "$release_tree"
    test ! -L "$release_tree"
    if test -n "$(find "$release_tree" -type l -print -quit)"; then
      echo 'campaign release tree contains a symbolic link' >&2
      exit 1
    fi
    if test -n "$(find "$release_tree" ! -type d ! -type f -print -quit)"; then
      echo 'campaign release tree contains an unsupported filesystem object' >&2
      exit 1
    fi
    find "$release_tree" -type f -printf '%P\n' | sort \
      > "$validation_tmp/actual-release-files"
    cmp "$release_allowlist" "$validation_tmp/actual-release-files"

    : > "$validation_tmp/release-files.ndjson"
    while IFS= read -r relative_path; do
      input="$release_tree/$relative_path"
      test -f "$input"
      test ! -L "$input"
      test -s "$input"
      jq -cnS \
        --arg path "$relative_path" \
        --arg sha256 "sha256:$(sha256sum "$input" | cut -d ' ' -f 1)" \
        --argjson size_bytes "$(stat --format=%s "$input")" \
        '{path: $path, sha256: $sha256, size_bytes: $size_bytes}' \
        >> "$validation_tmp/release-files.ndjson"
    done < "$release_allowlist"
    jq -csS . "$validation_tmp/release-files.ndjson" \
      > "$validation_tmp/release-files.json"
    release_files_json="$(< "$validation_tmp/release-files.json")"
    kaiba-stable-campaign-contract delegated-wrapper "$delegated_manifest" \
      > "$validation_tmp/validated-delegated-wrapper"
    release_id="$(cat "$validation_tmp/validated-delegated-wrapper")"
    test "$(wc -l < "$validation_tmp/validated-delegated-wrapper")" -eq 1
    delegated_bundle_digest="sha256:$({
      printf '%s\0%s\0%s' \
        'kaiba.provisioning.rpi5-delegated-release-spike.v1alpha1' \
        "$release_id" \
        "$release_files_json"
    } | sha256sum | cut -d ' ' -f 1)"
    jq -e \
      --arg release_id "$release_id" \
      --arg bundle_digest "$delegated_bundle_digest" \
      --argjson files "$release_files_json" \
      '
        keys == ["bundle_digest", "files", "hardware_observed", "production_ready", "release_id", "schema_version", "signature_verification", "source_revision", "storage_format"]
        and .schema_version == "kaiba.provisioning.rpi5-delegated-release-spike/v1alpha1"
        and .release_id == $release_id
        and (.source_revision | test("^(?:[0-9a-f]{40}|[0-9a-f]{64})$"))
        and .storage_format == "nvme-directory-payload"
        and .bundle_digest == $bundle_digest
        and .files == $files
        and .signature_verification == "deferred_to_stable_verifier"
        and .hardware_observed == false
        and .production_ready == false
      ' "$delegated_manifest" > /dev/null
    delegated_manifest_digest="sha256:$(sha256sum "$delegated_manifest" | cut -d ' ' -f 1)"
    delegated_manifest_size="$(stat --format=%s "$delegated_manifest")"

    readonly release_manifest="$release_tree/release-manifest.json"
    kaiba-stable-campaign-contract release-manifest "$release_manifest" \
      > "$validation_tmp/validated-release-manifest"
    inner_release_id="$(cat "$validation_tmp/validated-release-manifest")"
    if test "$inner_release_id" != "$release_id"; then
      echo 'delegated wrapper release_id does not match the parsed inner release manifest' >&2
      exit 1
    fi
    release_manifest_digest="sha256:$(sha256sum "$release_manifest" | cut -d ' ' -f 1)"
    release_manifest_size="$(stat --format=%s "$release_manifest")"

    component_path() {
      case "$1" in
        kernel) printf '%s\n' kernel ;;
        initramfs) printf '%s\n' initramfs ;;
        resolved_device_tree) printf '%s\n' device-tree.dtb ;;
        kernel_command_line) printf '%s\n' cmdline.txt ;;
        root_image) printf '%s\n' root.img ;;
        dm_verity_metadata) printf '%s\n' dm-verity.json ;;
        slot_metadata) printf '%s\n' slot.txt ;;
        *) echo "unsupported delegated-release component role: $1" >&2; return 1 ;;
      esac
    }
    while IFS=$'\t' read -r role digest size_bytes; do
      relative_path="$(component_path "$role")"
      test "$digest" = "sha256:$(sha256sum "$release_tree/$relative_path" | cut -d ' ' -f 1)"
      test "$size_bytes" = "$(stat --format=%s "$release_tree/$relative_path")"
    done < <(jq -r '.components[] | [.role, .digest, (.size_bytes | tostring)] | @tsv' "$release_manifest")

    jq -r '.overlays[].name' "$release_manifest" | sort \
      > "$validation_tmp/manifest-overlay-names"
    sed -n 's#^overlays/\([a-z0-9][a-z0-9_-]*\)\.dtbo$#\1#p' "$release_allowlist" \
      > "$validation_tmp/release-overlay-names"
    cmp "$validation_tmp/release-overlay-names" "$validation_tmp/manifest-overlay-names"
    while IFS=$'\t' read -r overlay_name digest size_bytes; do
      overlay="$release_tree/overlays/$overlay_name.dtbo"
      test "$digest" = "sha256:$(sha256sum "$overlay" | cut -d ' ' -f 1)"
      test "$size_bytes" = "$(stat --format=%s "$overlay")"
    done < <(jq -r '.overlays[] | [.name, .digest, (.size_bytes | tostring)] | @tsv' "$release_manifest")

    # The fixed plan has an overlay mutation, so its selected target must be
    # one of the exact positive-release overlay bytes just checked.
    overlay_target="$(jq -er '
      [.byte_xor_mutations[]
       | select(.test_id == "component-byte-mutations-rejected" and .subcase_id == "overlay")
       | .target] | if length == 1 then .[0] else error("missing unique overlay mutation") end
    ' "$campaign_plan")"
    case "$overlay_target" in
      release/overlays/*.dtbo) ;;
      *) echo 'campaign overlay mutation target is not canonical' >&2; exit 1 ;;
    esac
    test -f "$release_tree/''${overlay_target#release/}"

    release_tree_digest="sha256:$({
      printf '%s\0' 'kaiba.provisioning.rpi5-stable-verifier-campaign-release-tree.v1alpha1'
      printf '%s' "$release_files_json"
    } | sha256sum | cut -d ' ' -f 1)"
    require_plan_binding positive-release-manifest "$release_manifest_digest" "$release_manifest_size"
    release_tree_binding_size="$({
      printf '%s\0' 'kaiba.provisioning.rpi5-stable-verifier-campaign-release-tree.v1alpha1'
      printf '%s' "$release_files_json"
    } | wc -c)"
    require_plan_binding positive-release-tree "$release_tree_digest" "$release_tree_binding_size"

    # This is deliberately only a PEM/OpenSSH marker check. A non-match says
    # nothing about DER, encrypted blobs, or novel encodings, so no
    # public-inputs-only/private-material-absence claim is emitted.
    find "$release_tree" -type f -print > "$validation_tmp/release-scan-files"
    while IFS= read -r input; do
      set +e
      grep -aEq -- \
        '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----' \
        "$input"
      scan_status="$?"
      set -e
      case "$scan_status" in
        0)
          echo 'private-key PEM/OpenSSH marker is forbidden in the campaign release tree' >&2
          exit 1
          ;;
        1) ;;
        *)
          echo "private-key marker scanner failed for $input" >&2
          exit 1
          ;;
      esac
    done < "$validation_tmp/release-scan-files"

    # Re-open every security-relevant public input after validation. Nix store
    # paths are immutable, but this second read keeps the same invariant when
    # the validator is exercised independently in tests.
    test "$boot_image_digest" = "sha256:$(sha256sum "$boot_image" | cut -d ' ' -f 1)"
    test "$boot_image_size" = "$(stat --format=%s "$boot_image")"
    test "$boot_signature_digest" = "sha256:$(sha256sum "$boot_signature" | cut -d ' ' -f 1)"
    test "$public_key_digest" = "sha256:$(sha256sum "$public_key" | cut -d ' ' -f 1)"
    test "$campaign_plan_digest" = "sha256:$(sha256sum "$campaign_plan" | cut -d ' ' -f 1)"
    test "$release_manifest_digest" = "sha256:$(sha256sum "$release_manifest" | cut -d ' ' -f 1)"
    : > "$validation_tmp/reopened-release-files.ndjson"
    while IFS= read -r relative_path; do
      jq -cnS \
        --arg path "$relative_path" \
        --arg sha256 "sha256:$(sha256sum "$release_tree/$relative_path" | cut -d ' ' -f 1)" \
        --argjson size_bytes "$(stat --format=%s "$release_tree/$relative_path")" \
        '{path: $path, sha256: $sha256, size_bytes: $size_bytes}' \
        >> "$validation_tmp/reopened-release-files.ndjson"
    done < "$release_allowlist"
    jq -csS . "$validation_tmp/reopened-release-files.ndjson" \
      > "$validation_tmp/reopened-release-files.json"
    cmp "$validation_tmp/release-files.json" "$validation_tmp/reopened-release-files.json"

    jq -nS \
      --arg campaign_id "$campaign_id" \
      --arg plan_digest "$plan_digest" \
      --arg campaign_plan_digest "$campaign_plan_digest" \
      --argjson campaign_plan_size "$campaign_plan_size" \
      --arg boot_image_digest "$boot_image_digest" \
      --argjson boot_image_size "$boot_image_size" \
      --arg boot_signature_digest "$boot_signature_digest" \
      --argjson boot_signature_size "$boot_signature_size" \
      --arg public_key_digest "$public_key_digest" \
      --argjson public_key_size "$public_key_size" \
      --arg public_key_fingerprint "$public_key_fingerprint" \
      --arg signer_review_digest "$signer_review_digest" \
      --argjson signer_review_size "$signer_review_size" \
      --arg delegated_manifest_digest "$delegated_manifest_digest" \
      --argjson delegated_manifest_size "$delegated_manifest_size" \
      --arg release_manifest_digest "$release_manifest_digest" \
      --argjson release_manifest_size "$release_manifest_size" \
      --arg release_tree_digest "$release_tree_digest" \
      --argjson release_tree_size_bytes "$release_tree_binding_size" \
      --arg mutation_input_set_content_digest "$mutation_input_set_content_digest" \
      --argjson mutation_inputs "$mutation_inputs_json" \
      '{
        campaign_id: $campaign_id,
        plan_digest: $plan_digest,
        campaign_plan: {sha256: $campaign_plan_digest, size_bytes: $campaign_plan_size},
        verified_signed_boot: {
          boot_image: {sha256: $boot_image_digest, size_bytes: $boot_image_size},
          boot_signature: {sha256: $boot_signature_digest, size_bytes: $boot_signature_size},
          public_key: {
            sha256: $public_key_digest,
            size_bytes: $public_key_size,
            fingerprint: $public_key_fingerprint
          },
          signer_independent_review: {
            sha256: $signer_review_digest,
            size_bytes: $signer_review_size
          },
          signature_verification: "reverified"
        },
        delegated_release: {
          wrapper_manifest: {sha256: $delegated_manifest_digest, size_bytes: $delegated_manifest_size},
          release_manifest: {sha256: $release_manifest_digest, size_bytes: $release_manifest_size},
          release_tree_digest: $release_tree_digest,
          release_tree_size_bytes: $release_tree_size_bytes,
          signature_verification: "deferred_to_stable_verifier"
        },
        campaign_mutation_inputs: {
          content_digest: $mutation_input_set_content_digest,
          files: $mutation_inputs
        },
        delegated_release_private_key_pem_marker_scan: "passed_defense_in_depth_not_proof_of_absence"
      }' > "$metadata_out"
  '';
  validatorRuntimeInputs = [
    pkgs.coreutils
    pkgs.cryptsetup
    pkgs.diffutils
    pkgs.findutils
    pkgs.gnugrep
    pkgs.python3
  ];
  campaignMediaValidator = pkgs.writeShellScriptBin "kaiba-stable-verifier-campaign-media-validate" ''
    set -euo pipefail
    export LC_ALL=C
    export PATH=${lib.makeBinPath validatorRuntimeInputs}

    release_tree=
    release_allowlist=
    root_data=
    root_hash_tree=
    root_hash=
    data_device=
    hash_device=

    while test "$#" -gt 0; do
      test "$#" -ge 2 || {
        echo 'campaign media validator received an option without a value' >&2
        exit 64
      }
      case "$1" in
        --release-tree) release_tree="$2" ;;
        --release-allowlist) release_allowlist="$2" ;;
        --root-data) root_data="$2" ;;
        --root-hash-tree) root_hash_tree="$2" ;;
        --root-hash) root_hash="$2" ;;
        --data-device) data_device="$2" ;;
        --hash-device) hash_device="$2" ;;
        *)
          echo "campaign media validator received an unknown option: $1" >&2
          exit 64
          ;;
      esac
      shift 2
    done

    for value in \
      "$release_tree" \
      "$release_allowlist" \
      "$root_data" \
      "$root_hash_tree" \
      "$root_hash" \
      "$data_device" \
      "$hash_device"
    do
      test -n "$value" || {
        echo 'campaign media validator is missing a required argument' >&2
        exit 64
      }
    done

    test -d "$release_tree"
    test ! -L "$release_tree"
    test -f "$release_allowlist"
    test ! -L "$release_allowlist"
    test -f "$root_data"
    test ! -L "$root_data"
    test -s "$root_data"
    test -f "$root_hash_tree"
    test ! -L "$root_hash_tree"
    test -s "$root_hash_tree"

    validation_tmp="$(mktemp -d)"
    trap 'rm -rf -- "$validation_tmp"' EXIT

    if test -n "$(find "$release_tree" -type l -print -quit)"; then
      echo 'campaign release tree contains a symbolic link' >&2
      exit 1
    fi
    if test -n "$(find "$release_tree" ! -type d ! -type f -print -quit)"; then
      echo 'campaign release tree contains an unsupported filesystem object' >&2
      exit 1
    fi
    find "$release_tree" -type f -printf '%P\n' | sort \
      > "$validation_tmp/actual-files"
    if ! cmp "$release_allowlist" "$validation_tmp/actual-files"; then
      echo 'campaign release tree differs from its exact file allowlist' >&2
      exit 1
    fi
    find "$release_tree" -mindepth 1 -type d -printf '%P\n' | sort \
      > "$validation_tmp/actual-directories"
    if grep -q '^overlays/' "$release_allowlist"; then
      printf '%s\n' overlays > "$validation_tmp/expected-directories"
    else
      : > "$validation_tmp/expected-directories"
    fi
    if ! cmp "$validation_tmp/expected-directories" "$validation_tmp/actual-directories"; then
      echo 'campaign release tree contains a directory outside the file allowlist' >&2
      exit 1
    fi
    while IFS= read -r relative_path; do
      test -n "$relative_path"
      test -f "$release_tree/$relative_path"
      test ! -L "$release_tree/$relative_path"
      test -s "$release_tree/$relative_path"
    done < "$release_allowlist"

    find "$release_tree" -type f -print > "$validation_tmp/release-scan-files"
    while IFS= read -r input; do
      set +e
      grep -aEq -- \
        '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----' \
        "$input"
      scan_status="$?"
      set -e
      case "$scan_status" in
        0)
          echo 'private-key PEM/OpenSSH marker is forbidden in the campaign release tree' >&2
          exit 1
          ;;
        1) ;;
        *)
          echo "private-key marker scanner failed for $input" >&2
          exit 1
          ;;
      esac
    done < "$validation_tmp/release-scan-files"

    cmp "$release_tree/root.img" "$root_data"
    root_data_size="$(stat --format=%s "$root_data")"
    test "$root_data_size" -gt 0
    test $((root_data_size % 4096)) -eq 0

    python3 - \
      "$release_tree/dm-verity.json" \
      "$release_tree/cmdline.txt" \
      "$root_hash" \
      "$data_device" \
      "$hash_device" <<'PY'
    import json
    import re
    import sys

    metadata_path, command_line_path, root_hash, data_device, hash_device = sys.argv[1:]

    digest_pattern = re.compile(r"[0-9a-f]{64}")
    device_pattern = re.compile(
        r"PARTUUID=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    )
    if digest_pattern.fullmatch(root_hash) is None:
        raise SystemExit("campaign root hash is not one lowercase SHA-256 value")
    if device_pattern.fullmatch(data_device) is None or device_pattern.fullmatch(hash_device) is None:
        raise SystemExit("campaign dm-verity devices are not canonical PARTUUID selectors")
    if data_device == hash_device or data_device.endswith("00000000-0000-0000-0000-000000000000") or hash_device.endswith("00000000-0000-0000-0000-000000000000"):
        raise SystemExit("campaign dm-verity devices must be distinct and non-zero")

    def reject_duplicate_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    encoded_metadata = open(metadata_path, "rb").read()
    if not encoded_metadata or len(encoded_metadata) > 65536:
        raise SystemExit("dm-verity metadata must contain between 1 and 65536 bytes")
    try:
        metadata = json.loads(encoded_metadata, object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"dm-verity metadata is not strict JSON: {error}") from error

    expected_keys = {
        "algorithm",
        "data_block_size",
        "data_device",
        "hash_block_size",
        "hash_device",
        "no_superblock",
        "root_hash",
        "schema",
    }
    if not isinstance(metadata, dict) or set(metadata) != expected_keys:
        raise SystemExit("dm-verity metadata does not have the exact canonical field set")
    expected_metadata = {
        "schema": "provisioning.kaiba.network/rpi5-boot-integrity/v1alpha1",
        "algorithm": "sha256",
        "data_block_size": 4096,
        "hash_block_size": 4096,
        "no_superblock": False,
        "root_hash": root_hash,
        "data_device": data_device,
        "hash_device": hash_device,
    }
    if metadata != expected_metadata:
        raise SystemExit("dm-verity metadata differs from the generated campaign contract")
    if type(metadata["data_block_size"]) is not int or type(metadata["hash_block_size"]) is not int or type(metadata["no_superblock"]) is not bool:
        raise SystemExit("dm-verity metadata uses non-canonical JSON scalar types")

    command_line_bytes = open(command_line_path, "rb").read()
    if not command_line_bytes or len(command_line_bytes) > 2048:
        raise SystemExit("campaign command line must contain at most 2047 bytes plus one LF")
    if not command_line_bytes.endswith(b"\n") or command_line_bytes.count(b"\n") != 1:
        raise SystemExit("campaign command line must end in exactly one LF")
    command_line_bytes = command_line_bytes[:-1]
    if not command_line_bytes or any(byte < 0x20 or byte > 0x7E for byte in command_line_bytes):
        raise SystemExit("campaign command line must contain printable ASCII")
    try:
        command_line = command_line_bytes.decode("ascii")
    except UnicodeDecodeError as error:
        raise SystemExit("campaign command line must contain printable ASCII") from error
    if command_line != " ".join(command_line.split(" ")) or "" in command_line.split(" "):
        raise SystemExit("campaign command line arguments must use single spaces")
    if "/dev/nvme" in command_line:
        raise SystemExit("campaign command line contains a topology-dependent NVMe selector")

    expected_arguments = {
        "root": "root=fstab",
        "rd.systemd.verity": "rd.systemd.verity=1",
        "roothash": f"roothash={root_hash}",
        "systemd.verity_root_data": f"systemd.verity_root_data={data_device}",
        "systemd.verity_root_hash": f"systemd.verity_root_hash={hash_device}",
    }
    seen = set()
    read_only_count = 0
    for argument in command_line.split(" "):
        if argument == "ro":
            read_only_count += 1
            continue
        if argument == "rw":
            raise SystemExit("campaign command line enables a writable root")
        key = argument.split("=", 1)[0]
        if key in expected_arguments:
            if argument != expected_arguments[key] or key in seen:
                raise SystemExit(f"campaign command line has a non-canonical or repeated {key} selector")
            seen.add(key)
            continue
        if key == "rootfstype":
            raise SystemExit("campaign command line bypasses the sealed initramfs fstab type")
        if key == "systemd.verity" or key.startswith("systemd.verity_root_") or key.startswith("rd.systemd.verity_root_"):
            raise SystemExit(f"campaign command line contains unsupported verity selector {key!r}")
    if read_only_count != 1:
        raise SystemExit("campaign command line must contain ro exactly once")
    missing = set(expected_arguments) - seen
    if missing:
        raise SystemExit(f"campaign command line is missing required selectors: {sorted(missing)!r}")
    PY

    veritysetup verify \
      --hash=sha256 \
      --data-block-size=4096 \
      --hash-block-size=4096 \
      "$root_data" \
      "$root_hash_tree" \
      "$root_hash" \
      > "$validation_tmp/verity-verify.txt"
  '';
in
{
  verifiedSignedBoot,
  campaignPlan,
  campaignMutationInputs,
  delegatedRelease,
  rootDataPartitionGUID,
  rootHashPartitionGUID,
  bootFilesystemSizeMiB ? 128,
  name ? "kaiba-rpi5-stable-verifier-campaign-media",
}:

assert lib.assertMsg (canonicalDigest expectedCustomerKeyHash)
  "expectedCustomerKeyHash must be one canonical SHA-256 digest";
assert lib.assertMsg (
  builtins.isString expectedPublicKeyFileSHA256
  && builtins.match "[0-9a-f]{64}" expectedPublicKeyFileSHA256 != null
) "expectedPublicKeyFileSHA256 must contain exactly 64 lowercase hexadecimal characters";
assert lib.assertMsg (canonicalDigest expectedPublicKeyFingerprint)
  "expectedPublicKeyFingerprint must be one canonical SHA-256 digest";
assert lib.assertMsg (storeBacked signerIndependentReview)
  "signerIndependentReview must be one fixed public Nix-store path";
assert lib.assertMsg (storeBacked verifiedSignedBoot)
  "verifiedSignedBoot must be one fixed public Nix-store path";
assert lib.assertMsg (verifiedSignedBootContractValid verifiedSignedBoot)
  "verifiedSignedBoot must carry mkRpi5VerifiedSignedBoot pure-offline lineage";
assert lib.assertMsg (storeBacked campaignPlan)
  "campaignPlan must be one fixed public Nix-store path";
assert lib.assertMsg (storeBacked campaignMutationInputs)
  "campaignMutationInputs must be one fixed public Nix-store path";
assert lib.assertMsg (campaignMutationInputsContractValid campaignMutationInputs)
  "campaignMutationInputs must carry the fixed typed public mutation-input contract";
assert lib.assertMsg (storeBacked delegatedRelease)
  "delegatedRelease must be one fixed public Nix-store path";
assert lib.assertMsg (delegatedReleaseContractValid delegatedRelease)
  "delegatedRelease must be produced by mkRpi5DelegatedReleaseSpike";
assert lib.assertMsg (
  builtins.isInt bootFilesystemSizeMiB && bootFilesystemSizeMiB >= 112 && bootFilesystemSizeMiB <= 256
) "bootFilesystemSizeMiB must be an integer from 112 through 256";
let
  releaseAllowlist = delegatedRelease.kaibaRpi5DelegatedReleaseSpike.releaseAllowlist;
in
assert lib.assertMsg (exactAllowlist releaseAllowlist)
  "releaseAllowlist must be a sorted, unique list of 1 through 128 canonical relative paths";
assert lib.assertMsg (lib.all (
  path: builtins.elem path releaseAllowlist
) delegatedReleaseFixedPaths) "releaseAllowlist must include every fixed delegated-release role";
assert lib.assertMsg (lib.all delegatedReleasePath releaseAllowlist)
  "releaseAllowlist may contain only fixed roles and canonical overlays/[name].dtbo paths";
assert lib.assertMsg (canonicalPartitionGUID rootDataPartitionGUID)
  "rootDataPartitionGUID must be one canonical non-zero lowercase GPT partition GUID";
assert lib.assertMsg (canonicalPartitionGUID rootHashPartitionGUID)
  "rootHashPartitionGUID must be one canonical non-zero lowercase GPT partition GUID";
assert lib.assertMsg (
  rootDataPartitionGUID != rootHashPartitionGUID
) "rootDataPartitionGUID and rootHashPartitionGUID must be distinct";

let
  dataDevice = "PARTUUID=${rootDataPartitionGUID}";
  hashDevice = "PARTUUID=${rootHashPartitionGUID}";
  releaseTree = "${delegatedRelease}/nvme-release";
  releaseAllowlistFile = pkgs.writeText "${name}-release-allowlist" (
    lib.concatStringsSep "\n" releaseAllowlist + "\n"
  );
  releaseFilesystemUUID = "4b414942-4152-454c-9400-000000000001";
  releaseFilesystemHashSeed = "4b414942-4152-454c-9400-000000000002";
in
pkgs.runCommand name
  {
    campaignPlanInput = campaignPlan;
    campaignMutationInputsInput = campaignMutationInputs;
    delegatedReleaseInput = delegatedRelease;
    releaseAllowlistInput = releaseAllowlistFile;
    verifiedSignedBootInput = verifiedSignedBoot;
    nativeBuildInputs = [
      campaignInputValidator
      campaignMediaValidator
      pkgs.coreutils
      pkgs.cryptsetup
      pkgs.dosfstools
      pkgs.e2fsprogs
      pkgs.findutils
      pkgs.gnugrep
      pkgs.jq
      pkgs.mtools
    ];
    passthru.kaibaRpi5StableVerifierCampaignMedia = {
      inherit
        dataDevice
        delegatedRelease
        hashDevice
        campaignPlan
        campaignMutationInputs
        releaseAllowlist
        releaseTree
        rootDataPartitionGUID
        rootHashPartitionGUID
        verifiedSignedBoot
        ;
      artifactSchemaVersion = "kaiba.provisioning.rpi5-stable-verifier-campaign-media/v1alpha1";
      blockDeviceWriteCapable = false;
      delegatedReleaseSignatureVerification = "deferred_to_stable_verifier";
      directHardwareAccess = false;
      hardwareObserved = false;
      mutationCapable = false;
      privateKeyOperationCapable = false;
      physicalLayoutBound = false;
      productionReady = false;
      delegatedReleasePEMMarkerScan = "defense_in_depth_not_proof_of_absence";
      signingAuthorityConfigured = false;
      signingCapable = false;
      stableVerifierRootSignatureVerification = "reverified_during_build";
      storageFormat = "partition-payload-set-not-whole-device";
      runArtifactMaterializationContractTool = campaignContractTool;
      inputValidationTool = campaignInputValidator;
      validationTool = campaignMediaValidator;
      runID = "positive-baseline";
      recipeID = null;
    };
    preferLocalBuild = true;
  }
  ''
    set -euo pipefail
    export E2FSPROGS_FAKE_TIME=315532800
    export LC_ALL=C
    export SOURCE_DATE_EPOCH=315532800
    export TZ=UTC
    umask 022

    readonly stage="$TMPDIR/release-tree"
    readonly boot_filesystem="$out/sd/boot-filesystem.img"
    readonly release_image="$out/nvme/release-filesystem.img"
    readonly root_data="$out/sd/root-data.img"
    readonly root_hash_tree="$out/sd/root-hash.img"
    mkdir -p "$stage" "$out/nvme" "$out/sd"

    kaiba-stable-verifier-campaign-input-validate \
      --verified-signed-boot "$verifiedSignedBootInput" \
      --campaign-plan "$campaignPlanInput" \
      --campaign-mutation-inputs "$campaignMutationInputsInput" \
      --delegated-release "$delegatedReleaseInput" \
      --release-allowlist "$releaseAllowlistInput" \
      --metadata-out "$TMPDIR/validated-inputs.json"

    readonly releaseTreeInput="$delegatedReleaseInput/nvme-release"

    # Construct the boot partition from the exact verified signed-boot files.
    # No caller-authored FAT image or truth flag crosses this boundary.
    readonly boot_stage="$TMPDIR/sd-boot"
    mkdir -p "$boot_stage"
    install -m 0444 "$verifiedSignedBootInput/boot.img" "$boot_stage/boot.img"
    install -m 0444 "$verifiedSignedBootInput/boot.sig" "$boot_stage/boot.sig"
    printf '%s\n' 'boot_ramdisk=1' > "$boot_stage/config.txt"
    chmod 0444 "$boot_stage/config.txt"
    touch --date=@315532800 "$boot_stage"/*

    truncate --size=${toString bootFilesystemSizeMiB}M "$boot_filesystem"
    mkfs.vfat \
      --invariant \
      -F 32 \
      -i 4b535632 \
      -n KAIBA_SV_SD \
      "$boot_filesystem" > "$TMPDIR/mkfs-vfat.txt"
    mcopy -p -m -i "$boot_filesystem" "$boot_stage"/* ::/
    readonly boot_readback="$TMPDIR/sd-readback"
    mkdir -p "$boot_readback"
    mcopy -s -i "$boot_filesystem" '::*' "$boot_readback/"
    find "$boot_readback" -type f -printf '%P\n' | sort \
      > "$TMPDIR/actual-sd-files"
    printf '%s\n' boot.img boot.sig config.txt > "$TMPDIR/expected-sd-files"
    cmp "$TMPDIR/expected-sd-files" "$TMPDIR/actual-sd-files"
    while IFS= read -r relative_path; do
      cmp "$boot_stage/$relative_path" "$boot_readback/$relative_path"
    done < "$TMPDIR/expected-sd-files"
    boot_filesystem_digest="$(sha256sum "$boot_filesystem" | cut -d ' ' -f 1)"
    boot_filesystem_size="$(stat --format=%s "$boot_filesystem")"

    test -f "$releaseTreeInput/root.img"
    test ! -L "$releaseTreeInput/root.img"
    test -s "$releaseTreeInput/root.img"
    cp --reflink=auto --sparse=always "$releaseTreeInput/root.img" "$root_data"
    cmp "$releaseTreeInput/root.img" "$root_data"
    root_data_size="$(stat --format=%s "$root_data")"
    test $((root_data_size % 4096)) -eq 0
    root_data_digest="$(sha256sum "$root_data" | cut -d ' ' -f 1)"
    verity_uuid="''${root_data_digest:0:8}-''${root_data_digest:8:4}-''${root_data_digest:12:4}-''${root_data_digest:16:4}-''${root_data_digest:20:12}"

    : > "$root_hash_tree"
    veritysetup format \
      --hash=sha256 \
      --data-block-size=4096 \
      --hash-block-size=4096 \
      --salt="$root_data_digest" \
      --uuid="$verity_uuid" \
      --root-hash-file="$TMPDIR/root-hash" \
      "$root_data" \
      "$root_hash_tree" \
      > "$TMPDIR/verity-format.txt"
    root_hash="$(tr -d '\n' < "$TMPDIR/root-hash")"
    case "$root_hash" in
      ([0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
      (*)
        echo 'veritysetup returned a non-canonical root hash' >&2
        exit 1
        ;;
    esac
    test "''${#root_hash}" -eq 64

    kaiba-stable-verifier-campaign-media-validate \
      --release-tree "$releaseTreeInput" \
      --release-allowlist "$releaseAllowlistInput" \
      --root-data "$root_data" \
      --root-hash-tree "$root_hash_tree" \
      --root-hash "$root_hash" \
      --data-device '${dataDevice}' \
      --hash-device '${hashDevice}'

    while IFS= read -r relative_path; do
      install -D -m 0444 \
        "$releaseTreeInput/$relative_path" \
        "$stage/$relative_path"
    done < "$releaseAllowlistInput"
    find "$stage" -type d -exec chmod 0555 '{}' +
    find "$stage" -exec touch --date=@315532800 '{}' +

    release_bytes=0
    while IFS= read -r relative_path; do
      file_bytes="$(stat --format=%s "$stage/$relative_path")"
      release_bytes=$((release_bytes + file_bytes))
    done < "$releaseAllowlistInput"
    readonly mebibyte=1048576
    readonly filesystem_overhead=$((64 * mebibyte))
    release_image_size=$((
      (release_bytes + filesystem_overhead + mebibyte - 1) / mebibyte * mebibyte
    ))
    truncate --size="$release_image_size" "$release_image"
    mkfs.ext4 \
      -F \
      -L KAIBA_RELEASE \
      -U '${releaseFilesystemUUID}' \
      -N 4096 \
      -m 0 \
      -O '^has_journal' \
      -E hash_seed=${releaseFilesystemHashSeed},root_owner=0:0,lazy_itable_init=0,lazy_journal_init=0 \
      "$release_image" \
      > "$TMPDIR/mkfs-ext4.txt"

    # Normalize ext4 directory hashing across host architectures before any
    # directory entries are inserted. flags=1 is EXT2_FLAGS_SIGNED_HASH.
    printf '%s\n' \
      'set_super_value flags 1' \
      'close -a' \
      | debugfs -w "$release_image" > /dev/null
    debugfs -w -R 'rmdir /lost+found' "$release_image" > /dev/null
    if grep -q '^overlays/' "$releaseAllowlistInput"; then
      debugfs -w -R 'mkdir /overlays' "$release_image" > /dev/null
    fi
    while IFS= read -r relative_path; do
      debugfs -w \
        -R "write $stage/$relative_path /$relative_path" \
        "$release_image" > /dev/null
      debugfs -w -R "set_inode_field /$relative_path uid 0" "$release_image" > /dev/null
      debugfs -w -R "set_inode_field /$relative_path gid 0" "$release_image" > /dev/null
      debugfs -w -R "set_inode_field /$relative_path mode 0100444" "$release_image" > /dev/null
      for field in atime ctime mtime crtime; do
        debugfs -w \
          -R "set_inode_field /$relative_path $field @315532800" \
          "$release_image" > /dev/null
      done
    done < "$releaseAllowlistInput"
    for directory in / $(
      if grep -q '^overlays/' "$releaseAllowlistInput"; then
        printf '%s\n' /overlays
      fi
    ); do
      debugfs -w -R "set_inode_field $directory uid 0" "$release_image" > /dev/null
      debugfs -w -R "set_inode_field $directory gid 0" "$release_image" > /dev/null
      debugfs -w -R "set_inode_field $directory mode 040555" "$release_image" > /dev/null
      for field in atime ctime mtime crtime; do
        debugfs -w \
          -R "set_inode_field $directory $field @315532800" \
          "$release_image" > /dev/null
      done
    done
    e2fsck -fn "$release_image" > "$TMPDIR/e2fsck.txt"
    release_filesystem_label="$(${pkgs.e2fsprogs}/bin/tune2fs -l "$release_image" \
      | sed -n 's/^Filesystem volume name:[[:space:]]*//p')"
    release_filesystem_uuid="$(${pkgs.e2fsprogs}/bin/tune2fs -l "$release_image" \
      | sed -n 's/^Filesystem UUID:[[:space:]]*//p')"
    test "$release_filesystem_label" = KAIBA_RELEASE
    test "$release_filesystem_uuid" = '${releaseFilesystemUUID}'

    readonly readback="$TMPDIR/release-readback"
    mkdir -p "$readback"
    debugfs -R "rdump / $readback" "$release_image" > /dev/null
    find "$readback" -type f -printf '%P\n' | sort \
      > "$TMPDIR/readback-release-files"
    cmp "$releaseAllowlistInput" "$TMPDIR/readback-release-files"
    while IFS= read -r relative_path; do
      cmp "$stage/$relative_path" "$readback/$relative_path"
    done < "$releaseAllowlistInput"

    release_filesystem_digest="$(sha256sum "$release_image" | cut -d ' ' -f 1)"
    release_filesystem_size="$(stat --format=%s "$release_image")"
    root_hash_tree_digest="$(sha256sum "$root_hash_tree" | cut -d ' ' -f 1)"
    root_hash_tree_size="$(stat --format=%s "$root_hash_tree")"
    test $((root_hash_tree_size % 4096)) -eq 0

    : > "$TMPDIR/release-files.ndjson"
    while IFS= read -r relative_path; do
      file_size="$(stat --format=%s "$stage/$relative_path")"
      file_digest="$(sha256sum "$stage/$relative_path" | cut -d ' ' -f 1)"
      jq --null-input --compact-output --sort-keys \
        --arg path "$relative_path" \
        --arg sha256 "sha256:$file_digest" \
        --argjson size_bytes "$file_size" \
        '{path: $path, sha256: $sha256, size_bytes: $size_bytes}' \
        >> "$TMPDIR/release-files.ndjson"
    done < "$releaseAllowlistInput"
    jq --slurp --compact-output --sort-keys . \
      "$TMPDIR/release-files.ndjson" > "$TMPDIR/release-files.json"
    release_files_json="$(< "$TMPDIR/release-files.json")"
    release_tree_digest="sha256:$({
      printf '%s\0' 'kaiba.provisioning.rpi5-stable-verifier-campaign-release-tree.v1alpha1'
      printf '%s' "$release_files_json"
    } | sha256sum | cut -d ' ' -f 1)"
    test "$release_tree_digest" = \
      "$(jq -r .delegated_release.release_tree_digest "$TMPDIR/validated-inputs.json")"

    # Resolve the complete campaign plan against the exact bytes that will be
    # staged. This independently recomputes every byte-XOR after binding and
    # every manifest JSON-pointer difference, including the generated verity
    # tree targets that do not exist until this builder has constructed them.
    readonly resolver_public_inputs="$TMPDIR/resolver-public-inputs"
    readonly resolver_targets="$TMPDIR/resolver-targets"
    mkdir "$resolver_public_inputs" "$resolver_targets"
    install -m 0444 "$verifiedSignedBootInput/boot.img" \
      "$resolver_public_inputs/unsigned-verifier-boot"
    install -m 0444 "$verifiedSignedBootInput/public.pem" \
      "$resolver_public_inputs/customer-boot-public-key"
    install -m 0444 "$releaseTreeInput/release-manifest.json" \
      "$resolver_public_inputs/positive-release-manifest"
    mcopy -i "$verifiedSignedBootInput/boot.img" \
      '::/kaiba/stable-verifier-policy.json' \
      "$resolver_public_inputs/stable-verifier-policy"
    mcopy -i "$verifiedSignedBootInput/boot.img" \
      '::/kaiba/root-public.pem' \
      "$resolver_public_inputs/release-policy-root-public-key"
    mcopy -i "$verifiedSignedBootInput/boot.img" \
      '::/kaiba/authority-ca.pem' \
      "$resolver_public_inputs/authorization-trust-anchor"
    {
      printf '%s\0' 'kaiba.provisioning.rpi5-stable-verifier-campaign-release-tree.v1alpha1'
      printf '%s' "$release_files_json"
    } > "$resolver_public_inputs/positive-release-tree"
    while IFS= read -r binding_name; do
      install -m 0444 \
        "$campaignMutationInputsInput/$binding_name.json" \
        "$resolver_public_inputs/$binding_name"
    done < ${
      pkgs.writeText "kaiba-stable-campaign-resolver-mutation-input-names" (
        lib.concatStringsSep "\n" campaignMutationInputNames + "\n"
      )
    }
    jq -r '.byte_xor_mutations[].target' "$campaignPlanInput" \
      | while IFS= read -r target; do
        case "$target" in
          release/*) source="$releaseTreeInput/''${target#release/}" ;;
          media/root-data) source="$root_data" ;;
          media/root-hash) source="$root_hash_tree" ;;
          *) echo "unsupported campaign resolver target: $target" >&2; exit 1 ;;
        esac
        mkdir -p "$(dirname "$resolver_targets/$target")"
        cp --reflink=auto --sparse=always "$source" "$resolver_targets/$target"
        chmod 0444 "$resolver_targets/$target"
        test "$(stat --format=%s "$source")" = \
          "$(stat --format=%s "$resolver_targets/$target")"
      done
    ${campaignContractTool}/bin/kaiba-stable-campaign-contract resolve \
      "$campaignPlanInput" \
      "$resolver_public_inputs" \
      "$resolver_targets" \
      > "$TMPDIR/campaign-resolution"
    test "$(sed -n '1p' "$TMPDIR/campaign-resolution")" = \
      "$(jq -r .plan_digest "$campaignPlanInput")"
    test "$(sed -n '2p' "$TMPDIR/campaign-resolution")" = 27
    test "$(sed -n '3p' "$TMPDIR/campaign-resolution")" = 10
    test "$(sed -n '4p' "$TMPDIR/campaign-resolution")" = 20
    for line in 5 6 7 8; do
      sed -n "''${line}p" "$TMPDIR/campaign-resolution" \
        | grep -Ex 'sha256:[0-9a-f]{64}' > /dev/null
    done
    test "$(sed -n '9p' "$TMPDIR/campaign-resolution")" -gt 0
    test -n "$(sed -n '10p' "$TMPDIR/campaign-resolution")"
    test "$(wc -l < "$TMPDIR/campaign-resolution")" -eq 10
    jq -S \
      --slurpfile campaign_plan "$campaignPlanInput" \
      --arg plan_digest "$(sed -n '1p' "$TMPDIR/campaign-resolution")" \
      --argjson public_input_count "$(sed -n '2p' "$TMPDIR/campaign-resolution")" \
      --argjson byte_xor_mutation_count "$(sed -n '3p' "$TMPDIR/campaign-resolution")" \
      --argjson bound_replacement_count "$(sed -n '4p' "$TMPDIR/campaign-resolution")" \
      --arg policy_semantic_digest "$(sed -n '5p' "$TMPDIR/campaign-resolution")" \
      --arg positive_manifest_semantic_digest "$(sed -n '6p' "$TMPDIR/campaign-resolution")" \
      --arg replacement_manifest_semantic_digest "$(sed -n '7p' "$TMPDIR/campaign-resolution")" \
      --arg positive_tree_digest "$(sed -n '8p' "$TMPDIR/campaign-resolution")" \
      --argjson positive_tree_size "$(sed -n '9p' "$TMPDIR/campaign-resolution")" \
      --arg kernel_command_line "$(sed -n '10p' "$TMPDIR/campaign-resolution")" \
      '
      def input($name): ($campaign_plan[0].public_inputs[] | select(.name == $name));
      def file($binding): {sha256: $binding.digest, size_bytes: $binding.size_bytes};
      def command_line_recipe:
        ($campaign_plan[0].byte_xor_mutations[]
         | select(.recipe_id == "component-byte-mutations-rejected:kernel-command-line"));
      . + {campaign_plan_resolution: {
        plan_digest: $plan_digest,
        public_input_count: $public_input_count,
        byte_xor_mutation_count: $byte_xor_mutation_count,
        bound_replacement_count: $bound_replacement_count,
        status: "resolved_against_exact_bytes"
      }, semantic_resolution: {
        stable_verifier_policy: {
          file: file(input("stable-verifier-policy")),
          semantic_digest: $policy_semantic_digest
        },
        positive_release_manifest: {
          file: file(input("positive-release-manifest")),
          semantic_digest: $positive_manifest_semantic_digest
        },
        replacement_release_manifest: {
          file: file(input("replacement-release-manifest")),
          semantic_digest: $replacement_manifest_semantic_digest
        },
        positive_release_tree: {
          sha256: $positive_tree_digest,
          size_bytes: $positive_tree_size
        },
        kernel_command_line: {
          file: file(command_line_recipe.before),
          value: $kernel_command_line
        }
      }}' "$TMPDIR/validated-inputs.json" \
      > "$TMPDIR/validated-inputs-resolved.json"
    mv "$TMPDIR/validated-inputs-resolved.json" "$TMPDIR/validated-inputs.json"
    validated_inputs_json="$(jq -cS . "$TMPDIR/validated-inputs.json")"
    campaign_id="$(jq -r .campaign_id "$TMPDIR/validated-inputs.json")"
    plan_digest="$(jq -r .plan_digest "$TMPDIR/validated-inputs.json")"

    # This compact artifact-set is the sole cross-layer source for staging and
    # execution contracts. It binds payload bytes, not target geometry or a
    # device readback. Those belong to a later, separately authorized plan.
    jq -cnS \
      --arg campaign_id "$campaign_id" \
      --arg plan_digest "$plan_digest" \
      --argjson validated_inputs "$validated_inputs_json" \
      --arg boot_digest "sha256:$boot_filesystem_digest" \
      --argjson boot_size "$boot_filesystem_size" \
      --arg release_digest "sha256:$release_filesystem_digest" \
      --argjson release_size "$release_filesystem_size" \
      --arg root_data_digest "sha256:$root_data_digest" \
      --argjson root_data_size "$root_data_size" \
      --arg root_hash_digest "sha256:$root_hash_tree_digest" \
      --argjson root_hash_size "$root_hash_tree_size" \
      --arg root_hash "sha256:$root_hash" \
      --arg data_device '${dataDevice}' \
      --arg hash_device '${hashDevice}' \
      --arg data_guid '${rootDataPartitionGUID}' \
      --arg hash_guid '${rootHashPartitionGUID}' \
      '{
        schema_version: "kaiba.provisioning.rpi5-stable-verifier-campaign-artifact-set/v1alpha1",
        campaign_id: $campaign_id,
        campaign_plan_resolution: $validated_inputs.campaign_plan_resolution,
        plan_digest: $plan_digest,
        run_id: "positive-baseline",
        recipe_id: null,
        storage_format: "partition-payload-set-not-whole-device",
        physical_layout_bound: false,
        artifacts: [
          {role: "boot-filesystem", name: "sd/boot-filesystem.img", digest: $boot_digest, size_bytes: $boot_size},
          {role: "release-filesystem", name: "nvme/release-filesystem.img", digest: $release_digest, size_bytes: $release_size},
          {role: "root-data", name: "sd/root-data.img", digest: $root_data_digest, size_bytes: $root_data_size},
          {role: "root-hash", name: "sd/root-hash.img", digest: $root_hash_digest, size_bytes: $root_hash_size}
        ],
        verity: {
          algorithm: "sha256",
          data_block_size: 4096,
          hash_block_size: 4096,
          no_superblock: false,
          root_hash: $root_hash,
          data_device: $data_device,
          hash_device: $hash_device,
          data_partition_guid: $data_guid,
          hash_partition_guid: $hash_guid
        },
        provenance: {
          campaign_plan: $validated_inputs.campaign_plan,
          verified_signed_boot: $validated_inputs.verified_signed_boot,
          delegated_release: $validated_inputs.delegated_release
        },
        semantic_resolution: $validated_inputs.semantic_resolution,
        capabilities: {
          delegated_release_private_key_pem_marker_scan: "passed_defense_in_depth_not_proof_of_absence",
          private_key_operation_performed: false,
          signing_performed: false,
          device_writes_performed: false,
          hardware_observed: false,
          mutation_performed: false,
          production_ready: false
        }
      }' > "$TMPDIR/artifact-set-without-digest.json"
    public_artifact_set_material="$(< "$TMPDIR/artifact-set-without-digest.json")"
    public_artifact_set_digest="sha256:$({
      printf '%s\0' 'kaiba.provisioning.rpi5-stable-verifier-campaign-artifact-set.v1alpha1'
      printf '%s' "$public_artifact_set_material"
    } | sha256sum | cut -d ' ' -f 1)"
    jq -cS \
      --arg artifact_set_content_digest "$public_artifact_set_digest" \
      '. + {artifact_set_content_digest: $artifact_set_content_digest}' \
      "$TMPDIR/artifact-set-without-digest.json" \
      > "$out/artifact-set.json"
    ${campaignContractTool}/bin/kaiba-stable-campaign-contract artifact-set \
      "$campaignPlanInput" "$out/artifact-set.json" \
      "$resolver_public_inputs" "$resolver_targets" \
      > "$TMPDIR/validated-artifact-set-digest"
    test "$(cat "$TMPDIR/validated-artifact-set-digest")" = \
      "$public_artifact_set_digest"
    test "$(wc -l < "$TMPDIR/validated-artifact-set-digest")" -eq 1
    public_artifact_set_file_digest="sha256:$(sha256sum "$out/artifact-set.json" | cut -d ' ' -f 1)"
    public_artifact_set_file_size="$(stat --format=%s "$out/artifact-set.json")"

    jq --null-input --sort-keys \
      --arg schema_version 'kaiba.provisioning.rpi5-stable-verifier-campaign-media/v1alpha1' \
      --arg campaign_id "$campaign_id" \
      --arg plan_digest "$plan_digest" \
      --argjson validated_inputs "$validated_inputs_json" \
      --arg public_artifact_set_digest "$public_artifact_set_file_digest" \
      --argjson public_artifact_set_size "$public_artifact_set_file_size" \
      --argjson release_allowlist ${lib.escapeShellArg (builtins.toJSON releaseAllowlist)} \
      --argjson release_files "$release_files_json" \
      --arg release_tree_digest "$release_tree_digest" \
      --arg boot_filesystem_digest "sha256:$boot_filesystem_digest" \
      --argjson boot_filesystem_size "$boot_filesystem_size" \
      --arg release_filesystem_digest "sha256:$release_filesystem_digest" \
      --argjson release_filesystem_size "$release_filesystem_size" \
      --arg root_data_digest "sha256:$root_data_digest" \
      --argjson root_data_size "$root_data_size" \
      --arg root_hash_tree_digest "sha256:$root_hash_tree_digest" \
      --argjson root_hash_tree_size "$root_hash_tree_size" \
      --arg root_hash "sha256:$root_hash" \
      --arg data_device '${dataDevice}' \
      --arg hash_device '${hashDevice}' \
      --arg data_guid '${rootDataPartitionGUID}' \
      --arg hash_guid '${rootHashPartitionGUID}' \
      --arg release_filesystem_label "$release_filesystem_label" \
      --arg release_filesystem_uuid "$release_filesystem_uuid" \
      --arg cryptsetup_version '${lib.getVersion pkgs.cryptsetup}' \
      --arg e2fsprogs_version '${lib.getVersion pkgs.e2fsprogs}' \
      '{
        schema_version: $schema_version,
        campaign_id: $campaign_id,
        campaign_plan_resolution: $validated_inputs.campaign_plan_resolution,
        plan_digest: $plan_digest,
        run: {
          run_id: "positive-baseline",
          recipe_id: null
        },
        physical_layout_bound: false,
        public_artifact_set: {
          path: "artifact-set.json",
          sha256: $public_artifact_set_digest,
          size_bytes: $public_artifact_set_size
        },
        validated_inputs: $validated_inputs,
        storage_format: "partition-payload-set-not-whole-device",
        release: {
          allowlist: $release_allowlist,
          files: $release_files,
          tree_digest: $release_tree_digest,
          signature_verification: "deferred_to_stable_verifier"
        },
        artifacts: {
          stable_verifier_boot_filesystem: {
            path: "sd/boot-filesystem.img",
            sha256: $boot_filesystem_digest,
            size_bytes: $boot_filesystem_size,
            filesystem: "vfat",
            signature_verification: "reverified_from_verified_signed_boot",
            boot_image_sha256: $validated_inputs.verified_signed_boot.boot_image.sha256,
            boot_signature_sha256: $validated_inputs.verified_signed_boot.boot_signature.sha256,
            public_key_sha256: $validated_inputs.verified_signed_boot.public_key.sha256,
            public_key_fingerprint: $validated_inputs.verified_signed_boot.public_key.fingerprint
          },
          release_filesystem: {
            path: "nvme/release-filesystem.img",
            sha256: $release_filesystem_digest,
            size_bytes: $release_filesystem_size,
            filesystem: "ext4",
            filesystem_label: $release_filesystem_label,
            filesystem_uuid: $release_filesystem_uuid,
            required_partition_label: "KAIBA_RELEASE"
          },
          root_data: {
            path: "sd/root-data.img",
            sha256: $root_data_digest,
            size_bytes: $root_data_size,
            required_partition_guid: $data_guid
          },
          root_hash_tree: {
            path: "sd/root-hash.img",
            sha256: $root_hash_tree_digest,
            size_bytes: $root_hash_tree_size,
            required_partition_guid: $hash_guid
          }
        },
        verity: {
          algorithm: "sha256",
          data_block_size: 4096,
          hash_block_size: 4096,
          no_superblock: false,
          root_hash: $root_hash,
          data_device: $data_device,
          hash_device: $hash_device,
          mapper: "/dev/mapper/root",
          offline_verification: "passed"
        },
        toolchain: {
          cryptsetup: $cryptsetup_version,
          e2fsprogs: $e2fsprogs_version
        },
        capabilities: {
          delegated_release_private_key_pem_marker_scan: "passed_defense_in_depth_not_proof_of_absence",
          private_key_operation_performed: false,
          signing_performed: false,
          device_writes_performed: false,
          hardware_observed: false,
          mutation_performed: false,
          production_ready: false
        }
      }' > "$TMPDIR/manifest-without-artifact-set-digest.json"
    canonical_manifest="$(jq --compact-output --sort-keys . \
      "$TMPDIR/manifest-without-artifact-set-digest.json")"
    manifest_content_digest="sha256:$({
      printf '%s\0' 'kaiba.provisioning.rpi5-stable-verifier-campaign-media.v1alpha1'
      printf '%s' "$canonical_manifest"
    } | sha256sum | cut -d ' ' -f 1)"
    jq --sort-keys \
      --arg manifest_content_digest "$manifest_content_digest" \
      '. + {manifest_content_digest: $manifest_content_digest}' \
      "$TMPDIR/manifest-without-artifact-set-digest.json" \
      > "$out/manifest.json"

    chmod 0444 \
      "$out/artifact-set.json" \
      "$out/manifest.json" \
      "$boot_filesystem" \
      "$release_image" \
      "$root_data" \
      "$root_hash_tree"
  ''
