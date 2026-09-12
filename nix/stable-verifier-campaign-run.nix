{
  lib,
  pkgs,
}:

let
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
  baselineContractValid =
    artifact:
    let
      contract =
        if builtins.isAttrs artifact && artifact ? kaibaRpi5StableVerifierCampaignMedia then
          artifact.kaibaRpi5StableVerifierCampaignMedia
        else
          { };
    in
    (contract.artifactSchemaVersion or null)
    == "kaiba.provisioning.rpi5-stable-verifier-campaign-media/v1alpha1"
    && (contract.storageFormat or null) == "partition-payload-set-not-whole-device"
    && (contract.runID or null) == "positive-baseline"
    && (contract.recipeID or false) == null
    && !(contract.blockDeviceWriteCapable or true)
    && !(contract.directHardwareAccess or true)
    && !(contract.hardwareObserved or true)
    && !(contract.mutationCapable or true)
    && !(contract.privateKeyOperationCapable or true)
    && !(contract.productionReady or true)
    && !(contract.signingAuthorityConfigured or true)
    && !(contract.signingCapable or true)
    && storeBacked (contract.campaignPlan or "")
    && storeBacked (contract.campaignMutationInputs or "")
    && storeBacked (contract.delegatedRelease or "")
    && storeBacked (contract.verifiedSignedBoot or "")
    && storeBacked (contract.runArtifactMaterializationContractTool or "");

  runSelectorMain = pkgs.writeText "kaiba-stable-campaign-run-select-main.go" ''
    package main

    import (
      "encoding/json"
      "fmt"
      "os"
      "strconv"

      "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
    )

    const schemaVersion = "kaiba.provisioning.rpi5-stable-verifier-campaign-run-selection/v1alpha1"

    type selection struct {
      SchemaVersion string `json:"schema_version"`
      RunIndex uint16 `json:"run_index"`
      RunID string `json:"run_id"`
      RecipeID string `json:"recipe_id,omitempty"`
    }

    func fail(err error) {
      fmt.Fprintln(os.Stderr, err)
      os.Exit(1)
    }

    func main() {
      if len(os.Args) != 3 {
        fail(fmt.Errorf("usage: %s CAMPAIGN_PLAN RUN_INDEX", os.Args[0]))
      }
      encoded, err := os.ReadFile(os.Args[1])
      if err != nil {
        fail(err)
      }
      plan, err := stablecampaign.ParsePlan(encoded)
      if err != nil {
        fail(err)
      }
      runs, err := stablecampaign.ExpectedRuns(plan)
      if err != nil {
        fail(err)
      }
      parsed, err := strconv.ParseUint(os.Args[2], 10, 16)
      if err != nil || parsed == 0 || int(parsed) > len(runs) {
        fail(fmt.Errorf("run_index must be between 1 and %d", len(runs)))
      }
      run := runs[parsed-1]
      output := selection{
        SchemaVersion: schemaVersion,
        RunIndex: run.Index,
        RunID: run.RunID,
        RecipeID: run.MutationRecipeID,
      }
      encoder := json.NewEncoder(os.Stdout)
      encoder.SetEscapeHTML(false)
      if err := encoder.Encode(output); err != nil {
        fail(err)
      }
    }
  '';
  runSelectorSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../internal/provisioning
    ];
  };
  runSelectorPreparedSource = pkgs.runCommand "kaiba-stable-campaign-run-select-source" { } ''
    cp -R --no-preserve=ownership ${runSelectorSource}/. "$out/"
    chmod -R u+w "$out"
    mkdir -p "$out/cmd/kaiba-stable-campaign-run-select"
    install -m 0444 ${runSelectorMain} \
      "$out/cmd/kaiba-stable-campaign-run-select/main.go"
  '';
  runSelector = pkgs.buildGoModule {
    pname = "kaiba-stable-campaign-run-select";
    version = "0.1.0";
    src = runSelectorPreparedSource;
    subPackages = [ "cmd/kaiba-stable-campaign-run-select" ];
    vendorHash = null;
    doCheck = false;
    meta.mainProgram = "kaiba-stable-campaign-run-select";
  };
in
{
  baselineMedia,
  runIndex,
  name ? "kaiba-rpi5-stable-verifier-campaign-run-${toString runIndex}",
}:

assert lib.assertMsg (storeBacked baselineMedia) "baselineMedia must be one fixed Nix-store path";
assert lib.assertMsg (baselineContractValid baselineMedia)
  "baselineMedia must carry the validated, non-mutating campaign-media contract";
assert lib.assertMsg (
  builtins.isInt runIndex && runIndex >= 1 && runIndex <= 33
) "runIndex must be an integer from 1 through 33";

let
  baselineContract = baselineMedia.kaibaRpi5StableVerifierCampaignMedia;
  campaignPlan = baselineContract.campaignPlan;
  campaignMutationInputs = baselineContract.campaignMutationInputs;
  delegatedRelease = baselineContract.delegatedRelease;
  verifiedSignedBoot = baselineContract.verifiedSignedBoot;
  runArtifactMaterializationContractTool = baselineContract.runArtifactMaterializationContractTool;
in
pkgs.runCommand name
  {
    baselineMediaInput = baselineMedia;
    campaignPlanInput = campaignPlan;
    campaignMutationInputsInput = campaignMutationInputs;
    delegatedReleaseInput = delegatedRelease;
    verifiedSignedBootInput = verifiedSignedBoot;
    nativeBuildInputs = [
      runArtifactMaterializationContractTool
      runSelector
      pkgs.coreutils
      pkgs.diffutils
      pkgs.e2fsprogs
      pkgs.findutils
      pkgs.gnugrep
      pkgs.gnused
      pkgs.jq
      pkgs.mtools
      pkgs.python3
    ];
    passthru.kaibaRpi5StableVerifierCampaignRun = {
      artifactSchemaVersion = "kaiba.provisioning.rpi5-stable-verifier-campaign-run-media/v1alpha1";
      materializationSchemaVersion = "kaiba.provisioning.rpi5-stable-verifier-run-artifact-materialization/v1alpha1";
      inherit
        baselineMedia
        campaignMutationInputs
        campaignPlan
        runIndex
        ;
      blockDeviceWriteCapable = false;
      claimClosureCapable = false;
      createNew = true;
      createNewScope = "nix-store-output-only";
      directHardwareAccess = false;
      executionCapable = false;
      hardwareObserved = false;
      mutationCapable = true;
      mutationScope = "copied-partition-payloads-in-nix-store-only";
      physicalLayoutBound = false;
      privateKeyAccess = false;
      privateKeyOperationCapable = false;
      productionReady = false;
      signingAuthorityConfigured = false;
      signingCapable = false;
      storageFormat = "partition-payload-set-not-whole-device";
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

    readonly baseline="$baselineMediaInput"
    readonly baseline_manifest="$baseline/manifest.json"
    readonly baseline_artifact_set="$baseline/artifact-set.json"
    readonly boot_filesystem="$out/sd/boot-filesystem.img"
    readonly release_filesystem="$out/nvme/release-filesystem.img"
    readonly root_data="$out/sd/root-data.img"
    readonly root_hash="$out/sd/root-hash.img"
    readonly run_index='${toString runIndex}'

    test -f "$baseline_manifest"
    test ! -L "$baseline_manifest"
    test -f "$baseline_artifact_set"
    test ! -L "$baseline_artifact_set"
    jq -e '
      .schema_version == "kaiba.provisioning.rpi5-stable-verifier-campaign-media/v1alpha1"
      and .run == {recipe_id: null, run_id: "positive-baseline"}
      and .storage_format == "partition-payload-set-not-whole-device"
      and .physical_layout_bound == false
      and .capabilities.private_key_operation_performed == false
      and .capabilities.signing_performed == false
      and .capabilities.device_writes_performed == false
      and .capabilities.hardware_observed == false
      and .capabilities.mutation_performed == false
      and .capabilities.production_ready == false
    ' "$baseline_manifest" > "$TMPDIR/baseline-manifest-validation"
    jq -e '
      .schema_version == "kaiba.provisioning.rpi5-stable-verifier-campaign-artifact-set/v1alpha1"
      and .run_id == "positive-baseline"
      and .recipe_id == null
      and .storage_format == "partition-payload-set-not-whole-device"
      and .physical_layout_bound == false
    ' "$baseline_artifact_set" > "$TMPDIR/baseline-artifact-set-validation"
    baseline_artifact_set_material="$(
      jq -cS 'del(.artifact_set_content_digest)' "$baseline_artifact_set"
    )"
    derived_baseline_artifact_set_content_digest="sha256:$({
      printf '%s\0' 'kaiba.provisioning.rpi5-stable-verifier-campaign-artifact-set.v1alpha1'
      printf '%s' "$baseline_artifact_set_material"
    } | sha256sum | cut -d ' ' -f 1)"
    test "$(jq -er .artifact_set_content_digest "$baseline_artifact_set")" = \
      "$derived_baseline_artifact_set_content_digest"
    baseline_manifest_material="$(
      jq -cS 'del(.manifest_content_digest)' "$baseline_manifest"
    )"
    derived_baseline_manifest_content_digest="sha256:$({
      printf '%s\0' 'kaiba.provisioning.rpi5-stable-verifier-campaign-media.v1alpha1'
      printf '%s' "$baseline_manifest_material"
    } | sha256sum | cut -d ' ' -f 1)"
    test "$(jq -er .manifest_content_digest "$baseline_manifest")" = \
      "$derived_baseline_manifest_content_digest"
    test "$(jq -er .public_artifact_set.sha256 "$baseline_manifest")" = \
      "sha256:$(sha256sum "$baseline_artifact_set" | cut -d ' ' -f 1)"
    test "$(jq -er '.public_artifact_set.size_bytes | tostring' "$baseline_manifest")" = \
      "$(stat --format=%s "$baseline_artifact_set")"
    test "$(jq -er .campaign_id "$baseline_manifest")" = \
      "$(jq -er .campaign_id "$baseline_artifact_set")"
    test "$(jq -r .plan_digest "$baseline_manifest")" = \
      "$(jq -r .plan_digest "$campaignPlanInput")"
    test "$(jq -r .plan_digest "$baseline_artifact_set")" = \
      "$(jq -r .plan_digest "$campaignPlanInput")"

    verify_binding() {
      local input="$1"
      local expected_digest="$2"
      local expected_size="$3"
      test -f "$input"
      test ! -L "$input"
      test "$(stat --format=%s "$input")" = "$expected_size"
      test "sha256:$(sha256sum "$input" | cut -d ' ' -f 1)" = "$expected_digest"
    }

    same_bytes() {
      test "$(stat --format=%s "$1")" = "$(stat --format=%s "$2")" \
        && test "$(sha256sum "$1" | cut -d ' ' -f 1)" = \
          "$(sha256sum "$2" | cut -d ' ' -f 1)"
    }

    verify_single_byte_difference() {
      python3 - "$1" "$2" "$3" <<'PY'
    import pathlib
    import sys

    before_path = pathlib.Path(sys.argv[1])
    after_path = pathlib.Path(sys.argv[2])
    expected_offset = int(sys.argv[3])
    differences = []
    position = 0
    with before_path.open("rb") as before, after_path.open("rb") as after:
        while True:
            before_chunk = before.read(1024 * 1024)
            after_chunk = after.read(1024 * 1024)
            if len(before_chunk) != len(after_chunk):
                raise SystemExit("materialized payload size differs from byte-XOR baseline")
            if not before_chunk:
                break
            differences.extend(
                position + index
                for index, (left, right) in enumerate(zip(before_chunk, after_chunk))
                if left != right
            )
            if len(differences) > 1:
                raise SystemExit("byte-XOR changed more than one partition-payload byte")
            position += len(before_chunk)
    if differences != [expected_offset]:
        raise SystemExit(
            f"byte-XOR differences {differences!r} do not equal offset {expected_offset}"
        )
    PY
    }

    baseline_binding() {
      local key="$1"
      jq -er --arg key "$key" '.artifacts[$key] | [.sha256, (.size_bytes | tostring)] | @tsv' \
        "$baseline_manifest"
    }

    while IFS=$'\t' read -r source key; do
      IFS=$'\t' read -r digest size < <(baseline_binding "$key")
      verify_binding "$baseline/$source" "$digest" "$size"
    done <<'EOF'
    sd/boot-filesystem.img	stable_verifier_boot_filesystem
    nvme/release-filesystem.img	release_filesystem
    sd/root-data.img	root_data
    sd/root-hash.img	root_hash_tree
    EOF
    jq -e --slurpfile media "$baseline_manifest" '
      def media_artifact($key):
        $media[0].artifacts[$key] | {digest: .sha256, size_bytes};
      def set_artifact($role):
        .artifacts[] | select(.role == $role) | {digest, size_bytes};
      set_artifact("boot-filesystem") == media_artifact("stable_verifier_boot_filesystem")
      and set_artifact("release-filesystem") == media_artifact("release_filesystem")
      and set_artifact("root-data") == media_artifact("root_data")
      and set_artifact("root-hash") == media_artifact("root_hash_tree")
    ' "$baseline_artifact_set" > "$TMPDIR/baseline-cross-binding-validation"

    mkdir -p "$out/nvme" "$out/sd"
    cp --reflink=never --sparse=always \
      "$baseline/sd/boot-filesystem.img" "$boot_filesystem"
    cp --reflink=never --sparse=always \
      "$baseline/nvme/release-filesystem.img" "$release_filesystem"
    cp --reflink=never --sparse=always \
      "$baseline/sd/root-data.img" "$root_data"
    cp --reflink=never --sparse=always \
      "$baseline/sd/root-hash.img" "$root_hash"
    chmod 0644 "$boot_filesystem" "$release_filesystem" "$root_data" "$root_hash"

    kaiba-stable-campaign-run-select "$campaignPlanInput" "$run_index" \
      > "$TMPDIR/run-selection.json"
    jq -e \
      --argjson run_index "$run_index" \
      '
        .schema_version == "kaiba.provisioning.rpi5-stable-verifier-campaign-run-selection/v1alpha1"
        and .run_index == $run_index
        and (.run_id | test("^[a-z0-9][a-z0-9-]*(?::[a-z0-9][a-z0-9-]*)?$"))
        and ((.recipe_id // "") | test("^(|[a-z0-9][a-z0-9-]*:[a-z0-9][a-z0-9-]*)$"))
      ' "$TMPDIR/run-selection.json" > "$TMPDIR/run-selection-validation"
    readonly run_id="$(jq -er .run_id "$TMPDIR/run-selection.json")"
    readonly recipe_id="$(jq -r '.recipe_id // ""' "$TMPDIR/run-selection.json")"

    recipe_kind=none
    changed_role=
    mutation_json=null
    if test -n "$recipe_id"; then
      byte_count="$(jq --arg recipe_id "$recipe_id" \
        '[.byte_xor_mutations[] | select(.recipe_id == $recipe_id)] | length' \
        "$campaignPlanInput")"
      replacement_count="$(jq --arg recipe_id "$recipe_id" \
        '[.bound_replacements[] | select(.recipe_id == $recipe_id)] | length' \
        "$campaignPlanInput")"
      test "$((byte_count + replacement_count))" -eq 1

      if test "$byte_count" -eq 1; then
        recipe_kind=byte-xor
        jq -cS --arg recipe_id "$recipe_id" \
          '.byte_xor_mutations[] | select(.recipe_id == $recipe_id)' \
          "$campaignPlanInput" > "$TMPDIR/recipe.json"
        test "$(jq -r .offset_bytes "$TMPDIR/recipe.json")" = 0
        test "$(jq -r .xor_mask "$TMPDIR/recipe.json")" = 1
        target="$(jq -er .target "$TMPDIR/recipe.json")"
        before_digest="$(jq -er .before.digest "$TMPDIR/recipe.json")"
        before_size="$(jq -er '.before.size_bytes | tostring' "$TMPDIR/recipe.json")"
        after_digest="$(jq -er .after.digest "$TMPDIR/recipe.json")"
        after_size="$(jq -er '.after.size_bytes | tostring' "$TMPDIR/recipe.json")"
        test "$before_size" = "$after_size"

        case "$target" in
          release/*)
            relative="''${target#release/}"
            printf '%s\n' "$relative" \
              | grep -Ex '(kernel|initramfs|device-tree\.dtb|cmdline\.txt|root\.img|dm-verity\.json|slot\.txt|overlays/[a-z0-9][a-z0-9_-]{0,63}\.dtbo)' \
              > "$TMPDIR/release-target-validation"
            changed_role=release-filesystem
            debugfs -R "dump /$relative $TMPDIR/target-before" \
              "$release_filesystem" > "$TMPDIR/debugfs-target-before"
            verify_binding "$TMPDIR/target-before" "$before_digest" "$before_size"

            block_size="$(tune2fs -l "$release_filesystem" \
              | sed -n 's/^Block size:[[:space:]]*//p')"
            block_number="$(debugfs -R "bmap /$relative 0" \
              "$release_filesystem" 2>"$TMPDIR/debugfs-bmap-stderr")"
            printf '%s\n' "$block_size" | grep -Ex '[1-9][0-9]*' \
              > "$TMPDIR/block-size-validation"
            printf '%s\n' "$block_number" | grep -Ex '[1-9][0-9]*' \
              > "$TMPDIR/block-number-validation"
            image_offset="$((block_number * block_size))"
            old_byte="$(dd if="$release_filesystem" bs=1 skip="$image_offset" count=1 \
              status=none | od -An -tu1 | tr -d ' ')"
            printf '%s\n' "$old_byte" | grep -Ex '([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])' \
              > "$TMPDIR/old-byte-validation"
            new_byte="$((old_byte ^ 1))"
            printf "\\$(printf '%03o' "$new_byte")" > "$TMPDIR/xor-byte"
            test "$(stat --format=%s "$TMPDIR/xor-byte")" -eq 1
            dd if="$TMPDIR/xor-byte" of="$release_filesystem" \
              bs=1 seek="$image_offset" count=1 conv=notrunc status=none
            test "$(dd if="$release_filesystem" bs=1 skip="$image_offset" count=1 \
              status=none | od -An -tu1 | tr -d ' ')" -eq "$new_byte"

            verify_single_byte_difference \
              "$baseline/nvme/release-filesystem.img" \
              "$release_filesystem" \
              "$image_offset"
            debugfs -R "dump /$relative $TMPDIR/target-after" \
              "$release_filesystem" > "$TMPDIR/debugfs-target-after"
            verify_binding "$TMPDIR/target-after" "$after_digest" "$after_size"
            e2fsck -fn "$release_filesystem" > "$TMPDIR/e2fsck-byte-xor.txt"
            ;;
          media/root-data)
            changed_role=root-data
            verify_binding "$root_data" "$before_digest" "$before_size"
            old_byte="$(dd if="$root_data" bs=1 count=1 status=none \
              | od -An -tu1 | tr -d ' ')"
            new_byte="$((old_byte ^ 1))"
            printf "\\$(printf '%03o' "$new_byte")" > "$TMPDIR/xor-byte"
            test "$(stat --format=%s "$TMPDIR/xor-byte")" -eq 1
            dd if="$TMPDIR/xor-byte" of="$root_data" \
              bs=1 seek=0 count=1 conv=notrunc status=none
            verify_binding "$root_data" "$after_digest" "$after_size"
            verify_single_byte_difference \
              "$baseline/sd/root-data.img" "$root_data" 0
            ;;
          media/root-hash)
            changed_role=root-hash
            verify_binding "$root_hash" "$before_digest" "$before_size"
            old_byte="$(dd if="$root_hash" bs=1 count=1 status=none \
              | od -An -tu1 | tr -d ' ')"
            new_byte="$((old_byte ^ 1))"
            printf "\\$(printf '%03o' "$new_byte")" > "$TMPDIR/xor-byte"
            test "$(stat --format=%s "$TMPDIR/xor-byte")" -eq 1
            dd if="$TMPDIR/xor-byte" of="$root_hash" \
              bs=1 seek=0 count=1 conv=notrunc status=none
            verify_binding "$root_hash" "$after_digest" "$after_size"
            verify_single_byte_difference \
              "$baseline/sd/root-hash.img" "$root_hash" 0
            ;;
          *)
            echo "unsupported byte-XOR campaign target: $target" >&2
            exit 1
            ;;
        esac
        mutation_json="$(jq -cS '{
          kind: "byte-xor",
          recipe_id,
          target,
          before,
          after,
          offset_bytes,
          xor_mask
        }' "$TMPDIR/recipe.json")"
      else
        recipe_kind=bound-replacement
        changed_role=release-filesystem
        jq -cS --arg recipe_id "$recipe_id" \
          '.bound_replacements[] | select(.recipe_id == $recipe_id)' \
          "$campaignPlanInput" > "$TMPDIR/recipe.json"
        test "$(jq -r .target "$TMPDIR/recipe.json")" = \
          release/release-manifest.json
        replacement_input="$(jq -er .replacement_input "$TMPDIR/recipe.json")"
        printf '%s\n' "$replacement_input" \
          | grep -Ex '[a-z0-9][a-z0-9-]{0,127}' \
            > "$TMPDIR/replacement-input-validation"
        replacement="$campaignMutationInputsInput/$replacement_input.json"
        before_digest="$(jq -er .before.digest "$TMPDIR/recipe.json")"
        before_size="$(jq -er '.before.size_bytes | tostring' "$TMPDIR/recipe.json")"
        after_digest="$(jq -er .after.digest "$TMPDIR/recipe.json")"
        after_size="$(jq -er '.after.size_bytes | tostring' "$TMPDIR/recipe.json")"
        debugfs -R "dump /release-manifest.json $TMPDIR/release-manifest-before" \
          "$release_filesystem" > "$TMPDIR/debugfs-manifest-before"
        verify_binding "$TMPDIR/release-manifest-before" "$before_digest" "$before_size"
        verify_binding "$replacement" "$after_digest" "$after_size"

        readonly baseline_release_tree="$TMPDIR/baseline-release-tree"
        readonly materialized_release_tree="$TMPDIR/materialized-release-tree"
        mkdir "$baseline_release_tree" "$materialized_release_tree"
        debugfs -R "rdump / $baseline_release_tree" \
          "$baseline/nvme/release-filesystem.img" > "$TMPDIR/debugfs-baseline-rdump"
        debugfs -w -R 'rm /release-manifest.json' "$release_filesystem" \
          > "$TMPDIR/debugfs-manifest-remove"
        debugfs -w -R "write $replacement /release-manifest.json" \
          "$release_filesystem" > "$TMPDIR/debugfs-manifest-write"
        debugfs -w -R 'set_inode_field /release-manifest.json uid 0' \
          "$release_filesystem" > "$TMPDIR/debugfs-manifest-uid"
        debugfs -w -R 'set_inode_field /release-manifest.json gid 0' \
          "$release_filesystem" > "$TMPDIR/debugfs-manifest-gid"
        debugfs -w -R 'set_inode_field /release-manifest.json mode 0100444' \
          "$release_filesystem" > "$TMPDIR/debugfs-manifest-mode"
        for field in atime ctime mtime crtime; do
          debugfs -w -R "set_inode_field /release-manifest.json $field @315532800" \
            "$release_filesystem" > "$TMPDIR/debugfs-manifest-$field"
          debugfs -w -R "set_inode_field / $field @315532800" \
            "$release_filesystem" > "$TMPDIR/debugfs-root-$field"
        done
        e2fsck -fn "$release_filesystem" > "$TMPDIR/e2fsck-replacement.txt"
        debugfs -R "rdump / $materialized_release_tree" \
          "$release_filesystem" > "$TMPDIR/debugfs-materialized-rdump"
        verify_binding "$materialized_release_tree/release-manifest.json" \
          "$after_digest" "$after_size"
        find "$baseline_release_tree" -type f -printf '%P\n' | sort \
          > "$TMPDIR/baseline-release-files"
        find "$materialized_release_tree" -type f -printf '%P\n' | sort \
          > "$TMPDIR/materialized-release-files"
        cmp "$TMPDIR/baseline-release-files" "$TMPDIR/materialized-release-files"
        while IFS= read -r relative; do
          if test "$relative" != release-manifest.json; then
            cmp "$baseline_release_tree/$relative" "$materialized_release_tree/$relative"
          fi
        done < "$TMPDIR/baseline-release-files"
        mutation_json="$(jq -cS '{
          kind: "bound-replacement",
          recipe_id,
          target,
          before,
          after,
          replacement_input,
          difference_selector
        }' "$TMPDIR/recipe.json")"
      fi
    fi

    # The boot partition is never mutable in this campaign. Every other role
    # must either be the sole plan-selected role or remain byte-identical.
    same_bytes "$baseline/sd/boot-filesystem.img" "$boot_filesystem"
    while IFS=$'\t' read -r role baseline_path materialized_path; do
      if test "$role" = "$changed_role"; then
        if same_bytes "$baseline/$baseline_path" "$materialized_path"; then
          echo "selected mutation left $role byte-identical to baseline" >&2
          exit 1
        fi
      else
        same_bytes "$baseline/$baseline_path" "$materialized_path"
      fi
    done <<EOF
    release-filesystem	nvme/release-filesystem.img	$release_filesystem
    root-data	sd/root-data.img	$root_data
    root-hash	sd/root-hash.img	$root_hash
    EOF
    # Re-read every sealed input after the selected mutation. This proves the
    # create-new operation did not alter a baseline payload through shared
    # storage, even transiently within the build sandbox.
    while IFS=$'\t' read -r source key; do
      IFS=$'\t' read -r digest size < <(baseline_binding "$key")
      verify_binding "$baseline/$source" "$digest" "$size"
    done <<'EOF'
    sd/boot-filesystem.img	stable_verifier_boot_filesystem
    nvme/release-filesystem.img	release_filesystem
    sd/root-data.img	root_data
    sd/root-hash.img	root_hash_tree
    EOF

    : > "$TMPDIR/partition-bindings.ndjson"
    while IFS=$'\t' read -r role relative_path; do
      input="$out/$relative_path"
      baseline_input="$baseline/$relative_path"
      changed=false
      if ! same_bytes "$baseline_input" "$input"; then
        changed=true
      fi
      jq -cnS \
        --arg role "$role" \
        --arg name "$relative_path" \
        --arg digest "sha256:$(sha256sum "$input" | cut -d ' ' -f 1)" \
        --argjson size_bytes "$(stat --format=%s "$input")" \
        --arg baseline_digest "sha256:$(sha256sum "$baseline_input" | cut -d ' ' -f 1)" \
        --argjson changed_from_baseline "$changed" \
        '{
          role: $role,
          name: $name,
          digest: $digest,
          size_bytes: $size_bytes,
          baseline_digest: $baseline_digest,
          changed_from_baseline: $changed_from_baseline
        }' >> "$TMPDIR/partition-bindings.ndjson"
    done <<'EOF'
    boot-filesystem	sd/boot-filesystem.img
    release-filesystem	nvme/release-filesystem.img
    root-data	sd/root-data.img
    root-hash	sd/root-hash.img
    EOF
    jq -csS . "$TMPDIR/partition-bindings.ndjson" \
      > "$TMPDIR/partition-bindings.json"
    readonly partition_bindings="$(< "$TMPDIR/partition-bindings.json")"
    readonly campaign_id="$(jq -er .campaign_id "$campaignPlanInput")"
    readonly plan_digest="$(jq -er .plan_digest "$campaignPlanInput")"
    readonly baseline_artifact_set_content_digest="$(
      jq -er .artifact_set_content_digest "$baseline_artifact_set"
    )"
    readonly baseline_manifest_content_digest="$(
      jq -er .manifest_content_digest "$baseline_manifest"
    )"

    # Reconstruct the exact public resolver inputs from the baseline's typed
    # provenance. The Go contract independently revalidates all 27 public
    # bindings and all 10 before/after mutation digests before it seals this
    # run. These are ordinary files in the Nix sandbox; no device path is
    # accepted or opened.
    readonly resolver_public_inputs="$TMPDIR/resolver-public-inputs"
    readonly resolver_targets="$TMPDIR/resolver-targets"
    mkdir "$resolver_public_inputs" "$resolver_targets"
    install -m 0444 "$verifiedSignedBootInput/boot.img" \
      "$resolver_public_inputs/unsigned-verifier-boot"
    install -m 0444 "$verifiedSignedBootInput/public.pem" \
      "$resolver_public_inputs/customer-boot-public-key"
    install -m 0444 \
      "$delegatedReleaseInput/nvme-release/release-manifest.json" \
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
    jq -cS '.release.files' "$baseline_manifest" \
      > "$TMPDIR/positive-release-files.json"
    {
      printf '%s\0' \
        'kaiba.provisioning.rpi5-stable-verifier-campaign-release-tree.v1alpha1'
      printf '%s' "$(< "$TMPDIR/positive-release-files.json")"
    } > "$resolver_public_inputs/positive-release-tree"
    jq -r '.bound_replacements[].replacement_input' "$campaignPlanInput" \
      | sort -u > "$TMPDIR/replacement-input-names"
    test "$(wc -l < "$TMPDIR/replacement-input-names")" -eq 20
    while IFS= read -r replacement_input; do
      printf '%s\n' "$replacement_input" \
        | grep -Ex '[a-z0-9][a-z0-9-]{0,127}' > /dev/null
      install -m 0444 \
        "$campaignMutationInputsInput/$replacement_input.json" \
        "$resolver_public_inputs/$replacement_input"
    done < "$TMPDIR/replacement-input-names"
    jq -r '.byte_xor_mutations[].target' "$campaignPlanInput" \
      | sort -u > "$TMPDIR/byte-target-names"
    test "$(wc -l < "$TMPDIR/byte-target-names")" -eq 10
    while IFS= read -r target; do
      case "$target" in
        release/*)
          source="$delegatedReleaseInput/nvme-release/''${target#release/}"
          ;;
        media/root-data)
          source="$baseline/sd/root-data.img"
          ;;
        media/root-hash)
          source="$baseline/sd/root-hash.img"
          ;;
        *)
          echo "unsupported resolver target: $target" >&2
          exit 1
          ;;
      esac
      mkdir -p "$(dirname "$resolver_targets/$target")"
      install -m 0444 "$source" "$resolver_targets/$target"
    done < "$TMPDIR/byte-target-names"

    jq -cS '[.[] | {digest, name, role, size_bytes}]' \
      "$TMPDIR/partition-bindings.json" \
      > "$TMPDIR/materialized-artifacts.json"
    kaiba-stable-campaign-contract run-artifact-materialization \
      "$campaignPlanInput" \
      "$baseline_artifact_set" \
      "$resolver_public_inputs" \
      "$resolver_targets" \
      "$run_index" \
      "$TMPDIR/materialized-artifacts.json" \
      > "$out/materialization.json"
    jq -e \
      --arg campaign_id "$campaign_id" \
      --arg plan_digest "$plan_digest" \
      --arg baseline_digest "$baseline_artifact_set_content_digest" \
      --argjson run_index "$run_index" \
      '
        .schema_version == "kaiba.provisioning.rpi5-stable-verifier-run-artifact-materialization/v1alpha1"
        and .campaign_id == $campaign_id
        and .plan_digest == $plan_digest
        and .artifact_set_content_digest == $baseline_digest
        and .run_index == $run_index
        and .capabilities == {
          claim_closure_performed: false,
          creation_mode: "create-new",
          device_access_performed: false,
          execution_performed: false,
          hardware_observed: false,
          output_scope: "nix-store-only",
          private_key_operation_performed: false,
          production_ready: false,
          signing_performed: false
        }
      ' "$out/materialization.json" > /dev/null

    jq -cnS \
      --arg campaign_id "$campaign_id" \
      --arg plan_digest "$plan_digest" \
      --arg baseline_artifact_set_content_digest "$baseline_artifact_set_content_digest" \
      --arg baseline_manifest_content_digest "$baseline_manifest_content_digest" \
      --argjson run_index "$run_index" \
      --arg run_id "$run_id" \
      --arg recipe_id "$recipe_id" \
      --argjson mutation "$mutation_json" \
      --argjson artifacts "$partition_bindings" \
      '{
        schema_version: "kaiba.provisioning.rpi5-stable-verifier-campaign-run-raw-binding/v1alpha1",
        campaign_id: $campaign_id,
        plan_digest: $plan_digest,
        baseline_artifact_set_content_digest: $baseline_artifact_set_content_digest,
        baseline_manifest_content_digest: $baseline_manifest_content_digest,
        run_index: $run_index,
        run_id: $run_id,
        recipe_id: (if $recipe_id == "" then null else $recipe_id end),
        mutation: $mutation,
        artifacts: $artifacts,
        physical_layout_bound: false,
        evidence_observed: false
      }' > "$TMPDIR/raw-binding-without-digest.json"
    raw_binding_material="$(jq -cS . "$TMPDIR/raw-binding-without-digest.json")"
    raw_binding_content_digest="sha256:$({
      printf '%s\0' 'kaiba.provisioning.rpi5-stable-verifier-campaign-run-raw-binding.v1alpha1'
      printf '%s' "$raw_binding_material"
    } | sha256sum | cut -d ' ' -f 1)"
    jq -S \
      --arg content_digest "$raw_binding_content_digest" \
      '. + {content_digest: $content_digest}' \
      "$TMPDIR/raw-binding-without-digest.json" > "$out/raw-binding.json"

    raw_binding_file_digest="sha256:$(sha256sum "$out/raw-binding.json" | cut -d ' ' -f 1)"
    raw_binding_file_size="$(stat --format=%s "$out/raw-binding.json")"
    materialization_file_digest="sha256:$(sha256sum "$out/materialization.json" | cut -d ' ' -f 1)"
    materialization_file_size="$(stat --format=%s "$out/materialization.json")"
    materialization_content_digest="$(jq -er .materialization_digest \
      "$out/materialization.json")"
    jq -nS \
      --arg campaign_id "$campaign_id" \
      --arg plan_digest "$plan_digest" \
      --arg baseline_artifact_set_content_digest "$baseline_artifact_set_content_digest" \
      --argjson run_index "$run_index" \
      --arg run_id "$run_id" \
      --arg recipe_id "$recipe_id" \
      --arg recipe_kind "$recipe_kind" \
      --arg raw_binding_digest "$raw_binding_file_digest" \
      --argjson raw_binding_size "$raw_binding_file_size" \
      --arg materialization_digest "$materialization_file_digest" \
      --argjson materialization_size "$materialization_file_size" \
      --arg materialization_content_digest "$materialization_content_digest" \
      --argjson artifacts "$partition_bindings" \
      --argjson mutation_performed "$(test -n "$recipe_id" && echo true || echo false)" \
      '{
        schema_version: "kaiba.provisioning.rpi5-stable-verifier-campaign-run-media/v1alpha1",
        campaign_id: $campaign_id,
        plan_digest: $plan_digest,
        baseline_artifact_set_content_digest: $baseline_artifact_set_content_digest,
        run: {
          run_index: $run_index,
          run_id: $run_id,
          recipe_id: (if $recipe_id == "" then null else $recipe_id end),
          recipe_kind: $recipe_kind
        },
        storage_format: "partition-payload-set-not-whole-device",
        create_new: true,
        physical_layout_bound: false,
        artifacts: $artifacts,
        raw_binding: {
          path: "raw-binding.json",
          sha256: $raw_binding_digest,
          size_bytes: $raw_binding_size
        },
        materialization: {
          path: "materialization.json",
          sha256: $materialization_digest,
          size_bytes: $materialization_size,
          content_digest: $materialization_content_digest
        },
        capabilities: {
          block_device_write_capable: false,
          claim_closure_capable: false,
          claim_closure_performed: false,
          create_new_nix_store_output: true,
          direct_hardware_access: false,
          execution_capable: false,
          execution_performed: false,
          hardware_observed: false,
          mutation_capable: true,
          mutation_performed: $mutation_performed,
          mutation_scope: "copied-partition-payloads-in-nix-store-only",
          private_key_access: false,
          private_key_operation_capable: false,
          private_key_operation_performed: false,
          production_ready: false,
          signing_authority_configured: false,
          signing_capable: false,
          signing_performed: false
        }
      }' > "$TMPDIR/manifest-without-digest.json"
    manifest_material="$(jq -cS . "$TMPDIR/manifest-without-digest.json")"
    manifest_content_digest="sha256:$({
      printf '%s\0' 'kaiba.provisioning.rpi5-stable-verifier-campaign-run-media.v1alpha1'
      printf '%s' "$manifest_material"
    } | sha256sum | cut -d ' ' -f 1)"
    jq -S \
      --arg manifest_content_digest "$manifest_content_digest" \
      '. + {manifest_content_digest: $manifest_content_digest}' \
      "$TMPDIR/manifest-without-digest.json" > "$out/manifest.json"

    chmod 0444 \
      "$boot_filesystem" \
      "$release_filesystem" \
      "$root_data" \
      "$root_hash" \
      "$out/manifest.json" \
      "$out/materialization.json" \
      "$out/raw-binding.json"
  ''
