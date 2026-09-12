{
  lib,
  pkgs,
  baselineMedia,
  campaignRunBuilder ? import ../nix/stable-verifier-campaign-run.nix { inherit lib pkgs; },
}:

let
  pad2 = value: if value < 10 then "0${toString value}" else toString value;
  indexes = lib.range 1 33;
  mkRun =
    suffix: runIndex:
    campaignRunBuilder {
      inherit baselineMedia runIndex;
      name = "kaiba-stable-verifier-campaign-run-test-${pad2 runIndex}-${suffix}";
    };
  runs = map (runIndex: mkRun "matrix" runIndex) indexes;
  runFarm = pkgs.linkFarm "kaiba-stable-verifier-campaign-run-test-matrix" (
    lib.zipListsWith (runIndex: path: {
      name = "run-${pad2 runIndex}";
      inherit path;
    }) indexes runs
  );
  deterministicXORA = builtins.elemAt runs 3;
  deterministicXORB = mkRun "determinism" 4;
  deterministicReplacementA = builtins.elemAt runs 11;
  deterministicReplacementB = mkRun "determinism" 12;
  contracts = map (run: run.kaibaRpi5StableVerifierCampaignRun) runs;
  safeContract =
    contract:
    contract.artifactSchemaVersion
    == "kaiba.provisioning.rpi5-stable-verifier-campaign-run-media/v1alpha1"
    &&
      contract.materializationSchemaVersion
      == "kaiba.provisioning.rpi5-stable-verifier-run-artifact-materialization/v1alpha1"
    && contract.storageFormat == "partition-payload-set-not-whole-device"
    && contract.createNew
    && contract.createNewScope == "nix-store-output-only"
    && contract.mutationCapable
    && contract.mutationScope == "copied-partition-payloads-in-nix-store-only"
    && !contract.blockDeviceWriteCapable
    && !contract.claimClosureCapable
    && !contract.directHardwareAccess
    && !contract.executionCapable
    && !contract.hardwareObserved
    && !contract.physicalLayoutBound
    && !contract.privateKeyAccess
    && !contract.privateKeyOperationCapable
    && !contract.productionReady
    && !contract.signingAuthorityConfigured
    && !contract.signingCapable;
in
assert lib.assertMsg (lib.all safeContract contracts)
  "campaign run materializer passthru widened its Nix-store-only mutation boundary";
assert lib.assertMsg (
  (map (contract: contract.runIndex) contracts) == indexes
) "campaign run materializer passthru did not preserve all 33 code-selected indexes";

pkgs.runCommand "kaiba-stable-verifier-campaign-run-test"
  {
    baselineMediaInput = baselineMedia;
    campaignMutationInputsInput =
      baselineMedia.kaibaRpi5StableVerifierCampaignMedia.campaignMutationInputs;
    campaignPlanInput = baselineMedia.kaibaRpi5StableVerifierCampaignMedia.campaignPlan;
    campaignRunsInput = runFarm;
    deterministicXORAInput = deterministicXORA;
    deterministicXORBInput = deterministicXORB;
    deterministicReplacementAInput = deterministicReplacementA;
    deterministicReplacementBInput = deterministicReplacementB;
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.e2fsprogs
      pkgs.findutils
      pkgs.gnugrep
      pkgs.gnused
      pkgs.jq
    ];
    preferLocalBuild = true;
  }
  ''
    set -euo pipefail
    export LC_ALL=C
    export TZ=UTC

    readonly baseline="$baselineMediaInput"
    readonly plan="$campaignPlanInput"
    readonly mutation_inputs="$campaignMutationInputsInput"
    readonly expected_campaign_id="$(jq -er .campaign_id "$plan")"
    readonly expected_plan_digest="$(jq -er .plan_digest "$plan")"

    verify_binding() {
      local input="$1"
      local expected_digest="$2"
      local expected_size="$3"
      test -f "$input"
      test ! -L "$input"
      test "sha256:$(sha256sum "$input" | cut -d ' ' -f 1)" = "$expected_digest"
      test "$(stat --format=%s "$input")" = "$expected_size"
    }

    verify_content_digest() {
      local input="$1"
      local field="$2"
      local domain="$3"
      local material
      local derived
      material="$(jq -cS --arg field "$field" 'del(.[$field])' "$input")"
      derived="sha256:$({
        printf '%s\0' "$domain"
        printf '%s' "$material"
      } | sha256sum | cut -d ' ' -f 1)"
      test "$(jq -er --arg field "$field" '.[$field]' "$input")" = "$derived"
    }

    verify_go_materialization_digest() {
      local input="$1"
      local material
      local derived
      # Preserve the Go struct field order emitted by CanonicalJSON. The Go
      # digest deliberately does not sort object keys as jq-authored records do.
      material="$(jq -c 'del(.materialization_digest)' "$input")"
      derived="sha256:$({
        printf '%s\0' \
          'kaiba.provisioning.rpi5-stable-verifier-run-artifact-materialization.v1alpha1'
        printf '%s' "$material"
      } | sha256sum | cut -d ' ' -f 1)"
      test "$(jq -er .materialization_digest "$input")" = "$derived"
    }

    artifact_path() {
      case "$1" in
        boot-filesystem) printf '%s\n' sd/boot-filesystem.img ;;
        release-filesystem) printf '%s\n' nvme/release-filesystem.img ;;
        root-data) printf '%s\n' sd/root-data.img ;;
        root-hash) printf '%s\n' sd/root-hash.img ;;
        *) echo "unknown partition-payload role: $1" >&2; return 1 ;;
      esac
    }

    compare_output_trees() {
      local first="$1"
      local second="$2"
      find "$first" -type f -printf '%P\n' | sort > "$TMPDIR/first-files"
      find "$second" -type f -printf '%P\n' | sort > "$TMPDIR/second-files"
      cmp "$TMPDIR/first-files" "$TMPDIR/second-files"
      while IFS= read -r relative; do
        cmp "$first/$relative" "$second/$relative"
      done < "$TMPDIR/first-files"
    }

    : > "$TMPDIR/run-ids"
    : > "$TMPDIR/recipe-ids"
    : > "$TMPDIR/changed-roles"
    mutation_count=0
    byte_xor_count=0
    replacement_count=0
    no_mutation_count=0

    for run_index in $(seq 1 33); do
      padded="$(printf '%02d' "$run_index")"
      run="$campaignRunsInput/run-$padded"
      manifest="$run/manifest.json"
      raw_binding="$run/raw-binding.json"
      test -d "$run"

      find -H "$run" -type f -printf '%P\n' | sort > "$TMPDIR/run-files-$padded"
      printf '%s\n' \
        manifest.json \
        materialization.json \
        nvme/release-filesystem.img \
        raw-binding.json \
        sd/boot-filesystem.img \
        sd/root-data.img \
        sd/root-hash.img \
        > "$TMPDIR/expected-run-files"
      cmp "$TMPDIR/expected-run-files" "$TMPDIR/run-files-$padded"
      while IFS= read -r relative; do
        test "$(stat --format=%a "$run/$relative")" = 444
      done < "$TMPDIR/expected-run-files"

      jq -e \
        --arg campaign_id "$expected_campaign_id" \
        --arg plan_digest "$expected_plan_digest" \
        --argjson run_index "$run_index" \
        '
          .schema_version == "kaiba.provisioning.rpi5-stable-verifier-campaign-run-media/v1alpha1"
          and .campaign_id == $campaign_id
          and .plan_digest == $plan_digest
          and .run.run_index == $run_index
          and .storage_format == "partition-payload-set-not-whole-device"
          and .create_new == true
          and .physical_layout_bound == false
          and [.artifacts[].role] == [
            "boot-filesystem", "release-filesystem", "root-data", "root-hash"
          ]
          and [.artifacts[].name] == [
            "sd/boot-filesystem.img", "nvme/release-filesystem.img",
            "sd/root-data.img", "sd/root-hash.img"
          ]
          and ([.artifacts[] |
            (.digest | test("^sha256:[0-9a-f]{64}$"))
            and (.baseline_digest | test("^sha256:[0-9a-f]{64}$"))
            and .size_bytes > 0
          ] | all)
          and .capabilities == {
            block_device_write_capable: false,
            claim_closure_capable: false,
            claim_closure_performed: false,
            create_new_nix_store_output: true,
            direct_hardware_access: false,
            execution_capable: false,
            execution_performed: false,
            hardware_observed: false,
            mutation_capable: true,
            mutation_performed: (.run.recipe_id != null),
            mutation_scope: "copied-partition-payloads-in-nix-store-only",
            private_key_access: false,
            private_key_operation_capable: false,
            private_key_operation_performed: false,
            production_ready: false,
            signing_authority_configured: false,
            signing_capable: false,
            signing_performed: false
          }
        ' "$manifest" > "$TMPDIR/manifest-validation-$padded"
      jq -e \
        --arg campaign_id "$expected_campaign_id" \
        --arg plan_digest "$expected_plan_digest" \
        --argjson run_index "$run_index" \
        --slurpfile manifest "$manifest" \
        '
          .schema_version == "kaiba.provisioning.rpi5-stable-verifier-campaign-run-raw-binding/v1alpha1"
          and .campaign_id == $campaign_id
          and .plan_digest == $plan_digest
          and .run_index == $run_index
          and .run_id == $manifest[0].run.run_id
          and .recipe_id == $manifest[0].run.recipe_id
          and .baseline_artifact_set_content_digest == $manifest[0].baseline_artifact_set_content_digest
          and .artifacts == $manifest[0].artifacts
          and .physical_layout_bound == false
          and .evidence_observed == false
        ' "$raw_binding" > "$TMPDIR/raw-binding-validation-$padded"
      verify_content_digest \
        "$manifest" manifest_content_digest \
        kaiba.provisioning.rpi5-stable-verifier-campaign-run-media.v1alpha1
      verify_content_digest \
        "$raw_binding" content_digest \
        kaiba.provisioning.rpi5-stable-verifier-campaign-run-raw-binding.v1alpha1
      verify_binding \
        "$raw_binding" \
        "$(jq -er .raw_binding.sha256 "$manifest")" \
        "$(jq -er '.raw_binding.size_bytes | tostring' "$manifest")"
      materialization="$run/materialization.json"
      verify_go_materialization_digest "$materialization"
      verify_binding \
        "$materialization" \
        "$(jq -er .materialization.sha256 "$manifest")" \
        "$(jq -er '.materialization.size_bytes | tostring' "$manifest")"
      test "$(jq -er .materialization.content_digest "$manifest")" = \
        "$(jq -er .materialization_digest "$materialization")"
      jq -e \
        --arg campaign_id "$expected_campaign_id" \
        --arg plan_digest "$expected_plan_digest" \
        --argjson run_index "$run_index" \
        --slurpfile manifest "$manifest" \
        '
          .schema_version == "kaiba.provisioning.rpi5-stable-verifier-run-artifact-materialization/v1alpha1"
          and .campaign_id == $campaign_id
          and .plan_digest == $plan_digest
          and .artifact_set_content_digest == $manifest[0].baseline_artifact_set_content_digest
          and .run_index == $run_index
          and .run_id == $manifest[0].run.run_id
          and .materialized_artifacts == [
            $manifest[0].artifacts[] | {digest, name, role, size_bytes}
          ]
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
          and ((.mutation == null) == ($manifest[0].run.recipe_id == null))
        ' "$materialization" > "$TMPDIR/materialization-validation-$padded"

      jq -r .run.run_id "$manifest" >> "$TMPDIR/run-ids"
      recipe_id="$(jq -r '.run.recipe_id // ""' "$manifest")"
      recipe_kind="$(jq -er .run.recipe_kind "$manifest")"
      mutation="$(jq -cS .mutation "$raw_binding")"
      if test -z "$recipe_id"; then
        no_mutation_count="$((no_mutation_count + 1))"
        test "$recipe_kind" = none
        test "$mutation" = null
        test "$(jq -cS '.mutation // null' "$materialization")" = null
        if test "$run_index" -eq 1; then
          test "$(jq -r .run.run_id "$manifest")" = positive-baseline
        elif test "$run_index" -eq 2; then
          test "$(jq -r .run.run_id "$manifest")" = \
            authorization-offline-rejected:authority-offline
        elif test "$run_index" -eq 3; then
          test "$(jq -r .run.run_id "$manifest")" = \
            authorization-replay-rejected:stale-authorization
        else
          echo "unexpected recipe-free run index $run_index" >&2
          exit 1
        fi
      else
        mutation_count="$((mutation_count + 1))"
        printf '%s\n' "$recipe_id" >> "$TMPDIR/recipe-ids"
        plan_byte_count="$(jq --arg recipe_id "$recipe_id" \
          '[.byte_xor_mutations[] | select(.recipe_id == $recipe_id)] | length' "$plan")"
        plan_replacement_count="$(jq --arg recipe_id "$recipe_id" \
          '[.bound_replacements[] | select(.recipe_id == $recipe_id)] | length' "$plan")"
        test "$((plan_byte_count + plan_replacement_count))" -eq 1

        if test "$plan_byte_count" -eq 1; then
          byte_xor_count="$((byte_xor_count + 1))"
          test "$recipe_kind" = byte-xor
          jq -cS --arg recipe_id "$recipe_id" '
            .byte_xor_mutations[] | select(.recipe_id == $recipe_id) | {
              kind: "byte-xor", recipe_id, target, before, after, offset_bytes, xor_mask
            }
          ' "$plan" > "$TMPDIR/expected-mutation-$padded"
        else
          replacement_count="$((replacement_count + 1))"
          test "$recipe_kind" = bound-replacement
          jq -cS --arg recipe_id "$recipe_id" '
            .bound_replacements[] | select(.recipe_id == $recipe_id) | {
              kind: "bound-replacement", recipe_id, target, before, after,
              replacement_input, difference_selector
            }
          ' "$plan" > "$TMPDIR/expected-mutation-$padded"
        fi
        test "$mutation" = "$(< "$TMPDIR/expected-mutation-$padded")"
        jq -e \
          --arg recipe_id "$recipe_id" \
          --slurpfile raw "$raw_binding" \
          '
            .mutation.recipe_id == $recipe_id
            and .mutation.kind == $raw[0].mutation.kind
            and .mutation.selected_target == {
              after: $raw[0].mutation.after,
              before: $raw[0].mutation.before,
              target: $raw[0].mutation.target
            }
            and .mutation.affected_artifact_role == (
              if ($raw[0].mutation.target | startswith("release/")) then
                "release-filesystem"
              elif $raw[0].mutation.target == "media/root-data" then
                "root-data"
              else
                "root-hash"
              end
            )
            and (
              if .mutation.kind == "byte-xor" then
                .mutation.offset_bytes == $raw[0].mutation.offset_bytes
                and .mutation.xor_mask == $raw[0].mutation.xor_mask
                and (.mutation | has("replacement_input") | not)
                and (.mutation | has("difference_selector") | not)
              else
                .mutation.replacement_input == $raw[0].mutation.replacement_input
                and .mutation.difference_selector == $raw[0].mutation.difference_selector
                and (.mutation | has("offset_bytes") | not)
                and (.mutation | has("xor_mask") | not)
              end
            )
          ' "$materialization" > "$TMPDIR/materialization-mutation-validation-$padded"
      fi

      expected_changed_role=
      if test -n "$recipe_id"; then
        target="$(jq -er .mutation.target "$raw_binding")"
        case "$target" in
          release/*) expected_changed_role=release-filesystem ;;
          media/root-data) expected_changed_role=root-data ;;
          media/root-hash) expected_changed_role=root-hash ;;
          *) echo "unexpected materialized target: $target" >&2; exit 1 ;;
        esac
      fi
      actual_changed_count="$(jq '[.artifacts[] | select(.changed_from_baseline)] | length' "$manifest")"
      if test -z "$expected_changed_role"; then
        test "$actual_changed_count" -eq 0
      else
        test "$actual_changed_count" -eq 1
        test "$(jq -r '.artifacts[] | select(.changed_from_baseline) | .role' "$manifest")" = \
          "$expected_changed_role"
        printf '%s\n' "$expected_changed_role" >> "$TMPDIR/changed-roles"
      fi

      for role in boot-filesystem release-filesystem root-data root-hash; do
        relative="$(artifact_path "$role")"
        artifact_digest="$(jq -er --arg role "$role" \
          '.artifacts[] | select(.role == $role) | .digest' "$manifest")"
        artifact_size="$(jq -er --arg role "$role" \
          '.artifacts[] | select(.role == $role) | .size_bytes | tostring' "$manifest")"
        baseline_digest="$(jq -er --arg role "$role" \
          '.artifacts[] | select(.role == $role) | .baseline_digest' "$manifest")"
        verify_binding "$run/$relative" "$artifact_digest" "$artifact_size"
        test "$baseline_digest" = \
          "sha256:$(sha256sum "$baseline/$relative" | cut -d ' ' -f 1)"
        if test "$role" = "$expected_changed_role"; then
          if cmp --silent "$baseline/$relative" "$run/$relative"; then
            echo "run $run_index did not change selected role $role" >&2
            exit 1
          fi
        else
          cmp "$baseline/$relative" "$run/$relative"
        fi
      done

      if test -n "$recipe_id"; then
        after_digest="$(jq -er .mutation.after.digest "$raw_binding")"
        after_size="$(jq -er '.mutation.after.size_bytes | tostring' "$raw_binding")"
        target="$(jq -er .mutation.target "$raw_binding")"
        case "$target" in
          release/*)
            relative="''${target#release/}"
            debugfs -R "dump /$relative $TMPDIR/target-$padded" \
              "$run/nvme/release-filesystem.img" > "$TMPDIR/debugfs-target-$padded"
            verify_binding "$TMPDIR/target-$padded" "$after_digest" "$after_size"
            ;;
          media/root-data)
            verify_binding "$run/sd/root-data.img" "$after_digest" "$after_size"
            ;;
          media/root-hash)
            verify_binding "$run/sd/root-hash.img" "$after_digest" "$after_size"
            ;;
        esac
      fi
    done

    test "$mutation_count" -eq 30
    test "$byte_xor_count" -eq 10
    test "$replacement_count" -eq 20
    test "$no_mutation_count" -eq 3
    test "$(sort -u "$TMPDIR/run-ids" | wc -l)" -eq 33
    test "$(sort -u "$TMPDIR/recipe-ids" | wc -l)" -eq 30
    test "$(grep -cx release-filesystem "$TMPDIR/changed-roles")" -eq 28
    test "$(grep -cx root-data "$TMPDIR/changed-roles")" -eq 1
    test "$(grep -cx root-hash "$TMPDIR/changed-roles")" -eq 1
    if grep -Fx boot-filesystem "$TMPDIR/changed-roles" \
      > "$TMPDIR/unexpected-boot-change"; then
      echo 'campaign materializer changed the verifier boot partition' >&2
      exit 1
    fi

    jq -r '.byte_xor_mutations[].recipe_id' "$plan" | sort \
      > "$TMPDIR/expected-byte-recipes"
    jq -r '.bound_replacements[].recipe_id' "$plan" | sort \
      > "$TMPDIR/expected-replacement-recipes"
    {
      cat "$TMPDIR/expected-byte-recipes"
      cat "$TMPDIR/expected-replacement-recipes"
    } | sort > "$TMPDIR/expected-recipes"
    sort "$TMPDIR/recipe-ids" > "$TMPDIR/actual-recipes"
    cmp "$TMPDIR/expected-recipes" "$TMPDIR/actual-recipes"

    compare_output_trees "$deterministicXORAInput" "$deterministicXORBInput"
    compare_output_trees \
      "$deterministicReplacementAInput" "$deterministicReplacementBInput"

    mkdir "$out"
    printf '%s\n' \
      'all 33 code-derived campaign run media sets validated' \
      'all 30 plan-bound mutations and the complete role-change matrix validated' \
      'representative byte-XOR and bound-replacement outputs are deterministic' \
      > "$out/result"
  ''
