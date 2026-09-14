{
  lib,
  pkgs,
  mutationsTool,
  planTool,
  stagingPlanTool,
  recoveryTool,
  packetTool,
  mkMedia,
  mkRun,
}:

{
  campaignID,
  sourceRevision,
  verifiedSignedBoot,
  delegatedRelease,
  replacementManifest,
  revokedManifest,
  sdDiskGUID,
  nvmeDiskGUID,
  bootPartitionGUID,
  rootDataPartitionGUID,
  rootHashPartitionGUID,
  releasePartitionGUID,
  sdEnvelope,
  nvmeEnvelope,
}:

let
  immutable = path: lib.hasPrefix "${builtins.storeDir}/" (toString path);
  mutationNames = [
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
  release = "${delegatedRelease}/nvme-release";
  allowlist = delegatedRelease.kaibaRpi5DelegatedReleaseSpike.releaseAllowlist;
  releaseAllowlist = pkgs.writeText "kaiba-campaign-preparation-release-allowlist" (
    lib.concatStringsSep "\n" allowlist + "\n"
  );
  trust =
    pkgs.runCommand "kaiba-campaign-preparation-verifier-trust" { nativeBuildInputs = [ pkgs.mtools ]; }
      ''
        mkdir "$out"
        mcopy -i ${verifiedSignedBoot}/boot.img '::/kaiba/stable-verifier-policy.json' "$out/policy.json"
        mcopy -i ${verifiedSignedBoot}/boot.img '::/kaiba/root-public.pem' "$out/root-public.pem"
        mcopy -i ${verifiedSignedBoot}/boot.img '::/kaiba/authority-ca.pem' "$out/authority-ca.pem"
      '';
  campaignMutationInputs =
    pkgs.runCommand "kaiba-campaign-preparation-mutations"
      {
        nativeBuildInputs = [ mutationsTool ];
        replacementManifestInput = replacementManifest;
        revokedManifestInput = revokedManifest;
        passthru.kaibaRpi5StableVerifierCampaignMutationInputs = {
          artifactSchemaVersion = "kaiba.provisioning.rpi5-stable-verifier-campaign-mutation-inputs/v1alpha1";
          inputNames = mutationNames;
          blockDeviceWriteCapable = false;
          directHardwareAccess = false;
          hardwareObserved = false;
          privateKeyAccess = false;
          productionReady = false;
          signingAuthorityConfigured = false;
          storageFormat = "named-public-file-set";
        };
      }
      ''
        kaiba-rpi5-stable-campaign-mutations \
          --policy ${trust}/policy.json \
          --root-public-key ${trust}/root-public.pem \
          --positive-manifest ${release}/release-manifest.json \
          --replacement-manifest "$replacementManifestInput" \
          --revoked-manifest "$revokedManifestInput" \
          --output "$out"
      '';
  # Compute root/hash bytes before the campaign plan: the plan binds their
  # mutations, while mkMedia independently reproduces these exact bytes later.
  rootPayloads =
    pkgs.runCommand "kaiba-campaign-preparation-root-payloads"
      {
        nativeBuildInputs = [
          pkgs.cryptsetup
          pkgs.coreutils
        ];
      }
      ''
        mkdir "$out"
        cp --reflink=auto --sparse=always ${release}/root.img "$out/root-data.img"
        digest="$(sha256sum "$out/root-data.img" | cut -d ' ' -f 1)"
        uuid="''${digest:0:8}-''${digest:8:4}-''${digest:12:4}-''${digest:16:4}-''${digest:20:12}"
        : > "$out/root-hash.img"
        veritysetup format --hash=sha256 --data-block-size=4096 --hash-block-size=4096 \
          --salt="$digest" --uuid="$uuid" --root-hash-file="$out/root-hash.txt" \
          "$out/root-data.img" "$out/root-hash.img" > "$TMPDIR/verity-format.txt"
        veritysetup verify --hash=sha256 --data-block-size=4096 --hash-block-size=4096 \
          "$out/root-data.img" "$out/root-hash.img" "$(cat "$out/root-hash.txt")"
      '';
  planInputs =
    pkgs.runCommand "kaiba-campaign-preparation-plan-inputs"
      {
        nativeBuildInputs = [
          pkgs.python3
          pkgs.coreutils
        ];
        releasePath = release;
        allowlistPath = releaseAllowlist;
        trustPath = trust;
        bootPath = verifiedSignedBoot;
        mutationsPath = campaignMutationInputs;
        rootPayloadsPath = rootPayloads;
      }
      ''
        python3 ${./campaign-preparation-inputs.py}
      '';
  campaignPlan =
    pkgs.runCommand "kaiba-campaign-preparation-plan.json"
      {
        nativeBuildInputs = [
          planTool
          pkgs.coreutils
        ];
      }
      ''
        # Store optimization may coalesce identical root roles into hard links.
        # Recopy roles before invoking the strict file-identity readers.
        cp -R --no-preserve=ownership ${planInputs}/. "$TMPDIR/plan-inputs"
        args=()
        while IFS= read -r name; do
          args+=(--public-input "$name=$TMPDIR/plan-inputs/public-inputs/$name")
        done < ${planInputs}/public-input-names.txt
        while IFS= read -r name; do
          args+=(--byte-mutation-target "$name=$TMPDIR/plan-inputs/mutation-targets/$name")
        done < ${planInputs}/mutation-target-names.txt
        kaiba-rpi5-stable-campaign-plan --campaign-id ${lib.escapeShellArg campaignID} \
          "''${args[@]}" > "$out"
      '';
  baselineMedia = mkMedia {
    inherit
      verifiedSignedBoot
      delegatedRelease
      campaignPlan
      campaignMutationInputs
      rootDataPartitionGUID
      rootHashPartitionGUID
      ;
  };
  run1 = mkRun {
    inherit baselineMedia;
    runIndex = 1;
  };
  run2 = mkRun {
    inherit baselineMedia;
    runIndex = 2;
  };
  stagingPlan =
    pkgs.runCommand "kaiba-campaign-preparation-staging-plan.json"
      { nativeBuildInputs = [ stagingPlanTool ]; }
      ''
        kaiba-rpi5-stable-campaign-staging-plan \
          --campaign-plan ${campaignPlan} --artifact-set ${baselineMedia}/artifact-set.json \
          --sd-disk-guid ${lib.escapeShellArg sdDiskGUID} \
          --nvme-disk-guid ${lib.escapeShellArg nvmeDiskGUID} \
          --boot-partition-guid ${lib.escapeShellArg bootPartitionGUID} \
          --root-data-partition-guid ${lib.escapeShellArg rootDataPartitionGUID} \
          --root-hash-partition-guid ${lib.escapeShellArg rootHashPartitionGUID} \
          --release-partition-guid ${lib.escapeShellArg releasePartitionGUID} \
          --boot-filesystem ${baselineMedia}/sd/boot-filesystem.img \
          --root-data ${baselineMedia}/sd/root-data.img \
          --root-hash ${baselineMedia}/sd/root-hash.img \
          --release-filesystem ${baselineMedia}/nvme/release-filesystem.img > "$out"
      '';
  recoveryRequirements =
    pkgs.runCommand "kaiba-campaign-preparation-recovery-requirements.json"
      {
        nativeBuildInputs = [ recoveryTool ];
        sdEnvelopeInput = sdEnvelope;
        nvmeEnvelopeInput = nvmeEnvelope;
      }
      ''
        kaiba-rpi5-stable-campaign-recovery-requirements --staging-plan ${stagingPlan} \
          --sd-envelope "$sdEnvelopeInput" \
          --nvme-envelope "$nvmeEnvelopeInput" > "$out"
      '';
  packet =
    pkgs.runCommand "kaiba-campaign-preparation-packet.json"
      {
        nativeBuildInputs = [
          packetTool
          pkgs.coreutils
        ];
        sdEnvelopeInput = sdEnvelope;
        nvmeEnvelopeInput = nvmeEnvelope;
      }
      ''
        cp -R --no-preserve=ownership ${planInputs}/. "$TMPDIR/plan-inputs"
        args=()
        while IFS= read -r name; do
          args+=(--public-input "$name=$TMPDIR/plan-inputs/public-inputs/$name")
        done < ${planInputs}/public-input-names.txt
        while IFS= read -r name; do
          args+=(--byte-mutation-target "$name=$TMPDIR/plan-inputs/mutation-targets/$name")
        done < ${planInputs}/mutation-target-names.txt
        kaiba-rpi5-stable-campaign-packet \
          --source-revision ${lib.escapeShellArg sourceRevision} \
          --campaign-plan ${campaignPlan} --artifact-set ${baselineMedia}/artifact-set.json \
          --run-1-materialization ${run1}/materialization.json \
          --run-2-materialization ${run2}/materialization.json \
          --staging-plan ${stagingPlan} --requirements ${recoveryRequirements} \
          --sd-envelope "$sdEnvelopeInput" \
          --nvme-envelope "$nvmeEnvelopeInput" \
          --boot-filesystem ${baselineMedia}/sd/boot-filesystem.img \
          --root-data ${baselineMedia}/sd/root-data.img \
          --root-hash ${baselineMedia}/sd/root-hash.img \
          --release-filesystem ${baselineMedia}/nvme/release-filesystem.img \
          "''${args[@]}" > "$out"
      '';
in
assert lib.assertMsg (
  builtins.isString campaignID && builtins.match "[a-z0-9][a-z0-9.-]{0,127}" campaignID != null
) "campaignID must be canonical";
assert lib.assertMsg (
  builtins.isString sourceRevision && builtins.match "[0-9a-f]{40}" sourceRevision != null
) "sourceRevision must be a full lowercase commit SHA";
assert lib.assertMsg (
  builtins.isAttrs delegatedRelease && delegatedRelease ? kaibaRpi5DelegatedReleaseSpike
) "delegatedRelease must carry the public delegated-release constructor contract";
assert lib.assertMsg (lib.all immutable [
  verifiedSignedBoot
  delegatedRelease
  replacementManifest
  revokedManifest
  sdEnvelope
  nvmeEnvelope
]) "campaign preparation inputs must be fixed public Nix-store paths";
{
  inherit
    campaignMutationInputs
    planInputs
    campaignPlan
    baselineMedia
    run1
    run2
    stagingPlan
    recoveryRequirements
    packet
    ;
  payloads = {
    boot-filesystem = "${baselineMedia}/sd/boot-filesystem.img";
    root-data = "${baselineMedia}/sd/root-data.img";
    root-hash = "${baselineMedia}/sd/root-hash.img";
    release-filesystem = "${baselineMedia}/nvme/release-filesystem.img";
  };
  signingPerformed = false;
  hardwareObserved = false;
  destructiveStagingReady = false;
}
