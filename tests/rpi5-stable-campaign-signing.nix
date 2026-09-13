{
  built,
  lib,
  pkgs,
}:

let
  constructors = import ../nix/rpi5-stable-campaign-signing.nix {
    inherit lib pkgs;
    inherit (built) signingReceiptsTool stableCampaignSigningTool;
  };
  fixtureSourceRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  fixtureSourceDateEpoch = 1786968000;
  fixtureCustomerKeyHash = "sha256:75889a936354d53b58be5584e94825fde88671207d374eb6b7611861d13dc9ef";
  fixturePublicKeyFileDigest = "sha256:4daa5735839b74fa10950b9ea3d8e193f0163f634a7ebcb3967b29976c72eea1";
  fixturePublicKeyFingerprint = "sha256:649339461d2755f68c7e72104b9b9ba3d3643c2dae7d9712f2c81a6d44a5c202";
  fixtureSignerPolicyDigest = "sha256:42632f59978c8fd2e92644b4a2e8f2be8ca1abf3112860f4377c87a456507985";
  productionCustomerKeyHash = "sha256:b8818acea4e71173903ee003e33ed37e969def7d2ea67bec15c0b73cb36c3895";
  fixtureUnsignedSchema = pkgs.writeText "kaiba-stable-signing-fixture-unsigned.schema.json" (
    builtins.replaceStrings [ productionCustomerKeyHash ] [ fixtureCustomerKeyHash ] (
      builtins.readFile ../schemas/rpi5-stable-campaign-provisioner-artifact-set-v1alpha1.schema.json
    )
  );
  fixturePublicKey =
    pkgs.runCommand "kaiba-stable-signing-fixture-public-key"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.openssl
          pkgs.python3
        ];
      }
      ''
        set -euo pipefail
        python3 ${./deterministic-rsa-fixture.py} --private "$TMPDIR/private.pem"
        mkdir "$out"
        openssl pkey -in "$TMPDIR/private.pem" -pubout -out "$out/public.pem"
        test "sha256:$(sha256sum "$out/public.pem" | cut -d ' ' -f 1)" = \
          '${fixturePublicKeyFileDigest}'
        test "sha256:$(openssl pkey -pubin -in "$out/public.pem" -outform DER \
          | sha256sum | cut -d ' ' -f 1)" = '${fixturePublicKeyFingerprint}'
        chmod 0444 "$out/public.pem"
        test ! -e "$out/private.pem"
      '';
  fixtureUnsignedArtifacts =
    pkgs.runCommand "kaiba-stable-signing-fixture-unsigned-artifacts"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
        ];
        passthru.kaibaUnsignedArtifacts = {
          blockDeviceWriteCapable = false;
          directHardwareAccess = false;
          eepromProgrammingCapable = false;
          expectedCustomerKeyHash = lib.removePrefix "sha256:" fixtureCustomerKeyHash;
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          privateKeyAccess = false;
          schemaVersion = "provisioning.kaiba.network/rpi5-stable-campaign-provisioner-artifact-set/v1alpha1";
          signingAuthorityConfigured = false;
          signingStatus = "unsigned";
          sourceRevision = fixtureSourceRevision;
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        mkdir -p "$out/unsigned"
        truncate --size=100663296 "$out/unsigned/boot.img"
        printf '%s' 'kaiba stable signing fixture' \
          | dd of="$out/unsigned/boot.img" conv=notrunc status=none
        boot_digest="sha256:$(sha256sum "$out/unsigned/boot.img" | cut -d ' ' -f 1)"
        jq --null-input --compact-output --sort-keys \
          --arg boot_digest "$boot_digest" '
            {
              schema: "provisioning.kaiba.network/rpi5-stable-campaign-provisioner-artifact-set/v1alpha1",
              source_revision: "${fixtureSourceRevision}",
              expected_customer_key_hash: "${fixtureCustomerKeyHash}",
              boot_order_policy: "nvme-sd-tftp-restart-development",
              boot_command_line_path: "nixos/default/cmdline.txt",
              firmware_allowlist: [
                "config.txt",
                "kaiba-root-integrity.json",
                "nixos/default/bcm2712-rpi-5-b.dtb",
                "nixos/default/cmdline.txt",
                "nixos/default/initrd",
                "nixos/default/kernel.img",
                "nixos/default/overlays/README",
                "nixos/default/overlays/bcm2712d0.dtbo",
                "nixos/default/overlays/dwc2.dtbo",
                "nixos/default/overlays/overlay_map.dtb"
              ],
              boot_image_size_bytes: 100663296,
              persistent_mutable_state: "tmpfs-only",
              rollback_policy: "unimplemented-block-enrollment-ready",
              debug_policy: "videocore-jtag-unlocked-development",
              eeprom_write_protection_policy: "unlocked-development",
              toolchain: {cryptsetup: "fixture", dosfstools: "fixture", mtools: "fixture"},
              artifacts: {
                boot_image: {
                  path: "unsigned/boot.img",
                  digest: $boot_digest,
                  artifact_role: "signing-input",
                  storage_format: "fat-boot-ramdisk-not-partition"
                },
                root_data: {
                  path: "sd/root-data.img",
                  digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                },
                root_hash_tree: {
                  path: "sd/root-hash.img",
                  digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                }
              },
              verity: {
                algorithm: "sha256",
                data_block_size: 4096,
                hash_block_size: 4096,
                uuid: "4b414942-4152-4f4f-9488-888888888888",
                data_device: "/dev/mmcblk0p2",
                hash_device: "/dev/mmcblk0p3",
                mapper: "/dev/mapper/root"
              },
              device_binding: {
                profile: "rpi5-sd-mmcblk0-fixed-partitions",
                boot_media: "/dev/mmcblk0",
                disk_guid: "5625eee2-0c8a-402f-8c2f-5a1347652bb2",
                boot_partition: 1,
                boot_partition_guid: "59d06b61-bf85-4d77-89c3-9e5395934ff8",
                boot_partition_size_bytes: 134217728,
                data_partition: 2,
                data_partition_guid: "bdd5be20-f7ea-56e7-ae90-4465ae950596",
                data_partition_size_bytes: 2418016256,
                hash_partition: 3,
                hash_partition_guid: "62616022-71fb-5036-8cc4-b7949cc6e52c",
                hash_partition_size_bytes: 19922944
              },
              root_integrity_digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
              signing_status: "unsigned",
              hardware_observed: false,
              physical_staging_ready: false,
              production_ready: false
            }
          ' > "$TMPDIR/manifest-without-bundle-digest.json"
        canonical_manifest="$(cat "$TMPDIR/manifest-without-bundle-digest.json")"
        bundle_digest="sha256:$({
          printf '%s\0' 'kaiba.rpi5.stable-campaign-provisioner-artifacts.v1'
          printf '%s' "$canonical_manifest"
        } | sha256sum | cut -d ' ' -f 1)"
        jq --compact-output --sort-keys \
          --arg bundle_digest "$bundle_digest" \
          '. + {bundle_digest: $bundle_digest}' \
          "$TMPDIR/manifest-without-bundle-digest.json" \
          > "$out/manifest.json"
        chmod 0444 "$out/manifest.json" "$out/unsigned/boot.img"
      '';
  fixtureProfile = {
    bootImageSizeBytes = 100663296;
    expectedCustomerKeyHash = fixtureCustomerKeyHash;
    publicKeyFileDigest = fixturePublicKeyFileDigest;
    publicKeyFingerprint = fixturePublicKeyFingerprint;
    reviewedPublicKeyPEM = "${fixturePublicKey}/public.pem";
    signerPolicyDigest = fixtureSignerPolicyDigest;
    unsignedArtifactSchema = fixtureUnsignedSchema;
  };
  fixtureSigningPlan = constructors._testOnly.mkSigningPlanForProfile fixtureProfile {
    name = "kaiba-stable-signing-fixture-plan";
    sourceDateEpoch = fixtureSourceDateEpoch;
    sourceRevision = fixtureSourceRevision;
    unsignedArtifacts = fixtureUnsignedArtifacts;
  };
  fixtureEvidence =
    pkgs.runCommand "kaiba-stable-signing-one-grant-evidence-fixture"
      {
        nativeBuildInputs = [
          pkgs.go
          pkgs.python3
        ];
      }
      ''
        set -euo pipefail
        export CGO_ENABLED=0
        export GOCACHE="$TMPDIR/go-cache"
        export GOPATH="$TMPDIR/go-path"
        python3 ${./deterministic-rsa-fixture.py} --private "$TMPDIR/private.pem"
        cd ${built.goSource}
        go run ./internal/provisioning/stablecampaignsigning/testfixture \
          --plan ${fixtureSigningPlan} \
          --private-key "$TMPDIR/private.pem" \
          --output "$out" \
          --signer-id signer:stable-fixture \
          --cohort-id cohort:stable-fixture \
          --pkcs11-uri 'pkcs11:serial=12345678;id=%02;type=private' \
          --reviewer-id reviewer:stable-fixture \
          --approved-at 2026-08-27T12:00:00Z \
          --expires-at 2026-08-28T12:00:00Z \
          --signed-at 2026-08-27T12:01:00Z
        test ! -e "$out/private.pem"
      '';
  verifiedFixture = constructors.mkRpi5VerifiedStableCampaignProvisionerSigning {
    name = "kaiba-verified-stable-signing-one-grant-fixture";
    authorization = "${fixtureEvidence}/authorization";
    receiptExport = "${fixtureEvidence}/signing-receipts.json";
    signedOutput = "${fixtureEvidence}/signed";
    signingPlan = fixtureSigningPlan;
  };
  publicConstructorRejectsFixture =
    !(builtins.tryEval (
      (constructors.mkRpi5StableCampaignProvisionerSigningPlan {
        sourceDateEpoch = fixtureSourceDateEpoch;
        sourceRevision = fixtureSourceRevision;
        unsignedArtifacts = fixtureUnsignedArtifacts;
      }).drvPath
    )).success;
  untypedPlanRejected =
    !(builtins.tryEval (
      (constructors.mkRpi5VerifiedStableCampaignProvisionerSigning {
        authorization = "${fixtureEvidence}/authorization";
        receiptExport = "${fixtureEvidence}/signing-receipts.json";
        signedOutput = "${fixtureEvidence}/signed";
        signingPlan = pkgs.writeText "kaiba-untyped-stable-signing-plan" "{}";
      }).drvPath
    )).success;
  contract = verifiedFixture.kaibaVerifiedStableCampaignSigning;
in
assert lib.assertMsg publicConstructorRejectsFixture
  "the production stable signing-plan constructor accepted a fixture trust root";
assert lib.assertMsg untypedPlanRejected
  "the stable signing verifier accepted an untyped signing plan";
assert lib.assertMsg (
  contract.authorizationScope == "stable_campaign_provisioner_boot"
  && contract.authenticatedReceiptCount == 1
  && contract.receiptAttestationRequired
  && contract.verificationMode == "authenticated_offline"
  && lib.all (value: value == false) [
    contract.blockDeviceWriteCapable
    contract.directHardwareAccess
    contract.eepromProgrammingCapable
    contract.mutationCapable
    contract.oneTimeSettingCapable
    contract.otpCapable
    contract.privateKeyAccess
    contract.signingAuthorityConfigured
  ]
) "the verified stable signing evidence gained authority or lost receipt authentication";
pkgs.runCommand "kaiba-rpi5-stable-campaign-signing-contract"
  {
    nativeBuildInputs = [
      built.signingReceiptsTool
      built.stableCampaignSigningTool
      pkgs.check-jsonschema
      pkgs.coreutils
      pkgs.findutils
      pkgs.jq
    ];
  }
  ''
    set -euo pipefail
    export LC_ALL=C

    check-jsonschema --check-metaschema \
      ${../schemas/rpi5-stable-campaign-provisioner-signing-intent-v1alpha1.schema.json} \
      ${../schemas/rpi5-stable-campaign-provisioner-signing-approval-v1alpha1.schema.json}
    check-jsonschema \
      --schemafile ${../schemas/rpi5-stable-campaign-provisioner-signing-intent-v1alpha1.schema.json} \
      ${fixtureSigningPlan}/release-intent.json
    check-jsonschema \
      --schemafile ${../schemas/rpi5-stable-campaign-provisioner-signing-approval-v1alpha1.schema.json} \
      ${fixtureEvidence}/authorization/approval.json
    check-jsonschema \
      --base-uri file://${built.goSource}/schemas/ \
      --schemafile ${../schemas/signing-grant-registry-v1alpha2.schema.json} \
      ${fixtureEvidence}/authorization/signing-grants.json

    kaiba-rpi5-stable-campaign-signing validate-plan \
      --plan ${fixtureSigningPlan} > "$TMPDIR/plan-verification.json"
    kaiba-rpi5-stable-campaign-signing validate-authorization \
      --plan ${fixtureSigningPlan} \
      --approval ${fixtureEvidence}/authorization/approval.json \
      --registry ${fixtureEvidence}/authorization/signing-grants.json \
      > "$TMPDIR/authorization-verification.json"
    jq -e '
      .status == "valid" and .grant_count == 1
    ' "$TMPDIR/authorization-verification.json" > /dev/null
    jq -e '
      .grants | length == 1
      and .[0].request.role == "rpi5.boot_image"
      and .[0].request.algorithm == "rsa2048-sha256"
    ' ${fixtureEvidence}/authorization/signing-grants.json > /dev/null

    live_receipt="$(jq -r .gate_receipt_digest \
      ${fixtureEvidence}/signed/signing-result.json)"
    test "$(jq -r '.receipt_digests | length' \
      ${verifiedFixture}/receipt-verification.json)" -eq 1
    test "$(jq -r '.receipt_digests[0]' \
      ${verifiedFixture}/receipt-verification.json)" = "$live_receipt"
    test "$(find ${fixtureEvidence}/signed -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 2
    test "$(find ${verifiedFixture} -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 12

    mkdir "$TMPDIR/changed-signed"
    cp ${fixtureEvidence}/signed/boot.sig "$TMPDIR/changed-signed/boot.sig"
    jq --compact-output \
      '.gate_receipt_digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
      ${fixtureEvidence}/signed/signing-result.json \
      > "$TMPDIR/changed-signed/signing-result.json"
    set +e
    kaiba-rpi5-stable-campaign-signing finalize \
      --plan ${fixtureSigningPlan} \
      --signed "$TMPDIR/changed-signed" \
      --approval ${fixtureEvidence}/authorization/approval.json \
      --registry ${fixtureEvidence}/authorization/signing-grants.json \
      --receipt-export ${fixtureEvidence}/signing-receipts.json \
      --output "$TMPDIR/changed-finalized" \
      > "$TMPDIR/wrong-receipt.stdout" \
      2> "$TMPDIR/wrong-receipt.stderr"
    wrong_receipt_status="$?"
    set -e
    test "$wrong_receipt_status" -ne 0
    test ! -s "$TMPDIR/wrong-receipt.stdout"
    test ! -e "$TMPDIR/changed-finalized"
    grep -F 'authenticated signing receipt' "$TMPDIR/wrong-receipt.stderr" > /dev/null

    find ${verifiedFixture} -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
      > "$TMPDIR/actual-evidence-files"
    printf '%s\n' \
      approval.json \
      boot.img \
      boot.sig \
      manifest.json \
      public.pem \
      receipt-verification.json \
      release-intent.json \
      signing-grants.json \
      signing-plan.json \
      signing-receipts.json \
      signing-result.json \
      unsigned-artifact-manifest.json \
      > "$TMPDIR/expected-evidence-files"
    cmp "$TMPDIR/expected-evidence-files" "$TMPDIR/actual-evidence-files"

    mkdir "$out"
    touch "$out/passed"
  ''
