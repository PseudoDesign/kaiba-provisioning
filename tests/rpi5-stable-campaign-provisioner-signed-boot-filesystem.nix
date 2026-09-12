{
  lib,
  pkgs,
}:

let
  constructors = import ../nix/rpi5-stable-campaign-provisioner-signed-boot-filesystem.nix {
    inherit lib pkgs;
  };
  fixtureCustomerKeyHash = "sha256:75889a936354d53b58be5584e94825fde88671207d374eb6b7611861d13dc9ef";
  fixturePublicKeyFileDigest = "sha256:4daa5735839b74fa10950b9ea3d8e193f0163f634a7ebcb3967b29976c72eea1";
  fixturePublicKeyFingerprint = "sha256:649339461d2755f68c7e72104b9b9ba3d3643c2dae7d9712f2c81a6d44a5c202";
  developmentCustomerKeyHash = "sha256:b8818acea4e71173903ee003e33ed37e969def7d2ea67bec15c0b73cb36c3895";
  developmentPublicKeyFileDigest = "sha256:93923fb1b289c39e8b336b90defb881f5d15ce3832c74655b295e1a35bfdab80";
  developmentPublicKeyFingerprint = "sha256:0e68e7196fedc382ca435b995598e92d0fe36e4b1a1f949f85f5f2e6e2920fb9";
  fixtureBootImageSizeBytes = 67108864;
  fixtureRootDataPartitionSizeBytes = 4194304;
  fixtureRootHashPartitionSizeBytes = 65536;
  fixtureSourceRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  fixtureSystemToplevel = "/nix/store/00000000000000000000000000000000-nixos-system-kaiba-rpi5-provisioner-sd-card-26.05.20260912.aaaaaaaa";
  fixtureInitArgument = "init=${fixtureSystemToplevel}/init";
  fixtureEtcTree = "/nix/store/11111111111111111111111111111111-etc/etc";
  fixturePolicyStorePath = "/nix/store/22222222222222222222222222222222-etc-kaiba-provisioning-target-policy.json";
  fixtureExpectedRootPolicy = constructors._testOnly.mkExpectedRootTargetPolicy {
    expectedCustomerKeyHash = fixtureCustomerKeyHash;
    sourceRevision = fixtureSourceRevision;
  };

  fixtureUnsignedSchema = pkgs.writeText "kaiba-fixture-stable-campaign-unsigned.schema.json" (
    builtins.replaceStrings
      [
        developmentCustomerKeyHash
        "100663296"
        "2418016256"
        "19922944"
      ]
      [
        fixtureCustomerKeyHash
        (toString fixtureBootImageSizeBytes)
        (toString fixtureRootDataPartitionSizeBytes)
        (toString fixtureRootHashPartitionSizeBytes)
      ]
      (builtins.readFile ../schemas/rpi5-stable-campaign-provisioner-artifact-set-v1alpha1.schema.json)
  );
  fixtureSignedSchema = pkgs.writeText "kaiba-fixture-stable-campaign-signed-boot.schema.json" (
    builtins.replaceStrings
      [
        developmentCustomerKeyHash
        developmentPublicKeyFileDigest
        developmentPublicKeyFingerprint
        "100663296"
      ]
      [
        fixtureCustomerKeyHash
        fixturePublicKeyFileDigest
        fixturePublicKeyFingerprint
        (toString fixtureBootImageSizeBytes)
      ]
      (
        builtins.readFile ../schemas/rpi5-stable-campaign-provisioner-signed-boot-filesystem-v1alpha1.schema.json
      )
  );

  fixtureUnsignedArtifacts =
    pkgs.runCommand "kaiba-fixture-stable-campaign-unsigned-artifacts"
      {
        nativeBuildInputs = with pkgs; [
          coreutils
          cryptsetup
          dosfstools
          e2fsprogs
          findutils
          jq
          mtools
        ];
        passthru.kaibaUnsignedArtifacts = {
          blockDeviceWriteCapable = false;
          bootImageSizeMiB = fixtureBootImageSizeBytes / 1048576;
          bootPartitionGUID = "59d06b61-bf85-4d77-89c3-9e5395934ff8";
          bootPartitionSizeBytes = 134217728;
          dataDevice = "/dev/mmcblk0p2";
          directHardwareAccess = false;
          diskGUID = "5625eee2-0c8a-402f-8c2f-5a1347652bb2";
          eepromProgrammingCapable = false;
          expectedCustomerKeyHash = lib.removePrefix "sha256:" fixtureCustomerKeyHash;
          hashDevice = "/dev/mmcblk0p3";
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          privateKeyAccess = false;
          rootDataPartitionGUID = "bdd5be20-f7ea-56e7-ae90-4465ae950596";
          rootDataPartitionSizeBytes = fixtureRootDataPartitionSizeBytes;
          rootDeviceBinding = "rpi5-sd-card";
          rootHashPartitionGUID = "62616022-71fb-5036-8cc4-b7949cc6e52c";
          rootHashPartitionSizeBytes = fixtureRootHashPartitionSizeBytes;
          schemaVersion = "provisioning.kaiba.network/rpi5-stable-campaign-provisioner-artifact-set/v1alpha1";
          signingAuthorityConfigured = false;
          signingStatus = "unsigned";
          sourceRevision = fixtureSourceRevision;
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        export TZ=UTC

        mkdir -p \
          "$out/unsigned" \
          "$out/sd" \
          "$TMPDIR/boot-tree/nixos/default" \
          "$TMPDIR/root-tree/etc" \
          "$TMPDIR/root-tree${fixtureSystemToplevel}" \
          "$TMPDIR/root-tree${fixtureEtcTree}/kaiba-provisioning"
        truncate --size=${toString fixtureBootImageSizeBytes} "$out/unsigned/boot.img"
        mkfs.vfat --invariant -F 32 -i 4b414942 -n KAIBA_BOOT \
          "$out/unsigned/boot.img" > "$TMPDIR/mkfs.txt"

        printf '%s\n' '#!/bin/sh' 'exit 0' \
          > "$TMPDIR/root-tree${fixtureSystemToplevel}/init"
        chmod 0555 "$TMPDIR/root-tree${fixtureSystemToplevel}/init"
        ln -s ${lib.escapeShellArg fixtureEtcTree} \
          "$TMPDIR/root-tree${fixtureSystemToplevel}/etc"
        ln -s ${lib.escapeShellArg fixturePolicyStorePath} \
          "$TMPDIR/root-tree${fixtureEtcTree}/kaiba-provisioning/target-policy.json"
        install -m 0444 ${fixtureExpectedRootPolicy} \
          "$TMPDIR/root-tree${fixturePolicyStorePath}"
        find "$TMPDIR/root-tree/nix/store" -type d -exec chmod 0555 {} +
        chmod 0555 "$TMPDIR/root-tree/etc"
        find "$TMPDIR/root-tree" \
          -exec touch --no-dereference --date=@315532800 {} +
        truncate --size=${toString fixtureRootDataPartitionSizeBytes} "$out/sd/root-data.img"
        E2FSPROGS_FAKE_TIME=315532800 mkfs.ext4 \
          -F \
          -q \
          -U 4b414942-4152-4f4f-9488-888888888888 \
          -L KAIBA_ROOT \
          -O '^has_journal' \
          -E lazy_itable_init=0,lazy_journal_init=0 \
          -d "$TMPDIR/root-tree" \
          "$out/sd/root-data.img"
        root_data_digest="$(sha256sum "$out/sd/root-data.img" | cut -d ' ' -f 1)"
        verity_uuid="''${root_data_digest:0:8}-''${root_data_digest:8:4}-''${root_data_digest:12:4}-''${root_data_digest:16:4}-''${root_data_digest:20:12}"
        : > "$out/sd/root-hash.img"
        veritysetup format \
          --format=1 \
          --hash=sha256 \
          --data-block-size=4096 \
          --hash-block-size=4096 \
          --salt="$root_data_digest" \
          --uuid="$verity_uuid" \
          --root-hash-file="$TMPDIR/root-hash" \
          "$out/sd/root-data.img" \
          "$out/sd/root-hash.img" \
          > "$TMPDIR/verity-format.txt"
        root_hash="$(tr -d '\n' < "$TMPDIR/root-hash")"
        truncate --size=${toString fixtureRootHashPartitionSizeBytes} "$out/sd/root-hash.img"
        veritysetup verify \
          --format=1 \
          --hash=sha256 \
          --data-block-size=4096 \
          --hash-block-size=4096 \
          "$out/sd/root-data.img" \
          "$out/sd/root-hash.img" \
          "$root_hash"

        jq --null-input --compact-output --sort-keys \
          --arg root_hash "$root_hash" \
          '{
            schema: "provisioning.kaiba.network/rpi5-stable-campaign-provisioner-boot-integrity/v1alpha1",
            algorithm: "sha256",
            data_block_size: 4096,
            hash_block_size: 4096,
            no_superblock: false,
            root_hash: $root_hash,
            data_device: "/dev/mmcblk0p2",
            hash_device: "/dev/mmcblk0p3"
          }' > "$TMPDIR/boot-tree/kaiba-root-integrity.json"
        printf '%s\n' \
          "console=serial0,115200 ${fixtureInitArgument} ro root=fstab rd.systemd.verity=1 roothash=$root_hash systemd.verity_root_data=/dev/mmcblk0p2 systemd.verity_root_hash=/dev/mmcblk0p3" \
          > "$TMPDIR/boot-tree/nixos/default/cmdline.txt"
        find "$TMPDIR/boot-tree" -exec touch --date=@315532800 {} +
        mcopy -s -p -m -i "$out/unsigned/boot.img" \
          "$TMPDIR/boot-tree"/* ::/

        boot_digest="sha256:$(sha256sum "$out/unsigned/boot.img" | cut -d ' ' -f 1)"
        root_data_artifact_digest="sha256:$root_data_digest"
        root_hash_artifact_digest="sha256:$(sha256sum "$out/sd/root-hash.img" | cut -d ' ' -f 1)"
        jq --null-input --compact-output --sort-keys \
          --arg boot_digest "$boot_digest" \
          --arg root_data_digest "$root_data_artifact_digest" \
          --arg root_hash_digest "$root_hash_artifact_digest" \
          --arg root_hash "sha256:$root_hash" \
          --arg verity_uuid "$verity_uuid" \
          '{
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
            boot_image_size_bytes: ${toString fixtureBootImageSizeBytes},
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
              root_data: {path: "sd/root-data.img", digest: $root_data_digest},
              root_hash_tree: {path: "sd/root-hash.img", digest: $root_hash_digest}
            },
            verity: {
              algorithm: "sha256",
              data_block_size: 4096,
              hash_block_size: 4096,
              uuid: $verity_uuid,
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
              data_partition_size_bytes: ${toString fixtureRootDataPartitionSizeBytes},
              hash_partition: 3,
              hash_partition_guid: "62616022-71fb-5036-8cc4-b7949cc6e52c",
              hash_partition_size_bytes: ${toString fixtureRootHashPartitionSizeBytes}
            },
            root_integrity_digest: $root_hash,
            signing_status: "unsigned",
            hardware_observed: false,
            physical_staging_ready: false,
            production_ready: false
          }' > "$TMPDIR/manifest-without-bundle-digest.json"
        canonical_manifest="$(cat "$TMPDIR/manifest-without-bundle-digest.json")"
        bundle_digest="sha256:$({
          printf '%s\0' 'kaiba.rpi5.stable-campaign-provisioner-artifacts.v1'
          printf '%s' "$canonical_manifest"
        } | sha256sum | cut -d ' ' -f 1)"
        jq --compact-output --sort-keys \
          --arg bundle_digest "$bundle_digest" \
          '. + {bundle_digest: $bundle_digest}' \
          "$TMPDIR/manifest-without-bundle-digest.json" > "$out/manifest.json"
        chmod 0444 "$out/manifest.json" "$out/unsigned/boot.img" "$out/sd"/*.img
      '';

  fixtureSigningMaterial =
    pkgs.runCommand "kaiba-fixture-stable-campaign-signing-material"
      {
        nativeBuildInputs = with pkgs; [
          coreutils
          openssl
          python3
          xxd
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C

        python3 ${./deterministic-rsa-fixture.py} --private "$TMPDIR/private.pem"
        openssl pkey -in "$TMPDIR/private.pem" -pubout -out "$TMPDIR/public.pem"
        test "sha256:$(sha256sum "$TMPDIR/public.pem" | cut -d ' ' -f 1)" = \
          '${fixturePublicKeyFileDigest}'
        test "sha256:$(openssl pkey -pubin -in "$TMPDIR/public.pem" -outform DER \
          | sha256sum | cut -d ' ' -f 1)" = '${fixturePublicKeyFingerprint}'

        readonly boot=${fixtureUnsignedArtifacts}/unsigned/boot.img
        openssl dgst -sha256 -sign "$TMPDIR/private.pem" "$boot" \
          > "$TMPDIR/signature.bin"
        mkdir "$out"
        install -m 0444 "$TMPDIR/public.pem" "$out/public.pem"
        printf '%s\nts: %s\nrsa2048: %s\n' \
          "$(sha256sum "$boot" | cut -d ' ' -f 1)" \
          1786968000 \
          "$(xxd -p -c 4096 "$TMPDIR/signature.bin")" \
          > "$out/boot.sig"
        chmod 0444 "$out/boot.sig"
        test ! -e "$out/private.pem"
      '';

  fixtureProfile = {
    bootIntegritySchema = ../schemas/rpi5-stable-campaign-provisioner-boot-integrity-v1alpha1.schema.json;
    unsignedArtifactSchema = fixtureUnsignedSchema;
    signedBootFilesystemSchema = fixtureSignedSchema;
    expectedPublicKeyFileDigest = fixturePublicKeyFileDigest;
    expectedPublicKeyFingerprint = fixturePublicKeyFingerprint;
    expectedCustomerKeyHash = fixtureCustomerKeyHash;
    diskGUID = "5625eee2-0c8a-402f-8c2f-5a1347652bb2";
    bootPartitionGUID = "59d06b61-bf85-4d77-89c3-9e5395934ff8";
    dataPartitionGUID = "bdd5be20-f7ea-56e7-ae90-4465ae950596";
    hashPartitionGUID = "62616022-71fb-5036-8cc4-b7949cc6e52c";
    bootImageSizeBytes = fixtureBootImageSizeBytes;
    bootPartitionSizeBytes = 134217728;
    rootDataPartitionSizeBytes = fixtureRootDataPartitionSizeBytes;
    rootHashPartitionSizeBytes = fixtureRootHashPartitionSizeBytes;
  };
  fixtureSignedBootFilesystem = constructors._testOnly.mkForProfile fixtureProfile {
    bootSignature = "${fixtureSigningMaterial}/boot.sig";
    reviewedPublicKeyPEM = "${fixtureSigningMaterial}/public.pem";
    unsignedArtifacts = fixtureUnsignedArtifacts;
  };
  fixtureSignedBootFilesystemSecond = constructors._testOnly.mkForProfile fixtureProfile {
    bootSignature = "${fixtureSigningMaterial}/boot.sig";
    name = "kaiba-fixture-stable-campaign-signed-boot-filesystem-second";
    reviewedPublicKeyPEM = "${fixtureSigningMaterial}/public.pem";
    unsignedArtifacts = fixtureUnsignedArtifacts;
  };
  closedDevelopmentWrapperRejectsFixture =
    !(builtins.tryEval (
      (constructors.mkRpi5StableCampaignProvisionerSignedBootFilesystem {
        bootSignature = "${fixtureSigningMaterial}/boot.sig";
        unsignedArtifacts = fixtureUnsignedArtifacts;
      }).drvPath
    )).success;
  contract = fixtureSignedBootFilesystem.kaibaRpi5StableCampaignProvisionerSignedBootFilesystem;
in
assert lib.assertMsg closedDevelopmentWrapperRejectsFixture
  "the closed development signed-boot wrapper accepted a fixture trust root";
assert lib.assertMsg (
  contract.schemaVersion
  == "provisioning.kaiba.network/rpi5-stable-campaign-provisioner-signed-boot-filesystem/v1alpha1"
  && contract.sourceRevision == fixtureSourceRevision
  && contract.diskGUID == "5625eee2-0c8a-402f-8c2f-5a1347652bb2"
  && contract.bootPartitionGUID == "59d06b61-bf85-4d77-89c3-9e5395934ff8"
  && contract.bootPartitionSizeBytes == 134217728
  && contract.expectedCustomerKeyHash == fixtureCustomerKeyHash
  && contract.expectedPublicKeyFileDigest == fixturePublicKeyFileDigest
  && contract.expectedPublicKeyFingerprint == fixturePublicKeyFingerprint
  && contract.rootPolicyVerified
  && contract.signatureVerified
  && lib.all (value: value == false) [
    contract.blockDeviceWriteCapable
    contract.directHardwareAccess
    contract.eepromProgrammingCapable
    contract.hardwareObserved
    contract.mutationCapable
    contract.oneTimeSettingCapable
    contract.otpCapable
    contract.physicalStagingReady
    contract.privateKeyAccess
    contract.productionReady
    contract.signingAuthorityConfigured
  ]
) "the signed-boot filesystem capability or identity contract changed";
pkgs.runCommand "kaiba-rpi5-stable-campaign-provisioner-signed-boot-filesystem-contract"
  {
    nativeBuildInputs = with pkgs; [
      check-jsonschema
      coreutils
      cryptsetup
      dosfstools
      e2fsprogs
      findutils
      jq
      mtools
      openssl
      xxd
    ];
  }
  ''
    set -euo pipefail
    export LC_ALL=C

    readonly bundle=${fixtureSignedBootFilesystem}
    readonly second_bundle=${fixtureSignedBootFilesystemSecond}
    readonly manifest="$bundle/manifest.json"
    readonly boot_filesystem="$bundle/sd/boot-filesystem.img"
    check-jsonschema --check-metaschema ${fixtureSignedSchema}
    check-jsonschema --schemafile ${fixtureSignedSchema} "$manifest"
    test "$(stat --format=%s "$boot_filesystem")" -eq 134217728
    test "sha256:$(sha256sum "$boot_filesystem" | cut -d ' ' -f 1)" = \
      "$(jq -r .artifacts.boot_filesystem.digest "$manifest")"
    test "$(jq -r .unsigned_artifact_set.bundle_digest "$manifest")" = \
      "$(jq -r .bundle_digest ${fixtureUnsignedArtifacts}/manifest.json)"

    ${constructors._testOnly.verityMetadataVerifier}/bin/kaiba-rpi5-stable-campaign-provisioner-verify-verity-metadata \
      ${fixtureUnsignedArtifacts}/sd/root-hash.img \
      ${fixtureUnsignedArtifacts}/sd/root-data.img \
      ${fixtureUnsignedArtifacts}/manifest.json

    readonly fixture_verity_uuid="$(jq -r .verity.uuid \
      ${fixtureUnsignedArtifacts}/manifest.json)"
    readonly fixture_root_data_digest="$(jq -r .artifacts.root_data.digest \
      ${fixtureUnsignedArtifacts}/manifest.json)"
    : > "$TMPDIR/wrong-algorithm-root-hash.img"
    veritysetup format \
      --format=1 \
      --hash=sha512 \
      --data-block-size=4096 \
      --hash-block-size=4096 \
      --salt="''${fixture_root_data_digest#sha256:}" \
      --uuid="$fixture_verity_uuid" \
      ${fixtureUnsignedArtifacts}/sd/root-data.img \
      "$TMPDIR/wrong-algorithm-root-hash.img" \
      > "$TMPDIR/wrong-algorithm-verity-format.txt"
    truncate --size=${toString fixtureRootHashPartitionSizeBytes} \
      "$TMPDIR/wrong-algorithm-root-hash.img"
    if ${constructors._testOnly.verityMetadataVerifier}/bin/kaiba-rpi5-stable-campaign-provisioner-verify-verity-metadata \
      "$TMPDIR/wrong-algorithm-root-hash.img" \
      ${fixtureUnsignedArtifacts}/sd/root-data.img \
      ${fixtureUnsignedArtifacts}/manifest.json; then
      echo 'verity metadata verifier accepted an on-disk SHA-512 tree labeled SHA-256' >&2
      exit 1
    fi

    : > "$TMPDIR/no-superblock-root-hash.img"
    veritysetup format \
      --format=0 \
      --no-superblock \
      --hash=sha256 \
      --data-block-size=4096 \
      --hash-block-size=4096 \
      --salt="''${fixture_root_data_digest#sha256:}" \
      --uuid="$fixture_verity_uuid" \
      ${fixtureUnsignedArtifacts}/sd/root-data.img \
      "$TMPDIR/no-superblock-root-hash.img" \
      > "$TMPDIR/no-superblock-verity-format.txt"
    truncate --size=${toString fixtureRootHashPartitionSizeBytes} \
      "$TMPDIR/no-superblock-root-hash.img"
    if ${constructors._testOnly.verityMetadataVerifier}/bin/kaiba-rpi5-stable-campaign-provisioner-verify-verity-metadata \
      "$TMPDIR/no-superblock-root-hash.img" \
      ${fixtureUnsignedArtifacts}/sd/root-data.img \
      ${fixtureUnsignedArtifacts}/manifest.json; then
      echo 'verity metadata verifier accepted a tree without the required superblock' >&2
      exit 1
    fi

    mcopy -i ${fixtureUnsignedArtifacts}/unsigned/boot.img \
      '::nixos/default/cmdline.txt' "$TMPDIR/valid-cmdline.txt"

    ${constructors._testOnly.rootPolicyVerifier}/bin/kaiba-rpi5-stable-campaign-provisioner-verify-root-policy \
      ${fixtureUnsignedArtifacts}/sd/root-data.img \
      ${fixtureUnsignedArtifacts}/manifest.json \
      "$TMPDIR/valid-cmdline.txt" \
      ${lib.escapeShellArg fixtureSourceRevision} \
      ${lib.escapeShellArg fixtureCustomerKeyHash} \
      ${fixtureExpectedRootPolicy} \
      "$TMPDIR/extracted-root-policy.json"
    test "sha256:$(sha256sum "$TMPDIR/extracted-root-policy.json" | cut -d ' ' -f 1)" = \
      "$(jq -r .root_target_policy.digest "$manifest")"

    readonly relabeled_revision=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    jq --compact-output --sort-keys \
      --arg source_revision "$relabeled_revision" \
      '.source_revision = $source_revision | del(.bundle_digest)' \
      ${fixtureUnsignedArtifacts}/manifest.json \
      > "$TMPDIR/relabeled-manifest-without-digest.json"
    relabeled_canonical="$(cat "$TMPDIR/relabeled-manifest-without-digest.json")"
    relabeled_digest="sha256:$({
      printf '%s\0' 'kaiba.rpi5.stable-campaign-provisioner-artifacts.v1'
      printf '%s' "$relabeled_canonical"
    } | sha256sum | cut -d ' ' -f 1)"
    jq --compact-output --sort-keys \
      --arg bundle_digest "$relabeled_digest" \
      '. + {bundle_digest: $bundle_digest}' \
      "$TMPDIR/relabeled-manifest-without-digest.json" \
      > "$TMPDIR/relabeled-manifest.json"
    if ${constructors._testOnly.rootPolicyVerifier}/bin/kaiba-rpi5-stable-campaign-provisioner-verify-root-policy \
      ${fixtureUnsignedArtifacts}/sd/root-data.img \
      "$TMPDIR/relabeled-manifest.json" \
      "$TMPDIR/valid-cmdline.txt" \
      "$relabeled_revision" \
      ${lib.escapeShellArg fixtureCustomerKeyHash} \
      ${
        constructors._testOnly.mkExpectedRootTargetPolicy {
          expectedCustomerKeyHash = fixtureCustomerKeyHash;
          sourceRevision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        }
      } \
      "$TMPDIR/relabeled-root-policy.json"; then
      echo 'root policy verifier accepted a relabeled unsigned manifest' >&2
      exit 1
    fi

    readonly newline_root_tree="$TMPDIR/newline-root-tree"
    mkdir -p \
      "$newline_root_tree/etc" \
      "$newline_root_tree${fixtureSystemToplevel}" \
      "$newline_root_tree${fixtureEtcTree}/kaiba-provisioning"
    printf '%s\n' '#!/bin/sh' 'exit 0' \
      > "$newline_root_tree${fixtureSystemToplevel}/init"
    chmod 0555 "$newline_root_tree${fixtureSystemToplevel}/init"
    ln -s ${lib.escapeShellArg fixtureEtcTree} \
      "$newline_root_tree${fixtureSystemToplevel}/etc"
    install -m 0444 ${fixtureExpectedRootPolicy} \
      "$newline_root_tree${fixturePolicyStorePath}"
    find "$newline_root_tree/nix/store" -type d -exec chmod 0555 {} +
    chmod 0555 "$newline_root_tree/etc"
    truncate --size=${toString fixtureRootDataPartitionSizeBytes} \
      "$TMPDIR/newline-root-data.img"
    E2FSPROGS_FAKE_TIME=315532800 mkfs.ext4 \
      -F \
      -q \
      -U 4b414942-4152-4f4f-9488-888888888888 \
      -L KAIBA_ROOT \
      -O '^has_journal' \
      -E lazy_itable_init=0,lazy_journal_init=0 \
      -d "$newline_root_tree" \
      "$TMPDIR/newline-root-data.img"
    printf '%s\n' ${lib.escapeShellArg fixturePolicyStorePath} \
      > "$TMPDIR/newline-policy-link-bytes"
    debugfs -w \
      -R "write $TMPDIR/newline-policy-link-bytes ${fixtureEtcTree}/kaiba-provisioning/target-policy.json" \
      "$TMPDIR/newline-root-data.img" \
      > "$TMPDIR/newline-policy-write.stdout" \
      2> "$TMPDIR/newline-policy-write.stderr"
    debugfs -w \
      -R "set_inode_field ${fixtureEtcTree}/kaiba-provisioning/target-policy.json mode 0120777" \
      "$TMPDIR/newline-root-data.img" \
      > "$TMPDIR/newline-policy-mode.stdout" \
      2> "$TMPDIR/newline-policy-mode.stderr"
    if ${constructors._testOnly.rootPolicyVerifier}/bin/kaiba-rpi5-stable-campaign-provisioner-verify-root-policy \
      "$TMPDIR/newline-root-data.img" \
      ${fixtureUnsignedArtifacts}/manifest.json \
      "$TMPDIR/valid-cmdline.txt" \
      ${lib.escapeShellArg fixtureSourceRevision} \
      ${lib.escapeShellArg fixtureCustomerKeyHash} \
      ${fixtureExpectedRootPolicy} \
      "$TMPDIR/newline-root-policy.json"; then
      echo 'root policy verifier accepted a trailing-newline symlink target' >&2
      exit 1
    fi

    canonical_manifest="$(jq --compact-output --sort-keys 'del(.bundle_digest)' "$manifest")"
    expected_bundle_digest="sha256:$({
      printf '%s\0' 'kaiba.rpi5.stable-campaign-provisioner-signed-boot-filesystem.v1'
      printf '%s' "$canonical_manifest"
    } | sha256sum | cut -d ' ' -f 1)"
    test "$(jq -r .bundle_digest "$manifest")" = "$expected_bundle_digest"

    fsck.fat -vn "$boot_filesystem" > "$TMPDIR/fsck.txt"
    mkdir "$TMPDIR/readback"
    mcopy -s -i "$boot_filesystem" '::*' "$TMPDIR/readback/"
    find "$TMPDIR/readback" -type f -printf '%P\n' | sort > "$TMPDIR/actual-files"
    printf '%s\n' boot.img boot.sig config.txt > "$TMPDIR/expected-files"
    cmp "$TMPDIR/expected-files" "$TMPDIR/actual-files"
    cmp ${fixtureUnsignedArtifacts}/unsigned/boot.img "$TMPDIR/readback/boot.img"
    cmp ${fixtureSigningMaterial}/boot.sig "$TMPDIR/readback/boot.sig"
    printf '%s\n' 'boot_ramdisk=1' > "$TMPDIR/expected-config.txt"
    cmp "$TMPDIR/expected-config.txt" "$TMPDIR/readback/config.txt"

    readonly root_hash="$(jq -r .root_integrity_digest \
      ${fixtureUnsignedArtifacts}/manifest.json | cut -d: -f2)"
    ${constructors._testOnly.cmdlineVerifier}/bin/kaiba-rpi5-stable-campaign-provisioner-verify-cmdline \
      "$TMPDIR/valid-cmdline.txt" "$root_hash"
    valid_cmdline="$(tr -d '\n' < "$TMPDIR/valid-cmdline.txt")"
    expect_cmdline_rejection() {
      if ${constructors._testOnly.cmdlineVerifier}/bin/kaiba-rpi5-stable-campaign-provisioner-verify-cmdline \
        "$1" "$root_hash" > /dev/null 2>&1; then
        echo "cmdline verifier accepted rejected fixture: $1" >&2
        exit 1
      fi
    }
    printf '%s %s\n' "$valid_cmdline" '"root=/dev/sda1"' \
      > "$TMPDIR/double-quoted-root-cmdline.txt"
    expect_cmdline_rejection "$TMPDIR/double-quoted-root-cmdline.txt"
    printf '%s %s\n' "$valid_cmdline" "'root=/dev/sda1'" \
      > "$TMPDIR/single-quoted-root-cmdline.txt"
    expect_cmdline_rejection "$TMPDIR/single-quoted-root-cmdline.txt"
    printf '%s %s\n' "$valid_cmdline" 'systemd.verity_root_data=\/dev/sda1' \
      > "$TMPDIR/escaped-selector-cmdline.txt"
    expect_cmdline_rejection "$TMPDIR/escaped-selector-cmdline.txt"
    printf '%s -- root=/dev/sda1\n' "$valid_cmdline" \
      > "$TMPDIR/double-dash-cmdline.txt"
    expect_cmdline_rejection "$TMPDIR/double-dash-cmdline.txt"
    printf '%s systemd.verity-root-data=/dev/sda1 systemd.verity-root-hash=/dev/sda2\n' \
      "$valid_cmdline" > "$TMPDIR/hyphenated-selectors-cmdline.txt"
    expect_cmdline_rejection "$TMPDIR/hyphenated-selectors-cmdline.txt"
    printf '%s\0 root=/dev/sda1\n' "$valid_cmdline" \
      > "$TMPDIR/nul-cmdline.txt"
    expect_cmdline_rejection "$TMPDIR/nul-cmdline.txt"
    printf '%s %s\n' "$valid_cmdline" ${lib.escapeShellArg fixtureInitArgument} \
      > "$TMPDIR/duplicate-init-cmdline.txt"
    expect_cmdline_rejection "$TMPDIR/duplicate-init-cmdline.txt"
    printf '%s rdinit=/bin/sh\n' "$valid_cmdline" \
      > "$TMPDIR/rdinit-cmdline.txt"
    expect_cmdline_rejection "$TMPDIR/rdinit-cmdline.txt"

    sed -n 's/^rsa2048: //p' "$TMPDIR/readback/boot.sig" | xxd -r -p \
      > "$TMPDIR/signature.bin"
    openssl dgst -sha256 \
      -verify ${fixtureSigningMaterial}/public.pem \
      -signature "$TMPDIR/signature.bin" \
      "$TMPDIR/readback/boot.img" > "$TMPDIR/verification.txt"
    grep -Fx 'Verified OK' "$TMPDIR/verification.txt" > /dev/null

    cmp "$bundle/manifest.json" "$second_bundle/manifest.json"
    cmp "$bundle/sd/boot-filesystem.img" "$second_bundle/sd/boot-filesystem.img"

    jq '.physical_staging_ready = true' "$manifest" > "$TMPDIR/unsafe-manifest.json"
    if check-jsonschema --schemafile ${fixtureSignedSchema} "$TMPDIR/unsafe-manifest.json" \
      > /dev/null 2>&1; then
      echo 'signed-boot schema accepted physical_staging_ready=true' >&2
      exit 1
    fi
    jq '.artifacts.boot_filesystem.artifact_role = "signing-input"' "$manifest" \
      > "$TMPDIR/ambiguous-manifest.json"
    if check-jsonschema --schemafile ${fixtureSignedSchema} "$TMPDIR/ambiguous-manifest.json" \
      > /dev/null 2>&1; then
      echo 'signed-boot schema accepted an ambiguous outer artifact role' >&2
      exit 1
    fi
    jq '.artifacts.boot_signature.timestamp = "ts: 18446744073709551615"' \
      "$manifest" > "$TMPDIR/maximum-timestamp-manifest.json"
    check-jsonschema --schemafile ${fixtureSignedSchema} \
      "$TMPDIR/maximum-timestamp-manifest.json"
    jq '.artifacts.boot_signature.timestamp = "ts: 18446744073709551616"' \
      "$manifest" > "$TMPDIR/overflow-timestamp-manifest.json"
    if check-jsonschema --schemafile ${fixtureSignedSchema} \
      "$TMPDIR/overflow-timestamp-manifest.json" > /dev/null 2>&1; then
      echo 'signed-boot schema accepted a timestamp above uint64 maximum' >&2
      exit 1
    fi

    mkdir "$out"
    touch "$out/passed"
  ''
