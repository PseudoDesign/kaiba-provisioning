{
  lib,
  pkgs,
}:

let
  developmentPosture = builtins.fromJSON (
    builtins.readFile ../policies/raspberry-pi-5-development-posture-v1alpha1.json
  );
  stableCampaignProvisionerCustomerKeyHash = "b8818acea4e71173903ee003e33ed37e969def7d2ea67bec15c0b73cb36c3895";
  stableCampaignProvisionerDiskGUID = "5625eee2-0c8a-402f-8c2f-5a1347652bb2";
  stableCampaignProvisionerBootPartitionGUID = "59d06b61-bf85-4d77-89c3-9e5395934ff8";
  stableCampaignProvisionerFirmwareAllowlist = [
    "config.txt"
    "nixos/default/bcm2712-rpi-5-b.dtb"
    "nixos/default/cmdline.txt"
    "nixos/default/initrd"
    "nixos/default/kernel.img"
    "nixos/default/overlays/README"
    "nixos/default/overlays/bcm2712d0.dtbo"
    "nixos/default/overlays/dwc2.dtbo"
    "nixos/default/overlays/overlay_map.dtb"
  ];
in
{
  bootCommandLinePath ? "cmdline.txt",
  bootImageSizeMiB ? 96,
  bootOrderPolicy ? developmentPosture.boot_order.policy,
  expectedCustomerKeyHash,
  firmwareAllowlist,
  firmwareTree,
  name ? "kaiba-rpi5-secure-boot-unsigned-artifacts",
  rootImage,
  rootDataPartitionGUID,
  rootDeviceBinding ? "gpt-partuuid",
  rootHashPartitionGUID,
  sourceRevision,
}:

assert lib.assertMsg (
  bootImageSizeMiB >= 32 && bootImageSizeMiB <= 96
) "secure boot bootImageSizeMiB must be between 32 and the Raspberry Pi boot_ramdisk limit of 96";
assert lib.assertMsg (
  builtins.match "[0-9a-f]{64}" expectedCustomerKeyHash != null
) "expectedCustomerKeyHash must be one lowercase SHA-256 digest without a prefix";
assert lib.assertMsg (
  builtins.isString rootDataPartitionGUID
  &&
    builtins.match "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" rootDataPartitionGUID
    != null
  && rootDataPartitionGUID != "00000000-0000-0000-0000-000000000000"
) "rootDataPartitionGUID must be one canonical non-zero lowercase GPT partition GUID";
assert lib.assertMsg (
  builtins.isString rootHashPartitionGUID
  &&
    builtins.match "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" rootHashPartitionGUID
    != null
  && rootHashPartitionGUID != "00000000-0000-0000-0000-000000000000"
) "rootHashPartitionGUID must be one canonical non-zero lowercase GPT partition GUID";
assert lib.assertMsg (
  rootDataPartitionGUID != rootHashPartitionGUID
) "rootDataPartitionGUID and rootHashPartitionGUID must be distinct";
assert lib.assertMsg (builtins.elem rootDeviceBinding [
  "gpt-partuuid"
  "rpi5-sd-card"
]) "rootDeviceBinding must be gpt-partuuid or rpi5-sd-card";
assert lib.assertMsg (
  rootDeviceBinding != "rpi5-sd-card"
  || (
    bootImageSizeMiB == 96
    && bootCommandLinePath == "nixos/default/cmdline.txt"
    && expectedCustomerKeyHash == stableCampaignProvisionerCustomerKeyHash
    && firmwareAllowlist == stableCampaignProvisionerFirmwareAllowlist
    && rootDataPartitionGUID == "bdd5be20-f7ea-56e7-ae90-4465ae950596"
    && rootHashPartitionGUID == "62616022-71fb-5036-8cc4-b7949cc6e52c"
  )
) "rpi5-sd-card binding is reserved for the exact stable-campaign provisioner profile";
assert lib.assertMsg (
  builtins.isList firmwareAllowlist
  && firmwareAllowlist != [ ]
  && lib.all (
    path:
    builtins.isString path
    && builtins.match "[A-Za-z0-9_+.-][A-Za-z0-9_+./-]{0,254}" path != null
    && !(lib.hasPrefix "/" path)
    && !(lib.hasPrefix "." path)
    && !(lib.hasInfix "/." path)
    && !(lib.hasInfix ".." path)
    && !(lib.hasInfix "//" path)
  ) firmwareAllowlist
  && builtins.length firmwareAllowlist == builtins.length (lib.unique firmwareAllowlist)
) "firmwareAllowlist must be a non-empty unique list of canonical relative file paths";
assert lib.assertMsg (
  builtins.isString bootCommandLinePath
  && builtins.match "[A-Za-z0-9_+.-][A-Za-z0-9_+./-]{0,254}" bootCommandLinePath != null
  && !(lib.hasPrefix "/" bootCommandLinePath)
  && !(lib.hasPrefix "." bootCommandLinePath)
  && !(lib.hasInfix "/." bootCommandLinePath)
  && !(lib.hasInfix ".." bootCommandLinePath)
  && !(lib.hasInfix "//" bootCommandLinePath)
  && lib.elem bootCommandLinePath firmwareAllowlist
) "bootCommandLinePath must name one canonical regular file in firmwareAllowlist";
assert lib.assertMsg (
  bootOrderPolicy == developmentPosture.boot_order.policy
) "bootOrderPolicy must match the approved sacrificial development posture";
assert lib.assertMsg (
  builtins.isString sourceRevision
  && builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" sourceRevision != null
) "sourceRevision must be one canonical lowercase 40- or 64-hex Git revision";

let
  # These selectors are chosen before the boot image and signed-release
  # digests exist.  SB-04 must copy the exact GUID values into GPT instead of
  # deriving them from a downstream signed-release digest (which would create
  # a digest cycle).
  sdCardBound = rootDeviceBinding == "rpi5-sd-card";
  dataDevice = if sdCardBound then "/dev/mmcblk0p2" else "PARTUUID=${rootDataPartitionGUID}";
  hashDevice = if sdCardBound then "/dev/mmcblk0p3" else "PARTUUID=${rootHashPartitionGUID}";
  artifactDirectory = if sdCardBound then "sd" else "nvme";
  artifactSchema =
    if sdCardBound then
      "provisioning.kaiba.network/rpi5-stable-campaign-provisioner-artifact-set/v1alpha1"
    else
      "provisioning.kaiba.network/unsigned-artifact-set/v1alpha1";
  rootIntegritySchema =
    if sdCardBound then
      "provisioning.kaiba.network/rpi5-stable-campaign-provisioner-boot-integrity/v1alpha1"
    else
      "provisioning.kaiba.network/rpi5-boot-integrity/v1alpha1";
  # The provisioner runs from the already-reviewed development SD layout. Its
  # data and hash images are padded to the exact p2/p3 capacities so physical
  # staging and readback can bind complete partition bytes.
  rootDataPartitionSizeBytes = if sdCardBound then 2418016256 else null;
  rootHashPartitionSizeBytes = if sdCardBound then 19922944 else null;
  bootPartitionSizeBytes = if sdCardBound then 134217728 else null;
  bundleDigestDomain =
    if sdCardBound then
      "kaiba.rpi5.stable-campaign-provisioner-artifacts.v1"
    else
      "kaiba.rpi5.unsigned-artifacts.v1";
  generatedBootFiles = [ "kaiba-root-integrity.json" ];
  finalBootAllowlist = lib.sort builtins.lessThan (
    lib.unique (firmwareAllowlist ++ generatedBootFiles)
  );
in
pkgs.runCommand name
  {
    nativeBuildInputs = with pkgs; [
      coreutils
      cryptsetup
      dosfstools
      findutils
      gnugrep
      jq
      mtools
    ];
    passthru.kaibaUnsignedArtifacts = {
      inherit
        bootCommandLinePath
        bootImageSizeMiB
        bootOrderPolicy
        bootPartitionSizeBytes
        dataDevice
        expectedCustomerKeyHash
        firmwareAllowlist
        hashDevice
        rootDeviceBinding
        rootDataPartitionGUID
        rootDataPartitionSizeBytes
        rootHashPartitionGUID
        rootHashPartitionSizeBytes
        sourceRevision
        ;
      bootPartitionGUID = stableCampaignProvisionerBootPartitionGUID;
      blockDeviceWriteCapable = false;
      directHardwareAccess = false;
      eepromProgrammingCapable = false;
      mutationCapable = false;
      oneTimeSettingCapable = false;
      otpCapable = false;
      privateKeyAccess = false;
      diskGUID = stableCampaignProvisionerDiskGUID;
      schemaVersion = artifactSchema;
      signingAuthorityConfigured = false;
      signingStatus = "unsigned";
    };
    preferLocalBuild = true;
  }
  ''
    set -euo pipefail
    export TZ=UTC
    export LC_ALL=C

    readonly stage="$TMPDIR/boot-tree"
    readonly active_cmdline="$stage/${bootCommandLinePath}"
    mkdir -p "$stage" "$out/unsigned" "$out/${artifactDirectory}"

    # The caller supplies only public boot inputs. Kaiba release-signing
    # private material is deliberately absent from this derivation and
    # therefore from the Nix store and build logs.
    cp -R --no-preserve=ownership ${firmwareTree}/. "$stage/"
    if test -n "$(find "$stage" -type l -print -quit)"; then
      echo "firmware tree contains a symbolic link" >&2
      exit 1
    fi
    if test -n "$(find "$stage" ! -type d ! -type f -print -quit)"; then
      echo "firmware tree contains an unsupported filesystem object" >&2
      exit 1
    fi
    find "$stage" -type f -printf '%P\n' | LC_ALL=C sort > "$TMPDIR/actual-firmware-files"
    {
      ${lib.concatMapStringsSep "\n" (path: "printf '%s\\n' ${lib.escapeShellArg path}") (
        lib.sort builtins.lessThan firmwareAllowlist
      )}
    } > "$TMPDIR/expected-firmware-files"
    if ! cmp "$TMPDIR/expected-firmware-files" "$TMPDIR/actual-firmware-files"; then
      echo "firmware tree differs from firmwareAllowlist" >&2
      exit 1
    fi
    if test -e "$stage/kaiba-root-integrity.json"; then
      echo "firmware tree must not supply generated kaiba-root-integrity.json" >&2
      exit 1
    fi
    # FAT cannot encode pre-1980 timestamps.  Pin every entry to its first
    # representable UTC day so directory construction is reproducible.
    find "$stage" -exec touch --date=@315532800 '{}' +

    cp --reflink=auto ${rootImage} "$out/${artifactDirectory}/root-data.img"
    chmod u+w "$out/${artifactDirectory}/root-data.img"
    ${lib.optionalString sdCardBound ''
      root_image_size="$(stat --format=%s "$out/${artifactDirectory}/root-data.img")"
      if test "$root_image_size" -gt ${toString rootDataPartitionSizeBytes}; then
        echo "provisioner root image exceeds the fixed SD p2 capacity" >&2
        exit 1
      fi
      truncate --size=${toString rootDataPartitionSizeBytes} \
        "$out/${artifactDirectory}/root-data.img"
    ''}
    chmod 0444 "$out/${artifactDirectory}/root-data.img"
    root_image_digest="$(sha256sum "$out/${artifactDirectory}/root-data.img" | cut -d ' ' -f 1)"
    verity_uuid="''${root_image_digest:0:8}-''${root_image_digest:8:4}-''${root_image_digest:12:4}-''${root_image_digest:16:4}-''${root_image_digest:20:12}"

    # A digest-derived salt makes the unsigned artifact reproducible.  The
    # root hash is placed in the selected command line inside boot.img, so
    # it is covered by the Raspberry Pi signature rather than read from
    # mutable storage metadata.
    : > "$out/${artifactDirectory}/root-hash.img"
    veritysetup format \
      --format=1 \
      --hash=sha256 \
      --data-block-size=4096 \
      --hash-block-size=4096 \
      --salt="$root_image_digest" \
      --uuid="$verity_uuid" \
      --root-hash-file="$TMPDIR/root-hash" \
      "$out/${artifactDirectory}/root-data.img" \
      "$out/${artifactDirectory}/root-hash.img" \
      > "$TMPDIR/verity-format.txt"
    grep -Eq '^Hash type:[[:space:]]+1$' "$TMPDIR/verity-format.txt"
    grep -Eq '^Hash algorithm:[[:space:]]+sha256$' "$TMPDIR/verity-format.txt"
    grep -Eq '^Data block size:[[:space:]]+4096 \[bytes\]$' "$TMPDIR/verity-format.txt"
    grep -Eq '^Hash block size:[[:space:]]+4096 \[bytes\]$' "$TMPDIR/verity-format.txt"
    root_hash="$(tr -d '\n' < "$TMPDIR/root-hash")"
    if test "''${#root_hash}" -ne 64; then
      echo "veritysetup returned a root hash with the wrong length" >&2
      exit 1
    fi
    case "$root_hash" in
      (*[!0-9a-f]*)
        echo "veritysetup returned an invalid root hash" >&2
        exit 1
        ;;
    esac
    ${lib.optionalString sdCardBound ''
      root_hash_image_size="$(stat --format=%s "$out/${artifactDirectory}/root-hash.img")"
      if test "$root_hash_image_size" -gt ${toString rootHashPartitionSizeBytes}; then
        echo "provisioner hash tree exceeds the fixed SD p3 capacity" >&2
        exit 1
      fi
      truncate --size=${toString rootHashPartitionSizeBytes} \
        "$out/${artifactDirectory}/root-hash.img"
    ''}
    chmod 0444 "$out/${artifactDirectory}/root-hash.img"
    veritysetup verify \
      --format=1 \
      --hash=sha256 \
      --data-block-size=4096 \
      --hash-block-size=4096 \
      "$out/${artifactDirectory}/root-data.img" \
      "$out/${artifactDirectory}/root-hash.img" \
      "$root_hash"

    test -f "$active_cmdline" || {
      echo "bootCommandLinePath is not a regular file in the staged firmware" >&2
      exit 1
    }
    base_cmdline="$(tr '\n' ' ' < "$active_cmdline")"
    : > "$TMPDIR/sanitized-cmdline"
    # The upstream NixOS generation contributes console, init, and other
    # target parameters.  Remove every root/verity selector before adding the
    # signed, builder-owned values so kernel argument ordering cannot select a
    # different root or disable verification.
    for parameter in $base_cmdline; do
      case "$parameter" in
        ro|rw|root=*|rootfstype=*|roothash=*|systemd.verity=*|rd.systemd.verity=*|systemd.verity_root_*=*|rd.systemd.verity_root_*=*)
          ;;
        *)
          printf '%s\n' "$parameter" >> "$TMPDIR/sanitized-cmdline"
          ;;
      esac
    done
    sanitized_cmdline="$(paste -sd ' ' "$TMPDIR/sanitized-cmdline")"
    chmod u+w "$active_cmdline"
    printf '%s %s\n' "$sanitized_cmdline" \
      "ro root=fstab rd.systemd.verity=1 roothash=$root_hash systemd.verity_root_data=${dataDevice} systemd.verity_root_hash=${hashDevice}" \
      > "$active_cmdline"
    chmod 0444 "$active_cmdline"

    jq --null-input \
      --arg schema '${rootIntegritySchema}' \
      --arg root_hash "$root_hash" \
      --arg data_device '${dataDevice}' \
      --arg hash_device '${hashDevice}' \
      '{
        schema: $schema,
        algorithm: "sha256",
        data_block_size: 4096,
        hash_block_size: 4096,
        no_superblock: false,
        root_hash: $root_hash,
        data_device: $data_device,
        hash_device: $hash_device
      }' > "$stage/kaiba-root-integrity.json"
    chmod 0444 "$stage/kaiba-root-integrity.json"
    touch --date=@315532800 "$active_cmdline" "$stage/kaiba-root-integrity.json"

    # Normalize permissions only after every builder-owned file and command
    # line has been generated.  Earlier normalization would make the staged
    # tree immutable before kaiba-root-integrity.json can be created.
    find "$stage" -type d -exec chmod 0555 '{}' +
    find "$stage" -type f -exec chmod 0444 '{}' +

    find "$stage" -type f -printf '%P\n' | LC_ALL=C sort > "$TMPDIR/actual-boot-files"
    {
      ${lib.concatMapStringsSep "\n" (
        path: "printf '%s\\n' ${lib.escapeShellArg path}"
      ) finalBootAllowlist}
    } > "$TMPDIR/expected-boot-files"
    if ! cmp "$TMPDIR/expected-boot-files" "$TMPDIR/actual-boot-files"; then
      echo "generated boot tree differs from the final boot allowlist" >&2
      exit 1
    fi

    truncate --size=${toString bootImageSizeMiB}M "$out/unsigned/boot.img"
    mkfs.vfat \
      --invariant \
      -F 32 \
      -i 4b414942 \
      -n KAIBA_BOOT \
      "$out/unsigned/boot.img" \
      > "$TMPDIR/mkfs.txt"
    mcopy -s -p -m -i "$out/unsigned/boot.img" "$stage"/* ::/
    chmod 0444 "$out/unsigned/boot.img"

    boot_digest="$(sha256sum "$out/unsigned/boot.img" | cut -d ' ' -f 1)"
    hash_image_digest="$(sha256sum "$out/${artifactDirectory}/root-hash.img" | cut -d ' ' -f 1)"
    boot_size="$(stat --format=%s "$out/unsigned/boot.img")"

    jq --null-input \
      --arg schema '${artifactSchema}' \
      --arg source_revision ${lib.escapeShellArg sourceRevision} \
      --arg expected_customer_key_hash 'sha256:${expectedCustomerKeyHash}' \
      --arg boot_order_policy ${lib.escapeShellArg bootOrderPolicy} \
      --arg boot_command_line_path ${lib.escapeShellArg bootCommandLinePath} \
      --argjson firmware_allowlist ${lib.escapeShellArg (builtins.toJSON finalBootAllowlist)} \
      --argjson boot_size "$boot_size" \
      --arg boot_digest "sha256:$boot_digest" \
      --arg root_image_digest "sha256:$root_image_digest" \
      --arg hash_image_digest "sha256:$hash_image_digest" \
      --arg root_hash "sha256:$root_hash" \
      --arg verity_uuid "$verity_uuid" \
      --arg data_device '${dataDevice}' \
      --arg hash_device '${hashDevice}' \
      --arg root_device_binding '${rootDeviceBinding}' \
      --arg root_data_path '${artifactDirectory}/root-data.img' \
      --arg root_hash_path '${artifactDirectory}/root-hash.img' \
      --argjson boot_partition_size '${builtins.toJSON bootPartitionSizeBytes}' \
      --argjson root_data_partition_size '${builtins.toJSON rootDataPartitionSizeBytes}' \
      --argjson root_hash_partition_size '${builtins.toJSON rootHashPartitionSizeBytes}' \
      --arg cryptsetup_version '${lib.getVersion pkgs.cryptsetup}' \
      --arg dosfstools_version '${lib.getVersion pkgs.dosfstools}' \
      --arg mtools_version '${lib.getVersion pkgs.mtools}' \
      '{
        schema: $schema,
        source_revision: $source_revision,
        expected_customer_key_hash: $expected_customer_key_hash,
        boot_order_policy: $boot_order_policy,
        boot_command_line_path: $boot_command_line_path,
        firmware_allowlist: $firmware_allowlist,
        boot_image_size_bytes: $boot_size,
        persistent_mutable_state: "tmpfs-only",
        rollback_policy: "unimplemented-block-enrollment-ready",
        debug_policy: "videocore-jtag-unlocked-development",
        eeprom_write_protection_policy: "unlocked-development",
        toolchain: {
          cryptsetup: $cryptsetup_version,
          dosfstools: $dosfstools_version,
          mtools: $mtools_version
        },
      artifacts: {
          boot_image: { path: "unsigned/boot.img", digest: $boot_digest },
          root_data: { path: $root_data_path, digest: $root_image_digest },
          root_hash_tree: { path: $root_hash_path, digest: $hash_image_digest }
        },
        verity: {
          algorithm: "sha256",
          data_block_size: 4096,
          hash_block_size: 4096,
          uuid: $verity_uuid,
          data_device: $data_device,
          hash_device: $hash_device,
          mapper: "/dev/mapper/root"
        },
        root_integrity_digest: $root_hash,
        signing_status: "unsigned"
      }
      | if $root_device_binding == "rpi5-sd-card" then
          .artifacts.boot_image += {
            artifact_role: "signing-input",
            storage_format: "fat-boot-ramdisk-not-partition"
          }
          | . + {
            device_binding: {
              profile: "rpi5-sd-mmcblk0-fixed-partitions",
              boot_media: "/dev/mmcblk0",
              disk_guid: "${stableCampaignProvisionerDiskGUID}",
              boot_partition: 1,
              boot_partition_guid: "${stableCampaignProvisionerBootPartitionGUID}",
              boot_partition_size_bytes: $boot_partition_size,
              data_partition: 2,
              data_partition_guid: "${rootDataPartitionGUID}",
              data_partition_size_bytes: $root_data_partition_size,
              hash_partition: 3,
              hash_partition_guid: "${rootHashPartitionGUID}",
              hash_partition_size_bytes: $root_hash_partition_size
            },
            hardware_observed: false,
            physical_staging_ready: false,
            production_ready: false
          }
        else
          .
        end' > "$TMPDIR/manifest-without-bundle-digest.json"
    canonical_manifest="$(jq --compact-output --sort-keys . \
      "$TMPDIR/manifest-without-bundle-digest.json")"
    bundle_digest="$({
      printf '%s\0' '${bundleDigestDomain}'
      printf '%s' "$canonical_manifest"
    } | sha256sum | cut -d ' ' -f 1)"
    jq --arg bundle_digest "sha256:$bundle_digest" \
      '. + {bundle_digest: $bundle_digest}' \
      "$TMPDIR/manifest-without-bundle-digest.json" > "$out/manifest.json"
    chmod 0444 "$out/manifest.json"
  ''
