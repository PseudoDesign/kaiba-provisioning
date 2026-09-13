{
  artifacts,
  artifactSchema,
  bootIntegritySchema,
  lib,
  pkgs,
  sourceRevision,
}:

let
  contract = artifacts.kaibaUnsignedArtifacts or null;
in
assert lib.assertMsg (
  contract != null
  &&
    contract.schemaVersion
    == "provisioning.kaiba.network/rpi5-stable-campaign-provisioner-artifact-set/v1alpha1"
  && contract.rootDeviceBinding == "rpi5-sd-card"
  && contract.dataDevice == "/dev/mmcblk0p2"
  && contract.hashDevice == "/dev/mmcblk0p3"
  && contract.diskGUID == "5625eee2-0c8a-402f-8c2f-5a1347652bb2"
  && contract.bootPartitionGUID == "59d06b61-bf85-4d77-89c3-9e5395934ff8"
  && contract.bootPartitionSizeBytes == 134217728
  && contract.rootDataPartitionSizeBytes == 2418016256
  && contract.rootHashPartitionSizeBytes == 19922944
  && contract.signingStatus == "unsigned"
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
) "the stable-campaign provisioner artifact capability or SD binding changed";
pkgs.runCommand "kaiba-rpi5-stable-campaign-provisioner-artifact-contract"
  {
    nativeBuildInputs = [
      pkgs.check-jsonschema
      pkgs.coreutils
      pkgs.cryptsetup
      pkgs.gawk
      pkgs.gnugrep
      pkgs.jq
      pkgs.mtools
    ];
    preferLocalBuild = true;
  }
  ''
    set -euo pipefail
    export LC_ALL=C

    readonly bundle=${artifacts}
    readonly manifest="$bundle/manifest.json"
    readonly boot_image="$bundle/unsigned/boot.img"
    readonly root_data="$bundle/sd/root-data.img"
    readonly root_hash_tree="$bundle/sd/root-hash.img"

    check-jsonschema --check-metaschema ${artifactSchema}
    check-jsonschema --check-metaschema ${bootIntegritySchema}
    check-jsonschema --schemafile ${artifactSchema} "$manifest"
    jq -e '
      .artifacts.boot_image.artifact_role == "signing-input"
      and .artifacts.boot_image.storage_format == "fat-boot-ramdisk-not-partition"
      and .device_binding.disk_guid == "5625eee2-0c8a-402f-8c2f-5a1347652bb2"
      and .device_binding.boot_partition == 1
      and .device_binding.boot_partition_guid == "59d06b61-bf85-4d77-89c3-9e5395934ff8"
      and .device_binding.boot_partition_size_bytes == 134217728
      and .device_binding.data_partition_guid == "bdd5be20-f7ea-56e7-ae90-4465ae950596"
      and .device_binding.hash_partition_guid == "62616022-71fb-5036-8cc4-b7949cc6e52c"
      and .physical_staging_ready == false
    ' "$manifest" > /dev/null
    test "$(jq -r .source_revision "$manifest")" = ${lib.escapeShellArg sourceRevision}
    test "$(stat --format=%s "$boot_image")" -eq 100663296
    test "$(stat --format=%s "$root_data")" -eq 2418016256
    test "$(stat --format=%s "$root_hash_tree")" -eq 19922944

    for artifact in boot_image root_data root_hash_tree; do
      relative_path="$(jq -r --arg artifact "$artifact" '.artifacts[$artifact].path' "$manifest")"
      expected="$(jq -r --arg artifact "$artifact" '.artifacts[$artifact].digest' "$manifest")"
      actual="sha256:$(sha256sum "$bundle/$relative_path" | cut -d ' ' -f 1)"
      test "$actual" = "$expected"
    done

    canonical_manifest="$(jq --compact-output --sort-keys 'del(.bundle_digest)' "$manifest")"
    expected_bundle_digest="sha256:$({
      printf '%s\0' 'kaiba.rpi5.stable-campaign-provisioner-artifacts.v1'
      printf '%s' "$canonical_manifest"
    } | sha256sum | cut -d ' ' -f 1)"
    test "$(jq -r .bundle_digest "$manifest")" = "$expected_bundle_digest"

    integrity_digest="$(jq -r .root_integrity_digest "$manifest")"
    root_hash="''${integrity_digest#sha256:}"
    printf '%s\n' "$root_hash" | grep -Eq '^[0-9a-f]{64}$'
    veritysetup verify "$root_data" "$root_hash_tree" "$root_hash"

    mcopy -i "$boot_image" '::nixos/default/cmdline.txt' cmdline.txt
    test -f cmdline.txt
    test ! -L cmdline.txt
    test -s cmdline.txt
    test "$(tail -c 1 cmdline.txt | od -An -tu1 | tr -d ' \n')" = 10
    test "$(wc -l < cmdline.txt)" -eq 1
    od -An -tu1 -v cmdline.txt | awk '
      {
        for (i = 1; i <= NF; i++) {
          byte = $i + 0
          if (byte == 10) newlines++
          else if (byte < 32 || byte > 126 || byte == 34 || byte == 39 || byte == 92) bad++
        }
      }
      END {
        if (newlines != 1 || bad != 0) exit 1
      }
    '
    awk -v expected_hash="$root_hash" '
      {
        for (i = 1; i <= NF; i++) {
          token = $i
          key = token
          sub(/=.*/, "", key)
          normalized_key = key
          gsub(/-/, "_", normalized_key)
          if (token == "ro") ro++
          if (token == "rw") rw++
          if (token == "--") option_terminators++
          if (key == "init") inits++
          if (token ~ /^init=\/nix\/store\/[0-9abcdfghijklmnpqrsvwxyz]{32}-nixos-system-kaiba-rpi5-provisioner-[A-Za-z0-9+._%-]+\/init$/) exact_init++
          if (key == "rdinit") rd_inits++
          if (key == "root") roots++
          if (token == "root=fstab") root_fstab++
          if (key == "rootfstype") rootfstype++
          if (key == "roothash") roothashes++
          if (token == "roothash=" expected_hash) exact_roothash++
          if (normalized_key == "rd.systemd.verity") rd_verity++
          if (token == "rd.systemd.verity=1") exact_rd_verity++
          if (normalized_key == "systemd.verity") systemd_verity++
          if (normalized_key ~ /^systemd\.verity_root_/) root_selectors++
          if (normalized_key == "systemd.verity_root_data") data_selectors++
          if (token == "systemd.verity_root_data=/dev/mmcblk0p2") exact_data++
          if (normalized_key == "systemd.verity_root_hash") hash_selectors++
          if (token == "systemd.verity_root_hash=/dev/mmcblk0p3") exact_hash++
          if (normalized_key ~ /^rd\.systemd\.verity_root_/) rd_root_selectors++
          if (token ~ /PARTUUID=/) partuuid++
          if (token ~ /\/dev\/nvme/) nvme++
        }
      }
      END {
        if (NR != 1 || ro != 1 || rw != 0 || option_terminators != 0 ||
            inits != 1 || exact_init != 1 || rd_inits != 0 || roots != 1 || root_fstab != 1 ||
            rootfstype != 0 || roothashes != 1 || exact_roothash != 1 ||
            rd_verity != 1 || exact_rd_verity != 1 || systemd_verity != 0 ||
            root_selectors != 2 || data_selectors != 1 || exact_data != 1 || hash_selectors != 1 ||
            exact_hash != 1 || rd_root_selectors != 0 || partuuid != 0 || nvme != 0)
          exit 1
      }
    ' cmdline.txt

    mtype -i "$boot_image" ::kaiba-root-integrity.json | tr -d '\r' > integrity.json
    check-jsonschema --schemafile ${bootIntegritySchema} integrity.json
    jq -e \
      --arg root_hash "$root_hash" \
      --arg data_device "$(jq -r .verity.data_device "$manifest")" \
      --arg hash_device "$(jq -r .verity.hash_device "$manifest")" \
      '.root_hash == $root_hash
        and .data_device == $data_device
        and .hash_device == $hash_device' \
      integrity.json > /dev/null

    mtype -i "$boot_image" ::config.txt | tr -d '\r' > config.txt
    test "$(grep -Fxc 'os_prefix=nixos/default/' config.txt)" -eq 1
    test "$(grep -Fxc 'kernel=kernel.img' config.txt)" -eq 1
    test "$(grep -Fxc 'initramfs initrd followkernel' config.txt)" -eq 1
    test "$(grep -Fxc 'dtoverlay=dwc2' config.txt)" -ge 1
    test "$(grep -Fxc 'dtparam=dr_mode=peripheral' config.txt)" -eq 1

    mkdir "$out"
    touch "$out/passed"
  ''
