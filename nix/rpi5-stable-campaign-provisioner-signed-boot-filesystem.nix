{
  lib,
  pkgs,
}:

let
  unsignedSchemaVersion = "provisioning.kaiba.network/rpi5-stable-campaign-provisioner-artifact-set/v1alpha1";
  signedBootFilesystemSchemaVersion = "provisioning.kaiba.network/rpi5-stable-campaign-provisioner-signed-boot-filesystem/v1alpha1";
  bundleDigestDomain = "kaiba.rpi5.stable-campaign-provisioner-signed-boot-filesystem.v1";
  canonicalCmdlineERE = "[A-Za-z0-9][A-Za-z0-9._,:=+/@%-]*( [A-Za-z0-9][A-Za-z0-9._,:=+/@%-]*)*";
  nixStoreHashERE = "[0123456789abcdfghijklmnpqrsvwxyz]{32}";
  canonicalInitArgumentERE = "^init=/nix/store/${nixStoreHashERE}-nixos-system-kaiba-rpi5-provisioner-sd-card-[0-9][A-Za-z0-9.+_-]*/init$";
  canonicalEtcTreeERE = "^/nix/store/${nixStoreHashERE}-etc/etc$";
  canonicalTargetPolicyStorePathERE = "^/nix/store/${nixStoreHashERE}-etc-kaiba-provisioning-target-policy[.]json$";

  mkExpectedRootTargetPolicy =
    {
      expectedCustomerKeyHash,
      sourceRevision,
    }:
    pkgs.writeText "kaiba-rpi5-stable-campaign-provisioner-expected-target-policy.json" (
      builtins.toJSON {
        schema = "provisioning.kaiba.network/target-policy/v1alpha1";
        development_posture_id = "raspberry-pi-5-sacrificial-development-v1alpha1";
        source_revision = sourceRevision;
        expected_customer_key_hash = expectedCustomerKeyHash;
        persistent_root = "dm-verity";
        mutable_state = "tmpfs-only";
        rollback_gate = "unimplemented";
        enrollment_ready = false;
        videocore_jtag = "unlocked-development";
        eeprom_write_protection = "unlocked-development";
        development_access = {
          enabled = true;
          transport = "usb-gadget-ethernet";
          address = "10.0.0.2";
          user = "codex";
          root_via_passwordless_sudo = true;
          ephemeral_host_key = true;
        };
      }
    );

  cmdlineVerifier = pkgs.writeShellApplication {
    name = "kaiba-rpi5-stable-campaign-provisioner-verify-cmdline";
    runtimeInputs = with pkgs; [
      coreutils
      gawk
      gnugrep
    ];
    text = ''
      set -euo pipefail
      export LC_ALL=C

      if test "$#" -ne 2; then
        echo 'usage: kaiba-rpi5-stable-campaign-provisioner-verify-cmdline CMDLINE ROOT_HASH' >&2
        exit 64
      fi
      readonly cmdline=$1
      readonly expected_hash=$2
      test -f "$cmdline"
      test ! -L "$cmdline"
      test -s "$cmdline"
      printf '%s\n' "$expected_hash" | grep -Ex '[0-9a-f]{64}' > /dev/null
      test "$(tail -c 1 "$cmdline" | od -An -tx1 | tr -d ' \n')" = 0a
      test "$(wc -l < "$cmdline")" -eq 1
      od -An -v -tu1 "$cmdline" | awk '
        {
          for (i = 1; i <= NF; i++) {
            byte = $i + 0
            if (byte == 10)
              newlines++
            else {
              if (byte < 32 || byte > 126)
                exit 1
              payload_bytes++
            }
          }
        }
        END {
          if (newlines != 1 || payload_bytes == 0)
            exit 1
        }
      '
      grep -Ex ${lib.escapeShellArg canonicalCmdlineERE} "$cmdline" > /dev/null
      if grep -Eq '(^| )--( |$)' "$cmdline"; then
        echo 'boot command line contains the kernel/init argument delimiter' >&2
        exit 1
      fi
      awk \
        -v expected_hash="$expected_hash" \
        -v canonical_init_ere=${lib.escapeShellArg canonicalInitArgumentERE} '
        {
          for (i = 1; i <= NF; i++) {
            token = $i
            key = token
            sub(/=.*/, "", key)
            normalized_key = key
            gsub(/-/, "_", normalized_key)
            if (token == "ro") ro++
            if (token == "rw") rw++
            if (token ~ /^root=/) roots++
            if (token == "root=fstab") root_fstab++
            if (token ~ /^rootfstype=/) rootfstype++
            if (token ~ /^roothash=/) roothashes++
            if (token == "roothash=" expected_hash) exact_roothash++
            if (token ~ /^rd\.systemd\.verity=/) rd_verity++
            if (token == "rd.systemd.verity=1") exact_rd_verity++
            if (token ~ /^systemd\.verity=/) systemd_verity++
            if (normalized_key ~ /^systemd\.verity_root_/) root_selectors++
            if (normalized_key == "systemd.verity_root_data") data_selectors++
            if (token == "systemd.verity_root_data=/dev/mmcblk0p2") exact_data++
            if (normalized_key == "systemd.verity_root_hash") hash_selectors++
            if (token == "systemd.verity_root_hash=/dev/mmcblk0p3") exact_hash++
            if (normalized_key ~ /^rd\.systemd\.verity_root_/) rd_root_selectors++
            if (token ~ /PARTUUID=/) partuuid++
            if (token ~ /\/dev\/nvme/) nvme++
            if (token ~ /^init=/) init_arguments++
            if (token ~ canonical_init_ere) exact_init_arguments++
            if (token ~ /^rdinit=/) rdinit_arguments++
          }
        }
        END {
          if (NR != 1 || ro != 1 || rw != 0 || roots != 1 || root_fstab != 1 ||
              rootfstype != 0 || roothashes != 1 || exact_roothash != 1 ||
              rd_verity != 1 || exact_rd_verity != 1 || systemd_verity != 0 ||
              root_selectors != 2 || data_selectors != 1 || exact_data != 1 ||
              hash_selectors != 1 || exact_hash != 1 || rd_root_selectors != 0 ||
              partuuid != 0 || nvme != 0 || init_arguments != 1 ||
              exact_init_arguments != 1 || rdinit_arguments != 0)
            exit 1
        }
      ' "$cmdline"
    '';
  };

  verityMetadataVerifier = pkgs.writeShellApplication {
    name = "kaiba-rpi5-stable-campaign-provisioner-verify-verity-metadata";
    runtimeInputs = with pkgs; [
      coreutils
      cryptsetup
      gnugrep
      jq
    ];
    text = ''
      set -euo pipefail
      export LC_ALL=C

      if test "$#" -ne 3; then
        echo 'usage: kaiba-rpi5-stable-campaign-provisioner-verify-verity-metadata HASH_DEVICE ROOT_DATA MANIFEST' >&2
        exit 64
      fi
      readonly hash_device=$1
      readonly root_data=$2
      readonly manifest=$3
      for input in "$hash_device" "$root_data" "$manifest"; do
        test -f "$input"
        test ! -L "$input"
        test -s "$input"
      done

      jq -e '
        .verity.algorithm == "sha256"
        and .verity.data_block_size == 4096
        and .verity.hash_block_size == 4096
      ' "$manifest" > /dev/null
      expected_uuid="$(jq -r .verity.uuid "$manifest")"
      readonly expected_uuid
      printf '%s\n' "$expected_uuid" \
        | grep -Ex '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
        > /dev/null
      root_data_digest="$(jq -r .artifacts.root_data.digest "$manifest")"
      readonly root_data_digest
      printf '%s\n' "$root_data_digest" | grep -Ex 'sha256:[0-9a-f]{64}' > /dev/null
      readonly expected_salt="''${root_data_digest#sha256:}"
      root_data_size="$(stat --format=%s "$root_data")"
      readonly root_data_size
      test $((root_data_size % 4096)) -eq 0
      readonly expected_data_blocks=$((root_data_size / 4096))

      dump="$(mktemp)"
      readonly dump
      veritysetup dump "$hash_device" > "$dump"
      grep -Eq '^Hash type:[[:space:]]+1$' "$dump"
      grep -Eq '^Hash algorithm:[[:space:]]+sha256$' "$dump"
      grep -Eq '^Data block size:[[:space:]]+4096 \[bytes\]$' "$dump"
      grep -Eq '^Hash block size:[[:space:]]+4096 \[bytes\]$' "$dump"
      grep -Eq "^Data blocks:[[:space:]]+$expected_data_blocks$" "$dump"
      grep -Eq "^UUID:[[:space:]]+$expected_uuid$" "$dump"
      grep -Eq "^Salt:[[:space:]]+$expected_salt$" "$dump"
    '';
  };

  rootPolicyVerifier = pkgs.writeShellApplication {
    name = "kaiba-rpi5-stable-campaign-provisioner-verify-root-policy";
    runtimeInputs = with pkgs; [
      coreutils
      e2fsprogs
      findutils
      gawk
      gnugrep
      gnused
      jq
    ];
    text = ''
      set -euo pipefail
      export LC_ALL=C

      if test "$#" -ne 7; then
        echo 'usage: kaiba-rpi5-stable-campaign-provisioner-verify-root-policy ROOT_DATA MANIFEST CMDLINE SOURCE_REVISION CUSTOMER_KEY_HASH EXPECTED_POLICY OUTPUT' >&2
        exit 64
      fi
      readonly root_data=$1
      readonly manifest=$2
      readonly cmdline=$3
      readonly expected_source_revision=$4
      readonly expected_customer_key_hash=$5
      readonly expected_policy=$6
      readonly output=$7

      for input in "$root_data" "$manifest" "$cmdline" "$expected_policy"; do
        test -f "$input"
        test ! -L "$input"
        test -s "$input"
      done
      test ! -e "$output"
      printf '%s\n' "$expected_source_revision" \
        | grep -Ex '([0-9a-f]{40}|[0-9a-f]{64})' > /dev/null
      printf '%s\n' "$expected_customer_key_hash" \
        | grep -Ex 'sha256:[0-9a-f]{64}' > /dev/null
      jq -e \
        --arg source_revision "$expected_source_revision" \
        --arg customer_key_hash "$expected_customer_key_hash" \
        '.source_revision == $source_revision
          and .expected_customer_key_hash == $customer_key_hash' \
        "$manifest" > /dev/null

      work="$(mktemp -d)"
      readonly work

      test "$(tail -c 1 "$cmdline" | od -An -tx1 | tr -d ' \n')" = 0a
      test "$(wc -l < "$cmdline")" -eq 1
      od -An -v -tu1 "$cmdline" | awk '
        {
          for (i = 1; i <= NF; i++) {
            byte = $i + 0
            if (byte == 10)
              newlines++
            else {
              if (byte < 32 || byte > 126)
                exit 1
              payload_bytes++
            }
          }
        }
        END {
          if (newlines != 1 || payload_bytes == 0)
            exit 1
        }
      '
      grep -Ex ${lib.escapeShellArg canonicalCmdlineERE} "$cmdline" > /dev/null
      init_argument="$(awk \
        -v canonical_init_ere=${lib.escapeShellArg canonicalInitArgumentERE} '
        {
          for (i = 1; i <= NF; i++) {
            if ($i ~ /^init=/)
              init_arguments++
            if ($i ~ canonical_init_ere) {
              exact_init_arguments++
              selected = $i
            }
            if ($i ~ /^rdinit=/)
              rdinit_arguments++
          }
        }
        END {
          if (init_arguments != 1 || exact_init_arguments != 1 || rdinit_arguments != 0)
            exit 1
          print selected
        }
      ' "$cmdline")"
      readonly init_path="''${init_argument#init=}"
      readonly system_toplevel="''${init_path%/init}"

      toplevel_stat="$(debugfs -R "stat $system_toplevel" "$root_data" \
        2> "$work/toplevel-stat.stderr")"
      printf '%s\n' "$toplevel_stat" \
        | grep -E '^Inode: [1-9][0-9]*[[:space:]]+Type: directory[[:space:]]+Mode:[[:space:]]+0555([[:space:]]|$)' \
        > /dev/null
      init_stat="$(debugfs -R "stat $init_path" "$root_data" \
        2> "$work/init-stat.stderr")"
      printf '%s\n' "$init_stat" \
        | grep -E '^Inode: [1-9][0-9]*[[:space:]]+Type: regular[[:space:]]+Mode:[[:space:]]+0555([[:space:]]|$)' \
        > /dev/null

      extract_exact_symlink_target() {
        local image_path=$1
        local expected_basename=$2
        local expected_target_ere=$3
        local label=$4
        local target_file=$5
        local destination="$work/$label"
        local extracted

        test ! -e "$target_file" || return 1
        mkdir "$destination" || return 1
        debugfs -R "rdump $image_path $destination" "$root_data" \
          > "$work/$label-rdump.stdout" 2> "$work/$label-rdump.stderr" || return 1
        test "$(find "$destination" -mindepth 1 -maxdepth 1 -printf x | wc -c)" -eq 1 \
          || return 1
        extracted="$destination/$expected_basename"
        test -L "$extracted" || return 1
        readlink -n -- "$extracted" > "$target_file" || return 1
        test -s "$target_file" || return 1
        test "$(stat --format=%s "$target_file")" -eq "$(stat --format=%s "$extracted")" \
          || return 1
        od -An -v -tu1 "$target_file" | awk '
          BEGIN { bytes = 0 }
          {
            for (i = 1; i <= NF; i++) {
              byte = $i + 0
              if (byte < 33 || byte > 126)
                exit 1
              bytes++
            }
          }
          END { if (bytes == 0) exit 1 }
        ' || return 1
        grep -Ex "$expected_target_ere" "$target_file" > /dev/null || return 1
      }

      extract_exact_symlink_target \
        "$system_toplevel/etc" \
        etc \
        ${lib.escapeShellArg canonicalEtcTreeERE} \
        toplevel-etc \
        "$work/etc-tree-target" || exit 1
      etc_tree="$(cat "$work/etc-tree-target")"
      readonly etc_tree
      readonly policy_link="$etc_tree/kaiba-provisioning/target-policy.json"
      extract_exact_symlink_target \
        "$policy_link" \
        target-policy.json \
        ${lib.escapeShellArg canonicalTargetPolicyStorePathERE} \
        target-policy-link \
        "$work/final-policy-target" || exit 1
      final_policy="$(cat "$work/final-policy-target")"
      readonly final_policy

      policy_stat="$(debugfs -R "stat $final_policy" "$root_data" \
        2> "$work/policy-stat.stderr")"
      printf '%s\n' "$policy_stat" \
        | grep -E '^Inode: [1-9][0-9]*[[:space:]]+Type: regular[[:space:]]+Mode:[[:space:]]+0444([[:space:]]|$)' \
        > /dev/null
      printf '%s\n' "$policy_stat" \
        | sed -n 's/^User:.* Size: \([0-9][0-9]*\)$/\1/p' > "$work/policy-sizes"
      test "$(wc -l < "$work/policy-sizes")" -eq 1
      test "$(cat "$work/policy-sizes")" = "$(stat --format=%s "$expected_policy")"

      mkdir "$work/policy"
      debugfs -R "rdump $final_policy $work/policy" "$root_data" \
        > "$work/policy-rdump.stdout" 2> "$work/policy-rdump.stderr"
      test "$(find "$work/policy" -mindepth 1 -maxdepth 1 -printf x | wc -c)" -eq 1
      readonly extracted_policy="$work/policy/''${final_policy##*/}"
      test -f "$extracted_policy"
      test ! -L "$extracted_policy"
      test -s "$extracted_policy"
      test "$(stat --format=%a "$extracted_policy")" = 444
      test "$(stat --format=%s "$extracted_policy")" = "$(stat --format=%s "$expected_policy")"
      cmp "$expected_policy" "$extracted_policy"

      jq -e \
        --arg source_revision "$expected_source_revision" \
        --arg customer_key_hash "$expected_customer_key_hash" \
        'type == "object"
          and keys == [
            "development_access",
            "development_posture_id",
            "eeprom_write_protection",
            "enrollment_ready",
            "expected_customer_key_hash",
            "mutable_state",
            "persistent_root",
            "rollback_gate",
            "schema",
            "source_revision",
            "videocore_jtag"
          ]
          and .schema == "provisioning.kaiba.network/target-policy/v1alpha1"
          and .development_posture_id == "raspberry-pi-5-sacrificial-development-v1alpha1"
          and .source_revision == $source_revision
          and .expected_customer_key_hash == $customer_key_hash
          and .persistent_root == "dm-verity"
          and .mutable_state == "tmpfs-only"
          and .rollback_gate == "unimplemented"
          and .enrollment_ready == false
          and .videocore_jtag == "unlocked-development"
          and .eeprom_write_protection == "unlocked-development"
          and .development_access == {
            enabled: true,
            transport: "usb-gadget-ethernet",
            address: "10.0.0.2",
            user: "codex",
            root_via_passwordless_sudo: true,
            ephemeral_host_key: true
          }' \
        "$extracted_policy" > /dev/null
      install -m 0444 "$extracted_policy" "$output"
    '';
  };

  canonicalDigest =
    value: builtins.isString value && builtins.match "sha256:[0-9a-f]{64}" value != null;
  canonicalGUID =
    value:
    builtins.isString value
    && builtins.match "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" value != null
    && value != "00000000-0000-0000-0000-000000000000";
  canonicalRevision =
    value: builtins.isString value && builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" value != null;
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

  developmentProfile = {
    bootIntegritySchema = ../schemas/rpi5-stable-campaign-provisioner-boot-integrity-v1alpha1.schema.json;
    unsignedArtifactSchema = ../schemas/rpi5-stable-campaign-provisioner-artifact-set-v1alpha1.schema.json;
    signedBootFilesystemSchema = ../schemas/rpi5-stable-campaign-provisioner-signed-boot-filesystem-v1alpha1.schema.json;
    reviewedPublicKeyPEM = ../signers/development-prototype/reviewed-boot-public.pem;
    expectedPublicKeyFileDigest = "sha256:93923fb1b289c39e8b336b90defb881f5d15ce3832c74655b295e1a35bfdab80";
    expectedPublicKeyFingerprint = "sha256:0e68e7196fedc382ca435b995598e92d0fe36e4b1a1f949f85f5f2e6e2920fb9";
    expectedCustomerKeyHash = "sha256:b8818acea4e71173903ee003e33ed37e969def7d2ea67bec15c0b73cb36c3895";
    diskGUID = "5625eee2-0c8a-402f-8c2f-5a1347652bb2";
    bootPartitionGUID = "59d06b61-bf85-4d77-89c3-9e5395934ff8";
    dataPartitionGUID = "bdd5be20-f7ea-56e7-ae90-4465ae950596";
    hashPartitionGUID = "62616022-71fb-5036-8cc4-b7949cc6e52c";
    bootImageSizeBytes = 100663296;
    bootPartitionSizeBytes = 134217728;
    rootDataPartitionSizeBytes = 2418016256;
    rootHashPartitionSizeBytes = 19922944;
  };

  validProfile =
    profile:
    canonicalDigest profile.expectedPublicKeyFileDigest
    && canonicalDigest profile.expectedPublicKeyFingerprint
    && canonicalDigest profile.expectedCustomerKeyHash
    && lib.all canonicalGUID [
      profile.diskGUID
      profile.bootPartitionGUID
      profile.dataPartitionGUID
      profile.hashPartitionGUID
    ]
    &&
      builtins.length (
        lib.unique [
          profile.diskGUID
          profile.bootPartitionGUID
          profile.dataPartitionGUID
          profile.hashPartitionGUID
        ]
      ) == 4
    && lib.all builtins.isInt [
      profile.bootImageSizeBytes
      profile.bootPartitionSizeBytes
      profile.rootDataPartitionSizeBytes
      profile.rootHashPartitionSizeBytes
    ]
    && profile.bootImageSizeBytes > 0
    && profile.bootPartitionSizeBytes > profile.bootImageSizeBytes
    && profile.rootDataPartitionSizeBytes > 0
    && profile.rootHashPartitionSizeBytes > 0
    && lib.all (size: lib.mod size 512 == 0) [
      profile.bootImageSizeBytes
      profile.bootPartitionSizeBytes
      profile.rootDataPartitionSizeBytes
      profile.rootHashPartitionSizeBytes
    ];

  # This profile-parameterized constructor is intentionally retained only for
  # deterministic fixture coverage. The flake API must export the closed
  # development wrapper below, never this helper.
  mkForProfile =
    profile:
    {
      bootSignature,
      name ? "kaiba-rpi5-stable-campaign-provisioner-signed-boot-filesystem",
      reviewedPublicKeyPEM,
      unsignedArtifacts,
    }:
    let
      contract = unsignedArtifacts.kaibaUnsignedArtifacts or null;
      expectedRootTargetPolicy = mkExpectedRootTargetPolicy {
        expectedCustomerKeyHash = profile.expectedCustomerKeyHash;
        sourceRevision = contract.sourceRevision;
      };
    in
    assert lib.assertMsg (validProfile profile)
      "stable-campaign signed boot filesystem profile is malformed";
    assert lib.assertMsg (storeBacked unsignedArtifacts)
      "unsignedArtifacts must be one fixed Nix-store path";
    assert lib.assertMsg (storeBacked bootSignature) "bootSignature must be one fixed Nix-store path";
    assert lib.assertMsg (storeBacked reviewedPublicKeyPEM)
      "reviewedPublicKeyPEM must be one fixed Nix-store path";
    assert lib.assertMsg (
      contract != null
      && contract.schemaVersion == unsignedSchemaVersion
      && canonicalRevision contract.sourceRevision
      && "sha256:${contract.expectedCustomerKeyHash}" == profile.expectedCustomerKeyHash
      && contract.rootDeviceBinding == "rpi5-sd-card"
      && contract.diskGUID == profile.diskGUID
      && contract.bootPartitionGUID == profile.bootPartitionGUID
      && contract.bootPartitionSizeBytes == profile.bootPartitionSizeBytes
      && contract.rootDataPartitionGUID == profile.dataPartitionGUID
      && contract.rootDataPartitionSizeBytes == profile.rootDataPartitionSizeBytes
      && contract.rootHashPartitionGUID == profile.hashPartitionGUID
      && contract.rootHashPartitionSizeBytes == profile.rootHashPartitionSizeBytes
      && contract.dataDevice == "/dev/mmcblk0p2"
      && contract.hashDevice == "/dev/mmcblk0p3"
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
    ) "unsignedArtifacts is not the exact typed stable-campaign provisioner input";
    pkgs.runCommand name
      {
        bootSignatureInput = bootSignature;
        reviewedPublicKeyInput = reviewedPublicKeyPEM;
        unsignedArtifactsInput = unsignedArtifacts;
        nativeBuildInputs = with pkgs; [
          check-jsonschema
          coreutils
          cryptsetup
          dosfstools
          e2fsprogs
          findutils
          gnugrep
          gnused
          jq
          mtools
          openssl
          xxd
        ];
        passthru.kaibaRpi5StableCampaignProvisionerSignedBootFilesystem = {
          inherit
            bootSignature
            reviewedPublicKeyPEM
            unsignedArtifacts
            ;
          inherit (contract) sourceRevision;
          inherit (profile)
            bootPartitionGUID
            bootPartitionSizeBytes
            diskGUID
            expectedCustomerKeyHash
            expectedPublicKeyFileDigest
            expectedPublicKeyFingerprint
            ;
          blockDeviceWriteCapable = false;
          directHardwareAccess = false;
          eepromProgrammingCapable = false;
          hardwareObserved = false;
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          physicalStagingReady = false;
          privateKeyAccess = false;
          productionReady = false;
          rootPolicyVerified = true;
          schemaVersion = signedBootFilesystemSchemaVersion;
          signatureVerified = true;
          signingAuthorityConfigured = false;
          storageFormat = "fat32-filesystem-partition-image";
        };
        preferLocalBuild = true;
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        export TZ=UTC
        umask 022

        readonly unsigned_manifest="$unsignedArtifactsInput/manifest.json"
        readonly expected_customer_key_hash=${lib.escapeShellArg profile.expectedCustomerKeyHash}
        readonly expected_public_key_file_digest=${lib.escapeShellArg profile.expectedPublicKeyFileDigest}
        readonly expected_public_key_fingerprint=${lib.escapeShellArg profile.expectedPublicKeyFingerprint}
        readonly expected_disk_guid=${lib.escapeShellArg profile.diskGUID}
        readonly expected_boot_partition_guid=${lib.escapeShellArg profile.bootPartitionGUID}

        for input in "$unsigned_manifest" "$bootSignatureInput" "$reviewedPublicKeyInput"; do
          test -f "$input"
          test ! -L "$input"
          test -s "$input"
        done

        check-jsonschema --check-metaschema ${profile.unsignedArtifactSchema}
        check-jsonschema --check-metaschema ${profile.bootIntegritySchema}
        check-jsonschema --check-metaschema ${profile.signedBootFilesystemSchema}
        check-jsonschema --schemafile ${profile.unsignedArtifactSchema} "$unsigned_manifest"
        jq -e \
          --arg schema ${lib.escapeShellArg unsignedSchemaVersion} \
          --arg source_revision ${lib.escapeShellArg contract.sourceRevision} \
          --arg customer_key_hash "$expected_customer_key_hash" \
          --arg disk_guid "$expected_disk_guid" \
          --arg boot_partition_guid "$expected_boot_partition_guid" \
          --arg data_partition_guid ${lib.escapeShellArg profile.dataPartitionGUID} \
          --arg hash_partition_guid ${lib.escapeShellArg profile.hashPartitionGUID} \
          --argjson boot_image_size ${toString profile.bootImageSizeBytes} \
          --argjson boot_partition_size ${toString profile.bootPartitionSizeBytes} \
          --argjson root_data_size ${toString profile.rootDataPartitionSizeBytes} \
          --argjson root_hash_size ${toString profile.rootHashPartitionSizeBytes} \
          '.schema == $schema
            and .source_revision == $source_revision
            and .expected_customer_key_hash == $customer_key_hash
            and .boot_image_size_bytes == $boot_image_size
            and .artifacts.boot_image.path == "unsigned/boot.img"
            and .artifacts.boot_image.artifact_role == "signing-input"
            and .artifacts.boot_image.storage_format == "fat-boot-ramdisk-not-partition"
            and .artifacts.root_data.path == "sd/root-data.img"
            and .artifacts.root_hash_tree.path == "sd/root-hash.img"
            and .device_binding.profile == "rpi5-sd-mmcblk0-fixed-partitions"
            and .device_binding.boot_media == "/dev/mmcblk0"
            and .device_binding.disk_guid == $disk_guid
            and .device_binding.boot_partition == 1
            and .device_binding.boot_partition_guid == $boot_partition_guid
            and .device_binding.boot_partition_size_bytes == $boot_partition_size
            and .device_binding.data_partition == 2
            and .device_binding.data_partition_guid == $data_partition_guid
            and .device_binding.data_partition_size_bytes == $root_data_size
            and .device_binding.hash_partition == 3
            and .device_binding.hash_partition_guid == $hash_partition_guid
            and .device_binding.hash_partition_size_bytes == $root_hash_size
            and .verity.mapper == "/dev/mapper/root"
            and .signing_status == "unsigned"
            and .hardware_observed == false
            and .physical_staging_ready == false
            and .production_ready == false' \
          "$unsigned_manifest" > /dev/null

        canonical_unsigned_manifest="$(jq --compact-output --sort-keys \
          'del(.bundle_digest)' "$unsigned_manifest")"
        unsigned_bundle_digest="sha256:$({
          printf '%s\0' 'kaiba.rpi5.stable-campaign-provisioner-artifacts.v1'
          printf '%s' "$canonical_unsigned_manifest"
        } | sha256sum | cut -d ' ' -f 1)"
        test "$(jq -r .bundle_digest "$unsigned_manifest")" = "$unsigned_bundle_digest"

        readonly boot_image="$unsignedArtifactsInput/unsigned/boot.img"
        readonly root_data="$unsignedArtifactsInput/sd/root-data.img"
        readonly root_hash_tree="$unsignedArtifactsInput/sd/root-hash.img"
        for input in "$boot_image" "$root_data" "$root_hash_tree"; do
          test -f "$input"
          test ! -L "$input"
        done
        test "$(stat --format=%s "$boot_image")" -eq ${toString profile.bootImageSizeBytes}
        test "$(stat --format=%s "$root_data")" -eq ${toString profile.rootDataPartitionSizeBytes}
        test "$(stat --format=%s "$root_hash_tree")" -eq ${toString profile.rootHashPartitionSizeBytes}
        for artifact in boot_image root_data root_hash_tree; do
          relative_path="$(jq -r --arg artifact "$artifact" \
            '.artifacts[$artifact].path' "$unsigned_manifest")"
          expected_digest="$(jq -r --arg artifact "$artifact" \
            '.artifacts[$artifact].digest' "$unsigned_manifest")"
          test "sha256:$(sha256sum "$unsignedArtifactsInput/$relative_path" | cut -d ' ' -f 1)" = \
            "$expected_digest"
        done

        root_integrity_digest="$(jq -r .root_integrity_digest "$unsigned_manifest")"
        printf '%s\n' "$root_integrity_digest" \
          | grep -Ex 'sha256:[0-9a-f]{64}' > /dev/null
        ${verityMetadataVerifier}/bin/kaiba-rpi5-stable-campaign-provisioner-verify-verity-metadata \
          "$root_hash_tree" \
          "$root_data" \
          "$unsigned_manifest"
        veritysetup verify \
          --format=1 \
          --hash=sha256 \
          --data-block-size=4096 \
          --hash-block-size=4096 \
          "$root_data" \
          "$root_hash_tree" \
          "''${root_integrity_digest#sha256:}" \
          > "$TMPDIR/verity-verification.txt"

        readonly inner_cmdline="$TMPDIR/inner-cmdline.txt"
        readonly inner_integrity="$TMPDIR/inner-integrity.json"
        mcopy -i "$boot_image" '::nixos/default/cmdline.txt' "$inner_cmdline"
        mcopy -i "$boot_image" '::kaiba-root-integrity.json' "$inner_integrity"
        for input in "$inner_cmdline" "$inner_integrity"; do
          test -f "$input"
          test ! -L "$input"
          test -s "$input"
        done
        ${cmdlineVerifier}/bin/kaiba-rpi5-stable-campaign-provisioner-verify-cmdline \
          "$inner_cmdline" \
          "''${root_integrity_digest#sha256:}"

        readonly root_target_policy="$TMPDIR/root-target-policy.json"
        ${rootPolicyVerifier}/bin/kaiba-rpi5-stable-campaign-provisioner-verify-root-policy \
          "$root_data" \
          "$unsigned_manifest" \
          "$inner_cmdline" \
          ${lib.escapeShellArg contract.sourceRevision} \
          "$expected_customer_key_hash" \
          ${expectedRootTargetPolicy} \
          "$root_target_policy"
        root_target_policy_digest="sha256:$(sha256sum "$root_target_policy" | cut -d ' ' -f 1)"

        check-jsonschema --schemafile ${profile.bootIntegritySchema} "$inner_integrity"
        jq -e \
          --arg root_hash "''${root_integrity_digest#sha256:}" \
          '.root_hash == $root_hash
            and .data_device == "/dev/mmcblk0p2"
            and .hash_device == "/dev/mmcblk0p3"' \
          "$inner_integrity" > /dev/null

        public_key_file_digest="sha256:$(sha256sum "$reviewedPublicKeyInput" | cut -d ' ' -f 1)"
        test "$public_key_file_digest" = "$expected_public_key_file_digest"
        openssl rsa -pubin -in "$reviewedPublicKeyInput" -pubout \
          -out "$TMPDIR/canonical-public.pem" 2> "$TMPDIR/openssl-rsa.stderr"
        cmp "$reviewedPublicKeyInput" "$TMPDIR/canonical-public.pem"
        test "$(openssl pkey -pubin -in "$reviewedPublicKeyInput" -text -noout \
          | sed -n '1p')" = 'Public-Key: (2048 bit)'
        openssl pkey -pubin -in "$reviewedPublicKeyInput" -text -noout \
          | grep -Fx 'Exponent: 65537 (0x10001)' > /dev/null
        public_key_fingerprint="sha256:$(openssl pkey -pubin \
          -in "$reviewedPublicKeyInput" -outform DER \
          | sha256sum | cut -d ' ' -f 1)"
        test "$public_key_fingerprint" = "$expected_public_key_fingerprint"

        modulus_hex="$(openssl rsa -pubin -in "$reviewedPublicKeyInput" \
          -modulus -noout 2> "$TMPDIR/openssl-modulus.stderr" | cut -d= -f2)"
        printf '%s\n' "$modulus_hex" | grep -Ex '[0-9A-F]{512}' > /dev/null
        printf '%s' "$modulus_hex" | xxd -r -p | xxd -p -c1 | tac | xxd -r -p \
          > "$TMPDIR/customer-key.bin"
        printf '\001\000\001\000\000\000\000\000' >> "$TMPDIR/customer-key.bin"
        test "$(stat --format=%s "$TMPDIR/customer-key.bin")" -eq 264
        actual_customer_key_hash="sha256:$(sha256sum "$TMPDIR/customer-key.bin" | cut -d ' ' -f 1)"
        test "$actual_customer_key_hash" = "$expected_customer_key_hash"

        mapfile -t signature_lines < "$bootSignatureInput"
        test "''${#signature_lines[@]}" -eq 3
        test "$(tail -c 1 "$bootSignatureInput" | od -An -tx1 | tr -d ' \n')" = 0a
        printf '%s\n' "''${signature_lines[0]}" | grep -Ex '[0-9a-f]{64}' > /dev/null
        printf '%s\n' "''${signature_lines[1]}" \
          | grep -Ex 'ts: (0|[1-9][0-9]{0,19})' > /dev/null
        signature_timestamp="''${signature_lines[1]#ts: }"
        if test "''${#signature_timestamp}" -eq 20 \
          && [[ "$signature_timestamp" > "18446744073709551615" ]]; then
          echo 'boot signature timestamp exceeds canonical uint64 range' >&2
          exit 1
        fi
        printf '%s\n' "''${signature_lines[2]}" \
          | grep -Ex 'rsa2048: [0-9a-f]{512}' > /dev/null
        printf '%s\n%s\n%s\n' \
          "''${signature_lines[0]}" \
          "''${signature_lines[1]}" \
          "''${signature_lines[2]}" \
          > "$TMPDIR/canonical-boot.sig"
        cmp "$bootSignatureInput" "$TMPDIR/canonical-boot.sig"
        boot_image_digest="sha256:$(sha256sum "$boot_image" | cut -d ' ' -f 1)"
        test "''${signature_lines[0]}" = "''${boot_image_digest#sha256:}"
        test "$boot_image_digest" = "$(jq -r .artifacts.boot_image.digest "$unsigned_manifest")"
        printf '%s' "''${signature_lines[2]#rsa2048: }" | xxd -r -p \
          > "$TMPDIR/boot-signature.bin"
        test "$(stat --format=%s "$TMPDIR/boot-signature.bin")" -eq 256
        openssl dgst -sha256 \
          -verify "$reviewedPublicKeyInput" \
          -signature "$TMPDIR/boot-signature.bin" \
          "$boot_image" > "$TMPDIR/signature-verification.txt"
        grep -Fx 'Verified OK' "$TMPDIR/signature-verification.txt" > /dev/null
        boot_signature_digest="sha256:$(sha256sum "$bootSignatureInput" | cut -d ' ' -f 1)"
        boot_signature_size="$(stat --format=%s "$bootSignatureInput")"

        readonly stage="$TMPDIR/outer-fat"
        readonly readback="$TMPDIR/outer-fat-readback"
        mkdir -p "$stage" "$readback" "$out/sd"
        install -m 0444 "$boot_image" "$stage/boot.img"
        install -m 0444 "$bootSignatureInput" "$stage/boot.sig"
        printf '%s\n' 'boot_ramdisk=1' > "$stage/config.txt"
        chmod 0444 "$stage/config.txt"
        touch --date=@315532800 "$stage"/*

        readonly boot_filesystem="$out/sd/boot-filesystem.img"
        truncate --size=${toString profile.bootPartitionSizeBytes} "$boot_filesystem"
        mkfs.vfat \
          --invariant \
          -F 32 \
          -i 4b414942 \
          -n KAIBA_BOOT \
          "$boot_filesystem" > "$TMPDIR/mkfs-vfat.txt"
        mcopy -p -m -i "$boot_filesystem" \
          "$stage/boot.img" \
          "$stage/boot.sig" \
          "$stage/config.txt" \
          ::/
        fsck.fat -vn "$boot_filesystem" > "$TMPDIR/fsck-vfat.txt"

        mcopy -s -i "$boot_filesystem" '::*' "$readback/"
        find "$readback" -type f -printf '%P\n' | LC_ALL=C sort \
          > "$TMPDIR/actual-fat-files"
        printf '%s\n' boot.img boot.sig config.txt > "$TMPDIR/expected-fat-files"
        cmp "$TMPDIR/expected-fat-files" "$TMPDIR/actual-fat-files"
        test -z "$(find "$readback" -type l -print -quit)"
        test -z "$(find "$readback" ! -type d ! -type f -print -quit)"
        while IFS= read -r relative_path; do
          cmp "$stage/$relative_path" "$readback/$relative_path"
        done < "$TMPDIR/expected-fat-files"
        test "$(stat --format=%s "$boot_filesystem")" -eq ${toString profile.bootPartitionSizeBytes}
        chmod 0444 "$boot_filesystem"
        boot_filesystem_digest="sha256:$(sha256sum "$boot_filesystem" | cut -d ' ' -f 1)"

        jq --null-input --compact-output --sort-keys \
          --arg schema ${lib.escapeShellArg signedBootFilesystemSchemaVersion} \
          --arg source_revision ${lib.escapeShellArg contract.sourceRevision} \
          --arg unsigned_schema ${lib.escapeShellArg unsignedSchemaVersion} \
          --arg unsigned_bundle_digest "$unsigned_bundle_digest" \
          --arg expected_customer_key_hash "$expected_customer_key_hash" \
          --arg public_key_file_digest "$public_key_file_digest" \
          --arg public_key_fingerprint "$public_key_fingerprint" \
          --arg disk_guid "$expected_disk_guid" \
          --arg boot_partition_guid "$expected_boot_partition_guid" \
          --arg boot_image_digest "$boot_image_digest" \
          --argjson boot_image_size ${toString profile.bootImageSizeBytes} \
          --arg boot_signature_digest "$boot_signature_digest" \
          --argjson boot_signature_size "$boot_signature_size" \
          --arg signature_timestamp "''${signature_lines[1]}" \
          --arg boot_filesystem_digest "$boot_filesystem_digest" \
          --argjson boot_filesystem_size ${toString profile.bootPartitionSizeBytes} \
          --arg root_target_policy_digest "$root_target_policy_digest" \
          --slurpfile root_target_policy "$root_target_policy" \
          '{
            schema: $schema,
            source_revision: $source_revision,
            unsigned_artifact_set: {
              schema: $unsigned_schema,
              bundle_digest: $unsigned_bundle_digest
            },
            expected_customer_key_hash: $expected_customer_key_hash,
            public_key: {
              file_digest: $public_key_file_digest,
              fingerprint: $public_key_fingerprint,
              customer_key_hash: $expected_customer_key_hash
            },
            root_target_policy: ($root_target_policy[0] + {
              digest: $root_target_policy_digest
            }),
            signature_verification: {
              algorithm: "rsa2048-sha256",
              status: "verified"
            },
            device_binding: {
              profile: "rpi5-sd-mmcblk0-fixed-partitions",
              boot_media: "/dev/mmcblk0",
              disk_guid: $disk_guid,
              boot_partition: 1,
              boot_partition_guid: $boot_partition_guid,
              boot_partition_size_bytes: $boot_filesystem_size
            },
            artifacts: {
              boot_image_signing_input: {
                artifact_role: "signing-input",
                storage_format: "fat-boot-ramdisk-not-partition",
                digest: $boot_image_digest,
                size_bytes: $boot_image_size
              },
              boot_signature: {
                artifact_role: "signature",
                format: "raspberry-pi-three-line-rsa2048",
                digest: $boot_signature_digest,
                size_bytes: $boot_signature_size,
                timestamp: $signature_timestamp
              },
              boot_filesystem: {
                artifact_role: "boot-filesystem-partition-image",
                storage_format: "fat32-filesystem-partition-image",
                path: "sd/boot-filesystem.img",
                digest: $boot_filesystem_digest,
                size_bytes: $boot_filesystem_size
              }
            },
            fat: {
              volume_label: "KAIBA_BOOT",
              volume_id: "4b414942",
              files: ["boot.img", "boot.sig", "config.txt"],
              config_content: "boot_ramdisk=1\n"
            },
            signing_status: "signed-and-verified",
            hardware_observed: false,
            physical_staging_ready: false,
            production_ready: false
          }' > "$TMPDIR/manifest-without-bundle-digest.json"
        canonical_manifest="$(cat "$TMPDIR/manifest-without-bundle-digest.json")"
        signed_bundle_digest="sha256:$({
          printf '%s\0' ${lib.escapeShellArg bundleDigestDomain}
          printf '%s' "$canonical_manifest"
        } | sha256sum | cut -d ' ' -f 1)"
        jq --compact-output --sort-keys \
          --arg bundle_digest "$signed_bundle_digest" \
          '. + {bundle_digest: $bundle_digest}' \
          "$TMPDIR/manifest-without-bundle-digest.json" > "$out/manifest.json"
        check-jsonschema --schemafile ${profile.signedBootFilesystemSchema} "$out/manifest.json"
        chmod 0444 "$out/manifest.json"

        find "$out" -type f -printf '%P\n' | LC_ALL=C sort > "$TMPDIR/actual-output-files"
        printf '%s\n' manifest.json sd/boot-filesystem.img > "$TMPDIR/expected-output-files"
        cmp "$TMPDIR/expected-output-files" "$TMPDIR/actual-output-files"
      '';

  mkRpi5StableCampaignProvisionerSignedBootFilesystem =
    {
      bootSignature,
      name ? "kaiba-rpi5-stable-campaign-provisioner-signed-boot-filesystem",
      unsignedArtifacts,
    }:
    mkForProfile developmentProfile {
      inherit bootSignature name unsignedArtifacts;
      reviewedPublicKeyPEM = developmentProfile.reviewedPublicKeyPEM;
    };
in
{
  inherit mkRpi5StableCampaignProvisionerSignedBootFilesystem;

  # Tests exercise the complete post-sign materializer under a deterministic
  # fixture key. This helper is deliberately not part of the flake's public API.
  _testOnly = {
    inherit
      canonicalCmdlineERE
      canonicalInitArgumentERE
      cmdlineVerifier
      mkExpectedRootTargetPolicy
      mkForProfile
      rootPolicyVerifier
      verityMetadataVerifier
      ;
  };
}
