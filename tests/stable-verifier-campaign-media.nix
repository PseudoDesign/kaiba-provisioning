{
  lib,
  pkgs,
}:

let
  fixturePublicKeyFileSHA256 = "874984cc3d5e7348bffcb4ba0c0b703062510f21a142accfee1a3b2d37d36faa";
  fixturePublicKeyFingerprint = "sha256:56d73a770a7f8f38bbd5aeec970a32d0c94cd257594749469b946d811a0db526";
  fixtureCustomerKeyHash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  fixtureSignerPolicyDigest = "sha256:68498f57aa811b8a714260a4ac4390118c78efdb2af416cc64bfbd8eac4c42e3";
  fixtureSignerReview = pkgs.writeText "kaiba-campaign-media-fixture-signer-review.json" (
    builtins.toJSON {
      schema_version = "kaiba.provisioning.signer-independent-review/v1alpha1";
      status = "passed";
      scope = "development-sacrificial-signer";
      public_bindings = {
        public_key_file_sha256 = fixturePublicKeyFileSHA256;
        public_key_fingerprint = fixturePublicKeyFingerprint;
        customer_key_hash = fixtureCustomerKeyHash;
        signer_policy_digest = fixtureSignerPolicyDigest;
      };
      signing_authorized = false;
      production_approved = false;
    }
  );
  campaignMediaBuilder = import ../nix/stable-verifier-campaign-media.nix {
    inherit lib pkgs;
    signerIndependentReview = fixtureSignerReview;
    expectedCustomerKeyHash = fixtureCustomerKeyHash;
    expectedPublicKeyFileSHA256 = fixturePublicKeyFileSHA256;
    expectedPublicKeyFingerprint = fixturePublicKeyFingerprint;
  };
  built = import ../nix/packages.nix { inherit lib pkgs; };
  stableVerifierSpikeBuilders = import ../nix/stable-verifier-spike.nix {
    inherit lib pkgs;
    rpi5KexecInputValidator = pkgs.writeShellScriptBin "kaiba-rpi5-kexec-input-validate" ''
      set -euo pipefail
      test "$#" -eq 4
      test "$1" = --device-tree
      test "$3" = --command-line
      test -s "$2"
      test -s "$4"
    '';
  };

  rootDataPartitionGUID = "d6f72f33-10c8-4f0c-8c4d-cba239f106bb";
  rootHashPartitionGUID = "a84e3cc9-44f7-4ad4-b427-5bc16aec4bfe";
  dataDevice = "PARTUUID=${rootDataPartitionGUID}";
  hashDevice = "PARTUUID=${rootHashPartitionGUID}";
  sourceRevision = "1111111111111111111111111111111111111111";
  releaseAllowlist = [
    "cmdline.txt"
    "device-tree.dtb"
    "dm-verity.json"
    "initramfs"
    "kernel"
    "overlays/campaign.dtbo"
    "release-manifest.json"
    "root.img"
    "slot.txt"
  ];
  releaseAllowlistFile = pkgs.writeText "kaiba-campaign-media-test-release-allowlist" (
    lib.concatStringsSep "\n" releaseAllowlist + "\n"
  );

  verifierTrustFixture = import ./stable-verifier-vm-fixture.nix {
    inherit pkgs;
    source = ../.;
  };
  fixtureSigningKey =
    pkgs.runCommand "kaiba-campaign-media-signing-public-key"
      {
        nativeBuildInputs = [
          pkgs.openssl
          pkgs.python3
        ];
      }
      ''
        set -euo pipefail
        mkdir "$out"
        python3 ${./deterministic-rsa-fixture.py} \
          --label stable-verifier-campaign-media-test \
          --private "$TMPDIR/private.pem"
        openssl rsa -in "$TMPDIR/private.pem" -pubout \
          -out "$out/public.pem" 2>/dev/null
        chmod 0444 "$out/public.pem"
      '';
  fixturePublicKey = "${fixtureSigningKey}/public.pem";
  verifierBootImage =
    pkgs.runCommand "kaiba-campaign-media-signed-verifier-boot.img"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.dosfstools
          pkgs.mtools
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        truncate --size=32M "$out"
        mkfs.vfat --invariant -F 32 -i 4b435442 -n KAIBA_TEST "$out" > /dev/null
        mmd -i "$out" ::/kaiba
        mcopy -p -m -i "$out" \
          ${verifierTrustFixture}/policy.json \
          ::/kaiba/stable-verifier-policy.json
        mcopy -p -m -i "$out" \
          ${verifierTrustFixture}/root-public.pem \
          ::/kaiba/root-public.pem
        mcopy -p -m -i "$out" \
          ${verifierTrustFixture}/authority-ca.pem \
          ::/kaiba/authority-ca.pem
        chmod 0444 "$out"
      '';
  fixtureReleaseIntent =
    pkgs.runCommand "kaiba-campaign-media-fixture-release-intent"
      {
        bootInput = verifierBootImage;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        mkdir "$out"
        boot_digest="sha256:$(sha256sum "$bootInput" | cut -d ' ' -f 1)"
        boot_size="$(stat --format=%s "$bootInput")"
        jq -cn \
          --arg boot_digest "$boot_digest" \
          --argjson boot_size "$boot_size" \
          --arg public_key_fingerprint '${fixturePublicKeyFingerprint}' \
          --arg signer_policy_digest '${fixtureSignerPolicyDigest}' \
          --arg expected_customer_key_hash '${fixtureCustomerKeyHash}' \
          '{
            schema_version: "kaiba.provisioning.rpi5-release-intent/v1alpha1",
            release_id: "release:rpi5-campaign-media-fixture:1",
            device_class: "raspberry-pi-5-model-b-v1alpha1",
            source_revision: "1111111111111111111111111111111111111111",
            source_date_epoch: 1786968000,
            unsigned_artifact_set_digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            eeprom_release_manifest_digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            public_key_fingerprint: $public_key_fingerprint,
            signing_policy_digest: $signer_policy_digest,
            expected_customer_key_hash: $expected_customer_key_hash,
            authorization_scope: "cohort_release",
            signing_inputs: [
              {role: "rpi5.boot_image", digest: $boot_digest, size_bytes: $boot_size},
              {role: "rpi5.eeprom_bootcode", digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333", size_bytes: 1},
              {role: "rpi5.eeprom_bootsys", digest: "sha256:4444444444444444444444444444444444444444444444444444444444444444", size_bytes: 1},
              {role: "rpi5.eeprom_config", digest: "sha256:5555555555555555555555555555555555555555555555555555555555555555", size_bytes: 1},
              {role: "rpi5.owned_recovery_bootcode", digest: "sha256:6666666666666666666666666666666666666666666666666666666666666666", size_bytes: 1}
            ],
            required_output_roles: [
              "boot_public_key",
              "device_profile",
              "platform_adapter",
              "root_integrity",
              "rpi5.boot_image",
              "rpi5.boot_signature",
              "rpi5.eeprom_bootsys",
              "rpi5.eeprom_config",
              "rpi5.fresh_commit_bundle",
              "rpi5.fresh_readback_bundle",
              "rpi5.negative_boot_bundle",
              "rpi5.owned_readback_bundle",
              "rpi5.owned_recovery_bootcode",
              "rpi5.owned_recovery_bundle",
              "rpi5.root_data_image",
              "rpi5.root_hash_tree_image",
              "rpi5.root_integrity_test_bundle",
              "rpi5.signed_eeprom_image"
            ]
          }' > "$out/release-intent.json"
        chmod 0444 "$out/release-intent.json"
      '';
  verifierSigningPlan = built.mkRpi5BootSigningPlan {
    name = "kaiba-campaign-media-fixture-boot-signing-plan";
    bootImage = verifierBootImage;
    planID = "plan:rpi5-campaign-media-fixture:1";
    publicKeyFingerprint = fixturePublicKeyFingerprint;
    releaseIntent = fixtureReleaseIntent;
    reviewedPublicKeyPEM = fixturePublicKey;
    signerPolicyDigest = fixtureSignerPolicyDigest;
    sourceDateEpoch = 1786968000;
  };
  verifierSignedOutput =
    pkgs.runCommand "kaiba-campaign-media-fixture-signed-output"
      {
        signingPlanInput = verifierSigningPlan;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
          pkgs.openssl
          pkgs.python3
          pkgs.xxd
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        mkdir "$out"
        python3 ${./deterministic-rsa-fixture.py} \
          --label stable-verifier-campaign-media-test \
          --private "$TMPDIR/private.pem"
        image_digest="$(sha256sum ${verifierBootImage} | cut -d ' ' -f 1)"
        openssl dgst -sha256 -sign "$TMPDIR/private.pem" \
          -out "$TMPDIR/signature.bin" ${verifierBootImage}
        signature_hex="$(xxd -p -c 4096 "$TMPDIR/signature.bin")"
        test "''${#signature_hex}" -eq 512
        printf '%s\n' \
          "$image_digest" \
          'ts: 1786968000' \
          "rsa2048: $signature_hex" \
          > "$out/boot.sig"
        chmod 0444 "$out/boot.sig"
        plan_json="$(cat "$signingPlanInput/plan.json")"
        plan_digest="sha256:$({
          printf '%s\0' 'kaiba.provisioning.rpi5-boot-signing-plan.v1alpha2'
          printf '%s' "$plan_json"
        } | sha256sum | cut -d ' ' -f 1)"
        jq -cn \
          --argjson plan "$plan_json" \
          --arg plan_digest "$plan_digest" \
          --arg boot_signature_digest "sha256:$(sha256sum "$out/boot.sig" | cut -d ' ' -f 1)" \
          --argjson boot_signature_size "$(stat --format=%s "$out/boot.sig")" \
          '{
            schema_version: "kaiba.provisioning.rpi5-boot-signing-result/v1alpha2",
            plan_id: $plan.plan_id,
            plan_digest: $plan_digest,
            release_intent_digest: $plan.release_intent_digest,
            boot_image_digest: $plan.boot_image_digest,
            boot_image_size_bytes: $plan.boot_image_size_bytes,
            boot_signature_digest: $boot_signature_digest,
            boot_signature_size_bytes: $boot_signature_size,
            public_key_fingerprint: $plan.public_key_fingerprint,
            signer_policy_digest: $plan.signer_policy_digest,
            gate_receipt_digest: "sha256:7777777777777777777777777777777777777777777777777777777777777777",
            source_date_epoch: $plan.source_date_epoch
          }' > "$out/signing-result.json"
        chmod 0444 "$out/signing-result.json"
      '';
  verifiedSignedBoot = built.mkRpi5VerifiedSignedBoot {
    name = "kaiba-campaign-media-fixture-verified-signed-boot";
    signingPlan = verifierSigningPlan;
    signedOutput = verifierSignedOutput;
  };

  rootImage = pkgs.runCommand "kaiba-campaign-media-test-root.img" { } ''
    set -euo pipefail
    truncate --size=8M "$out"
    printf '%s\n' 'kaiba stable-verifier campaign root fixture' \
      | dd of="$out" conv=notrunc status=none
    chmod 0444 "$out"
  '';
  fixtureRootHashTree =
    pkgs.runCommand "kaiba-campaign-media-test-root-hash.img"
      {
        rootImageInput = rootImage;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.cryptsetup
        ];
      }
      ''
        set -euo pipefail
        root_digest="$(sha256sum "$rootImageInput" | cut -d ' ' -f 1)"
        verity_uuid="''${root_digest:0:8}-''${root_digest:8:4}-''${root_digest:12:4}-''${root_digest:16:4}-''${root_digest:20:12}"
        : > "$out"
        veritysetup format \
          --hash=sha256 \
          --data-block-size=4096 \
          --hash-block-size=4096 \
          --salt="$root_digest" \
          --uuid="$verity_uuid" \
          "$rootImageInput" \
          "$out" > /dev/null
        chmod 0444 "$out"
      '';

  mkReleaseTree =
    {
      name,
      kernelMutation ? "",
      manifestMutation ? "",
    }:
    pkgs.runCommand name
      {
        rootImageInput = rootImage;
        verifierTrustFixtureInput = verifierTrustFixture;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.cryptsetup
          pkgs.jq
        ];
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        export TZ=UTC
        umask 022

        mkdir -p "$out/overlays"
        cp --reflink=auto --sparse=always "$rootImageInput" "$out/root.img"
        root_digest="$(sha256sum "$out/root.img" | cut -d ' ' -f 1)"
        verity_uuid="''${root_digest:0:8}-''${root_digest:8:4}-''${root_digest:12:4}-''${root_digest:16:4}-''${root_digest:20:12}"
        : > "$TMPDIR/root-hash.img"
        veritysetup format \
          --hash=sha256 \
          --data-block-size=4096 \
          --hash-block-size=4096 \
          --salt="$root_digest" \
          --uuid="$verity_uuid" \
          --root-hash-file="$TMPDIR/root-hash" \
          "$out/root.img" \
          "$TMPDIR/root-hash.img" \
          > "$TMPDIR/verity-format.txt"
        root_hash="$(tr -d '\n' < "$TMPDIR/root-hash")"

        printf '%s\n' \
          "console=ttyAMA10,115200n8 earlycon=pl011,0x107d001000,115200n8 ro root=fstab rd.systemd.verity=1 roothash=$root_hash systemd.verity_root_data=${dataDevice} systemd.verity_root_hash=${hashDevice}" \
          > "$out/cmdline.txt"
        jq -nS \
          --arg root_hash "$root_hash" \
          --arg data_device '${dataDevice}' \
          --arg hash_device '${hashDevice}' \
          '{
            schema: "provisioning.kaiba.network/rpi5-boot-integrity/v1alpha1",
            algorithm: "sha256",
            data_block_size: 4096,
            hash_block_size: 4096,
            no_superblock: false,
            root_hash: $root_hash,
            data_device: $data_device,
            hash_device: $hash_device
          }' > "$out/dm-verity.json"
        printf '%s\n' 'fixture resolved Raspberry Pi 5 device tree' > "$out/device-tree.dtb"
        printf '%s\n' 'fixture released initramfs' > "$out/initramfs"
        printf '%s\n' 'fixture released kernel' > "$out/kernel"
        ${kernelMutation}
        printf '%s\n' 'fixture campaign overlay' > "$out/overlays/campaign.dtbo"
        printf '%s\n' a > "$out/slot.txt"

        digest() {
          printf 'sha256:%s' "$(sha256sum "$1" | cut -d ' ' -f 1)"
        }
        size() {
          stat --format=%s "$1"
        }
        dummy_signature="$(head --bytes=256 /dev/zero | base64 --wrap=0)"
        policy_digest="$(jq -er .policy_digest "$verifierTrustFixtureInput/fixture.json")"
        jq -cn \
          --arg kernel_digest "$(digest "$out/kernel")" \
          --argjson kernel_size "$(size "$out/kernel")" \
          --arg initramfs_digest "$(digest "$out/initramfs")" \
          --argjson initramfs_size "$(size "$out/initramfs")" \
          --arg device_tree_digest "$(digest "$out/device-tree.dtb")" \
          --argjson device_tree_size "$(size "$out/device-tree.dtb")" \
          --arg command_line_digest "$(digest "$out/cmdline.txt")" \
          --argjson command_line_size "$(size "$out/cmdline.txt")" \
          --arg root_image_digest "$(digest "$out/root.img")" \
          --argjson root_image_size "$(size "$out/root.img")" \
          --arg dm_verity_digest "$(digest "$out/dm-verity.json")" \
          --argjson dm_verity_size "$(size "$out/dm-verity.json")" \
          --arg slot_digest "$(digest "$out/slot.txt")" \
          --argjson slot_size "$(size "$out/slot.txt")" \
          --arg overlay_digest "$(digest "$out/overlays/campaign.dtbo")" \
          --argjson overlay_size "$(size "$out/overlays/campaign.dtbo")" \
          --arg signature "$dummy_signature" \
          --arg policy_digest "$policy_digest" \
          '{
            schema_version: "kaiba.provisioning.rpi5-delegated-release-manifest/v1alpha1",
            release_id: "campaign-media-fixture",
            device_class: "raspberry-pi-5-model-b-v1alpha1",
            cohort_id: "development",
            policy_digest: $policy_digest,
            security_epoch: 1,
            slot_id: "a",
            components: [
              {role: "kernel", digest: $kernel_digest, size_bytes: $kernel_size},
              {role: "initramfs", digest: $initramfs_digest, size_bytes: $initramfs_size},
              {role: "resolved_device_tree", digest: $device_tree_digest, size_bytes: $device_tree_size},
              {role: "kernel_command_line", digest: $command_line_digest, size_bytes: $command_line_size},
              {role: "root_image", digest: $root_image_digest, size_bytes: $root_image_size},
              {role: "dm_verity_metadata", digest: $dm_verity_digest, size_bytes: $dm_verity_size},
              {role: "slot_metadata", digest: $slot_digest, size_bytes: $slot_size}
            ],
            overlays: [
              {name: "campaign", digest: $overlay_digest, size_bytes: $overlay_size}
            ],
            signatures: [
              {key_id: "fixture-delegated", algorithm: "rsa-2048-sha256-pkcs1v15", value: $signature}
            ]
          }' > "$out/release-manifest.json"
        ${manifestMutation}

        find "$out" -type d -exec chmod 0555 '{}' +
        find "$out" -type f -exec chmod 0444 '{}' +
        find "$out" -exec touch --date=@315532800 '{}' +
      '';
  releaseTree = mkReleaseTree {
    name = "kaiba-campaign-media-test-release-tree";
  };
  delegatedRelease = stableVerifierSpikeBuilders.mkRpi5DelegatedReleaseSpike {
    inherit releaseAllowlist releaseTree sourceRevision;
    releaseID = "campaign-media-fixture";
    name = "kaiba-campaign-media-test-delegated-release";
  };

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
  campaignMutationProgram = pkgs.writeText "kaiba-campaign-mutation-input-fixture.py" ''
    import base64
    import copy
    import json
    import pathlib
    import sys

    positive_path = pathlib.Path(sys.argv[1])
    output = pathlib.Path(sys.argv[2])
    positive = json.loads(positive_path.read_bytes())
    output.mkdir()

    mutations = {
        "cohort-id": (["cohort_id"], "other-development"),
        "component-digest": (["components", 0, "digest"], "sha256:" + "c" * 64),
        "component-role": (["components", 0, "role"], "unknown_component"),
        "component-size-bytes": (["components", 0, "size_bytes"], positive["components"][0]["size_bytes"] + 1),
        "device-class": (["device_class"], "raspberry-pi-4-model-b-v1alpha1"),
        "overlay-digest": (["overlays", 0, "digest"], "sha256:" + "d" * 64),
        "overlay-name": (["overlays", 0, "name"], "other-campaign"),
        "overlay-size-bytes": (["overlays", 0, "size_bytes"], positive["overlays"][0]["size_bytes"] + 1),
        "policy-digest": (["policy_digest"], "sha256:" + "b" * 64),
        "release-id": (["release_id"], "campaign-media-field-fixture"),
        "schema-version": (["schema_version"], "kaiba.provisioning.rpi5-delegated-release-manifest/v1alpha0"),
        "security-epoch": (["security_epoch"], positive["security_epoch"] + 1),
        "signature-algorithm": (["signatures", 0, "algorithm"], "rsa-2048-sha512-pkcs1v15"),
        "signature-key-id": (["signatures", 0, "key_id"], "fixture-field-key"),
        "signature-value": (["signatures", 0, "value"], base64.b64encode(b"\x01" * 256).decode()),
        "slot-id": (["slot_id"], "b"),
    }

    def changed(path, value):
        result = copy.deepcopy(positive)
        target = result
        for element in path[:-1]:
            target = target[element]
        target[path[-1]] = value
        return result

    outputs = {
        "manifest-field-" + name: changed(path, value)
        for name, (path, value) in mutations.items()
    }
    outputs["replacement-release-manifest"] = changed(
        ["signatures", 0, "key_id"], "fixture-delegated-replacement"
    )
    outputs["revoked-release-manifest"] = changed(
        ["signatures", 0, "key_id"], "fixture-revoked"
    )
    outputs["unsigned-release-manifest"] = changed(["signatures"], [])
    outputs["wrong-key-release-manifest"] = changed(
        ["signatures", 0, "key_id"], "fixture-wrong"
    )

    expected = ${builtins.toJSON campaignMutationInputNames}
    if sorted(outputs) != expected:
        raise SystemExit("mutation fixture does not cover the exact required input names")
    encoded_positive = positive_path.read_bytes()
    digests = set()
    for name in expected:
        encoded = json.dumps(outputs[name], separators=(",", ":")).encode()
        if encoded == encoded_positive:
            raise SystemExit(f"mutation input {name} does not change the positive manifest")
        digest = __import__("hashlib").sha256(encoded).digest()
        if digest in digests:
            raise SystemExit(f"mutation input {name} duplicates another mutation")
        digests.add(digest)
        (output / (name + ".json")).write_bytes(encoded)
  '';
  campaignMutationInputsRaw =
    pkgs.runCommand "kaiba-campaign-media-mutation-inputs"
      {
        positiveManifestInput = "${delegatedRelease}/nvme-release/release-manifest.json";
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        set -euo pipefail
        python3 ${campaignMutationProgram} "$positiveManifestInput" "$out"
        find "$out" -type f -exec chmod 0444 '{}' +
        find "$out" -type d -exec chmod 0555 '{}' +
      '';
  campaignMutationInputs = campaignMutationInputsRaw.overrideAttrs (previous: {
    passthru = (previous.passthru or { }) // {
      kaibaRpi5StableVerifierCampaignMutationInputs = {
        artifactSchemaVersion = "kaiba.provisioning.rpi5-stable-verifier-campaign-mutation-inputs/v1alpha1";
        inherit campaignMutationInputNames;
        inputNames = campaignMutationInputNames;
        blockDeviceWriteCapable = false;
        directHardwareAccess = false;
        hardwareObserved = false;
        privateKeyAccess = false;
        productionReady = false;
        signingAuthorityConfigured = false;
        storageFormat = "named-public-file-set";
      };
    };
  });

  campaignPlanProgram = pkgs.writeText "kaiba-campaign-media-plan-fixture.py" ''
    import hashlib
    import json
    import os
    import pathlib
    import sys

    signed_boot = pathlib.Path(sys.argv[1])
    release_tree = pathlib.Path(sys.argv[2])
    verifier_trust = pathlib.Path(sys.argv[3])
    mutation_inputs = pathlib.Path(sys.argv[4])
    root_hash_tree = pathlib.Path(sys.argv[5])
    output = pathlib.Path(sys.argv[6])
    campaign_id = sys.argv[7]

    def binding(name, path=None, digest=None, size=None):
        if path is not None:
            payload = pathlib.Path(path).read_bytes()
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            size = len(payload)
        return {"name": name, "digest": digest, "size_bytes": size}

    paths = [
        "cmdline.txt", "device-tree.dtb", "dm-verity.json", "initramfs", "kernel",
        "overlays/campaign.dtbo", "release-manifest.json", "root.img", "slot.txt",
    ]
    release_records = []
    for relative in paths:
        payload = (release_tree / relative).read_bytes()
        release_records.append({
            "path": relative,
            "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
        })
    encoded_records = json.dumps(release_records, separators=(",", ":"), sort_keys=True).encode()
    tree_hash = hashlib.sha256()
    tree_hash.update(b"kaiba.provisioning.rpi5-stable-verifier-campaign-release-tree.v1alpha1\0")
    tree_hash.update(encoded_records)
    tree_material = b"kaiba.provisioning.rpi5-stable-verifier-campaign-release-tree.v1alpha1\0" + encoded_records
    tree_digest = "sha256:" + hashlib.sha256(tree_material).hexdigest()
    tree_size = len(tree_material)

    manifest_fields = [
        "schema-version", "release-id", "device-class", "cohort-id", "policy-digest",
        "security-epoch", "slot-id", "component-role", "component-digest",
        "component-size-bytes", "overlay-name", "overlay-digest", "overlay-size-bytes",
        "signature-key-id", "signature-algorithm", "signature-value",
    ]
    public_names = [
        "authorization-trust-anchor", "customer-boot-public-key", "positive-release-manifest",
        "positive-release-tree", "release-policy-root-public-key", "stable-verifier-policy",
        "unsigned-verifier-boot", "replacement-release-manifest",
        *["manifest-field-" + field for field in manifest_fields],
        "revoked-release-manifest", "unsigned-release-manifest", "wrong-key-release-manifest",
    ]
    public_names.sort()
    public_paths = {
        "authorization-trust-anchor": verifier_trust / "authority-ca.pem",
        "customer-boot-public-key": signed_boot / "public.pem",
        "positive-release-manifest": release_tree / "release-manifest.json",
        "release-policy-root-public-key": verifier_trust / "root-public.pem",
        "stable-verifier-policy": verifier_trust / "policy.json",
        "unsigned-verifier-boot": signed_boot / "boot.img",
        **{
            name: mutation_inputs / (name + ".json")
            for name in ${builtins.toJSON campaignMutationInputNames}
        },
    }
    public_inputs = [
        binding(name, public_paths[name])
        if name != "positive-release-tree"
        else binding(name, digest=tree_digest, size=tree_size)
        for name in public_names
    ]
    by_name = {record["name"]: record for record in public_inputs}

    safety = {
        "classification": "development-only",
        "private_material_embedded_in_contract": False,
        "production_ready": False,
        "signing_authorized": False,
        "device_writes_authorized": False,
    }
    cases = [
        ("approved-release-boots", ["positive-baseline"]),
        ("authorization-offline-rejected", ["authority-offline"]),
        ("authorization-replay-rejected", ["stale-authorization"]),
        ("component-byte-mutations-rejected", ["kernel", "initramfs", "resolved-device-tree", "kernel-command-line", "root-image", "dm-verity-metadata", "slot-metadata", "overlay"]),
        ("delegated-key-replacement-boots", ["replacement-manifest"]),
        ("dm-verity-corruption-rejected", ["root-data", "root-hash"]),
        ("kernel-command-line-observed", ["positive-baseline"]),
        ("manifest-field-mutations-rejected", manifest_fields),
        ("one-boot-key-bound", ["positive-baseline"]),
        ("released-os-bootstrap-reuse-rejected", ["positive-baseline"]),
        ("resolved-device-tree-observed", ["positive-baseline"]),
        ("revoked-delegated-key-rejected", ["revoked-manifest"]),
        ("unsigned-release-rejected", ["unsigned-manifest"]),
        ("wrong-delegated-key-rejected", ["wrong-key-manifest"]),
    ]

    byte_subcases = [
        ("component-byte-mutations-rejected", subcase)
        for subcase in cases[3][1]
    ] + [
        ("dm-verity-corruption-rejected", subcase)
        for subcase in cases[5][1]
    ]
    byte_subcases.sort(key=lambda pair: pair[0] + ":" + pair[1])
    targets = {
        "kernel": "release/kernel",
        "initramfs": "release/initramfs",
        "resolved-device-tree": "release/device-tree.dtb",
        "kernel-command-line": "release/cmdline.txt",
        "root-image": "release/root.img",
        "dm-verity-metadata": "release/dm-verity.json",
        "slot-metadata": "release/slot.txt",
        "overlay": "release/overlays/campaign.dtbo",
        "root-data": "media/root-data",
        "root-hash": "media/root-hash",
    }
    byte_recipes = []
    target_paths = {
        "release/kernel": release_tree / "kernel",
        "release/initramfs": release_tree / "initramfs",
        "release/device-tree.dtb": release_tree / "device-tree.dtb",
        "release/cmdline.txt": release_tree / "cmdline.txt",
        "release/root.img": release_tree / "root.img",
        "release/dm-verity.json": release_tree / "dm-verity.json",
        "release/slot.txt": release_tree / "slot.txt",
        "release/overlays/campaign.dtbo": release_tree / "overlays/campaign.dtbo",
        "media/root-data": release_tree / "root.img",
        "media/root-hash": root_hash_tree,
    }
    for index, (test_id, subcase) in enumerate(byte_subcases):
        name = test_id + "-" + subcase
        target_bytes = target_paths[targets[subcase]].read_bytes()
        mutated = bytes([target_bytes[0] ^ 1]) + target_bytes[1:]
        before = binding(name, digest="sha256:" + hashlib.sha256(target_bytes).hexdigest(), size=len(target_bytes))
        after = binding(name, digest="sha256:" + hashlib.sha256(mutated).hexdigest(), size=len(mutated))
        byte_recipes.append({
            "schema_version": "kaiba.provisioning.rpi5-stable-verifier-byte-xor-recipe/v1alpha1",
            "recipe_id": test_id + ":" + subcase,
            "test_id": test_id,
            "subcase_id": subcase,
            "safety_boundary": dict(safety),
            "target": targets[subcase],
            "before": before,
            "after": after,
            "offset_bytes": 0,
            "xor_mask": 1,
        })

    replacement_pairs = [
        ("delegated-key-replacement-boots", "replacement-manifest"),
        *[("manifest-field-mutations-rejected", field) for field in manifest_fields],
        ("revoked-delegated-key-rejected", "revoked-manifest"),
        ("unsigned-release-rejected", "unsigned-manifest"),
        ("wrong-delegated-key-rejected", "wrong-key-manifest"),
    ]
    replacement_pairs.sort(key=lambda pair: pair[0] + ":" + pair[1])
    selectors = {
        "schema-version": "/schema_version", "release-id": "/release_id",
        "device-class": "/device_class", "cohort-id": "/cohort_id",
        "policy-digest": "/policy_digest", "security-epoch": "/security_epoch",
        "slot-id": "/slot_id", "component-role": "/components/0/role",
        "component-digest": "/components/0/digest",
        "component-size-bytes": "/components/0/size_bytes",
        "overlay-name": "/overlays/0/name", "overlay-digest": "/overlays/0/digest",
        "overlay-size-bytes": "/overlays/0/size_bytes",
        "signature-key-id": "/signatures/0/key_id",
        "signature-algorithm": "/signatures/0/algorithm",
        "signature-value": "/signatures/0/value",
    }
    whole_inputs = {
        "delegated-key-replacement-boots": "replacement-release-manifest",
        "revoked-delegated-key-rejected": "revoked-release-manifest",
        "unsigned-release-rejected": "unsigned-release-manifest",
        "wrong-delegated-key-rejected": "wrong-key-release-manifest",
    }
    replacement_recipes = []
    for test_id, subcase in replacement_pairs:
        input_name = "manifest-field-" + subcase if test_id == "manifest-field-mutations-rejected" else whole_inputs[test_id]
        replacement_recipes.append({
            "schema_version": "kaiba.provisioning.rpi5-stable-verifier-bound-replacement-recipe/v1alpha1",
            "recipe_id": test_id + ":" + subcase,
            "test_id": test_id,
            "subcase_id": subcase,
            "safety_boundary": dict(safety),
            "target": "release/release-manifest.json",
            "before": dict(by_name["positive-release-manifest"]),
            "after": dict(by_name[input_name]),
            "replacement_input": input_name,
            "difference_selector": selectors[subcase] if test_id == "manifest-field-mutations-rejected" else "$",
        })

    plan = {
        "schema_version": "kaiba.provisioning.rpi5-stable-verifier-campaign-plan/v1alpha1",
        "campaign_id": campaign_id,
        "campaign_profile": "kaiba.provisioning.rpi5-stable-verifier-campaign/v1alpha1",
        "device_class": "raspberry-pi-5-model-b-v1alpha1",
        "safety_boundary": safety,
        "public_inputs": public_inputs,
        "cases": [{"test_id": test_id, "subcases": subcases} for test_id, subcases in cases],
        "byte_xor_mutations": byte_recipes,
        "bound_replacements": replacement_recipes,
        "plan_digest": "",
    }
    material = json.dumps(plan, separators=(",", ":")).encode()
    digest = hashlib.sha256()
    digest.update(b"kaiba.provisioning.rpi5-stable-verifier-campaign-plan.v1alpha1\0")
    digest.update(material)
    plan["plan_digest"] = "sha256:" + digest.hexdigest()
    output.write_bytes(json.dumps(plan, separators=(",", ":")).encode())
  '';
  mkCampaignPlan =
    {
      name,
      signedBoot ? verifiedSignedBoot,
      release ? delegatedRelease,
      campaignID ? "campaign-media-fixture",
    }:
    pkgs.runCommand name
      {
        signedBootInput = signedBoot;
        delegatedReleaseInput = release;
        mutationInputsInput = campaignMutationInputs;
        rootHashTreeInput = fixtureRootHashTree;
        verifierTrustInput = verifierTrustFixture;
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        set -euo pipefail
        python3 ${campaignPlanProgram} \
          "$signedBootInput" \
          "$delegatedReleaseInput/nvme-release" \
          "$verifierTrustInput" \
          "$mutationInputsInput" \
          "$rootHashTreeInput" \
          "$out" \
          '${campaignID}'
        chmod 0444 "$out"
      '';
  campaignPlan = mkCampaignPlan {
    name = "kaiba-campaign-media-fixture-plan";
  };

  mkCampaignMedia =
    name:
    campaignMediaBuilder {
      inherit
        campaignPlan
        campaignMutationInputs
        delegatedRelease
        name
        rootDataPartitionGUID
        rootHashPartitionGUID
        verifiedSignedBoot
        ;
      bootFilesystemSizeMiB = 112;
    };
  campaignMediaA = mkCampaignMedia "kaiba-campaign-media-test-a";
  campaignMediaB = mkCampaignMedia "kaiba-campaign-media-test-b";
  contract = campaignMediaA.kaibaRpi5StableVerifierCampaignMedia;

  mkRawTamperedRelease =
    name: mutation:
    pkgs.runCommand name
      {
        releaseTreeInput = "${delegatedRelease}/nvme-release";
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
          pkgs.gnused
        ];
      }
      ''
        set -euo pipefail
        cp -R --no-preserve=ownership "$releaseTreeInput" "$out"
        find "$out" -type d -exec chmod 0755 '{}' +
        find "$out" -type f -exec chmod 0644 '{}' +
        ${mutation}
        find "$out" -type d -exec chmod 0555 '{}' +
        find "$out" -type f -exec chmod 0444 '{}' +
      '';
  wrongMetadataRelease = mkRawTamperedRelease "kaiba-campaign-media-wrong-metadata" ''
    jq '.root_hash = "0000000000000000000000000000000000000000000000000000000000000000"' \
      "$out/dm-verity.json" > "$TMPDIR/dm-verity.json"
    mv "$TMPDIR/dm-verity.json" "$out/dm-verity.json"
  '';
  wrongCommandLineRelease = mkRawTamperedRelease "kaiba-campaign-media-wrong-command-line" ''
    sed -i \
      's/${dataDevice}/PARTUUID=11111111-2222-4333-8444-555555555555/' \
      "$out/cmdline.txt"
  '';
  privatePEMRelease = mkRawTamperedRelease "kaiba-campaign-media-private-pem-marker" ''
    printf '%s\n' '-----BEGIN PRIVATE KEY-----' 'fixture-only' > "$out/kernel"
  '';

  mismatchedReleaseTree = mkReleaseTree {
    name = "kaiba-campaign-media-component-mismatch-tree";
    manifestMutation = ''
      printf X | dd of="$out/kernel" bs=1 seek=0 count=1 conv=notrunc status=none
    '';
  };
  mismatchedDelegatedRelease = stableVerifierSpikeBuilders.mkRpi5DelegatedReleaseSpike {
    inherit releaseAllowlist sourceRevision;
    releaseTree = mismatchedReleaseTree;
    releaseID = "campaign-media-fixture";
    name = "kaiba-campaign-media-component-mismatch-delegated-release";
  };
  wrapperReleaseIDMismatch = stableVerifierSpikeBuilders.mkRpi5DelegatedReleaseSpike {
    inherit releaseAllowlist releaseTree sourceRevision;
    releaseID = "campaign-media-wrapper-mismatch";
    name = "kaiba-campaign-media-wrapper-release-id-mismatch";
  };
  duplicateWrapperRelease =
    pkgs.runCommand "kaiba-campaign-media-duplicate-wrapper-field"
      { delegatedReleaseInput = delegatedRelease; }
      ''
        set -euo pipefail
        cp -R --no-preserve=ownership "$delegatedReleaseInput" "$out"
        chmod u+w "$out/manifest.json"
        sed '1s/{/{"release_id":"campaign-media-fixture",/' \
          "$delegatedReleaseInput/manifest.json" > "$out/manifest.json"
        chmod 0444 "$out/manifest.json"
      '';

  derReleaseTree = mkReleaseTree {
    name = "kaiba-campaign-media-der-marker-bypass-tree";
    kernelMutation = ''
      # This is a syntactically binary DER-like fixture with no PEM marker.
      printf '\060\202\001\042\002\001\000\060\015\006\011\052\206\110\206\367\015\001\001\001' \
        > "$out/kernel"
    '';
  };
  derDelegatedRelease = stableVerifierSpikeBuilders.mkRpi5DelegatedReleaseSpike {
    inherit releaseAllowlist sourceRevision;
    releaseTree = derReleaseTree;
    releaseID = "campaign-media-fixture";
    name = "kaiba-campaign-media-der-marker-bypass-delegated-release";
  };
  derCampaignPlan = mkCampaignPlan {
    name = "kaiba-campaign-media-der-marker-bypass-plan";
    release = derDelegatedRelease;
    campaignID = "campaign-media-der-fixture";
  };

  differentBootBinding = pkgs.runCommand "kaiba-campaign-media-different-boot-binding" { } ''
    mkdir "$out"
    printf '%s\n' 'different old verifier boot' > "$out/boot.img"
    cp ${verifiedSignedBoot}/public.pem "$out/public.pem"
  '';
  oldBootCampaignPlan = mkCampaignPlan {
    name = "kaiba-campaign-media-old-boot-plan";
    signedBoot = differentBootBinding;
    campaignID = "campaign-media-old-boot-fixture";
  };
  tamperedCampaignPlan = pkgs.runCommand "kaiba-campaign-media-tampered-plan" { } ''
    sed 's/campaign-media-fixture/campaign-media-tampered/' ${campaignPlan} > "$out"
  '';

  wrongPublicKey =
    pkgs.runCommand "kaiba-campaign-media-wrong-public-key"
      {
        nativeBuildInputs = [
          pkgs.openssl
          pkgs.python3
        ];
      }
      ''
        python3 ${./deterministic-rsa-fixture.py} \
          --label campaign-media-wrong-key \
          --private "$TMPDIR/private.pem"
        openssl rsa -in "$TMPDIR/private.pem" -pubout -out "$out" 2>/dev/null
      '';
  wrongKeySignedBootRaw =
    pkgs.runCommand "kaiba-campaign-media-wrong-key-signed-boot"
      {
        verifiedSignedBootInput = verifiedSignedBoot;
      }
      ''
        cp -R --no-preserve=ownership "$verifiedSignedBootInput" "$out"
        chmod -R u+w "$out"
        cp ${wrongPublicKey} "$out/public.pem"
        chmod 0444 "$out"/*
      '';
  wrongKeySignedBoot = wrongKeySignedBootRaw.overrideAttrs (previous: {
    passthru = (previous.passthru or { }) // {
      kaibaVerifiedSignedBoot = verifiedSignedBoot.kaibaVerifiedSignedBoot;
    };
  });
  forgedLineageSignedBootRaw =
    pkgs.runCommand "kaiba-campaign-media-valid-bytes-forged-lineage"
      {
        verifiedSignedBootInput = verifiedSignedBoot;
        nativeBuildInputs = [ pkgs.jq ];
      }
      ''
        set -euo pipefail
        cp -R --no-preserve=ownership "$verifiedSignedBootInput" "$out"
        chmod -R u+w "$out"
        jq -c '.plan_digest = "sha256:8888888888888888888888888888888888888888888888888888888888888888"' \
          "$verifiedSignedBootInput/signing-result.json" \
          > "$out/signing-result.json"
        chmod 0444 "$out"/*
      '';
  forgedLineageSignedBoot = forgedLineageSignedBootRaw.overrideAttrs (previous: {
    passthru = (previous.passthru or { }) // {
      kaibaVerifiedSignedBoot = verifiedSignedBoot.kaibaVerifiedSignedBoot;
    };
  });
  forgedSignedBootRaw = pkgs.runCommand "kaiba-campaign-media-forged-passthru" { } ''
    mkdir "$out"
    for name in boot.img boot.sig manifest.json public.pem release-intent.json signing-plan.json signing-result.json; do
      printf '%s\n' forged > "$out/$name"
    done
  '';
  forgedSignedBoot = forgedSignedBootRaw.overrideAttrs (previous: {
    passthru = (previous.passthru or { }) // {
      kaibaVerifiedSignedBoot = {
        blockDeviceWriteCapable = false;
        directHardwareAccess = false;
        mutationCapable = false;
        privateKeyAccess = false;
        signatureVerificationRequired = true;
        signingAuthorityConfigured = false;
        verificationMode = "pure_offline";
      };
    };
  });
  tamperedCampaignMutationInputs =
    pkgs.runCommand "kaiba-campaign-media-tampered-mutation-inputs"
      { mutationInputsInput = campaignMutationInputs; }
      ''
        set -euo pipefail
        cp -R --no-preserve=ownership "$mutationInputsInput" "$out"
        chmod -R u+w "$out"
        printf '%s' '{"tampered":true}' \
          > "$out/manifest-field-release-id.json"
        find "$out" -type f -exec chmod 0444 '{}' +
      '';

  baseBuilderArguments = {
    inherit
      campaignPlan
      campaignMutationInputs
      delegatedRelease
      rootDataPartitionGUID
      rootHashPartitionGUID
      verifiedSignedBoot
      ;
  };
  evaluationRejected =
    overrides:
    !(builtins.tryEval ((campaignMediaBuilder (baseBuilderArguments // overrides)).drvPath)).success;
in
assert lib.assertMsg (
  !contract.privateKeyOperationCapable
  && !contract.signingCapable
  && !contract.signingAuthorityConfigured
  && !contract.blockDeviceWriteCapable
  && !contract.directHardwareAccess
  && !contract.mutationCapable
  && !contract.physicalLayoutBound
  && contract.delegatedReleasePEMMarkerScan == "defense_in_depth_not_proof_of_absence"
  && contract.delegatedReleaseSignatureVerification == "deferred_to_stable_verifier"
  && contract.stableVerifierRootSignatureVerification == "reverified_during_build"
  && contract.runID == "positive-baseline"
  && contract.recipeID == null
  && contract.storageFormat == "partition-payload-set-not-whole-device"
) "stable-verifier campaign media passthru widened its non-signing baseline boundary";
assert lib.assertMsg (evaluationRejected {
  campaignPlan = "/tmp/not-a-store-backed-plan";
}) "campaign media accepted a non-store-backed campaign plan";
assert lib.assertMsg (evaluationRejected {
  campaignMutationInputs = releaseTree;
}) "campaign media accepted mutation inputs without typed public lineage";
assert lib.assertMsg (evaluationRejected {
  verifiedSignedBoot = verifierBootImage;
}) "campaign media accepted an artifact without kaibaVerifiedSignedBoot lineage";
assert lib.assertMsg (evaluationRejected {
  delegatedRelease = releaseTree;
}) "campaign media accepted an artifact without delegated-release lineage";
assert lib.assertMsg (evaluationRejected {
  rootHashPartitionGUID = rootDataPartitionGUID;
}) "campaign media accepted duplicate root-data and root-hash PARTUUIDs";

pkgs.runCommand "kaiba-stable-verifier-campaign-media-test"
  {
    passthru.fixtureBaselineMedia = campaignMediaA;
    campaignMediaAInput = campaignMediaA;
    campaignMediaBInput = campaignMediaB;
    campaignMutationInputsInput = campaignMutationInputs;
    campaignPlanInput = campaignPlan;
    delegatedReleaseInput = delegatedRelease;
    derCampaignPlanInput = derCampaignPlan;
    derDelegatedReleaseInput = derDelegatedRelease;
    duplicateWrapperReleaseInput = duplicateWrapperRelease;
    forgedLineageSignedBootInput = forgedLineageSignedBoot;
    forgedSignedBootInput = forgedSignedBoot;
    inputValidationToolInput = contract.inputValidationTool;
    oldBootCampaignPlanInput = oldBootCampaignPlan;
    privatePEMReleaseInput = privatePEMRelease;
    releaseAllowlistInput = releaseAllowlistFile;
    tamperedCampaignPlanInput = tamperedCampaignPlan;
    tamperedCampaignMutationInputsInput = tamperedCampaignMutationInputs;
    validationToolInput = contract.validationTool;
    verifierTrustFixtureInput = verifierTrustFixture;
    verifiedSignedBootInput = verifiedSignedBoot;
    wrongCommandLineReleaseInput = wrongCommandLineRelease;
    wrongKeySignedBootInput = wrongKeySignedBoot;
    wrongMetadataReleaseInput = wrongMetadataRelease;
    mismatchedDelegatedReleaseInput = mismatchedDelegatedRelease;
    wrapperReleaseIDMismatchInput = wrapperReleaseIDMismatch;
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.cryptsetup
      pkgs.diffutils
      pkgs.e2fsprogs
      pkgs.findutils
      pkgs.gnugrep
      pkgs.jq
      pkgs.mtools
    ];
    preferLocalBuild = true;
  }
  ''
    set -euo pipefail
    export LC_ALL=C
    export TZ=UTC

    readonly media_a="$campaignMediaAInput"
    readonly media_b="$campaignMediaBInput"
    readonly manifest="$media_a/manifest.json"
    readonly artifact_set="$media_a/artifact-set.json"
    readonly boot_filesystem="$media_a/sd/boot-filesystem.img"
    readonly release_image="$media_a/nvme/release-filesystem.img"
    readonly root_data="$media_a/sd/root-data.img"
    readonly root_hash_tree="$media_a/sd/root-hash.img"

    semantic_json_digest() {
      local domain="$1"
      local input="$2"
      {
        printf '%s\0' "$domain"
        if test "$(tail --bytes=1 "$input" | wc -l)" -eq 1; then
          head --bytes=-1 "$input"
        else
          cat "$input"
        fi
      } | sha256sum | cut -d ' ' -f 1
    }

    readonly policy_semantic_digest="sha256:$(semantic_json_digest \
      'kaiba.provisioning.rpi5-stable-verifier-policy.v1alpha1' \
      "$verifierTrustFixtureInput/policy.json")"
    readonly positive_manifest_semantic_digest="sha256:$(semantic_json_digest \
      'kaiba.provisioning.rpi5-delegated-release-manifest.v1alpha1' \
      "$delegatedReleaseInput/nvme-release/release-manifest.json")"
    readonly replacement_manifest_semantic_digest="sha256:$(semantic_json_digest \
      'kaiba.provisioning.rpi5-delegated-release-manifest.v1alpha1' \
      "$campaignMutationInputsInput/replacement-release-manifest.json")"
    readonly expected_kernel_command_line="$(< \
      "$delegatedReleaseInput/nvme-release/cmdline.txt")"

    for artifact in \
      "$artifact_set" \
      "$manifest" \
      "$boot_filesystem" \
      "$release_image" \
      "$root_data" \
      "$root_hash_tree"
    do
      test -f "$artifact"
      test ! -L "$artifact"
      test -s "$artifact"
      test "$(stat --format=%a "$artifact")" = 444
    done

    jq -e \
      --arg data_device '${dataDevice}' \
      --arg hash_device '${hashDevice}' \
      --arg data_guid '${rootDataPartitionGUID}' \
      --arg hash_guid '${rootHashPartitionGUID}' \
      --argjson allowlist ${lib.escapeShellArg (builtins.toJSON releaseAllowlist)} \
      '
        .schema_version == "kaiba.provisioning.rpi5-stable-verifier-campaign-media/v1alpha1"
        and .campaign_id == "campaign-media-fixture"
        and (.plan_digest | test("^sha256:[0-9a-f]{64}$"))
        and .campaign_plan_resolution == {
          bound_replacement_count: 20,
          byte_xor_mutation_count: 10,
          plan_digest: .plan_digest,
          public_input_count: 27,
          status: "resolved_against_exact_bytes"
        }
        and .campaign_plan_resolution == .validated_inputs.campaign_plan_resolution
        and .run == {run_id: "positive-baseline", recipe_id: null}
        and .physical_layout_bound == false
        and .storage_format == "partition-payload-set-not-whole-device"
        and .release.allowlist == $allowlist
        and [.release.files[].path] == $allowlist
        and .release.signature_verification == "deferred_to_stable_verifier"
        and .validated_inputs.verified_signed_boot.signature_verification == "reverified"
        and .validated_inputs.verified_signed_boot.public_key.fingerprint == "${fixturePublicKeyFingerprint}"
        and .validated_inputs.verified_signed_boot.public_key.sha256 == "sha256:${fixturePublicKeyFileSHA256}"
        and .validated_inputs.delegated_release_private_key_pem_marker_scan == "passed_defense_in_depth_not_proof_of_absence"
        and .validated_inputs.delegated_release.release_tree_size_bytes > 0
        and .validated_inputs.semantic_resolution.positive_release_tree == {
          sha256: .validated_inputs.delegated_release.release_tree_digest,
          size_bytes: .validated_inputs.delegated_release.release_tree_size_bytes
        }
        and ([
          .validated_inputs.semantic_resolution.stable_verifier_policy.semantic_digest,
          .validated_inputs.semantic_resolution.positive_release_manifest.semantic_digest,
          .validated_inputs.semantic_resolution.replacement_release_manifest.semantic_digest,
          .validated_inputs.semantic_resolution.positive_release_tree.sha256
        ] | all(test("^sha256:[0-9a-f]{64}$")))
        and (.validated_inputs.semantic_resolution.kernel_command_line.value | length) > 0
        and (.validated_inputs.campaign_mutation_inputs.files | length) == 20
        and (.validated_inputs.campaign_mutation_inputs.content_digest | test("^sha256:[0-9a-f]{64}$"))
        and .artifacts.stable_verifier_boot_filesystem.path == "sd/boot-filesystem.img"
        and .artifacts.stable_verifier_boot_filesystem.filesystem == "vfat"
        and .artifacts.stable_verifier_boot_filesystem.signature_verification == "reverified_from_verified_signed_boot"
        and .artifacts.release_filesystem.path == "nvme/release-filesystem.img"
        and .artifacts.release_filesystem.filesystem == "ext4"
        and .artifacts.release_filesystem.filesystem_label == "KAIBA_RELEASE"
        and .artifacts.root_data.required_partition_guid == $data_guid
        and .artifacts.root_hash_tree.required_partition_guid == $hash_guid
        and .verity.data_device == $data_device
        and .verity.hash_device == $hash_device
        and .verity.offline_verification == "passed"
        and (.capabilities | has("public_inputs_only") | not)
        and .capabilities.delegated_release_private_key_pem_marker_scan == "passed_defense_in_depth_not_proof_of_absence"
        and .capabilities.private_key_operation_performed == false
        and .capabilities.signing_performed == false
        and .capabilities.device_writes_performed == false
        and .capabilities.hardware_observed == false
        and .capabilities.mutation_performed == false
        and .capabilities.production_ready == false
      ' "$manifest" > /dev/null

    jq -e '
      def input($name): ($plan[0].public_inputs[] | select(.name == $name));
      def file($binding): {sha256: $binding.digest, size_bytes: $binding.size_bytes};
      def byte_recipe($id):
        ($plan[0].byte_xor_mutations[] | select(.recipe_id == $id));
      def artifact($role):
        (.artifacts[] | select(.role == $role) | {sha256: .digest, size_bytes});
      .schema_version == "kaiba.provisioning.rpi5-stable-verifier-campaign-artifact-set/v1alpha1"
      and .campaign_id == "campaign-media-fixture"
      and .plan_digest == $plan_digest
      and .campaign_plan_resolution == {
        bound_replacement_count: 20,
        byte_xor_mutation_count: 10,
        plan_digest: $plan_digest,
        public_input_count: 27,
        status: "resolved_against_exact_bytes"
      }
      and .run_id == "positive-baseline"
      and .recipe_id == null
      and .storage_format == "partition-payload-set-not-whole-device"
      and .physical_layout_bound == false
      and [.artifacts[].role] == ["boot-filesystem", "release-filesystem", "root-data", "root-hash"]
      and [.artifacts[].name] == ["sd/boot-filesystem.img", "nvme/release-filesystem.img", "sd/root-data.img", "sd/root-hash.img"]
      and ([.artifacts[] | (.digest | test("^sha256:[0-9a-f]{64}$")) and (.size_bytes > 0)] | all)
      and artifact("root-data") == file(byte_recipe("component-byte-mutations-rejected:root-image").before)
      and artifact("root-data") == file(byte_recipe("dm-verity-corruption-rejected:root-data").before)
      and artifact("root-hash") == file(byte_recipe("dm-verity-corruption-rejected:root-hash").before)
      and .verity == {
        algorithm: "sha256",
        data_block_size: 4096,
        data_device: $data_device,
        data_partition_guid: $data_guid,
        hash_block_size: 4096,
        hash_device: $hash_device,
        hash_partition_guid: $hash_guid,
        no_superblock: false,
        root_hash: $root_hash
      }
      and .provenance.verified_signed_boot.signature_verification == "reverified"
      and .provenance.delegated_release.signature_verification == "deferred_to_stable_verifier"
      and .provenance.delegated_release.release_tree_size_bytes > 0
      and .semantic_resolution.stable_verifier_policy == {
        file: file(input("stable-verifier-policy")),
        semantic_digest: $policy_semantic_digest
      }
      and .semantic_resolution.positive_release_manifest == {
        file: file(input("positive-release-manifest")),
        semantic_digest: $positive_manifest_semantic_digest
      }
      and .semantic_resolution.positive_release_manifest.file ==
        .provenance.delegated_release.release_manifest
      and .semantic_resolution.replacement_release_manifest == {
        file: file(input("replacement-release-manifest")),
        semantic_digest: $replacement_manifest_semantic_digest
      }
      and .semantic_resolution.positive_release_tree == file(input("positive-release-tree"))
      and .semantic_resolution.positive_release_tree == {
        sha256: .provenance.delegated_release.release_tree_digest,
        size_bytes: .provenance.delegated_release.release_tree_size_bytes
      }
      and .semantic_resolution.kernel_command_line == {
        file: file(byte_recipe("component-byte-mutations-rejected:kernel-command-line").before),
        value: $expected_kernel_command_line
      }
      and (.capabilities | has("public_inputs_only") | not)
      and .capabilities.device_writes_performed == false
    ' \
      --arg plan_digest "$(jq -r .plan_digest "$campaignPlanInput")" \
      --arg data_device '${dataDevice}' \
      --arg hash_device '${hashDevice}' \
      --arg data_guid '${rootDataPartitionGUID}' \
      --arg hash_guid '${rootHashPartitionGUID}' \
      --arg root_hash "$(jq -r .verity.root_hash "$manifest")" \
      --arg policy_semantic_digest "$policy_semantic_digest" \
      --arg positive_manifest_semantic_digest "$positive_manifest_semantic_digest" \
      --arg replacement_manifest_semantic_digest "$replacement_manifest_semantic_digest" \
      --arg expected_kernel_command_line "$expected_kernel_command_line" \
      --slurpfile plan "$campaignPlanInput" \
      "$artifact_set" > /dev/null

    jq -e --slurpfile manifest_document "$manifest" \
      '.semantic_resolution == $manifest_document[0].validated_inputs.semantic_resolution' \
      "$artifact_set" > /dev/null

    derive_artifact_set_digest() {
      local input="$1"
      local artifact_set_material
      artifact_set_material="$(jq -cS 'del(.artifact_set_content_digest)' "$input")"
      {
        printf '%s\0' 'kaiba.provisioning.rpi5-stable-verifier-campaign-artifact-set.v1alpha1'
        printf '%s' "$artifact_set_material"
      } | sha256sum | sed 's/^/sha256:/' | cut -d ' ' -f 1
    }
    expected_artifact_set_digest="$(derive_artifact_set_digest "$artifact_set")"
    test "$(jq -r .artifact_set_content_digest "$artifact_set")" = "$expected_artifact_set_digest"

    jq -cS \
      '.semantic_resolution.stable_verifier_policy.semantic_digest |=
       (.[0:-1] + if endswith("0") then "1" else "0" end)' \
      "$artifact_set" > "$TMPDIR/artifact-set-semantic-tamper.json"
    test "$(jq -r .artifact_set_content_digest "$TMPDIR/artifact-set-semantic-tamper.json")" != \
      "$(derive_artifact_set_digest "$TMPDIR/artifact-set-semantic-tamper.json")"

    jq -cS '.provenance.delegated_release.release_tree_size_bytes += 1' \
      "$artifact_set" > "$TMPDIR/artifact-set-tree-size-tamper.json"
    test "$(jq -r .artifact_set_content_digest "$TMPDIR/artifact-set-tree-size-tamper.json")" != \
      "$(derive_artifact_set_digest "$TMPDIR/artifact-set-tree-size-tamper.json")"
    test "$(jq -r .public_artifact_set.sha256 "$manifest")" = \
      "sha256:$(sha256sum "$artifact_set" | cut -d ' ' -f 1)"
    test "$(jq -r .public_artifact_set.size_bytes "$manifest")" = \
      "$(stat --format=%s "$artifact_set")"
    manifest_material="$(jq -cS 'del(.manifest_content_digest)' "$manifest")"
    expected_manifest_content_digest="sha256:$({
      printf '%s\0' 'kaiba.provisioning.rpi5-stable-verifier-campaign-media.v1alpha1'
      printf '%s' "$manifest_material"
    } | sha256sum | cut -d ' ' -f 1)"
    test "$(jq -r .manifest_content_digest "$manifest")" = \
      "$expected_manifest_content_digest"

    test "$(jq -r .plan_digest "$campaignPlanInput")" = "$(jq -r .plan_digest "$manifest")"
    cmp "$delegatedReleaseInput/nvme-release/root.img" "$root_data"
    test "$(sha256sum "$boot_filesystem" | cut -d ' ' -f 1)" = \
      "$(jq -r '.artifacts.stable_verifier_boot_filesystem.sha256 | sub("^sha256:"; "")' "$manifest")"
    mkdir "$TMPDIR/boot-readback"
    mcopy -s -i "$boot_filesystem" '::*' "$TMPDIR/boot-readback/"
    cmp "$verifiedSignedBootInput/boot.img" "$TMPDIR/boot-readback/boot.img"
    cmp "$verifiedSignedBootInput/boot.sig" "$TMPDIR/boot-readback/boot.sig"
    test "$(cat "$TMPDIR/boot-readback/config.txt")" = boot_ramdisk=1

    root_hash="$(jq -r '.verity.root_hash | sub("^sha256:"; "")' "$manifest")"
    veritysetup verify \
      --hash=sha256 \
      --data-block-size=4096 \
      --hash-block-size=4096 \
      "$root_data" \
      "$root_hash_tree" \
      "$root_hash"
    e2fsck -fn "$release_image" > /dev/null

    cmp "$media_a/nvme/release-filesystem.img" "$media_b/nvme/release-filesystem.img"
    cmp "$media_a/sd/boot-filesystem.img" "$media_b/sd/boot-filesystem.img"
    cmp "$media_a/sd/root-data.img" "$media_b/sd/root-data.img"
    cmp "$media_a/sd/root-hash.img" "$media_b/sd/root-hash.img"
    cmp "$media_a/manifest.json" "$media_b/manifest.json"
    cmp "$media_a/artifact-set.json" "$media_b/artifact-set.json"

    validate_inputs() {
      label="$1"
      signed_boot="$2"
      plan="$3"
      release="$4"
      mutation_inputs="''${5:-$campaignMutationInputsInput}"
      "$inputValidationToolInput/bin/kaiba-stable-verifier-campaign-input-validate" \
        --verified-signed-boot "$signed_boot" \
        --campaign-plan "$plan" \
        --campaign-mutation-inputs "$mutation_inputs" \
        --delegated-release "$release" \
        --release-allowlist "$releaseAllowlistInput" \
        --metadata-out "$TMPDIR/$label-metadata.json"
    }
    expect_input_rejection() {
      label="$1"
      signed_boot="$2"
      plan="$3"
      release="$4"
      mutation_inputs="''${5:-$campaignMutationInputsInput}"
      if validate_inputs "$label" "$signed_boot" "$plan" "$release" "$mutation_inputs" \
        > "$TMPDIR/$label.stdout" 2> "$TMPDIR/$label.stderr"
      then
        echo "campaign input validator accepted tamper case: $label" >&2
        exit 1
      fi
    }

    validate_inputs baseline "$verifiedSignedBootInput" "$campaignPlanInput" "$delegatedReleaseInput"
    expect_input_rejection forged-passthru "$forgedSignedBootInput" "$campaignPlanInput" "$delegatedReleaseInput"
    expect_input_rejection forged-lineage-result "$forgedLineageSignedBootInput" "$campaignPlanInput" "$delegatedReleaseInput"
    grep -F 're-finalize signed-boot input' \
      "$TMPDIR/forged-lineage-result.stderr" > /dev/null
    grep -F 'signing result does not bind the exact signing plan' \
      "$TMPDIR/forged-lineage-result.stderr" > /dev/null
    expect_input_rejection wrong-key-signature "$wrongKeySignedBootInput" "$campaignPlanInput" "$delegatedReleaseInput"
    expect_input_rejection old-boot-plan "$verifiedSignedBootInput" "$oldBootCampaignPlanInput" "$delegatedReleaseInput"
    expect_input_rejection plan-tamper "$verifiedSignedBootInput" "$tamperedCampaignPlanInput" "$delegatedReleaseInput"
    expect_input_rejection component-manifest-mismatch "$verifiedSignedBootInput" "$campaignPlanInput" "$mismatchedDelegatedReleaseInput"
    expect_input_rejection wrapper-release-id-mismatch "$verifiedSignedBootInput" "$campaignPlanInput" "$wrapperReleaseIDMismatchInput"
    grep -F 'delegated wrapper release_id does not match the parsed inner release manifest' \
      "$TMPDIR/wrapper-release-id-mismatch.stderr" > /dev/null
    expect_input_rejection duplicate-wrapper-field "$verifiedSignedBootInput" "$campaignPlanInput" "$duplicateWrapperReleaseInput"
    grep -F 'duplicate JSON key "release_id"' \
      "$TMPDIR/duplicate-wrapper-field.stderr" > /dev/null
    expect_input_rejection mutation-input-tamper "$verifiedSignedBootInput" "$campaignPlanInput" "$delegatedReleaseInput" "$tamperedCampaignMutationInputsInput"

    # A DER-like binary intentionally bypasses the marker scan. This is a
    # regression check that the successful scan is never represented as proof
    # that every input is public or that private material is absent.
    validate_inputs der-bypass "$verifiedSignedBootInput" "$derCampaignPlanInput" "$derDelegatedReleaseInput"
    test "$(jq -r .delegated_release_private_key_pem_marker_scan "$TMPDIR/der-bypass-metadata.json")" = \
      passed_defense_in_depth_not_proof_of_absence
    test "$(jq 'has("public_inputs_only")' "$TMPDIR/der-bypass-metadata.json")" = false

    validate_tree() {
      "$validationToolInput/bin/kaiba-stable-verifier-campaign-media-validate" \
        --release-tree "$1" \
        --release-allowlist "$releaseAllowlistInput" \
        --root-data "$root_data" \
        --root-hash-tree "$root_hash_tree" \
        --root-hash "$root_hash" \
        --data-device '${dataDevice}' \
        --hash-device '${hashDevice}'
    }
    expect_tree_rejection() {
      label="$1"
      tree="$2"
      if validate_tree "$tree" > "$TMPDIR/tree-$label.stdout" 2> "$TMPDIR/tree-$label.stderr"; then
        echo "campaign media validator accepted tamper case: $label" >&2
        exit 1
      fi
    }
    validate_tree "$delegatedReleaseInput/nvme-release"
    expect_tree_rejection wrong-metadata "$wrongMetadataReleaseInput"
    expect_tree_rejection wrong-command-line "$wrongCommandLineReleaseInput"
    expect_tree_rejection private-pem-marker "$privatePEMReleaseInput"

    mkdir -p "$out"
    printf '%s\n' 'stable-verifier campaign media construction: pass' > "$out/result.txt"
  ''
