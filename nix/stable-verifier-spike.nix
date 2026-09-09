{
  lib,
  pkgs,
}:

let
  canonicalRevision =
    value: builtins.isString value && builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" value != null;
  canonicalNarHash =
    value: builtins.isString value && builtins.match "sha256-[A-Za-z0-9+/]{43}=" value != null;
  canonicalIdentifier =
    value: builtins.isString value && builtins.match "[a-z0-9][a-z0-9._:-]{0,127}" value != null;
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
  stableVerifierPackageContractValid =
    package:
    let
      contract = if builtins.isAttrs package then package.kaibaRpi5StableVerifier or { } else { };
    in
    (contract.runtimeBoundary or null) == "initramfs_only"
    && (contract.staticallyLinked or false)
    && (contract.kexecCapable or false)
    && (contract.nonProductionOnly or false)
    && !(contract.productionReady or true)
    && !(contract.hardwareObserved or true)
    && !(contract.privateKeyMaterialEmbedded or true)
    && !(contract.authoritySigningCapable or true)
    && !(contract.signingAuthorityConfigured or true);
  exactAllowlist =
    values:
    builtins.isList values
    && values != [ ]
    && builtins.length values <= 128
    && lib.all canonicalRelativePath values
    && builtins.length values == builtins.length (lib.unique values)
    && values == lib.sort builtins.lessThan values;
  containsReservedBootPath = path: path == "kaiba" || lib.hasPrefix "kaiba/" path;
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
  sensitiveMaterialScan = root: ''
    if find ${root} -type f -print0 \
      | xargs -0 -r grep -aEl -- \
        '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----' \
        > "$TMPDIR/private-material-paths"
    then
      printf 'private key material is forbidden in stable-verifier spike inputs:\n' >&2
      cat "$TMPDIR/private-material-paths" >&2
      exit 1
    fi
  '';

  mkRpi5StableVerifierUnsignedBoot =
    {
      firmwareTree,
      firmwareAllowlist,
      verifierPackage,
      stableVerifierPolicy,
      rootPublicKey,
      authorityCACertificate,
      sourceRevision,
      piPlatformSourceRevision,
      piPlatformSourceNarHash,
      verifierBinary ? "${verifierPackage}/bin/kaiba-rpi5-stable-verifier",
      bootImageSizeMiB ? 96,
      name ? "kaiba-rpi5-stable-verifier-unsigned-boot",
    }:
    assert lib.assertMsg (storeBacked firmwareTree) "firmwareTree must be one fixed Nix-store path";
    assert lib.assertMsg (exactAllowlist firmwareAllowlist)
      "firmwareAllowlist must be a sorted, unique list of 1 through 128 canonical relative paths";
    assert lib.assertMsg (
      !(builtins.any containsReservedBootPath firmwareAllowlist)
    ) "firmwareAllowlist must not use the builder-owned kaiba/ directory";
    assert lib.assertMsg (
      storeBacked verifierPackage && storeBacked verifierBinary
    ) "verifierPackage and verifierBinary must be fixed Nix-store paths";
    assert lib.assertMsg (stableVerifierPackageContractValid verifierPackage)
      "verifierPackage must expose the static, initramfs-only, non-production verifier contract";
    assert lib.assertMsg (
      toString verifierBinary == "${verifierPackage}/bin/kaiba-rpi5-stable-verifier"
    ) "verifierBinary must be the fixed kaiba-rpi5-stable-verifier executable from verifierPackage";
    assert lib.assertMsg (storeBacked stableVerifierPolicy)
      "stableVerifierPolicy must be one fixed public Nix-store path";
    assert lib.assertMsg (storeBacked rootPublicKey)
      "rootPublicKey must be one fixed public Nix-store path";
    assert lib.assertMsg (storeBacked authorityCACertificate)
      "authorityCACertificate must be one fixed public Nix-store path";
    assert lib.assertMsg (canonicalRevision sourceRevision)
      "sourceRevision must be one canonical lowercase 40- or 64-hex revision";
    assert lib.assertMsg (canonicalRevision piPlatformSourceRevision)
      "piPlatformSourceRevision must pin one canonical lowercase 40- or 64-hex revision";
    assert lib.assertMsg (canonicalNarHash piPlatformSourceNarHash)
      "piPlatformSourceNarHash must be one canonical SHA-256 SRI hash";
    assert lib.assertMsg (
      builtins.isInt bootImageSizeMiB && bootImageSizeMiB >= 32 && bootImageSizeMiB <= 96
    ) "bootImageSizeMiB must be an integer from 32 through 96";
    let
      finalAllowlist = lib.sort builtins.lessThan (
        firmwareAllowlist
        ++ [
          "kaiba/provenance.json"
          "kaiba/authority-ca.pem"
          "kaiba/root-public.pem"
          "kaiba/stable-verifier"
          "kaiba/stable-verifier-policy.json"
        ]
      );
    in
    pkgs.runCommand name
      {
        firmwareTreeInput = firmwareTree;
        policyInput = stableVerifierPolicy;
        rootPublicKeyInput = rootPublicKey;
        authorityCACertificateInput = authorityCACertificate;
        verifierBinaryInput = verifierBinary;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.dosfstools
          pkgs.findutils
          pkgs.gnugrep
          pkgs.jq
          pkgs.mtools
          pkgs.openssl
        ];
        passthru.kaibaRpi5StableVerifierUnsignedBoot = {
          inherit
            bootImageSizeMiB
            firmwareAllowlist
            piPlatformSourceNarHash
            piPlatformSourceRevision
            authorityCACertificate
            rootPublicKey
            sourceRevision
            stableVerifierPolicy
            verifierBinary
            verifierPackage
            ;
          artifactSchemaVersion = "kaiba.provisioning.rpi5-stable-verifier-boot-artifact/v1alpha1";
          blockDeviceWriteCapable = false;
          hardwareObserved = false;
          privateKeyAccess = false;
          productionReady = false;
          signatureVerified = false;
          signingAuthorityConfigured = false;
          status = "unsigned_requires_external_root_signature";
        };
        preferLocalBuild = true;
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        export TZ=UTC
        umask 022

        readonly stage="$TMPDIR/boot-tree"
        mkdir -p "$stage" "$out" "$stage/kaiba"
        cp -R --no-preserve=ownership "$firmwareTreeInput"/. "$stage/"

        if test -n "$(find "$stage" -type l -print -quit)"; then
          echo "firmware tree contains a symbolic link" >&2
          exit 1
        fi
        if test -n "$(find "$stage" ! -type d ! -type f -print -quit)"; then
          echo "firmware tree contains an unsupported filesystem object" >&2
          exit 1
        fi
        find "$stage" -type f -printf '%P\n' | LC_ALL=C sort \
          > "$TMPDIR/actual-firmware-files"
        {
          ${lib.concatMapStringsSep "\n" (
            path: "printf '%s\\n' ${lib.escapeShellArg path}"
          ) firmwareAllowlist}
        } > "$TMPDIR/expected-firmware-files"
        if ! cmp "$TMPDIR/expected-firmware-files" "$TMPDIR/actual-firmware-files"; then
          echo "firmware tree differs from firmwareAllowlist" >&2
          exit 1
        fi

        test -x "$verifierBinaryInput"
        for public_input in "$policyInput" "$rootPublicKeyInput" "$authorityCACertificateInput"; do
          test -f "$public_input"
          test ! -L "$public_input"
          test -s "$public_input"
          test "$(stat --format=%s "$public_input")" -le 1048576
        done
        jq -e 'type == "object"' "$policyInput" > /dev/null

        openssl rsa -pubin -in "$rootPublicKeyInput" -pubout \
          -out "$TMPDIR/canonical-root-public.pem"
        cmp "$rootPublicKeyInput" "$TMPDIR/canonical-root-public.pem"
        test "$(openssl pkey -pubin -in "$rootPublicKeyInput" -text -noout | sed -n '1p')" = \
          'Public-Key: (2048 bit)'
        openssl pkey -pubin -in "$rootPublicKeyInput" -text -noout \
          | grep -Fx 'Exponent: 65537 (0x10001)' > /dev/null
        openssl x509 -in "$authorityCACertificateInput" -noout

        install -m 0555 "$verifierBinaryInput" "$stage/kaiba/stable-verifier"
        install -m 0444 "$policyInput" "$stage/kaiba/stable-verifier-policy.json"
        install -m 0444 "$rootPublicKeyInput" "$stage/kaiba/root-public.pem"
        install -m 0444 "$authorityCACertificateInput" "$stage/kaiba/authority-ca.pem"

        verifier_digest="sha256:$(sha256sum "$verifierBinaryInput" | cut -d ' ' -f 1)"
        policy_file_sha256="sha256:$(sha256sum "$policyInput" | cut -d ' ' -f 1)"
        root_key_digest="sha256:$(sha256sum "$rootPublicKeyInput" | cut -d ' ' -f 1)"
        authority_ca_digest="sha256:$(sha256sum "$authorityCACertificateInput" | cut -d ' ' -f 1)"
        jq --null-input --sort-keys \
          --arg schema_version 'kaiba.provisioning.rpi5-stable-verifier-boot-provenance/v1alpha1' \
          --arg source_revision ${lib.escapeShellArg sourceRevision} \
          --arg pi_platform_revision ${lib.escapeShellArg piPlatformSourceRevision} \
          --arg pi_platform_nar_hash ${lib.escapeShellArg piPlatformSourceNarHash} \
          --arg verifier_digest "$verifier_digest" \
          --arg policy_file_sha256 "$policy_file_sha256" \
          --arg root_key_digest "$root_key_digest" \
          --arg authority_ca_digest "$authority_ca_digest" \
          '{
            schema_version: $schema_version,
            source_revision: $source_revision,
            pi_platform_source: {
              revision: $pi_platform_revision,
              nar_hash: $pi_platform_nar_hash
            },
            public_inputs: {
              verifier: $verifier_digest,
              stable_verifier_policy_file: $policy_file_sha256,
              root_public_key: $root_key_digest,
              authority_ca_certificate: $authority_ca_digest
            },
            hardware_observed: false,
            production_ready: false,
            signing_status: "unsigned"
          }' > "$stage/kaiba/provenance.json"

        ${sensitiveMaterialScan ''"$stage"''}
        find "$stage" -type d -exec chmod 0555 '{}' +
        find "$stage" -type f ! -path '*/kaiba/stable-verifier' -exec chmod 0444 '{}' +
        touch --date=@315532800 "$stage"
        find "$stage" -exec touch --date=@315532800 '{}' +

        find "$stage" -type f -printf '%P\n' | LC_ALL=C sort \
          > "$TMPDIR/actual-boot-files"
        {
          ${lib.concatMapStringsSep "\n" (path: "printf '%s\\n' ${lib.escapeShellArg path}") finalAllowlist}
        } > "$TMPDIR/expected-boot-files"
        cmp "$TMPDIR/expected-boot-files" "$TMPDIR/actual-boot-files"

        truncate --size=${toString bootImageSizeMiB}M "$out/boot.img"
        mkfs.vfat \
          --invariant \
          -F 32 \
          -i 4b535631 \
          -n KAIBA_SV \
          "$out/boot.img" > "$TMPDIR/mkfs.txt"
        mcopy -s -p -m -i "$out/boot.img" "$stage"/* ::/
        chmod 0444 "$out/boot.img"

        readonly readback="$TMPDIR/boot-readback"
        mkdir -p "$readback"
        mcopy -s -i "$out/boot.img" '::*' "$readback/"
        find "$readback" -type f -printf '%P\n' | LC_ALL=C sort \
          > "$TMPDIR/readback-boot-files"
        cmp "$TMPDIR/expected-boot-files" "$TMPDIR/readback-boot-files"
        while IFS= read -r relative_path; do
          cmp "$stage/$relative_path" "$readback/$relative_path"
        done < "$TMPDIR/expected-boot-files"

        boot_digest="sha256:$(sha256sum "$out/boot.img" | cut -d ' ' -f 1)"
        boot_size="$(stat --format=%s "$out/boot.img")"
        jq --null-input --sort-keys \
          --arg schema_version 'kaiba.provisioning.rpi5-stable-verifier-boot-artifact/v1alpha1' \
          --arg source_revision ${lib.escapeShellArg sourceRevision} \
          --arg pi_platform_revision ${lib.escapeShellArg piPlatformSourceRevision} \
          --arg pi_platform_nar_hash ${lib.escapeShellArg piPlatformSourceNarHash} \
          --arg boot_digest "$boot_digest" \
          --argjson boot_size "$boot_size" \
          --argjson files ${lib.escapeShellArg (builtins.toJSON finalAllowlist)} \
          '{
            schema_version: $schema_version,
            source_revision: $source_revision,
            pi_platform_source: {
              revision: $pi_platform_revision,
              nar_hash: $pi_platform_nar_hash
            },
            boot_image: {path: "boot.img", sha256: $boot_digest, size_bytes: $boot_size},
            files: $files,
            hardware_observed: false,
            production_ready: false,
            signing_status: "unsigned_requires_external_root_signature"
          }' > "$out/manifest.json"
        chmod 0444 "$out/manifest.json"
      '';

  mkRpi5StableVerifierTestSD =
    {
      stableVerifierUnsignedBoot,
      bootSignature,
      firmwareSigningPublicKey,
      bootFilesystemSizeMiB ? 128,
      name ? "kaiba-rpi5-stable-verifier-test-sd",
    }:
    assert lib.assertMsg (storeBacked stableVerifierUnsignedBoot)
      "stableVerifierUnsignedBoot must be one fixed Nix-store path";
    assert lib.assertMsg (
      builtins.isAttrs stableVerifierUnsignedBoot
      && stableVerifierUnsignedBoot ? kaibaRpi5StableVerifierUnsignedBoot
    ) "stableVerifierUnsignedBoot must be produced by mkRpi5StableVerifierUnsignedBoot";
    assert lib.assertMsg (storeBacked bootSignature)
      "bootSignature must be one fixed public Nix-store path";
    assert lib.assertMsg (storeBacked firmwareSigningPublicKey)
      "firmwareSigningPublicKey must be one fixed public Nix-store path";
    assert lib.assertMsg (
      builtins.isInt bootFilesystemSizeMiB && bootFilesystemSizeMiB >= 112 && bootFilesystemSizeMiB <= 256
    ) "bootFilesystemSizeMiB must be an integer from 112 through 256";
    pkgs.runCommand name
      {
        bootInput = stableVerifierUnsignedBoot;
        bootSignatureInput = bootSignature;
        firmwareSigningPublicKeyInput = firmwareSigningPublicKey;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.dosfstools
          pkgs.findutils
          pkgs.gnugrep
          pkgs.jq
          pkgs.mtools
          pkgs.openssl
          pkgs.xxd
        ];
        passthru.kaibaRpi5StableVerifierTestSD = {
          inherit
            bootFilesystemSizeMiB
            bootSignature
            firmwareSigningPublicKey
            stableVerifierUnsignedBoot
            ;
          artifactSchemaVersion = "kaiba.provisioning.rpi5-stable-verifier-test-sd/v1alpha1";
          blockDeviceWriteCapable = false;
          hardwareObserved = false;
          privateKeyAccess = false;
          productionReady = false;
          signatureVerified = true;
          signingAuthorityConfigured = false;
          storageFormat = "fat-filesystem-image-not-whole-disk";
        };
        preferLocalBuild = true;
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        export TZ=UTC
        umask 022

        readonly boot_image="$bootInput/boot.img"
        readonly boot_signature="$bootSignatureInput"
        test -f "$boot_image"
        test ! -L "$boot_image"
        test -s "$boot_image"
        test -f "$boot_signature"
        test ! -L "$boot_signature"
        test -s "$boot_signature"
        test "$(wc -l < "$boot_signature")" -eq 3

        image_digest="$(sed -n '1p' "$boot_signature")"
        timestamp_line="$(sed -n '2p' "$boot_signature")"
        signature_line="$(sed -n '3p' "$boot_signature")"
        printf '%s\n' "$image_digest" | grep -Ex '[0-9a-f]{64}' > /dev/null
        printf '%s\n' "$timestamp_line" | grep -Ex 'ts: (0|[1-9][0-9]{0,19})' > /dev/null
        printf '%s\n' "$signature_line" | grep -Ex 'rsa2048: [0-9a-f]{512}' > /dev/null
        test "sha256:$image_digest" = "sha256:$(sha256sum "$boot_image" | cut -d ' ' -f 1)"

        printf '%s' "''${signature_line#rsa2048: }" | xxd -r -p > "$TMPDIR/boot-signature.bin"
        test "$(stat --format=%s "$TMPDIR/boot-signature.bin")" -eq 256
        openssl dgst -sha256 \
          -verify "$firmwareSigningPublicKeyInput" \
          -signature "$TMPDIR/boot-signature.bin" \
          "$boot_image" > "$TMPDIR/signature-verification.txt"
        grep -Fx 'Verified OK' "$TMPDIR/signature-verification.txt" > /dev/null

        readonly stage="$TMPDIR/sd-boot"
        mkdir -p "$stage" "$out"
        install -m 0444 "$boot_image" "$stage/boot.img"
        install -m 0444 "$boot_signature" "$stage/boot.sig"
        printf '%s\n' 'boot_ramdisk=1' > "$stage/config.txt"
        chmod 0444 "$stage/config.txt"
        touch --date=@315532800 "$stage"/*

        truncate --size=${toString bootFilesystemSizeMiB}M "$out/boot-filesystem.img"
        mkfs.vfat \
          --invariant \
          -F 32 \
          -i 4b535632 \
          -n KAIBA_SV_SD \
          "$out/boot-filesystem.img" > "$TMPDIR/mkfs.txt"
        mcopy -p -m -i "$out/boot-filesystem.img" "$stage"/* ::/
        chmod 0444 "$out/boot-filesystem.img"

        readonly readback="$TMPDIR/sd-readback"
        mkdir -p "$readback"
        mcopy -s -i "$out/boot-filesystem.img" '::*' "$readback/"
        find "$readback" -type f -printf '%P\n' | LC_ALL=C sort \
          > "$TMPDIR/actual-sd-files"
        printf '%s\n' boot.img boot.sig config.txt > "$TMPDIR/expected-sd-files"
        cmp "$TMPDIR/expected-sd-files" "$TMPDIR/actual-sd-files"
        while IFS= read -r relative_path; do
          cmp "$stage/$relative_path" "$readback/$relative_path"
        done < "$TMPDIR/expected-sd-files"

        sd_digest="sha256:$(sha256sum "$out/boot-filesystem.img" | cut -d ' ' -f 1)"
        sd_size="$(stat --format=%s "$out/boot-filesystem.img")"
        boot_digest="sha256:$image_digest"
        signature_digest="sha256:$(sha256sum "$boot_signature" | cut -d ' ' -f 1)"
        jq --null-input --sort-keys \
          --arg schema_version 'kaiba.provisioning.rpi5-stable-verifier-test-sd/v1alpha1' \
          --arg sd_digest "$sd_digest" \
          --argjson sd_size "$sd_size" \
          --arg boot_digest "$boot_digest" \
          --arg signature_digest "$signature_digest" \
          '{
            schema_version: $schema_version,
            storage_format: "fat-filesystem-image-not-whole-disk",
            boot_filesystem: {path: "boot-filesystem.img", sha256: $sd_digest, size_bytes: $sd_size},
            files: [
              {path: "boot.img", sha256: $boot_digest},
              {path: "boot.sig", sha256: $signature_digest},
              {path: "config.txt", content: "boot_ramdisk=1\\n"}
            ],
            root_signature_verified: true,
            hardware_observed: false,
            production_ready: false
          }' > "$out/manifest.json"
        chmod 0444 "$out/manifest.json"
      '';

  mkRpi5DelegatedReleaseSpike =
    {
      releaseTree,
      releaseAllowlist,
      releaseID,
      sourceRevision,
      name ? "kaiba-rpi5-delegated-release-spike",
    }:
    assert lib.assertMsg (storeBacked releaseTree) "releaseTree must be one fixed Nix-store path";
    assert lib.assertMsg (exactAllowlist releaseAllowlist)
      "releaseAllowlist must be a sorted, unique list of 1 through 128 canonical relative paths";
    assert lib.assertMsg (lib.all (
      path: builtins.elem path releaseAllowlist
    ) delegatedReleaseFixedPaths) "releaseAllowlist must include every fixed delegated-release role";
    assert lib.assertMsg (lib.all delegatedReleasePath releaseAllowlist)
      "releaseAllowlist may contain only fixed roles and canonical overlays/[a-z0-9][a-z0-9_-]{0,63}.dtbo paths";
    assert lib.assertMsg (canonicalIdentifier releaseID)
      "releaseID must be one canonical lowercase identifier";
    assert lib.assertMsg (canonicalRevision sourceRevision)
      "sourceRevision must be one canonical lowercase 40- or 64-hex revision";
    pkgs.runCommand name
      {
        releaseTreeInput = releaseTree;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.findutils
          pkgs.gnugrep
          pkgs.jq
        ];
        passthru.kaibaRpi5DelegatedReleaseSpike = {
          inherit
            releaseAllowlist
            releaseID
            releaseTree
            sourceRevision
            ;
          artifactSchemaVersion = "kaiba.provisioning.rpi5-delegated-release-spike/v1alpha1";
          blockDeviceWriteCapable = false;
          hardwareObserved = false;
          privateKeyAccess = false;
          productionReady = false;
          signatureVerified = false;
          signingAuthorityConfigured = false;
          storageFormat = "nvme-directory-payload";
        };
        preferLocalBuild = true;
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        export TZ=UTC
        umask 022

        test -d "$releaseTreeInput"
        test ! -L "$releaseTreeInput"
        if test -n "$(find "$releaseTreeInput" -type l -print -quit)"; then
          echo "delegated release contains a symbolic link" >&2
          exit 1
        fi
        if test -n "$(find "$releaseTreeInput" ! -type d ! -type f -print -quit)"; then
          echo "delegated release contains an unsupported filesystem object" >&2
          exit 1
        fi
        find "$releaseTreeInput" -type f -printf '%P\n' | LC_ALL=C sort \
          > "$TMPDIR/actual-release-files"
        {
          ${lib.concatMapStringsSep "\n" (
            path: "printf '%s\\n' ${lib.escapeShellArg path}"
          ) releaseAllowlist}
        } > "$TMPDIR/expected-release-files"
        if ! cmp "$TMPDIR/expected-release-files" "$TMPDIR/actual-release-files"; then
          echo "delegated release tree differs from releaseAllowlist" >&2
          exit 1
        fi
        ${sensitiveMaterialScan ''"$releaseTreeInput"''}

        mkdir -p "$out/nvme-release/overlays"
        while IFS= read -r relative_path; do
          test -s "$releaseTreeInput/$relative_path"
          install -D -m 0444 \
            "$releaseTreeInput/$relative_path" \
            "$out/nvme-release/$relative_path"
        done < "$TMPDIR/expected-release-files"
        find "$out/nvme-release" -type d -exec chmod 0555 '{}' +
        find "$out/nvme-release" -exec touch --date=@315532800 '{}' +

        : > "$TMPDIR/file-records.ndjson"
        while IFS= read -r relative_path; do
          size_bytes="$(stat --format=%s "$out/nvme-release/$relative_path")"
          digest="sha256:$(sha256sum "$out/nvme-release/$relative_path" | cut -d ' ' -f 1)"
          jq --null-input --compact-output \
            --arg path "$relative_path" \
            --argjson size_bytes "$size_bytes" \
            --arg sha256 "$digest" \
            '{path: $path, size_bytes: $size_bytes, sha256: $sha256}' \
            >> "$TMPDIR/file-records.ndjson"
        done < "$TMPDIR/expected-release-files"
        jq --slurp . "$TMPDIR/file-records.ndjson" > "$TMPDIR/files.json"
        files_json="$(jq --compact-output --sort-keys . "$TMPDIR/files.json")"
        bundle_digest="sha256:$({
          printf '%s\0%s\0%s' \
            'kaiba.provisioning.rpi5-delegated-release-spike.v1alpha1' \
            ${lib.escapeShellArg releaseID} \
            "$files_json"
        } | sha256sum | cut -d ' ' -f 1)"
        jq --null-input --sort-keys \
          --arg schema_version 'kaiba.provisioning.rpi5-delegated-release-spike/v1alpha1' \
          --arg release_id ${lib.escapeShellArg releaseID} \
          --arg source_revision ${lib.escapeShellArg sourceRevision} \
          --arg bundle_digest "$bundle_digest" \
          --argjson files "$files_json" \
          '{
            schema_version: $schema_version,
            release_id: $release_id,
            source_revision: $source_revision,
            storage_format: "nvme-directory-payload",
            bundle_digest: $bundle_digest,
            files: $files,
            signature_verification: "deferred_to_stable_verifier",
            hardware_observed: false,
            production_ready: false
          }' > "$out/manifest.json"
        chmod 0444 "$out/manifest.json"
      '';

  mkRpi5StableVerifierSpikeRig =
    {
      stableVerifierUnsignedBoot,
      bootSignature,
      firmwareSigningPublicKey,
      delegatedRelease,
      bootFilesystemSizeMiB ? 128,
      name ? "kaiba-rpi5-stable-verifier-spike-rig",
    }:
    assert lib.assertMsg (
      builtins.isAttrs delegatedRelease && delegatedRelease ? kaibaRpi5DelegatedReleaseSpike
    ) "delegatedRelease must be produced by mkRpi5DelegatedReleaseSpike";
    let
      testSD = mkRpi5StableVerifierTestSD {
        inherit
          bootFilesystemSizeMiB
          bootSignature
          firmwareSigningPublicKey
          stableVerifierUnsignedBoot
          ;
        name = "${name}-test-sd";
      };
      rig = pkgs.linkFarm name [
        {
          name = "test-sd";
          path = testSD;
        }
        {
          name = "nvme-release";
          path = "${delegatedRelease}/nvme-release";
        }
      ];
    in
    rig.overrideAttrs (previous: {
      passthru = (previous.passthru or { }) // {
        kaibaRpi5StableVerifierSpikeRig = {
          inherit delegatedRelease stableVerifierUnsignedBoot testSD;
          hardwareObserved = false;
          privateKeyAccess = false;
          productionReady = false;
        };
      };
      meta = (previous.meta or { }) // {
        description = "Development-only initramfs verifier SD and NVMe release inputs";
        platforms = lib.platforms.linux;
      };
    });

  mkRpi5StableVerifierSpikeContractCheck =
    {
      stableVerifierModule ? ./modules/stable-verifier-spike.nix,
      verifierPackage ? null,
    }:
    let
      fixtureFirmware = pkgs.runCommand "kaiba-stable-verifier-fixture-firmware" { } ''
        mkdir -p "$out/overlays"
        printf '%s\n' 'console=serial0,115200' > "$out/cmdline.txt"
        printf '%s\n' 'fixture-kernel' > "$out/kernel_2712.img"
        printf '%s\n' 'fixture-initramfs' > "$out/initramfs_2712"
        printf '%s\n' 'fixture-device-tree' > "$out/bcm2712-rpi-5-b.dtb"
        printf '%s\n' 'fixture-overlay' > "$out/overlays/README"
      '';
      fixtureVerifier =
        (pkgs.writeShellScriptBin "kaiba-rpi5-stable-verifier" ''
          exit 1
        '').overrideAttrs
          (previous: {
            passthru = (previous.passthru or { }) // {
              kaibaRpi5StableVerifier = {
                runtimeBoundary = "initramfs_only";
                staticallyLinked = true;
                kexecCapable = true;
                nonProductionOnly = true;
                productionReady = false;
                hardwareObserved = false;
                privateKeyMaterialEmbedded = false;
                authoritySigningCapable = false;
                signingAuthorityConfigured = false;
              };
            };
          });
      checkedVerifierPackage = if verifierPackage == null then fixtureVerifier else verifierPackage;
      fixturePolicy = pkgs.writeText "stable-verifier-policy.json" (
        builtins.toJSON {
          schema_version = "kaiba.provisioning.rpi5-stable-verifier-policy/v1alpha1";
          policy_id = "policy:test";
          root_signature = {
            key_id = "root:test";
            algorithm = "rsa-2048-sha256-pkcs1v15";
            value = lib.concatStrings (builtins.genList (_: "A") 344);
          };
        }
      );
      fixtureRootPublicKey = ../tests/fixtures/signed-boot-finalizer-public.pem;
      fixtureAuthorityCA = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
      fixtureSignedBootImage = pkgs.writeText "kaiba-signed-boot-finalizer-boot.img" ''
        kaiba signed-boot finalizer fixture
      '';
      fixtureSignedBoot =
        pkgs.runCommand "kaiba-stable-verifier-signed-boot-fixture"
          {
            passthru.kaibaRpi5StableVerifierUnsignedBoot = {
              rootPublicKey = fixtureRootPublicKey;
            };
          }
          ''
            mkdir -p "$out"
            install -m 0444 ${fixtureSignedBootImage} "$out/boot.img"
          '';
      fixtureTestSD = mkRpi5StableVerifierTestSD {
        stableVerifierUnsignedBoot = fixtureSignedBoot;
        bootSignature = ../tests/fixtures/signed-boot-finalizer/boot.sig;
        firmwareSigningPublicKey = fixtureRootPublicKey;
        bootFilesystemSizeMiB = 112;
      };
      fixtureRelease = pkgs.runCommand "kaiba-delegated-release-fixture" { } ''
        mkdir -p "$out/overlays"
        printf '%s\n' '{"schema_version":"kaiba.provisioning.rpi5-delegated-release-manifest/v1alpha1"}' \
          > "$out/release-manifest.json"
        printf '%s\n' fixture-kernel > "$out/kernel"
        printf '%s\n' fixture-initramfs > "$out/initramfs"
        printf '%s\n' fixture-dtb > "$out/device-tree.dtb"
        printf '%s\n' fixture-overlay > "$out/overlays/fixture.dtbo"
        printf '%s\n' 'console=serial0,115200' > "$out/cmdline.txt"
        printf '%s\n' fixture-root-data > "$out/root.img"
        printf '%s\n' '{"root_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' \
          > "$out/dm-verity.json"
        printf '%s\n' a > "$out/slot.txt"
      '';
      fixtureReleaseNoOverlays = pkgs.runCommand "kaiba-delegated-release-no-overlays-fixture" { } ''
        mkdir -p "$out"
        printf '%s\n' '{"schema_version":"kaiba.provisioning.rpi5-delegated-release-manifest/v1alpha1"}' \
          > "$out/release-manifest.json"
        printf '%s\n' fixture-kernel > "$out/kernel"
        printf '%s\n' fixture-initramfs > "$out/initramfs"
        printf '%s\n' fixture-dtb > "$out/device-tree.dtb"
        printf '%s\n' 'console=serial0,115200' > "$out/cmdline.txt"
        printf '%s\n' fixture-root-data > "$out/root.img"
        printf '%s\n' '{"root_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' \
          > "$out/dm-verity.json"
        printf '%s\n' a > "$out/slot.txt"
      '';
      fixtureSourceRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      unsignedBoot = mkRpi5StableVerifierUnsignedBoot {
        firmwareTree = fixtureFirmware;
        firmwareAllowlist = [
          "bcm2712-rpi-5-b.dtb"
          "cmdline.txt"
          "initramfs_2712"
          "kernel_2712.img"
          "overlays/README"
        ];
        verifierPackage = checkedVerifierPackage;
        stableVerifierPolicy = fixturePolicy;
        rootPublicKey = fixtureRootPublicKey;
        authorityCACertificate = fixtureAuthorityCA;
        sourceRevision = fixtureSourceRevision;
        piPlatformSourceRevision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        piPlatformSourceNarHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        bootImageSizeMiB = 32;
      };
      delegatedRelease = mkRpi5DelegatedReleaseSpike {
        releaseTree = fixtureRelease;
        releaseAllowlist = [
          "cmdline.txt"
          "device-tree.dtb"
          "dm-verity.json"
          "initramfs"
          "kernel"
          "overlays/fixture.dtbo"
          "release-manifest.json"
          "root.img"
          "slot.txt"
        ];
        releaseID = "release:test";
        sourceRevision = fixtureSourceRevision;
      };
      delegatedReleaseNoOverlays = mkRpi5DelegatedReleaseSpike {
        releaseTree = fixtureReleaseNoOverlays;
        releaseAllowlist = delegatedReleaseFixedPaths;
        releaseID = "release:no-overlays";
        sourceRevision = fixtureSourceRevision;
      };
      nonCanonicalOverlayRejected =
        !(builtins.tryEval (mkRpi5DelegatedReleaseSpike {
          releaseTree = fixtureRelease;
          releaseAllowlist = [
            "cmdline.txt"
            "device-tree.dtb"
            "dm-verity.json"
            "initramfs"
            "kernel"
            "overlays/Not_Canonical.dtbo"
            "release-manifest.json"
            "root.img"
            "slot.txt"
          ];
          releaseID = "release:invalid-overlay";
          sourceRevision = fixtureSourceRevision;
        })).success;
      fixtureRig = mkRpi5StableVerifierSpikeRig {
        stableVerifierUnsignedBoot = fixtureSignedBoot;
        bootSignature = ../tests/fixtures/signed-boot-finalizer/boot.sig;
        firmwareSigningPublicKey = fixtureRootPublicKey;
        delegatedRelease = delegatedRelease;
        bootFilesystemSizeMiB = 112;
      };
      evaluated =
        (lib.nixosSystem {
          system = pkgs.stdenv.hostPlatform.system;
          modules = [
            {
              boot.loader.grub.devices = [ "nodev" ];
              fileSystems."/" = {
                device = "none";
                fsType = "tmpfs";
              };
              system.stateVersion = "26.05";
            }
            stableVerifierModule
            {
              kaiba.stableVerifierSpike = {
                enable = true;
                package = checkedVerifierPackage;
                policy = fixturePolicy;
                rootPublicKey = fixtureRootPublicKey;
                authorityCACertificate = fixtureAuthorityCA;
                authorityKeyID = "authority:test";
                audience = "verifier:test";
                verifierVersion = 1;
                cohortID = "cohort:test";
                slotID = "a";
                minimumSecurityEpoch = 0;
                authorityURL = "https://192.0.2.10:8443";
                logicalIdentity = "rpi5-spike:test";
                networkInterface = "eth0";
              };
            }
          ];
        }).config;
      moduleAssertionsPass = builtins.all (assertion: assertion.assertion) evaluated.assertions;
      verifierService = evaluated.boot.initrd.systemd.services.kaiba-stable-verifier;
      verifierExecStart = verifierService.serviceConfig.ExecStart;
      moduleBoundary =
        moduleAssertionsPass
        && evaluated.boot.initrd.systemd.enable
        && !evaluated.boot.initrd.systemd.emergencyAccess
        && !evaluated.boot.initrd.systemd.shell.enable
        && evaluated.boot.initrd.systemd.network.enable
        && builtins.elem "nvme" evaluated.boot.initrd.availableKernelModules
        && verifierService.unitConfig.FailureAction == "poweroff-force"
        && verifierService.unitConfig.SuccessAction == "poweroff-force"
        && verifierService.serviceConfig.NoNewPrivileges
        && verifierService.serviceConfig.PrivateDevices
        && verifierService.serviceConfig.ProtectKernelModules
        && verifierService.serviceConfig.ProtectKernelTunables
        && verifierService.serviceConfig.ProtectSystem == "strict"
        && verifierService.serviceConfig.ReadOnlyPaths == [ "/run/kaiba-release" ]
        &&
          verifierService.serviceConfig.CapabilityBoundingSet == [
            "CAP_SYS_ADMIN"
            "CAP_SYS_BOOT"
          ]
        &&
          verifierService.serviceConfig.AmbientCapabilities == [
            "CAP_SYS_ADMIN"
            "CAP_SYS_BOOT"
          ]
        && verifierService.serviceConfig.SystemCallFilter == [ "~@mount" ]
        && lib.hasInfix "--policy" verifierExecStart
        && lib.hasInfix "--root-public-key" verifierExecStart
        && lib.hasInfix "--release-dir" verifierExecStart
        && lib.hasInfix "--verifier-version" verifierExecStart
        && lib.hasInfix "--cohort-id" verifierExecStart
        && lib.hasInfix "--slot-id" verifierExecStart
        && lib.hasInfix "--minimum-security-epoch" verifierExecStart
        && lib.hasInfix "--authority-url" verifierExecStart
        && lib.hasInfix "--authority-ca" verifierExecStart
        && lib.hasInfix "--authority-key-id" verifierExecStart
        && lib.hasInfix "--audience" verifierExecStart
        && lib.hasInfix "--logical-identity" verifierExecStart
        && lib.hasInfix "--kexec" verifierExecStart
        && !(lib.hasInfix "--policy-signature" verifierExecStart)
        && !evaluated.services.openssh.enable;
    in
    assert lib.assertMsg nonCanonicalOverlayRejected
      "delegated-release constructor admitted a non-canonical overlay path";
    assert lib.assertMsg moduleBoundary
      "stable-verifier initramfs module evaluation did not preserve its fail-closed boundary";
    pkgs.runCommand "kaiba-rpi5-stable-verifier-spike-contract-check"
      {
        unsignedBootInput = unsignedBoot;
        delegatedReleaseInput = delegatedRelease;
        delegatedReleaseNoOverlaysInput = delegatedReleaseNoOverlays;
        rigInput = fixtureRig;
        testSDInput = fixtureTestSD;
        modulePublicInputs = evaluated.system.build.kaibaStableVerifierPublicInputs;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.findutils
          pkgs.jq
          pkgs.mtools
        ];
      }
      ''
        set -euo pipefail
        test -f "$unsignedBootInput/boot.img"
        jq -e '
          .signing_status == "unsigned_requires_external_root_signature"
          and .hardware_observed == false
          and .production_ready == false
          and (.files | index("kaiba/stable-verifier")) != null
          and (.files | index("kaiba/stable-verifier-policy.json")) != null
        ' "$unsignedBootInput/manifest.json" > /dev/null
        mdir -b -i "$unsignedBootInput/boot.img" ::kaiba/stable-verifier > /dev/null
        mdir -b -i "$unsignedBootInput/boot.img" ::kaiba/stable-verifier-policy.json > /dev/null

        test -f "$testSDInput/boot-filesystem.img"
        jq -e '
          .root_signature_verified == true
          and .storage_format == "fat-filesystem-image-not-whole-disk"
          and .hardware_observed == false
          and .production_ready == false
        ' "$testSDInput/manifest.json" > /dev/null
        mdir -b -i "$testSDInput/boot-filesystem.img" ::boot.img > /dev/null
        mdir -b -i "$testSDInput/boot-filesystem.img" ::boot.sig > /dev/null
        mdir -b -i "$testSDInput/boot-filesystem.img" ::config.txt > /dev/null

        test -f "$modulePublicInputs/policy.json"
        test -f "$modulePublicInputs/root-public.pem"
        test -f "$modulePublicInputs/authority-ca.pem"

        test -d "$delegatedReleaseInput/nvme-release"
        jq -e '
          .storage_format == "nvme-directory-payload"
          and .signature_verification == "deferred_to_stable_verifier"
          and .hardware_observed == false
          and .production_ready == false
          and (.files | length) == 9
        ' "$delegatedReleaseInput/manifest.json" > /dev/null
        find "$delegatedReleaseInput/nvme-release" -type f -printf '%P\n' | sort \
          > "$TMPDIR/actual-release-files"
        printf '%s\n' \
          cmdline.txt \
          device-tree.dtb \
          dm-verity.json \
          initramfs \
          kernel \
          overlays/fixture.dtbo \
          release-manifest.json \
          root.img \
          slot.txt \
          > "$TMPDIR/expected-release-files"
        cmp "$TMPDIR/expected-release-files" "$TMPDIR/actual-release-files"

        test -d "$delegatedReleaseNoOverlaysInput/nvme-release/overlays"
        test -z "$(find "$delegatedReleaseNoOverlaysInput/nvme-release/overlays" -mindepth 1 -print -quit)"

        test -f "$rigInput/test-sd/boot-filesystem.img"
        test -f "$rigInput/nvme-release/kernel"
        test ! -e "$rigInput/nvme-release/nvme-release"

        mkdir -p "$out"
        printf '%s\n' 'stable verifier spike Nix contracts: pass' > "$out/results.txt"
      '';
in
{
  inherit
    mkRpi5DelegatedReleaseSpike
    mkRpi5StableVerifierSpikeContractCheck
    mkRpi5StableVerifierSpikeRig
    mkRpi5StableVerifierTestSD
    mkRpi5StableVerifierUnsignedBoot
    ;
}
