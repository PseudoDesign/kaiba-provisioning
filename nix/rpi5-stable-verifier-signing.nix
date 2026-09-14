{
  lib,
  pkgs,
  signingReceiptsTool,
  stableVerifierSigningTool,
}:

let
  canonicalDigest =
    value: builtins.isString value && builtins.match "sha256:[0-9a-f]{64}" value != null;
  canonicalRevision =
    value:
    builtins.isString value
    && (builtins.match "[0-9a-f]{40}" value != null || builtins.match "[0-9a-f]{64}" value != null);
  canonicalEpoch = value: builtins.isInt value && value > 0 && value <= 253402300799;
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

  signingIntentSchema = ../schemas/rpi5-stable-campaign-verifier-signing-intent-v1alpha1.schema.json;
  signingApprovalSchema = ../schemas/rpi5-stable-campaign-verifier-signing-approval-v1alpha1.schema.json;
  signingPlanSchema = ../schemas/rpi5-boot-signing-plan-v1alpha2.schema.json;
  receiptVerificationSchema = ../schemas/signing-gate-receipt-verification-v1alpha2.schema.json;
  independentSignerReview = builtins.fromJSON (
    builtins.readFile ../signers/development-prototype/independent-review-2026-08-27.json
  );
  productionProfile = {
    bootImageSizeBytes = 100663296;
    expectedCustomerKeyHash = independentSignerReview.public_bindings.customer_key_hash;
    publicKeyFileDigest = "sha256:${independentSignerReview.public_bindings.public_key_file_sha256}";
    publicKeyFingerprint = independentSignerReview.public_bindings.public_key_fingerprint;
    reviewedPublicKeyPEM = ../signers/development-prototype/reviewed-boot-public.pem;
    signerPolicyDigest = independentSignerReview.public_bindings.signer_policy_digest;
  };
  mkUnsignedManifestBindingsValidator =
    {
      sourceRevision,
      piPlatformSourceRevision,
      piPlatformSourceNarHash,
      expectedFiles,
    }:
    pkgs.writeShellApplication {
      name = "kaiba-stable-verifier-unsigned-manifest-bindings";
      runtimeInputs = [
        pkgs.coreutils
        pkgs.jq
      ];
      text = ''
        test "$#" -eq 1
        readonly manifest=$1
        test -f "$manifest"
        test ! -L "$manifest"
        test -s "$manifest"
        test "$(stat --format=%s "$manifest")" -le 65536
        jq -e \
          --arg source_revision ${lib.escapeShellArg sourceRevision} \
          --arg platform_revision ${lib.escapeShellArg piPlatformSourceRevision} \
          --arg platform_nar_hash ${lib.escapeShellArg piPlatformSourceNarHash} \
          --argjson files ${lib.escapeShellArg (builtins.toJSON expectedFiles)} '
            .source_revision == $source_revision
            and .pi_platform_source.revision == $platform_revision
            and .pi_platform_source.nar_hash == $platform_nar_hash
            and .files == $files
          ' "$manifest" > /dev/null
      '';
    };

  # Construct the deterministic, authority-free public plan for the sole
  # stable-verifier signing operation. The unsigned artifact derivation is
  # revalidated from bytes; its passthru is only an evaluation-time type
  # boundary, never the source of an artifact digest.
  mkSigningPlanForProfile =
    profile:
    {
      sourceDateEpoch,
      sourceRevision,
      stableVerifierUnsignedBoot,
      name ? "kaiba-rpi5-stable-campaign-verifier-signing-plan",
    }:
    let
      inherit (profile)
        bootImageSizeBytes
        expectedCustomerKeyHash
        publicKeyFileDigest
        publicKeyFingerprint
        reviewedPublicKeyPEM
        signerPolicyDigest
        ;
    in
    assert lib.assertMsg (storeBacked stableVerifierUnsignedBoot)
      "stableVerifierUnsignedBoot must be a fixed Nix-store path";
    assert lib.assertMsg (
      builtins.isAttrs stableVerifierUnsignedBoot
      && stableVerifierUnsignedBoot ? kaibaRpi5StableVerifierUnsignedBoot
    ) "stableVerifierUnsignedBoot must be the typed unsigned stable verifier boot artifact";
    assert lib.assertMsg (
      let
        contract = stableVerifierUnsignedBoot.kaibaRpi5StableVerifierUnsignedBoot;
      in
      (contract.artifactSchemaVersion or null)
      == "kaiba.provisioning.rpi5-stable-verifier-boot-artifact/v1alpha1"
      && (contract.status or null) == "unsigned_requires_external_root_signature"
      && !(contract.signingAuthorityConfigured or true)
      && !(contract.blockDeviceWriteCapable or true)
      && !(contract.privateKeyAccess or true)
      && !(contract.hardwareObserved or true)
      && !(contract.productionReady or true)
      && !(contract.signatureVerified or true)
    ) "stableVerifierUnsignedBoot is not the authority-free unsigned verifier artifact";
    assert lib.assertMsg (storeBacked reviewedPublicKeyPEM)
      "reviewedPublicKeyPEM must be a fixed Nix-store path";
    assert lib.assertMsg (canonicalDigest expectedCustomerKeyHash)
      "expectedCustomerKeyHash must use canonical sha256:<64 lowercase hex> form";
    assert lib.assertMsg (canonicalDigest publicKeyFileDigest)
      "publicKeyFileDigest must use canonical sha256:<64 lowercase hex> form";
    assert lib.assertMsg (canonicalDigest publicKeyFingerprint)
      "publicKeyFingerprint must use canonical sha256:<64 lowercase hex> form";
    assert lib.assertMsg (canonicalDigest signerPolicyDigest)
      "signerPolicyDigest must use canonical sha256:<64 lowercase hex> form";
    assert lib.assertMsg (canonicalRevision sourceRevision)
      "sourceRevision must contain 40 or 64 lowercase hexadecimal characters";
    assert lib.assertMsg (canonicalEpoch sourceDateEpoch)
      "sourceDateEpoch must be a positive canonical Unix timestamp";
    assert lib.assertMsg (
      stableVerifierUnsignedBoot.kaibaRpi5StableVerifierUnsignedBoot.sourceRevision == sourceRevision
    ) "stableVerifierUnsignedBoot passthru does not match the selected source";
    let
      planID = "plan:rpi5-stable-verifier:${builtins.substring 0 16 sourceRevision}";
      unsignedContract = stableVerifierUnsignedBoot.kaibaRpi5StableVerifierUnsignedBoot;
      expectedFiles = lib.sort builtins.lessThan (
        unsignedContract.firmwareAllowlist
        ++ [
          "kaiba/authority-ca.pem"
          "kaiba/provenance.json"
          "kaiba/root-public.pem"
          "kaiba/stable-verifier"
          "kaiba/stable-verifier-policy.json"
        ]
      );
      manifestBindingsValidator = mkUnsignedManifestBindingsValidator {
        inherit sourceRevision expectedFiles;
        inherit (unsignedContract) piPlatformSourceRevision piPlatformSourceNarHash;
      };
    in
    pkgs.runCommand name
      {
        stableVerifierUnsignedBootInput = stableVerifierUnsignedBoot;
        reviewedPublicKeyInput = reviewedPublicKeyPEM;
        nativeBuildInputs = [
          pkgs.check-jsonschema
          pkgs.coreutils
          pkgs.findutils
          pkgs.jq
          pkgs.openssl
          (pkgs.python3.withPackages (pythonPackages: [ pythonPackages.pycryptodomex ]))
          stableVerifierSigningTool
        ];
        passthru.kaibaStableVerifierSigningPlan = {
          inherit
            expectedCustomerKeyHash
            planID
            publicKeyFileDigest
            publicKeyFingerprint
            reviewedPublicKeyPEM
            signerPolicyDigest
            sourceDateEpoch
            sourceRevision
            stableVerifierUnsignedBoot
            ;
          authorizationScope = "stable_campaign_verifier_boot";
          blockDeviceWriteCapable = false;
          directHardwareAccess = false;
          eepromProgrammingCapable = false;
          intentSchemaVersion = "kaiba.provisioning.rpi5-stable-campaign-verifier-signing-intent/v1alpha1";
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          privateKeyAccess = false;
          signingAuthorityConfigured = false;
          signingInputCount = 1;
        };
        meta = {
          description = "Deterministic public signing plan for the stable Pi 5 verifier";
          platforms = lib.platforms.linux;
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        umask 022

        for input in \
          "$stableVerifierUnsignedBootInput/manifest.json" \
          "$stableVerifierUnsignedBootInput/boot.img" \
          "$reviewedPublicKeyInput"
        do
          test -f "$input"
          test ! -L "$input"
          test -s "$input"
        done

        # The new intent binds these exact manifest bytes. Its schema describes
        # this verifier image, never the provisioner/root artifact set.
        ${manifestBindingsValidator}/bin/kaiba-stable-verifier-unsigned-manifest-bindings \
          "$stableVerifierUnsignedBootInput/manifest.json"
        unsigned_manifest_digest="sha256:$(
          sha256sum "$stableVerifierUnsignedBootInput/manifest.json" | cut -d ' ' -f 1
        )"
        boot_image_size_bytes="$(
          stat --format=%s "$stableVerifierUnsignedBootInput/boot.img"
        )"
        test "$boot_image_size_bytes" -eq ${toString bootImageSizeBytes}
        boot_image_digest="sha256:$(
          sha256sum "$stableVerifierUnsignedBootInput/boot.img" | cut -d ' ' -f 1
        )"
        jq -e \
          --arg digest "$boot_image_digest" \
          --argjson size_bytes "$boot_image_size_bytes" '
            .boot_image.size_bytes == $size_bytes
            and .boot_image.sha256 == $digest
          ' "$stableVerifierUnsignedBootInput/manifest.json" > /dev/null

        test "sha256:$(sha256sum "$reviewedPublicKeyInput" | cut -d ' ' -f 1)" = \
          '${publicKeyFileDigest}'
        openssl rsa \
          -pubin \
          -in "$reviewedPublicKeyInput" \
          -pubout \
          -out "$TMPDIR/canonical-public.pem"
        cmp "$reviewedPublicKeyInput" "$TMPDIR/canonical-public.pem"
        test "$({
          openssl pkey -pubin -in "$reviewedPublicKeyInput" -outform DER
        } | sha256sum | sed 's/^/sha256:/' | cut -d ' ' -f 1)" = \
          '${publicKeyFingerprint}'
        python3 \
          ${pkgs.raspberrypi-eeprom.src}/tools/rpi-bootloader-key-convert \
          "$reviewedPublicKeyInput" \
          --output "$TMPDIR/customer-public-key.bin"
        test "sha256:$(sha256sum "$TMPDIR/customer-public-key.bin" | cut -d ' ' -f 1)" = \
          '${expectedCustomerKeyHash}'

        mkdir "$out"
        install -m 0444 \
          "$stableVerifierUnsignedBootInput/boot.img" \
          "$out/boot.img"
        install -m 0444 "$reviewedPublicKeyInput" "$out/public.pem"

        jq \
          --null-input \
          --compact-output \
          --arg schema_version \
            'kaiba.provisioning.rpi5-stable-campaign-verifier-signing-intent/v1alpha1' \
          --arg authorization_scope 'stable_campaign_verifier_boot' \
          --arg source_revision '${sourceRevision}' \
          --argjson source_date_epoch '${toString sourceDateEpoch}' \
          --arg unsigned_manifest_digest "$unsigned_manifest_digest" \
          --arg expected_customer_key_hash '${expectedCustomerKeyHash}' \
          --arg public_key_file_digest '${publicKeyFileDigest}' \
          --arg public_key_fingerprint '${publicKeyFingerprint}' \
          --arg signer_policy_digest '${signerPolicyDigest}' \
          --arg signing_input_role 'rpi5.boot_image' \
          --arg signing_input_digest "$boot_image_digest" \
          --argjson signing_input_size_bytes "$boot_image_size_bytes" '
            {
              schema_version: $schema_version,
              authorization_scope: $authorization_scope,
              source_revision: $source_revision,
              source_date_epoch: $source_date_epoch,
              unsigned_manifest_digest: $unsigned_manifest_digest,
              expected_customer_key_hash: $expected_customer_key_hash,
              public_key_file_digest: $public_key_file_digest,
              public_key_fingerprint: $public_key_fingerprint,
              signer_policy_digest: $signer_policy_digest,
              signing_input: {
                role: $signing_input_role,
                digest: $signing_input_digest,
                size_bytes: $signing_input_size_bytes
              }
            }
          ' > "$out/release-intent.json"
        chmod 0444 "$out/release-intent.json"

        release_intent_json="$(cat "$out/release-intent.json")"
        release_intent_digest="sha256:$({
          printf '%s\0' \
            'kaiba.provisioning.rpi5-stable-campaign-verifier-signing-intent.v1alpha1'
          printf '%s' "$release_intent_json"
        } | sha256sum | cut -d ' ' -f 1)"
        jq \
          --null-input \
          --compact-output \
          --arg schema_version 'kaiba.provisioning.rpi5-boot-signing-plan/v1alpha2' \
          --arg plan_id '${planID}' \
          --arg release_intent_digest "$release_intent_digest" \
          --arg boot_image_digest "$boot_image_digest" \
          --argjson boot_image_size_bytes "$boot_image_size_bytes" \
          --arg public_key_fingerprint '${publicKeyFingerprint}' \
          --arg signer_policy_digest '${signerPolicyDigest}' \
          --argjson source_date_epoch '${toString sourceDateEpoch}' '
            {
              schema_version: $schema_version,
              plan_id: $plan_id,
              release_intent_digest: $release_intent_digest,
              boot_image_digest: $boot_image_digest,
              boot_image_size_bytes: $boot_image_size_bytes,
              public_key_fingerprint: $public_key_fingerprint,
              signer_policy_digest: $signer_policy_digest,
              source_date_epoch: $source_date_epoch
            }
          ' > "$out/plan.json"
        chmod 0444 "$out/plan.json"

        check-jsonschema --schemafile ${signingIntentSchema} "$out/release-intent.json"
        check-jsonschema --schemafile ${signingPlanSchema} "$out/plan.json"
        kaiba-rpi5-stable-verifier-signing validate-plan --plan "$out"
        kaiba-rpi5-stable-verifier-signing validate-unsigned \
          --plan "$out" \
          --manifest "$stableVerifierUnsignedBootInput/manifest.json"

        find "$out" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
          > "$TMPDIR/actual-plan-files"
        printf '%s\n' boot.img plan.json public.pem release-intent.json \
          > "$TMPDIR/expected-plan-files"
        cmp "$TMPDIR/expected-plan-files" "$TMPDIR/actual-plan-files"
      '';

  mkRpi5StableVerifierSigningPlan = args: mkSigningPlanForProfile productionProfile args;

  # Admit a public signing result only after independently validating the
  # stable authorization, boot signature/result binding, and the complete
  # gate receipt attestation.  The expected receipt digest is read solely from
  # the live signing-result handoff, never inferred from the receipt export.
  mkRpi5VerifiedStableVerifierSigning =
    {
      authorization,
      receiptExport,
      signedOutput,
      signingPlan,
      name ? "kaiba-rpi5-verified-stable-verifier-signing",
    }:
    assert lib.assertMsg (lib.all storeBacked [
      authorization
      receiptExport
      signedOutput
      signingPlan
    ]) "every stable signing verification input must be a fixed Nix-store path";
    assert lib.assertMsg (
      builtins.isAttrs signingPlan && signingPlan ? kaibaStableVerifierSigningPlan
    ) "signingPlan must be produced by mkRpi5StableVerifierSigningPlan";
    let
      planContract = signingPlan.kaibaStableVerifierSigningPlan;
    in
    pkgs.runCommand name
      {
        authorizationInput = authorization;
        receiptExportInput = receiptExport;
        signedOutputInput = signedOutput;
        signingPlanInput = signingPlan;
        stableVerifierUnsignedBootInput = planContract.stableVerifierUnsignedBoot;
        nativeBuildInputs = [
          pkgs.check-jsonschema
          pkgs.coreutils
          pkgs.findutils
          pkgs.jq
          signingReceiptsTool
          stableVerifierSigningTool
        ];
        passthru.kaibaVerifiedStableVerifierSigning = {
          inherit
            authorization
            receiptExport
            signedOutput
            signingPlan
            ;
          authorizationScope = "stable_campaign_verifier_boot";
          authenticatedReceiptCount = 1;
          blockDeviceWriteCapable = false;
          directHardwareAccess = false;
          eepromProgrammingCapable = false;
          mutationCapable = false;
          oneTimeSettingCapable = false;
          otpCapable = false;
          privateKeyAccess = false;
          receiptAttestationRequired = true;
          signingAuthorityConfigured = false;
          verificationMode = "authenticated_offline";
        };
        meta = {
          description = "Authenticated stable-verifier Pi 5 boot-signing evidence";
          platforms = lib.platforms.linux;
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        umask 022

        for directory in \
          "$authorizationInput" \
          "$signedOutputInput" \
          "$signingPlanInput"
        do
          test -d "$directory"
          test ! -L "$directory"
        done
        find "$authorizationInput" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
          > "$TMPDIR/actual-authorization-files"
        printf '%s\n' \
          approval.json \
          signing-grants.json \
          > "$TMPDIR/expected-authorization-files"
        cmp "$TMPDIR/expected-authorization-files" "$TMPDIR/actual-authorization-files"
        for input in \
          "$authorizationInput/approval.json" \
          "$authorizationInput/signing-grants.json" \
          "$receiptExportInput" \
          "$signedOutputInput/boot.sig" \
          "$signedOutputInput/signing-result.json" \
          "$signingPlanInput/public.pem" \
          "$signingPlanInput/release-intent.json" \
          "$stableVerifierUnsignedBootInput/manifest.json"
        do
          test -f "$input"
          test ! -L "$input"
          test -s "$input"
        done

        check-jsonschema \
          --schemafile ${signingApprovalSchema} \
          "$authorizationInput/approval.json"
        kaiba-rpi5-stable-verifier-signing validate-authorization \
          --plan "$signingPlanInput" \
          --approval "$authorizationInput/approval.json" \
          --registry "$authorizationInput/signing-grants.json"
        kaiba-rpi5-stable-verifier-signing validate-unsigned \
          --plan "$signingPlanInput" \
          --manifest "$stableVerifierUnsignedBootInput/manifest.json"

        mkdir "$TMPDIR/finalized"
        rmdir "$TMPDIR/finalized"
        kaiba-rpi5-stable-verifier-signing finalize \
          --plan "$signingPlanInput" \
          --signed "$signedOutputInput" \
          --approval "$authorizationInput/approval.json" \
          --registry "$authorizationInput/signing-grants.json" \
          --receipt-export "$receiptExportInput" \
          --output "$TMPDIR/finalized"

        live_receipt_digest="$(
          jq --exit-status --raw-output \
            '.gate_receipt_digest | select(type == "string")' \
            "$signedOutputInput/signing-result.json"
        )"
        test "$(printf '%s' "$live_receipt_digest" | grep -Ec '^sha256:[0-9a-f]{64}$')" -eq 1

        kaiba-provision-signing-receipts verify \
          --export "$receiptExportInput" \
          --registry "$authorizationInput/signing-grants.json" \
          --public-key "$signingPlanInput/public.pem" \
          --expected-receipt-digest "$live_receipt_digest" \
          > "$TMPDIR/receipt-verification.json"
        check-jsonschema \
          --schemafile ${receiptVerificationSchema} \
          "$TMPDIR/receipt-verification.json"
        jq -e \
          --arg digest "$live_receipt_digest" '
            .schema_version
              == "kaiba.provisioning.signing-gate-receipt-verification/v1alpha2"
            and .status == "valid"
            and .receipt_digests == [$digest]
          ' "$TMPDIR/receipt-verification.json" > /dev/null

        mkdir "$out"
        for name in \
          boot.img \
          boot.sig \
          manifest.json \
          public.pem \
          release-intent.json \
          signing-plan.json \
          signing-result.json
        do
          install -m 0444 "$TMPDIR/finalized/$name" "$out/$name"
        done
        install -m 0444 \
          "$stableVerifierUnsignedBootInput/manifest.json" \
          "$out/unsigned-artifact-manifest.json"
        install -m 0444 \
          "$authorizationInput/approval.json" \
          "$out/approval.json"
        install -m 0444 \
          "$authorizationInput/signing-grants.json" \
          "$out/signing-grants.json"
        install -m 0444 "$receiptExportInput" "$out/signing-receipts.json"
        install -m 0444 \
          "$TMPDIR/receipt-verification.json" \
          "$out/receipt-verification.json"

        test "sha256:$(sha256sum "$out/unsigned-artifact-manifest.json" | cut -d ' ' -f 1)" = \
          "$(jq -r .unsigned_manifest_digest "$out/release-intent.json")"
        find "$out" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort \
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
      '';
in
{
  inherit
    mkRpi5StableVerifierSigningPlan
    mkRpi5VerifiedStableVerifierSigning
    ;
  _testOnly = {
    inherit mkSigningPlanForProfile mkUnsignedManifestBindingsValidator;
  };
}
