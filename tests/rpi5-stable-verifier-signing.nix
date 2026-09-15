{
  built,
  lib,
  pkgs,
}:

let
  constructors = import ../nix/rpi5-stable-verifier-signing.nix {
    inherit lib pkgs;
    inherit (built) signingReceiptsTool stableVerifierSigningTool;
  };
  fixtureSourceRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  fixtureSourceDateEpoch = 1786968000;
  fixtureCustomerKeyHash = "sha256:5c9dcff802e78926082845de8de77800f34cfa80dfda9c4fc2d208237e933e5e";
  fixturePublicKeyFileDigest = "sha256:874984cc3d5e7348bffcb4ba0c0b703062510f21a142accfee1a3b2d37d36faa";
  fixturePublicKeyFingerprint = "sha256:56d73a770a7f8f38bbd5aeec970a32d0c94cd257594749469b946d811a0db526";
  fixtureSignerPolicyDigest = "sha256:70143c254eefe257cf59cd5e404591c91fc304eebe49f9cf0f9b6eefce6483a8";
  fixturePublicKey =
    pkgs.runCommand "kaiba-stable-verifier-signing-fixture-public-key"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.openssl
          pkgs.python3
        ];
      }
      ''
        set -euo pipefail
        python3 ${./deterministic-rsa-fixture.py} --label stable-verifier-campaign-media-test --private "$TMPDIR/private.pem"
        mkdir "$out"
        openssl pkey -in "$TMPDIR/private.pem" -pubout -out "$out/public.pem"
        test "sha256:$(sha256sum "$out/public.pem" | cut -d ' ' -f 1)" = \
          '${fixturePublicKeyFileDigest}'
        test "sha256:$(openssl pkey -pubin -in "$out/public.pem" -outform DER \
          | sha256sum | cut -d ' ' -f 1)" = '${fixturePublicKeyFingerprint}'
        chmod 0444 "$out/public.pem"
        test ! -e "$out/private.pem"
      '';
  fixtureTrust = import ./stable-verifier-vm-fixture.nix { inherit pkgs; };
  fixtureFirmware = pkgs.runCommand "kaiba-verifier-signing-fixture-firmware" { } ''
    mkdir "$out"
    printf '%s\n' 'arm_64bit=1' > "$out/config.txt"
  '';
  # Exercise the actual unsigned verifier constructor and its real FAT image
  # format. The firmware payload and signing identities remain test fixtures.
  fixtureUnsignedArtifacts = built.mkRpi5StableVerifierUnsignedBoot {
    sourceRevision = fixtureSourceRevision;
    firmwareTree = fixtureFirmware;
    firmwareAllowlist = [ "config.txt" ];
    verifierPackage = built.stableVerifierTool;
    stableVerifierPolicy = "${fixtureTrust}/policy.json";
    rootPublicKey = "${fixtureTrust}/root-public.pem";
    authorityCACertificate = "${fixtureTrust}/authority-ca.pem";
    piPlatformSourceRevision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    piPlatformSourceNarHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    bootImageSizeMiB = 32;
    name = "kaiba-verifier-signing-fixture-unsigned";
  };
  fixtureProfile = {
    bootImageSizeBytes = 33554432;
    expectedCustomerKeyHash = fixtureCustomerKeyHash;
    publicKeyFileDigest = fixturePublicKeyFileDigest;
    publicKeyFingerprint = fixturePublicKeyFingerprint;
    reviewedPublicKeyPEM = "${fixturePublicKey}/public.pem";
    signerPolicyDigest = fixtureSignerPolicyDigest;
  };
  fixtureSigningPlan = constructors._testOnly.mkSigningPlanForProfile fixtureProfile {
    name = "kaiba-stable-verifier-signing-fixture-plan";
    sourceDateEpoch = fixtureSourceDateEpoch;
    sourceRevision = fixtureSourceRevision;
    stableVerifierUnsignedBoot = fixtureUnsignedArtifacts;
  };
  fixtureManifestBindingsValidator = constructors._testOnly.mkUnsignedManifestBindingsValidator {
    sourceRevision = fixtureSourceRevision;
    inherit (fixtureUnsignedArtifacts.kaibaRpi5StableVerifierUnsignedBoot)
      piPlatformSourceRevision
      piPlatformSourceNarHash
      ;
    expectedFiles = [
      "config.txt"
      "kaiba/authority-ca.pem"
      "kaiba/provenance.json"
      "kaiba/root-public.pem"
      "kaiba/stable-verifier"
      "kaiba/stable-verifier-policy.json"
    ];
  };
  fixtureEvidence =
    pkgs.runCommand "kaiba-stable-verifier-signing-one-grant-evidence-fixture"
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
        python3 ${./deterministic-rsa-fixture.py} --label stable-verifier-campaign-media-test --private "$TMPDIR/private.pem"
        cd ${built.goSource}
        go run ./internal/provisioning/stableverifiersigning/testfixture \
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
  verifiedFixture = constructors.mkRpi5VerifiedStableVerifierSigning {
    name = "kaiba-verified-stable-verifier-signing-one-grant-fixture";
    authorization = "${fixtureEvidence}/authorization";
    receiptExport = "${fixtureEvidence}/signing-receipts.json";
    signedOutput = "${fixtureEvidence}/signed";
    signingPlan = fixtureSigningPlan;
  };
  wrongSourceRejected =
    !(builtins.tryEval (
      (constructors.mkRpi5StableVerifierSigningPlan {
        sourceDateEpoch = fixtureSourceDateEpoch;
        sourceRevision = "cccccccccccccccccccccccccccccccccccccccc";
        stableVerifierUnsignedBoot = fixtureUnsignedArtifacts;
      }).drvPath
    )).success;
  untypedPlanRejected =
    !(builtins.tryEval (
      (constructors.mkRpi5VerifiedStableVerifierSigning {
        authorization = "${fixtureEvidence}/authorization";
        receiptExport = "${fixtureEvidence}/signing-receipts.json";
        signedOutput = "${fixtureEvidence}/signed";
        signingPlan = pkgs.writeText "kaiba-untyped-stable-signing-plan" "{}";
      }).drvPath
    )).success;
  genericCampaignFixture = import ./stable-verifier-campaign-media.nix { inherit lib pkgs; };
  genericCampaign = genericCampaignFixture.fixtureBaselineMedia.kaibaRpi5StableVerifierCampaignMedia;
  fixtureSignerReview = pkgs.writeText "kaiba-verifier-signing-fixture-signer-review.json" (
    builtins.toJSON {
      schema_version = "kaiba.provisioning.signer-independent-review/v1alpha1";
      status = "passed";
      scope = "development-sacrificial-signer";
      public_bindings = {
        public_key_file_sha256 = lib.removePrefix "sha256:" fixturePublicKeyFileDigest;
        public_key_fingerprint = fixturePublicKeyFingerprint;
        customer_key_hash = fixtureCustomerKeyHash;
        signer_policy_digest = fixtureSignerPolicyDigest;
      };
      signing_authorized = false;
      production_approved = false;
    }
  );
  fixtureCampaignPlan =
    pkgs.runCommand "kaiba-verifier-signing-fixture-campaign-plan"
      { nativeBuildInputs = [ pkgs.python3 ]; }
      ''
        python3 - ${genericCampaign.campaignPlan} ${verifiedFixture} "$out" <<'PY'
        import hashlib
        import json
        import pathlib
        import sys
        plan = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
        signed_boot = pathlib.Path(sys.argv[2])
        paths = {"unsigned-verifier-boot": "boot.img", "customer-boot-public-key": "public.pem"}
        for item in plan["public_inputs"]:
            if item["name"] in paths:
                data = (signed_boot / paths[item["name"]]).read_bytes()
                item["digest"] = "sha256:" + hashlib.sha256(data).hexdigest()
                item["size_bytes"] = len(data)
        plan["plan_digest"] = ""
        material = json.dumps(plan, separators=(",", ":")).encode()
        plan["plan_digest"] = "sha256:" + hashlib.sha256(
            b"kaiba.provisioning.rpi5-stable-verifier-campaign-plan.v1alpha1\0" + material
        ).hexdigest()
        pathlib.Path(sys.argv[3]).write_bytes(json.dumps(plan, separators=(",", ":")).encode())
        PY
      '';
  releaseAllowlistFile = pkgs.writeText "kaiba-verifier-signing-fixture-release-allowlist" (
    lib.concatStringsSep "\n" genericCampaign.releaseAllowlist + "\n"
  );
  # Only extract the campaign's public validation tool: no baseline media or
  # ARM/NixOS system image is built by this check.
  verifierCampaign =
    (import ../nix/stable-verifier-campaign-media.nix {
      inherit lib pkgs;
      publicInputKeyScan = built.publicInputKeyScan;
      signerIndependentReview = fixtureSignerReview;
      expectedCustomerKeyHash = fixtureCustomerKeyHash;
      expectedPublicKeyFileSHA256 = lib.removePrefix "sha256:" fixturePublicKeyFileDigest;
      expectedPublicKeyFingerprint = fixturePublicKeyFingerprint;
    })
      {
        inherit (genericCampaign)
          campaignMutationInputs
          delegatedRelease
          rootDataPartitionGUID
          rootHashPartitionGUID
          ;
        campaignPlan = fixtureCampaignPlan;
        verifiedSignedBoot = verifiedFixture;
      };
  campaignContractTool =
    verifierCampaign.kaibaRpi5StableVerifierCampaignMedia.runArtifactMaterializationContractTool;
  contract = verifiedFixture.kaibaVerifiedStableVerifierSigning;
in
assert lib.assertMsg wrongSourceRejected
  "the verifier signing-plan constructor accepted the wrong source revision";
assert lib.assertMsg untypedPlanRejected
  "the stable signing verifier accepted an untyped signing plan";
assert lib.assertMsg (
  contract.authorizationScope == "stable_campaign_verifier_boot"
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
pkgs.runCommand "kaiba-rpi5-stable-verifier-signing-contract"
  {
    nativeBuildInputs = [
      built.signingReceiptsTool
      built.stableVerifierSigningTool
      campaignContractTool
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
      ${../schemas/rpi5-stable-campaign-verifier-signing-intent-v1alpha1.schema.json} \
      ${../schemas/rpi5-stable-campaign-verifier-signing-approval-v1alpha1.schema.json}
    check-jsonschema \
      --schemafile ${../schemas/rpi5-stable-campaign-verifier-signing-intent-v1alpha1.schema.json} \
      ${fixtureSigningPlan}/release-intent.json
    check-jsonschema \
      --schemafile ${../schemas/rpi5-stable-campaign-verifier-signing-approval-v1alpha1.schema.json} \
      ${fixtureEvidence}/authorization/approval.json
    check-jsonschema \
      --base-uri file://${built.goSource}/schemas/ \
      --schemafile ${../schemas/signing-grant-registry-v1alpha2.schema.json} \
      ${fixtureEvidence}/authorization/signing-grants.json

    kaiba-rpi5-stable-verifier-signing validate-plan \
      --plan ${fixtureSigningPlan} > "$TMPDIR/plan-verification.json"
    kaiba-rpi5-stable-verifier-signing validate-authorization \
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
    kaiba-rpi5-stable-verifier-signing finalize \
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

    kaiba-rpi5-stable-verifier-signing validate-unsigned \
      --plan ${fixtureSigningPlan} --manifest ${fixtureUnsignedArtifacts}/manifest.json
    cmp ${fixtureUnsignedArtifacts}/manifest.json ${verifiedFixture}/unsigned-artifact-manifest.json
    cmp ${fixtureUnsignedArtifacts}/boot.img ${verifiedFixture}/boot.img
    ${fixtureManifestBindingsValidator}/bin/kaiba-stable-verifier-unsigned-manifest-bindings \
      ${fixtureUnsignedArtifacts}/manifest.json
    for mutation in \
      '.pi_platform_source.revision = "cccccccccccccccccccccccccccccccccccccccc"' \
      '.pi_platform_source.nar_hash = "sha256-AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="' \
      '.files = ((.files + ["extra.txt"]) | sort)'
    do
      jq "$mutation" ${fixtureUnsignedArtifacts}/manifest.json > "$TMPDIR/changed-pinned-manifest.json"
      if ${fixtureManifestBindingsValidator}/bin/kaiba-stable-verifier-unsigned-manifest-bindings \
        "$TMPDIR/changed-pinned-manifest.json"; then
        echo "unsigned signing plan accepted a changed platform or file allowlist" >&2
        exit 1
      fi
    done

    # Campaign consumption independently authenticates both supported profiles.
    kaiba-stable-campaign-contract signed-boot ${verifiedFixture}
    kaiba-stable-campaign-contract signed-boot ${genericCampaign.verifiedSignedBoot}
    ${verifierCampaign.kaibaRpi5StableVerifierCampaignMedia.inputValidationTool}/bin/kaiba-stable-verifier-campaign-input-validate \
      --verified-signed-boot ${verifiedFixture} \
      --campaign-plan ${fixtureCampaignPlan} \
      --campaign-mutation-inputs ${genericCampaign.campaignMutationInputs} \
      --delegated-release ${genericCampaign.delegatedRelease} \
      --release-allowlist ${releaseAllowlistFile} \
      --metadata-out "$TMPDIR/verifier-campaign-inputs.json"
    test -s "$TMPDIR/verifier-campaign-inputs.json"

    expect_campaign_rejection() {
      local label=$1
      local directory=$2
      if kaiba-stable-campaign-contract signed-boot "$directory" \
        > "$TMPDIR/$label.stdout" 2> "$TMPDIR/$label.stderr"; then
        echo "campaign accepted $label" >&2
        exit 1
      fi
      test ! -s "$TMPDIR/$label.stdout"
      test -s "$TMPDIR/$label.stderr"
    }

    cp -R --no-preserve=ownership ${verifiedFixture} "$TMPDIR/changed-manifest"
    chmod -R u+w "$TMPDIR/changed-manifest"
    printf '\n' >> "$TMPDIR/changed-manifest/unsigned-artifact-manifest.json"
    expect_campaign_rejection changed-manifest "$TMPDIR/changed-manifest"

    cp -R --no-preserve=ownership ${verifiedFixture} "$TMPDIR/forged-summary"
    chmod -R u+w "$TMPDIR/forged-summary"
    printf '{}\n' > "$TMPDIR/forged-summary/receipt-verification.json"
    expect_campaign_rejection forged-summary "$TMPDIR/forged-summary"

    cp -R --no-preserve=ownership ${verifiedFixture} "$TMPDIR/extra-grant"
    chmod -R u+w "$TMPDIR/extra-grant"
    jq -c '.grants += [.grants[0]]' ${verifiedFixture}/signing-grants.json \
      > "$TMPDIR/extra-grant/signing-grants.json"
    expect_campaign_rejection extra-grant "$TMPDIR/extra-grant"

    cp -R --no-preserve=ownership ${verifiedFixture} "$TMPDIR/changed-boot"
    chmod -R u+w "$TMPDIR/changed-boot"
    printf 'changed' | dd of="$TMPDIR/changed-boot/boot.img" conv=notrunc status=none
    expect_campaign_rejection changed-boot "$TMPDIR/changed-boot"

    cp -R --no-preserve=ownership ${verifiedFixture} "$TMPDIR/missing-receipt"
    chmod -R u+w "$TMPDIR/missing-receipt"
    rm "$TMPDIR/missing-receipt/signing-receipts.json"
    expect_campaign_rejection missing-receipt "$TMPDIR/missing-receipt"

    cp -R --no-preserve=ownership ${verifiedFixture} "$TMPDIR/symlink-receipt"
    chmod -R u+w "$TMPDIR/symlink-receipt"
    rm "$TMPDIR/symlink-receipt/signing-receipts.json"
    ln -s ${verifiedFixture}/signing-receipts.json "$TMPDIR/symlink-receipt/signing-receipts.json"
    expect_campaign_rejection symlink-receipt "$TMPDIR/symlink-receipt"

    mkdir "$out"
    touch "$out/passed"
  ''
