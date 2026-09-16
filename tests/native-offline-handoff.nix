{
  pkgs,
  lib,
  built,
}:
let
  factories = import ../nix/native-offline-handoff.nix { inherit pkgs lib built; };
  sourceRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  key =
    pkgs.runCommand "native-offline-fixture-public-key"
      {
        nativeBuildInputs = [
          pkgs.python3
          pkgs.openssl
        ];
      }
      ''
        python3 ${./deterministic-rsa-fixture.py} --label stable-verifier-campaign-media-test --private "$TMPDIR/key.pem"
        mkdir "$out"
        openssl pkey -in "$TMPDIR/key.pem" -pubout -out "$out/public.pem"
      '';
  signerReview = pkgs.writeText "native-offline-fixture-signer-review.json" (
    builtins.toJSON {
      public_bindings = {
        customer_key_hash = "sha256:5c9dcff802e78926082845de8de77800f34cfa80dfda9c4fc2d208237e933e5e";
        public_key_file_sha256 = "874984cc3d5e7348bffcb4ba0c0b703062510f21a142accfee1a3b2d37d36faa";
        public_key_fingerprint = "sha256:56d73a770a7f8f38bbd5aeec970a32d0c94cd257594749469b946d811a0db526";
        signer_policy_digest = "sha256:70143c254eefe257cf59cd5e404591c91fc304eebe49f9cf0f9b6eefce6483a8";
      };
    }
  );
  rootImage =
    pkgs.runCommand "native-offline-handoff-fixture-root"
      {
        nativeBuildInputs = [
          pkgs.e2fsprogs
          pkgs.coreutils
        ];
      }
      ''
        mkdir contents
        seq 1 2048 > contents/kaiba-offline-read-probe
        truncate -s 32M "$out"
        mkfs.ext4 -q -F -b 4096 -d contents "$out"
      '';
  firmwareTree = pkgs.runCommand "native-offline-handoff-fixture-firmware" { } ''
    mkdir -p "$out/nixos/default"
    printf '%s\n' 'arm_64bit=1' 'cmdline=nixos/default/cmdline.txt' > "$out/config.txt"
    printf '%s\n' 'console=ttyAMA10,115200' > "$out/nixos/default/cmdline.txt"
  '';
  unsignedArtifacts = (import ../nix/secure-boot-artifacts.nix { inherit pkgs lib; }) {
    inherit sourceRevision rootImage firmwareTree;
    bootImageSizeMiB = 32;
    bootCommandLinePath = "nixos/default/cmdline.txt";
    expectedCustomerKeyHash = "5c9dcff802e78926082845de8de77800f34cfa80dfda9c4fc2d208237e933e5e";
    firmwareAllowlist = [
      "config.txt"
      "nixos/default/cmdline.txt"
    ];
    rootDataPartitionGUID = "b1a02b6c-8ec1-4ca9-9b8a-348211271de0";
    rootHashPartitionGUID = "66d98f80-4260-4de0-98b5-232bcac98e29";
  };
  review =
    pkgs.runCommand "native-offline-handoff-fixture-review"
      {
        nativeBuildInputs = [ pkgs.jq ];
      }
      ''
        mkdir "$out"
        jq '{source_revision, artifact_bundle_digest: .bundle_digest, signing_status,
          normal_boot_medium: "nvme", system_root_medium: "nvme",
          hardware_observed: false, fleet_admission: "unevaluated"}' \
          ${unsignedArtifacts}/manifest.json > "$out/review.json"
      '';
  signingPlan = factories.mkSigningPlan {
    inherit sourceRevision review signerReview;
    candidate = { inherit unsignedArtifacts; };
    sourceDateEpoch = 1786968000;
    publicKey = "${key}/public.pem";
  };
  evidence =
    pkgs.runCommand "native-offline-signing-fixture-evidence"
      {
        nativeBuildInputs = [
          pkgs.go
          pkgs.python3
        ];
      }
      ''
        export CGO_ENABLED=0 GOCACHE="$TMPDIR/go-cache" GOPATH="$TMPDIR/go-path"
        python3 ${./deterministic-rsa-fixture.py} --label stable-verifier-campaign-media-test --private "$TMPDIR/key.pem"
        cd ${built.goSource}
        go run ./internal/provisioning/nativeofflinesigning/testfixture \
          --plan ${signingPlan} --private-key "$TMPDIR/key.pem" --output "$out" \
          --signer-id signer:stable-fixture --cohort-id cohort:stable-fixture \
          --pkcs11-uri 'pkcs11:serial=12345678;id=%02;type=private' \
          --reviewer-id reviewer:fixture --approved-at 2026-08-27T12:00:00Z \
          --expires-at 2026-08-28T12:00:00Z --signed-at 2026-08-27T12:01:00Z
      '';
  verifiedSigning = factories.mkVerified {
    inherit signingPlan;
    authorization = "${evidence}/authorization";
    signedOutput = "${evidence}/signed";
    receiptExport = "${evidence}/signing-receipts.json";
  };
  media = factories.mkMedia {
    inherit verifiedSigning;
    targetSizeBytes = 512 * 1024 * 1024;
  };
in
pkgs.runCommand "native-offline-handoff-check"
  {
    nativeBuildInputs = [
      pkgs.python3
      pkgs.gptfdisk
      pkgs.mtools
      pkgs.cryptsetup
    ];
  }
  ''
    python3 ${./native-offline-handoff.py} ${media}
    mkdir "$out"
    cp ${media}/media-plan.json "$out/fixture-plan.json"
  ''
