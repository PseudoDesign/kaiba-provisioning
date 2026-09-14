{
  lib,
  pkgs,
  built,
  mediaFixture,
}:

let
  seed = mediaFixture.fixtureBaselineMedia.kaibaRpi5StableVerifierCampaignMedia;
  fixtureSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../internal/provisioning
      ../tests/campaign-preparation-fixture
    ];
  };
  fixtureTool = pkgs.buildGoModule {
    pname = "kaiba-campaign-preparation-test-fixture";
    version = "0.1.0";
    src = fixtureSource;
    vendorHash = null;
    subPackages = [ "tests/campaign-preparation-fixture" ];
    env.CGO_ENABLED = 0;
    doCheck = false;
  };
  trustSeed = import ./stable-verifier-vm-fixture.nix { inherit pkgs; };
  publicFixture =
    pkgs.runCommand "kaiba-campaign-preparation-public-fixture"
      {
        nativeBuildInputs = [
          pkgs.python3
          fixtureTool
        ];
      }
      ''
        for role in root primary replacement revoked; do
          python3 ${./deterministic-rsa-fixture.py} --label "campaign-preparation-test-$role" \
            --private "$TMPDIR/$role.pem"
        done
        campaign-preparation-fixture \
          --root-private-key "$TMPDIR/root.pem" --primary-private-key "$TMPDIR/primary.pem" \
          --replacement-private-key "$TMPDIR/replacement.pem" --revoked-private-key "$TMPDIR/revoked.pem" \
          --release ${seed.delegatedRelease}/nvme-release --authority-ca ${trustSeed}/authority-ca.pem --output "$out"
      '';
  release = pkgs.runCommand "kaiba-campaign-preparation-signed-release-fixture" { } ''
    cp -R --no-preserve=ownership ${seed.delegatedRelease}/nvme-release "$out"
    chmod -R u+w "$out"
    cp ${publicFixture}/positive-manifest.json "$out/release-manifest.json"
  '';
  fixture = import ./stable-verifier-campaign-media.nix {
    inherit lib pkgs;
    publicPreparationFixture = publicFixture;
    preparedReleaseTree = release;
  };
  prepare = import ../nix/campaign-preparation.nix {
    inherit lib pkgs;
    mutationsTool = built.stableCampaignMutationsTool;
    planTool = built.stableCampaignPlanTool;
    stagingPlanTool = built.stableCampaignStagingPlanTool;
    recoveryTool = built.stableCampaignRecoveryRequirementsTool;
    packetTool = built.stableCampaignPacketTool;
    mkMedia = fixture.fixtureMediaBuilder;
    mkRun = built.mkRpi5StableVerifierCampaignRun;
  };
  preparation = prepare {
    campaignID = "campaign-preparation-fixture";
    sourceRevision = "1111111111111111111111111111111111111111";
    verifiedSignedBoot = fixture.fixtureSignedBoot;
    delegatedRelease = fixture.fixtureDelegatedRelease;
    replacementManifest = "${publicFixture}/replacement-manifest.json";
    revokedManifest = "${publicFixture}/revoked-manifest.json";
    sdDiskGUID = "5625eee2-0c8a-402f-8c2f-5a1347652bb2";
    nvmeDiskGUID = "bb5289ea-2c0b-424f-a4c7-23c8fdf1ebae";
    bootPartitionGUID = "59d06b61-bf85-4d77-89c3-9e5395934ff8";
    rootDataPartitionGUID = "d6f72f33-10c8-4f0c-8c4d-cba239f106bb";
    rootHashPartitionGUID = "a84e3cc9-44f7-4ad4-b427-5bc16aec4bfe";
    releasePartitionGUID = "d8361116-a296-43d4-8f9e-65c35d00955b";
    # These are explicitly synthetic declarations from the existing tests.
    # They contain no hardware capture or recovery backup bytes.
    sdEnvelope = "${
      ../internal/provisioning/campaignmedia/testdata/recovery-v1alpha2/sd-envelope.json
    }";
    nvmeEnvelope = "${
      ../internal/provisioning/campaignmedia/testdata/recovery-v1alpha2/nvme-envelope.json
    }";
  };
in
pkgs.runCommand "kaiba-campaign-preparation-integration"
  {
    nativeBuildInputs = [
      pkgs.jq
      pkgs.coreutils
    ];
    passthru = { inherit preparation publicFixture; };
  }
  ''
    mkdir "$out"
    jq -e '.destructive_staging_ready == false and .initial_gpt_recovery_bound == false' \
      ${preparation.stagingPlan} > /dev/null
    cmp ${preparation.run1}/sd/root-data.img ${preparation.run2}/sd/root-data.img
    cmp ${preparation.run1}/sd/root-hash.img ${preparation.run2}/sd/root-hash.img
    cmp ${preparation.run1}/sd/boot-filesystem.img ${preparation.run2}/sd/boot-filesystem.img
    cmp ${preparation.run1}/nvme/release-filesystem.img ${preparation.run2}/nvme/release-filesystem.img
    cp ${preparation.packet} "$out/preparation.json"
    cp ${preparation.stagingPlan} "$out/staging-plan.json"
    cp ${preparation.campaignPlan} "$out/campaign-plan.json"
    test "$(jq '.public_inputs | length' "$out/campaign-plan.json")" -eq 27
    test "$(jq '.bound_replacements | length' "$out/campaign-plan.json")" -eq 20
    test "$(jq '.byte_xor_mutations | length' "$out/campaign-plan.json")" -eq 10
    touch "$out/passed"
  ''
