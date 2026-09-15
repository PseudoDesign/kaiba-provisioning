{
  lib,
  pkgs,
  built,
}:
let
  # Negative construction must not realize any foreign-architecture output.
  refuses =
    args: !(builtins.tryEval ((built.mkRpi5StableCampaignStagingDescriptor args).drvPath)).success;
  plan = pkgs.writeText "invalid-plan.json" "{}";
  payload = pkgs.writeText "invalid-payload" "test";
  descriptor = built.mkRpi5StableCampaignStagingDescriptor {
    stagingPlan = plan;
    payloads.release-filesystem = payload;
  };
  configuration = descriptor.kaibaRpi5StableCampaignStagingDescriptor.configuration;
  configurationClosure = pkgs.closureInfo { rootPaths = [ configuration ]; };
  # toFile/toSource create already-registered public roots at evaluation time,
  # modelling imports without requiring a derivation to be built during eval.
  importedPlan = builtins.toFile "imported-staging-plan.json" "{}";
  importedPayloadRoot = lib.fileset.toSource {
    root = ../.;
    fileset = ../internal/provisioning/campaignmedia/testdata/recovery-v1alpha2/staging-plan.json;
  };
  importedDescriptor = built.mkRpi5StableCampaignStagingDescriptor {
    stagingPlan = builtins.unsafeDiscardStringContext importedPlan;
    payloads.release-filesystem = builtins.unsafeDiscardStringContext "${importedPayloadRoot}/internal/provisioning/campaignmedia/testdata/recovery-v1alpha2/staging-plan.json";
  };
  importedConfiguration = importedDescriptor.kaibaRpi5StableCampaignStagingDescriptor.configuration;
  importedClosure = pkgs.closureInfo { rootPaths = [ importedConfiguration ]; };
in
assert refuses {
  leg = "malak-sd";
  stagingPlan = plan;
  payloads.release-filesystem = payload;
};
assert refuses {
  stagingPlan = "/tmp/plan.json";
  payloads.release-filesystem = payload;
};
assert refuses {
  stagingPlan = plan;
  payloads.boot-filesystem = payload;
};
pkgs.runCommand "kaiba-campaign-staging-split-contract"
  {
    nativeBuildInputs = [ pkgs.python3 ];
    KAIBA_STAGING_PLAN_VALIDATOR = "${built.stableCampaignStagingPlanCheck}/bin/kaiba-rpi5-stable-campaign-staging-plan-check";
    sourceInput = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../nix/campaign-staging-inputs.py
        ../tests/campaign-staging-split
        ../internal/provisioning/campaignmedia/testdata/recovery-v1alpha2/staging-plan.json
      ];
    };
  }
  ''
    cd "$sourceInput"
    python3 -B -m unittest discover -s tests/campaign-staging-split -p 'test_*.py' -v
    # The real local configuration retains both payload and plan references.
    # Inspect this tiny closure without realizing a foreign architecture or the
    # intentionally invalid descriptor fixture's output.
    grep -Fx ${lib.escapeShellArg (toString configuration)} ${configurationClosure}/store-paths
    grep -Fx ${lib.escapeShellArg (toString plan)} ${configurationClosure}/store-paths
    grep -Fx ${lib.escapeShellArg (toString payload)} ${configurationClosure}/store-paths
    grep -Fx ${lib.escapeShellArg importedPlan} ${importedClosure}/store-paths
    grep -Fx ${lib.escapeShellArg (toString importedPayloadRoot)} ${importedClosure}/store-paths
    mkdir "$out"
    printf '%s\n' 'split native staging descriptor and public assembly boundaries: pass' > "$out/result.txt"
  ''
