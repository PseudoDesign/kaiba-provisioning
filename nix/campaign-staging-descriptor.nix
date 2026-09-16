{
  lib,
  pkgs,
  planValidator,
}:
{
  stagingPlan,
  payloads,
  leg ? "pi-local-nvme",
}:
let
  configuration = import ./campaign-staging-configuration.nix { inherit lib pkgs; } {
    inherit leg stagingPlan payloads;
  };
in
assert lib.assertMsg (leg == "pi-local-nvme") "split staging exports support only pi-local-nvme";
pkgs.runCommand "kaiba-pi-local-nvme-staging-descriptor.json"
  {
    nativeBuildInputs = [ pkgs.python3 ];
    configurationInput = configuration;
    stagingPlanInput = stagingPlan;
    passthru.kaibaRpi5StableCampaignStagingDescriptor = {
      inherit
        configuration
        stagingPlan
        payloads
        leg
        ;
      targetSystem = "aarch64-linux";
      completeRuntimeClosure = false;
      hardwareQualified = false;
      productionReady = false;
    };
  }
  ''
    python3 ${./campaign-staging-inputs.py} author \
      --plan-validator ${planValidator}/bin/kaiba-rpi5-stable-campaign-staging-plan-check \
      --configuration "$configurationInput" --staging-plan "$stagingPlanInput" > "$out"
  ''
