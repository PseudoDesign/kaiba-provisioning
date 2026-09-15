{
  lib,
  pkgs,
  planValidator,
}:
{
  descriptor,
  nativeComponent,
  sourceRevision,
  stagingPlan,
  payloads,
  leg ? "pi-local-nvme",
}:
let
  storeInput = import ./campaign-staging-store-input.nix { inherit lib; };
  configuration = import ./campaign-staging-configuration.nix { inherit lib pkgs; } {
    inherit leg stagingPlan payloads;
  };
in
assert lib.assertMsg (leg == "pi-local-nvme") "split staging assembly supports only pi-local-nvme";
assert lib.assertMsg (
  builtins.match "[0-9a-f]{40}" sourceRevision != null
) "staging assembly requires the reviewed native component source revision";
assert lib.assertMsg (lib.hasPrefix "${builtins.storeDir}/" (
  toString nativeComponent
)) "staging assembly requires an immutable native component";
pkgs.runCommand "kaiba-pi-local-nvme-campaign-stage-assembled"
  {
    nativeBuildInputs = [ pkgs.python3 ];
    descriptorInput = descriptor;
    componentInput = storeInput nativeComponent;
    configurationInput = configuration;
    stagingPlanInput = stagingPlan;
    nativeSourceRevision = sourceRevision;
    passthru.kaibaRpi5StableCampaignStaging = {
      configured = true;
      inherit leg configuration;
      targetSystem = "aarch64-linux";
      completeRuntimeClosure = true;
      targetSelectorAuthority = "fixed-campaign-hardware-catalog";
      planAndPayloadAuthority = "linker-fixed-store-inputs";
      approvalScope = "explicit-local-operator-acknowledgement";
      genericDeviceAccess = false;
      hardwareQualified = false;
      campaignClaimsClosed = false;
      productionReady = false;
      retryAfterStartedExecution = false;
      recoveryScope = "all-v1alpha2-captured-ranges-not-whole-disk";
    };
    meta.mainProgram = "kaiba-rpi5-stable-campaign-stage";
  }
  ''
    python3 ${./campaign-staging-inputs.py} verify-component \
      --plan-validator ${planValidator}/bin/kaiba-rpi5-stable-campaign-staging-plan-check \
      --descriptor "$descriptorInput" --directory "$componentInput" \
      --source-revision "$nativeSourceRevision" > component-verification.json
    python3 ${./campaign-staging-inputs.py} verify-inputs \
      --plan-validator ${planValidator}/bin/kaiba-rpi5-stable-campaign-staging-plan-check \
      --descriptor "$descriptorInput" --configuration "$configurationInput" \
      --staging-plan "$stagingPlanInput" > input-verification.json
    mkdir -p "$out/bin" "$out/share/kaiba"
    ln -s "$componentInput/bin/kaiba-rpi5-stable-campaign-stage" "$out/bin/kaiba-rpi5-stable-campaign-stage"
    # These explicit references close the intentionally incomplete native export.
    ln -s "$configurationInput" "$out/share/kaiba/configuration.json"
    ln -s "$componentInput" "$out/share/kaiba/native-component"
    cp component-verification.json input-verification.json "$out/share/kaiba/"
  ''
