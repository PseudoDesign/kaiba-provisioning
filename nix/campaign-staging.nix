{
  lib,
  pkgs,
  tool,
}:

{
  leg,
  stagingPlan,
  payloads,
}:

let
  roles =
    if leg == "malak-sd" then
      [
        "boot-filesystem"
        "root-data"
        "root-hash"
      ]
    else if leg == "pi-local-nvme" then
      [ "release-filesystem" ]
    else
      throw "campaign staging requires exactly malak-sd or pi-local-nvme";
  immutablePath =
    value:
    (builtins.isPath value || lib.isDerivation value || builtins.isString value)
    && lib.hasPrefix "${builtins.storeDir}/" (toString value);
  configuration = pkgs.writeText "kaiba-${leg}-staging-configuration.json" (
    builtins.toJSON {
      inherit leg;
      payload_paths = lib.mapAttrs (_: value: toString value) payloads;
      schema_version = "kaiba.provisioning.rpi5-stable-campaign-staging-configuration/v1alpha1";
      staging_plan_path = toString stagingPlan;
    }
  );
in
assert lib.assertMsg (
  builtins.attrNames payloads == roles
) "campaign staging requires exactly the selected leg's complete partition payloads";
assert lib.assertMsg (
  immutablePath stagingPlan && lib.all immutablePath (builtins.attrValues payloads)
) "campaign staging requires immutable store paths for the plan and payloads";
tool.overrideAttrs (old: {
  pname = "kaiba-${leg}-campaign-stage";
  ldflags = (old.ldflags or [ ]) ++ [ "-X main.configurationPath=${configuration}" ];
  passthru = (old.passthru or { }) // {
    kaibaRpi5StableCampaignStaging = old.passthru.kaibaRpi5StableCampaignStaging // {
      configured = true;
      inherit leg configuration;
      targetSelectorAuthority = "fixed-campaign-hardware-catalog";
      planAndPayloadAuthority = "linker-fixed-store-inputs";
    };
  };
})
