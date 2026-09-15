{ lib, pkgs }:
{
  leg,
  stagingPlan,
  payloads,
}:
let
  storeInput = import ./campaign-staging-store-input.nix { inherit lib; };
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
in
assert lib.assertMsg (
  builtins.attrNames payloads == roles
) "campaign staging requires exactly the selected leg's complete partition payloads";
assert lib.assertMsg (
  immutablePath stagingPlan && lib.all immutablePath (builtins.attrValues payloads)
) "campaign staging requires immutable store paths for the plan and payloads";
pkgs.writeText "kaiba-${leg}-staging-configuration.json" (
  builtins.toJSON {
    inherit leg;
    payload_paths = lib.mapAttrs (_: value: storeInput value) payloads;
    schema_version = "kaiba.provisioning.rpi5-stable-campaign-staging-configuration/v1alpha1";
    staging_plan_path = storeInput stagingPlan;
  }
)
