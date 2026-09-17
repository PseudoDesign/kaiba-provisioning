{
  lib,
  nixpkgs,
  nixosRaspberryPi,
  secureBootTargetModule,
}:
{
  experiment,
  expectedCustomerKeyHash,
  sourceRevision,
}:
assert (experiment.source_revision or "") == sourceRevision;
let
  system =
    (import ./rpi5-native-offline-system.nix {
      inherit nixosRaspberryPi secureBootTargetModule;
    })
      {
        inherit expectedCustomerKeyHash sourceRevision;
        extraModules = [
          ./modules/device-secret-experiment.nix
          {
            kaiba.deviceSecretExperiment = {
              enable = true;
              inherit experiment;
            };
          }
        ];
      };
in
(import ./rpi5-native-offline-artifacts.nix {
  inherit lib;
  buildPkgs = import nixpkgs { system = "aarch64-linux"; };
  candidateSystem = system;
  artifactName = "kaiba-rpi5-device-secret-experiment-unsigned";
})
// {
  deviceSecretExperiment = experiment;
}
