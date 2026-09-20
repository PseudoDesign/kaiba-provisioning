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
          ./modules/device-secret-offline-storage.nix
          {
            kaiba.deviceSecretOfflineStorage = {
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
  artifactName = "kaiba-rpi5-offline-storage-development-unsigned";
})
// {
  deviceSecretOfflineStorage = experiment;
}
