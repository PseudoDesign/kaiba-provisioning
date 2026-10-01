{
  description = "Disposable Ace NVMe crash/recovery campaign (synthetic identities only)";
  inputs.raspberrypi.url = "github:ams-tech/nixos-raspberrypi/d3360e0b4b9ed0f7ccba5120cecb36dc886864e2";
  inputs.fleet.url = "github:PseudoDesign/kaiba-fleet/0bd55c576536c29825aada2f7ce6fa052a877402";
  outputs =
    {
      self,
      raspberrypi,
      fleet,
    }:
    let
      campaign = import ./image.nix { inherit raspberrypi fleet; };
      localRuntime = import ./runtime.nix {
        inherit fleet;
        system = "x86_64-linux";
      };
    in
    {
      packages.aarch64-linux.default = campaign.image;
      packages.aarch64-linux.system = campaign.system;
      packages.aarch64-linux.tools = campaign.tools;
      packages.x86_64-linux.runtime = localRuntime.settings;
      checks.x86_64-linux.operations =
        localRuntime.pkgs.runCommand "nvme-qualification-operations-tests"
          {
            nativeBuildInputs = [ localRuntime.python ];
          }
          ''
            python3 -B ${./.}/test_operations.py
            mkdir -p "$out"
            echo passed > "$out/result"
          '';
      checks.x86_64-linux.campaign =
        localRuntime.pkgs.runCommand "nvme-qualification-campaign-tests"
          {
            nativeBuildInputs = [
              localRuntime.python
              localRuntime.pkgs.openssl
            ];
          }
          ''
            python3 -B ${./test_campaign.py} ${localRuntime.settings} ${./campaign.py}
            mkdir -p "$out"
            cp report.json "$out/"
          '';
    };
}
