{ fleet, system }:
let
  pkgs = import fleet.inputs.nixpkgs { inherit system; };
  producer = import (fleet.inputs.provisioning + "/nix/packages.nix") {
    inherit pkgs;
    inherit (pkgs) lib;
  };
  fixture = pkgs.buildGoModule {
    pname = "kaiba-qualification-device-fixture";
    version = "1";
    src = fleet.inputs.provisioning;
    vendorHash = null;
    subPackages = [ "tests/pilot-device-fixture" ];
    doCheck = false;
  };
  python = pkgs.python3.withPackages (p: [
    p.cryptography
    p.jsonschema
    p.rfc8785
    p.rfc3339-validator
    p.rfc3986-validator
  ]);
  settings = pkgs.writeText "qualification-runtime.json" (
    builtins.toJSON {
      fleet_source = toString fleet;
      fleet = "${fleet.packages.${system}.default}/bin";
      provisioning = "${fleet.packages.${system}.authorities}/bin";
      postgres = "${pkgs.postgresql_18}/bin";
      fixture_client = "${fixture}/bin/pilot-device-fixture";
      device_client = "${producer.pilotDevice}/bin/kaiba-pilot-device";
    }
  );
in
{
  inherit pkgs python settings;
}
