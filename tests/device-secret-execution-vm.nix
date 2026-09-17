{ pkgs, fixture }:
let
  vm = pkgs.testers.runNixOSTest {
    name = "device-secret-media-loop-io";
    nodes.machine = { ... }: {
      virtualisation.memorySize = 1024;
      boot.kernelModules = [ "loop" ];
      environment.systemPackages = [
        pkgs.python3
        pkgs.util-linux
        pkgs.e2fsprogs
      ];
    };
    testScript = ''
      start_all()
      machine.wait_for_unit("multi-user.target")
      output = machine.succeed("python3 -I ${./device-secret-execution/vm.py} ${../scripts/device-secret} ${fixture}")
      assert "SOFTWARE_ONLY_LOOP_IO_PASSED hardware_qualified=false" in output
      machine.succeed("test $(stat -c %a /var/lib/kaiba-device-secret-synthetic) = 700")
      machine.succeed("test $(stat -c %a /var/lib/kaiba-device-secret-synthetic/gpt-primary.img.preimage) = 600")
    '';
  };
in
vm.overrideTestDerivation (_: {
  requiredSystemFeatures = [ "nixos-test" ];
})
