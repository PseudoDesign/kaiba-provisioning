{
  pkgs,
  source,
  testName ? null,
}:

assert pkgs.stdenv.hostPlatform.system == "x86_64-linux";

let
  allTests = [
    "TestCampaignStagingVMOpenTransitions"
    "TestCampaignStagingVM"
  ];
  testNames = if testName == null then allTests else [ testName ];
  testPattern = pkgs.lib.concatStringsSep "|" testNames;
  testBinary =
    pkgs.runCommand "kaiba-campaign-staging-vm-test-binary"
      {
        nativeBuildInputs = [ pkgs.go ];
        CGO_ENABLED = "0";
      }
      ''
        set -euo pipefail
        export GOCACHE="$TMPDIR/go-cache"
        export GOPATH="$TMPDIR/go-path"
        mkdir -p "$out/bin"
        cd ${source}
        go test -c -o "$out/bin/campaign-staging-vm-test" ./internal/provisioning/campaignstaging
      '';

  vm = pkgs.testers.runNixOSTest {
    name = "kaiba-campaign-staging-block-device-vm";
    # Complete preimage/source/readback checks hash about 234 GiB. TCG can
    # take over 90 minutes for those passes; KVM completes much sooner.
    globalTimeout = 9600;
    passthru.kaibaCampaignStagingVM = {
      architecture = "x86_64-linux";
      realLinuxBlockAdapter = true;
      disposableLoopDevices = true;
      fullFixedCampaignGeometry = builtins.elem "TestCampaignStagingVM" testNames;
      interruptedWriteAndRetryRejection = builtins.elem "TestCampaignStagingVM" testNames;
      readbackProbeTransitions = builtins.elem "TestCampaignStagingVMOpenTransitions" testNames;
      raspberryPiHardwareObserved = false;
      campaignClaimsClosed = false;
    };
    nodes.machine = {
      networking.hostName = "malak";
      virtualisation.memorySize = 3072;
      virtualisation.cores = 2;
      # Full source/backup passes are sparse; actual block-device writes
      # allocate the ~11 GiB of planned partitions. Keep ample recovery room.
      virtualisation.diskSize = 61440;
      boot.kernelModules = [
        "loop"
        "dm_mod"
      ];
      environment.systemPackages = [
        testBinary
        pkgs.util-linux
        pkgs.e2fsprogs
        pkgs.lvm2
      ];
      environment.etc."kaiba-campaign-staging-vm".text = "disposable-campaign-staging-test\n";
      environment.etc."kaiba-campaign-staging-fixture.json".source =
        ../internal/provisioning/campaignmedia/testdata/recovery-v1alpha2/staging-plan.json;
    };
    testScript = ''
      machine.start()
      machine.wait_for_unit("multi-user.target")
      machine.succeed("mkdir -p /var/lib/campaign-staging-vm")
      status, output = machine.execute(
          "set -o pipefail; env TMPDIR=/var/lib/campaign-staging-vm KAIBA_CAMPAIGN_STAGING_VM=1 "
          "campaign-staging-vm-test -test.run '^(${testPattern})$' "
          "-test.v -test.timeout=150m 2>&1 | tee /var/lib/campaign-staging-vm/test-results.txt > /dev/ttyS0",
          timeout=9300,
      )
      print(machine.succeed("cat /var/lib/campaign-staging-vm/test-results.txt"))
      assert status == 0, output
      for name in ${builtins.toJSON testNames}:
          machine.succeed("grep -F -- '--- PASS: " + name + " (' /var/lib/campaign-staging-vm/test-results.txt")
      machine.copy_from_machine("/var/lib/campaign-staging-vm/test-results.txt")
    '';
  };
in
# The NixOS launcher falls back to TCG when KVM is absent. Keep the isolated
# NixOS-test requirement while allowing this check on hosted builders.
assert testName == null || builtins.elem testName allTests;
vm.overrideTestDerivation (_: {
  requiredSystemFeatures = [ "nixos-test" ];
})
