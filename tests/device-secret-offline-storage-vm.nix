{ pkgs }:
let
  storage = import ../nix/device-secret-storage-development.nix { inherit pkgs; };
  config = (import ./device-secret-target/fixture-config.nix) // {
    schema_version = "kaiba.device-secret-storage-offline-development/v1alpha1";
  };
  configFile = pkgs.writeText "offline-storage-fixture.json" (builtins.toJSON config);
  vm = pkgs.testers.runNixOSTest {
    name = "kaiba-device-secret-offline-storage";
    nodes.machine = { ... }: {
      virtualisation.memorySize = 1024;
      virtualisation.emptyDiskImages = [ 67 ];
      swapDevices = [ ];
      systemd.coredump.enable = false;
      boot.kernelModules = [
        "dm_mod"
        "dm_crypt"
      ];
      environment.systemPackages = [
        pkgs.python3
        pkgs.util-linux
        pkgs.lvm2
      ];
      systemd.services.offline-storage = {
        # The fixture delays the first invocation until its disposable disk is
        # prepared; subsequent boots start automatically with no SSH upload.
        wantedBy = [ "multi-user.target" ];
        unitConfig.ConditionPathExists = "/var/lib/offline-storage-ready";
        serviceConfig = {
          Type = "oneshot";
          LimitMEMLOCK = "infinity";
          LimitCORE = 0;
          StandardOutput = "truncate:/run/storage-result";
          StandardError = "truncate:/run/storage-errors";
          EnvironmentFile = "-/run/storage-environment";
          Restart = "no";
          ExecStart = "${storage.offlineFixture}/bin/kaiba-device-secret-storage-development --run-reviewed-experiment ${configFile}";
        };
      };
    };
    testScript = ''
      import json
      machine.start(allow_reboot=True)
      machine.wait_for_unit("multi-user.target")
      machine.succeed("printf 'label: gpt\\nstart=2048,size=133120,type=linux,uuid=${config.partition_uuid}\\n' | sfdisk /dev/vdb")
      machine.succeed("udevadm settle")
      machine.succeed("touch /var/lib/offline-storage-ready")

      def result(passed=True):
          raw = machine.succeed("cat /run/storage-result")
          assert not machine.succeed("cat /run/storage-errors")
          prefix = "KAIBA_DEVICE_SECRET_STORAGE_RESULT="
          assert raw.count(prefix) == 1 and raw.startswith(prefix), raw
          value = json.loads(raw[len(prefix):])
          assert value["passed"] is passed, value
          assert value["mode"] == "synthetic-offline-development", value
          assert value["schema_version"] == "kaiba.device-secret-storage-offline-result/v1alpha1", value
          assert not value["hardware_qualified"] and not value["lock_rejection_qualified"], value
          assert "42"*32 not in raw and "KAIBA_PRIVATE_RECORD" not in raw, raw
          assert "kaiba-secret-experiment" not in machine.succeed("dmsetup info --columns --noheadings -o name")
          if passed:
              assert all(value[k] for k in ["volume_verified", "runtime_locks_closed", "storage_closed", "journal_completed"]), value
          return value

      machine.succeed("systemctl start offline-storage")
      created = result()
      assert created["phase"] == "create"
      machine.succeed("cp /dev/vdb1 /var/lib/created.img")
      machine.reboot()
      machine.wait_for_unit("multi-user.target")
      reopened = result()
      assert reopened["phase"] == "reopen" and reopened["boot_id"] != created["boot_id"]
      machine.succeed("sha256sum /dev/vdb1 > /var/lib/completed.sha256")
      machine.reboot()
      machine.wait_for_unit("multi-user.target")
      rejected = result(False)
      assert rejected["stop"] == "storage-prestate" and rejected["last_mailbox_tag"] == 0
      machine.succeed("sha256sum -c /var/lib/completed.sha256")
      machine.succeed("rm /var/lib/offline-storage-ready")

      # Only fixture setup can replace journals or one-shot markers.
      def attempt(fault=None):
          machine.succeed("rm -f /run/kaiba-device-secret-storage-attempted")
          machine.succeed("touch /var/lib/offline-storage-ready")
          machine.succeed("systemctl reset-failed offline-storage")
          machine.succeed("printf '%s' '" + ("KAIBA_TEST_FAULT=" + fault if fault else "") + "' > /run/storage-environment")
          machine.fail("systemctl start offline-storage")
          machine.succeed("rm /var/lib/offline-storage-ready")
          return result(False)

      for fault, stop in [("other-board", "volume-verification"), ("hmac-einval", "luks-derivation"), ("cleanup", "cleanup-locks")]:
          machine.succeed("dd if=/var/lib/created.img of=/dev/vdb1 bs=1M conv=fsync status=none")
          value = attempt(fault)
          assert value["stop"] == stop and not value["journal_completed"], value
          machine.succeed("sha256sum /dev/vdb1 > /run/failed.sha256")
          value = attempt()
          assert value["stop"] == "storage-prestate" and value["last_mailbox_tag"] == 0
          machine.succeed("sha256sum -c /run/failed.sha256")

      machine.succeed("dd if=/var/lib/created.img of=/dev/vdb1 bs=1M conv=fsync status=none")
      machine.succeed("printf x | dd of=/dev/vdb1 bs=1 seek=64 conv=notrunc,fsync status=none")
      machine.succeed("sha256sum /dev/vdb1 > /run/bad-binding.sha256")
      assert attempt()["stop"] == "storage-prestate"
      machine.succeed("sha256sum -c /run/bad-binding.sha256")
      machine.succeed("dd if=/dev/zero of=/dev/vdb1 bs=1M count=65 conv=fsync status=none")
      machine.succeed("modprobe -r dm_crypt")
      machine.succeed("sha256sum /dev/vdb1 > /run/blank.sha256")
      value = attempt()
      assert value["stop"] == "storage-drivers" and value["last_mailbox_tag"] == 0
      machine.succeed("sha256sum -c /run/blank.sha256")
    '';
  };
in
if pkgs.stdenv.hostPlatform.system == "aarch64-linux" then
  vm.overrideTestDerivation (_: {
    requiredSystemFeatures = [ "nixos-test" ];
  })
else
  vm
