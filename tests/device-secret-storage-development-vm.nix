{ pkgs }:
let
  storage = import ../nix/device-secret-storage-development.nix { inherit pkgs; };
  config = (import ./device-secret-target/fixture-config.nix) // {
    schema_version = "kaiba.device-secret-storage-development/v1alpha1";
  };
  configFile = pkgs.writeText "storage-development-fixture.json" (builtins.toJSON config);
  vm = pkgs.testers.runNixOSTest {
    name = "kaiba-device-secret-storage-development";
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
      systemd.services.storage-development = {
        unitConfig.StartLimitIntervalSec = 0;
        serviceConfig = {
          Type = "oneshot";
          LimitMEMLOCK = "infinity";
          LimitCORE = 0;
          StandardOutput = "truncate:/run/storage-result";
          StandardError = "truncate:/run/storage-errors";
          EnvironmentFile = "/run/storage-environment";
          Restart = "no";
        };
        script = ''
          exec ${storage.fixture}/bin/kaiba-device-secret-storage-development \
            "$STORAGE_PHASE" ${configFile} --expected-boot-id "$(cat /proc/sys/kernel/random/boot_id)"
        '';
      };
    };
    testScript = ''
      import json
      machine.start(allow_reboot=True)
      machine.wait_for_unit("multi-user.target")
      machine.succeed("printf 'label: gpt\\nstart=2048,size=133120,type=linux,uuid=${config.partition_uuid}\\n' | sfdisk /dev/vdb")
      machine.succeed("udevadm settle")
      machine.succeed("test $(blockdev --getsize64 /dev/vdb1) = 68157440")

      def run(phase, passed=True, fault=None):
          env = f"STORAGE_PHASE={phase}\\n" + (f"KAIBA_TEST_FAULT={fault}\\n" if fault else "")
          machine.succeed(f"printf '{env}' > /run/storage-environment")
          (machine.succeed if passed else machine.fail)("systemctl start storage-development.service")
          raw = machine.succeed("cat /run/storage-result")
          errors = machine.succeed("cat /run/storage-errors")
          assert not errors, errors
          value = json.loads(raw)
          assert value["passed"] is passed, value
          assert value["mode"] == "synthetic-development", value
          assert not value["hardware_qualified"] and not value["lock_rejection_qualified"], value
          assert "42"*32 not in raw and "KAIBA_PRIVATE_RECORD" not in raw, raw
          names = machine.succeed("dmsetup info --columns --noheadings -o name")
          assert "kaiba-secret-experiment" not in names, names
          if passed:
              assert value["volume_verified"] and value["runtime_locks_closed"] and value["storage_closed"] and value["journal_completed"], value
          return value

      created = run("create")
      machine.succeed("cp /dev/vdb1 /var/lib/created.img")
      machine.succeed("python3 -c \"from pathlib import Path; d=Path('/dev/vdb1').read_bytes(); assert b'KAIBA_PRIVATE_RECORD_V1' not in d; assert b'B'*32 not in d\"")
      machine.succeed("sha256sum /dev/vdb1 > /run/before-repeat.sha256")
      assert run("create", False)["stop"] == "same-boot-repeat"
      machine.succeed("sha256sum -c /run/before-repeat.sha256")
      machine.succeed("rm /run/kaiba-device-secret-storage-attempted")
      assert run("reopen", False)["stop"] == "storage-prestate"
      machine.succeed("sha256sum -c /run/before-repeat.sha256")

      machine.reboot()
      machine.wait_for_unit("multi-user.target")
      machine.succeed("udevadm settle")
      reopened = run("reopen")
      assert reopened["boot_id"] != created["boot_id"]
      machine.succeed("sha256sum /dev/vdb1 > /run/completed.sha256")
      machine.succeed("rm /run/kaiba-device-secret-storage-attempted")
      assert run("reopen", False)["stop"] == "storage-prestate"
      machine.succeed("sha256sum -c /run/completed.sha256")

      # Independent synthetic cases. Resetting the fixture is test setup only;
      # neither the helper nor its host runner exposes a reset/retry command.
      for fault, stop in [("other-board", "volume-verification"), ("hmac-einval", "luks-derivation"),
                          ("hmac-short", "luks-derivation"), ("cleanup", "cleanup-locks"),
                          ("interrupted", "interrupted")]:
          machine.succeed("dd if=/var/lib/created.img of=/dev/vdb1 bs=1M conv=fsync status=none")
          machine.succeed("rm -f /run/kaiba-device-secret-storage-attempted")
          value = run("reopen", False, fault)
          assert value["stop"] == stop and not value["journal_completed"], value
          if fault != "cleanup":
              assert value["runtime_locks_closed"], value
          if fault == "hmac-einval":
              assert (value["last_firmware_outcome"], value["last_mailbox_tag"], value["last_mailbox_errno"]) == (2, 0x30092, 22), value
          machine.succeed("sha256sum /dev/vdb1 > /run/failed.sha256")
          machine.succeed("rm /run/kaiba-device-secret-storage-attempted")
          assert run("reopen", False)["stop"] == "storage-prestate"
          machine.succeed("sha256sum -c /run/failed.sha256")

      for fault in ["preclosed", "wrong-usage"]:
          machine.succeed("dd if=/var/lib/created.img of=/dev/vdb1 bs=1M conv=fsync status=none")
          machine.succeed("rm /run/kaiba-device-secret-storage-attempted")
          machine.succeed("sha256sum /dev/vdb1 > /run/metadata.sha256")
          assert run("reopen", False, fault)["stop"] == "firmware-metadata"
          machine.succeed("sha256sum -c /run/metadata.sha256")

      machine.succeed("dd if=/dev/zero of=/dev/vdb1 bs=1M count=65 conv=fsync status=none")
      machine.succeed("rm /run/kaiba-device-secret-storage-attempted")
      machine.succeed("sha256sum /dev/vdb1 > /run/blank.sha256")
      assert run("reopen", False)["stop"] == "storage-prestate"
      machine.succeed("sha256sum -c /run/blank.sha256")
      machine.succeed("rm /run/kaiba-device-secret-storage-attempted")
      machine.succeed("modprobe -r dm_crypt")
      value = run("create", False)
      assert value["stop"] == "storage-drivers" and value["last_mailbox_tag"] == 0, value
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
