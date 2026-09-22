{ pkgs, client }:
let
  storage = import ../nix/enrollment-storage.nix { inherit pkgs; };
  config = (import ./device-secret-target/fixture-config.nix) // {
    schema_version = "kaiba.enrollment-storage-development/v1alpha1";
  };
  configFile = pkgs.writeText "enrollment-storage-fixture.json" (builtins.toJSON config);
  python = pkgs.python3.withPackages (p: [ p.cryptography ]);
  vm = pkgs.testers.runNixOSTest {
    name = "kaiba-enrollment-storage";
    nodes.machine = { ... }: {
      virtualisation.memorySize = 1536;
      virtualisation.emptyDiskImages = [ 67 ];
      swapDevices = [ ];
      systemd.coredump.enable = false;
      boot.kernelModules = [
        "dm_mod"
        "dm_crypt"
      ];
      environment.systemPackages = [
        python
        pkgs.util-linux
        pkgs.lvm2
        pkgs.cryptsetup
      ];
      systemd.services.enrollment-storage = {
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
          exec ${storage.fixture}/bin/kaiba-enrollment-storage \
            "$STORAGE_PHASE" ${configFile} /run/runtime.json \
            --expected-boot-id "$(cat /proc/sys/kernel/random/boot_id)"
        '';
      };
    };
    testScript = ''
      import json, shlex
      machine.start(allow_reboot=True)
      machine.wait_for_unit("multi-user.target")
      client = "${client}/bin/kaiba-device-enrollment"
      state = "/run/kaiba-enrollment-storage/volume/credentials"
      base = "/run/kaiba-enrollment-storage"
      results = []

      def prepare_runtime():
          runtime = dict(schema_version="kaiba.enrollment-storage-runtime/v1alpha1",
                         kernel_release=machine.succeed("uname -r").strip(),
                         firmware_version="synthetic-firmware", boot_image_sha256="b"*64,
                         verity_root_hash="c"*64)
          machine.succeed("printf %s " + shlex.quote(json.dumps(runtime)) + " > /run/runtime.json")

      def run(phase, passed=True, fault=None):
          env = f"STORAGE_PHASE={phase}\n" + (f"KAIBA_TEST_FAULT={fault}\n" if fault else "")
          machine.succeed("printf %s " + shlex.quote(env) + " > /run/storage-environment")
          exit_code, _ = machine.execute("systemctl start enrollment-storage.service")
          raw = machine.succeed("cat /run/storage-result")
          assert not machine.succeed("cat /run/storage-errors")
          value = json.loads(raw)
          assert (exit_code == 0) is passed, value
          assert value["passed"] is passed and value["mode"] == "synthetic-development", value
          assert not value["hardware_qualified"] and not value["production_enrollment"], value
          assert "42"*32 not in raw and "private_key_pkcs8" not in raw, raw
          results.append(dict(phase=phase, expected_pass=passed, fault=fault, result=value))
          return value

      def reset_created():
          # Only disposable VM setup can reset a consumed experiment.
          machine.succeed("test ! -e /dev/mapper/kaiba-secret-experiment-open")
          machine.succeed("dd if=/var/lib/created.img of=/dev/vdb1 bs=1M conv=fsync status=none")
          machine.succeed("rm -rf " + base)

      machine.succeed("printf 'label: gpt\nstart=2048,size=133120,type=linux,uuid=${config.partition_uuid}\n' | sfdisk /dev/vdb")
      machine.succeed("udevadm settle")
      prepare_runtime()
      created = run("create")
      assert created["mounted"] and created["runtime_locks_closed"] and not created["journal_completed"]
      machine.succeed("${python}/bin/python3 ${./enrollment-storage/client-fixture.py} " + client + " ${config.volume_uuid}")
      expected = json.loads(machine.succeed("cat /var/lib/enrollment-fixture/installed.json"))
      assert not expected["boot_change_observed"] and not expected["production_enrollment"]
      machine.succeed("sync")
      machine.succeed("python3 -c \"from pathlib import Path; d=Path('/dev/vdb1').read_bytes(); assert b'private_key_pkcs8' not in d; assert b'certificate_pem' not in d\"")

      # Mount disappearance cannot silently create a replacement software key.
      machine.succeed("mkdir -m700 /run/plain")
      machine.fail(client + " initialize --state /run/plain --input /var/lib/enrollment-fixture/config.json")
      machine.succeed("test ! -e /run/plain/state.json")
      assert run("create", False)["stop"] == "same-boot-repeat"
      # A shadow mount cannot be mistaken for the recorded encrypted volume.
      machine.succeed("mount -t tmpfs -o mode=0700 tmpfs " + base + "/volume")
      machine.succeed("mkdir -m700 " + state)
      machine.fail(client + " initialize --state " + state + " --input /var/lib/enrollment-fixture/config.json")
      machine.succeed("test ! -e " + state + "/state.json")
      assert run("close", False)["stop"] == "close-binding"
      machine.succeed("test ! -e " + base + "/close.intent.json")
      machine.succeed("umount " + base + "/volume")
      closed = run("close")
      assert closed["storage_closed"] and closed["journal_completed"] and not closed["mounted"]
      machine.succeed("test ! -e /dev/mapper/kaiba-secret-experiment-open")
      machine.fail(client + " status --state " + state)
      machine.succeed("test ! -e " + state)
      machine.succeed("cp /dev/vdb1 /var/lib/created.img")
      assert run("close", False)["stop"] == "close-binding"

      machine.reboot()
      machine.wait_for_unit("multi-user.target")
      machine.succeed("udevadm settle")
      prepare_runtime()
      reopened = run("reopen")
      assert reopened["boot_id"] != created["boot_id"] and reopened["mounted"] and reopened["runtime_locks_closed"]
      actual = json.loads(machine.succeed(client + " status --state " + state))
      assert actual == expected, (actual, expected)

      # A wrong volume binding is rejected before a new state file is generated.
      machine.succeed("python3 -c \"import json; p='/var/lib/enrollment-fixture/config.json'; c=json.load(open(p)); c['protected_volume_uuid']='99999999-9999-4999-8999-999999999999'; json.dump(c,open('/run/wrong.json','w'))\"")
      machine.succeed("mkdir -m700 " + base + "/volume/wrong")
      machine.fail(client + " initialize --state " + base + "/volume/wrong --input /run/wrong.json")
      machine.succeed("test ! -e " + base + "/volume/wrong/state.json")
      run("close")
      machine.succeed("cp /dev/vdb1 /var/lib/completed.img")
      machine.succeed("rm -rf " + base)
      assert run("reopen", False)["stop"] == "storage-prestate"
      machine.succeed("cmp /dev/vdb1 /var/lib/completed.img")

      for fault, stop in [("other-board", "volume-open"), ("hmac-einval", "luks-derivation"),
                          ("hmac-short", "luks-derivation"), ("cleanup", "close-runtime-locks"),
                          ("interrupted", "luks-derivation")]:
          reset_created()
          value = run("reopen", False, fault)
          assert value["stop"] == stop and not value["mounted"] and value["storage_closed"], value
          assert not value["journal_completed"], value
          if fault == "hmac-einval":
              assert (value["last_mailbox_tag"], value["last_mailbox_errno"]) == (0x30092, 22), value
          machine.succeed("cp /dev/vdb1 /var/lib/failed.img")
          machine.succeed("rm -rf " + base)
          assert run("reopen", False)["stop"] == "storage-prestate"
          machine.succeed("cmp /dev/vdb1 /var/lib/failed.img")

      for fault in ["preclosed", "wrong-usage"]:
          reset_created()
          assert run("reopen", False, fault)["stop"] == "firmware-metadata"
          machine.succeed("cmp /dev/vdb1 /var/lib/created.img")

      reset_created()
      machine.succeed("dd if=/dev/zero of=/var/lib/test.swap bs=1M count=16 status=none && chmod 600 /var/lib/test.swap && mkswap /var/lib/test.swap && swapon /var/lib/test.swap")
      assert run("reopen", False)["stop"] == "memory-protection"
      machine.succeed("cmp /dev/vdb1 /var/lib/created.img")
      machine.succeed("swapoff /var/lib/test.swap")
      machine.succeed("mkdir -p /run/systemd/system/enrollment-storage.service.d && printf '[Service]\nLimitMEMLOCK=0\nCapabilityBoundingSet=~CAP_IPC_LOCK\n' > /run/systemd/system/enrollment-storage.service.d/limit.conf && systemctl daemon-reload")
      assert run("reopen", False)["stop"] == "memory-protection"
      machine.succeed("cmp /dev/vdb1 /var/lib/created.img")
      machine.succeed("rm /run/systemd/system/enrollment-storage.service.d/limit.conf && systemctl daemon-reload")

      reset_created()
      machine.succeed("python3 -c \"import json; p='/run/runtime.json'; d=json.load(open(p)); d['boot_image_sha256']='d'*64; json.dump(d,open(p,'w'))\"")
      assert run("reopen", False)["stop"] == "runtime-binding"
      machine.succeed("cmp /dev/vdb1 /var/lib/created.img")
      prepare_runtime()
      # A partial create never becomes a fresh formatting request.
      machine.succeed("dd if=/dev/zero of=/dev/vdb1 bs=1M count=65 conv=fsync status=none")
      machine.succeed("rm -rf " + base)
      assert run("create", False, "hmac-einval")["stop"] == "luks-derivation"
      machine.succeed("cp /dev/vdb1 /var/lib/interrupted.img")
      machine.succeed("rm -rf " + base)
      assert run("create", False)["stop"] == "storage-prestate"
      machine.succeed("cmp /dev/vdb1 /var/lib/interrupted.img")

      reset_created()
      run("reopen")
      machine.succeed("python3 -c 'import os,time; os.chdir(\"" + state + "\"); time.sleep(600)' >/dev/null 2>&1 & echo $! > /run/holder.pid")
      machine.succeed("sleep 1")
      blocked = run("close", False)
      assert blocked["stop"] == "unmount" and blocked["mounted"] and not blocked["journal_completed"], blocked
      assert blocked["cleanup_error"] == "mounted-state-retained", blocked
      assert run("close", False)["stop"] == "close-intent"
      machine.succeed("kill $(cat /run/holder.pid)")
      machine.wait_until_succeeds("! kill -0 $(cat /run/holder.pid) 2>/dev/null")
      # Explicit cleanup of a failed synthetic case, not a helper retry feature.
      machine.succeed("umount " + base + "/volume && cryptsetup close kaiba-secret-experiment-open && dmsetup remove kaiba-secret-experiment-container")
      with open(driver.out_dir / "report.json", "w") as output:
          json.dump(dict(mode="synthetic-development", hardware_qualified=False,
                         production_enrollment=False, cases=results), output, indent=2)
    '';
  };
in
if pkgs.stdenv.hostPlatform.system == "aarch64-linux" then
  vm.overrideTestDerivation (_: {
    requiredSystemFeatures = [ "nixos-test" ];
  })
else
  vm
