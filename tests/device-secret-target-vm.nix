{ pkgs }:
let
  target = import ../nix/device-secret-target.nix { inherit pkgs; };
  fixtureConfig = import ./device-secret-target/fixture-config.nix;
  configFile = pkgs.writeText "device-secret-synthetic.json" (builtins.toJSON fixtureConfig);
in
pkgs.testers.runNixOSTest {
  name = "kaiba-device-secret-target-luks";
  nodes.machine = { lib, ... }: {
    virtualisation.memorySize = 1024;
    virtualisation.emptyDiskImages = [ 65 ];
    virtualisation.vlans = [ ];
    virtualisation.qemu.networkingOptions = lib.mkForce [ "-nic none" ];
    networking.useDHCP = false;
    services.timesyncd.enable = false;
    swapDevices = [ ];
    systemd.coredump.enable = false;
    boot.kernelModules = [
      "dm_mod"
      "dm_crypt"
    ];
    environment.systemPackages = [
      target.fixture
      pkgs.cryptsetup
      pkgs.lvm2
      pkgs.python3
    ];
    environment.etc."device-secret-fixture.json".source = configFile;
    systemd.services.device-secret-fixture = {
      unitConfig.StartLimitIntervalSec = 0;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${target.fixture}/bin/kaiba-device-secret-target --run-reviewed-experiment ${configFile}";
        LimitMEMLOCK = "infinity";
        LimitCORE = 0;
        StandardOutput = "truncate:/run/target-events";
        StandardError = "truncate:/run/target-errors";
        Restart = "no";
        EnvironmentFile = "-/run/device-secret-test-environment";
      };
    };
  };
  testScript = ''
    import json
    import hashlib
    import importlib.util
    spec = importlib.util.spec_from_file_location("runner", "${../scripts/device-secret/runner.py}")
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    host_plan = dict(schema_version=runner.PLAN_SCHEMA, experiment_id="synthetic-experiment",
        target_reference="synthetic-board", source_revision="a"*40, boot_image_sha256="b"*64,
        verity_root_hash="c"*64, volume_uuid="${fixtureConfig.volume_uuid}", slot_id=1,
        nonce_sha256=hashlib.sha256(bytes(range(32))).hexdigest(),
        uart_by_id="/dev/serial/by-id/synthetic-never-opened", uart_by_path="/dev/serial/by-path/synthetic-never-opened",
        idle_timeout_seconds=600, observation_seconds=10, maximum_bytes=65536)
    runner.validate_plan(host_plan)
    prior_boots = []
    start_all()
    machine.wait_for_unit("multi-user.target")

    def prepare():
        machine.succeed("mkdir -p /dev/disk/by-partuuid")
        machine.succeed("ln -s /dev/vdb /dev/disk/by-partuuid/${fixtureConfig.partition_uuid}")
        machine.succeed("test $(blockdev --getsize64 /dev/vdb) = 68157440")

    def records(phase):
        output = machine.succeed("cat /run/target-events")
        values = [json.loads(line.split("=", 1)[1]) for line in output.splitlines()]
        assert len(values) == 12, output
        assert all(value["passed"] and value["phase"] == phase for value in values)
        assert [v["sequence"] for v in values] == list(range(1, 13))
        assert values[-1]["check"] == "complete"
        assert all(line.startswith("KAIBA_DEVICE_SECRET_TEST_EVENT=") for line in output.splitlines())
        observer = runner.Events(host_plan, phase, prior_boots)
        # Explicit fixture adapter only: test events aren't production frames.
        observer.feed(output.replace("KAIBA_DEVICE_SECRET_TEST_EVENT=", "KAIBA_DEVICE_SECRET_EVENT=").encode())
        observer.finish()
        prior_boots.append(values[0]["boot_id"])
        machine.succeed("test ! -e /dev/mapper/kaiba-secret-experiment-open")
        machine.succeed("test ! -e /dev/mapper/kaiba-secret-experiment-container")
        return values[0]["boot_id"]

    prepare()
    machine.succeed("systemctl start device-secret-fixture.service")
    boot1 = records("create")
    machine.succeed("cp /dev/vdb /var/lib/device-secret-created.img")
    # The original canary and secret-test key do not appear on the raw medium.
    machine.succeed("python3 -c \"from pathlib import Path; d=Path('/dev/vdb').read_bytes(); assert b'KAIBA_PRIVATE_RECORD_V1' not in d; assert b'B'*32 not in d\"")
    machine.succeed("sha256sum /dev/vdb > /tmp/after-create.sha256")
    machine.fail("systemctl start device-secret-fixture.service")
    machine.succeed("sha256sum --check /tmp/after-create.sha256")
    machine.shutdown()
    machine.start()
    machine.wait_for_unit("multi-user.target")
    prepare()
    machine.succeed("systemctl start device-secret-fixture.service")
    boot2 = records("reopen")
    assert boot1 != boot2
    machine.shutdown()
    machine.start()
    machine.wait_for_unit("multi-user.target")
    prepare()
    machine.succeed("sha256sum /dev/vdb > /tmp/completed.sha256")
    machine.fail("systemctl start device-secret-fixture.service")
    machine.succeed("grep -F 'storage-prestate' /run/target-errors")
    machine.succeed("sha256sum --check /tmp/completed.sha256")

    # Independent negative fixtures, prepared by the VM test, never a target
    # reset/retry feature. The production helper has no journal-reset command.
    for fault, expected in [("other-board", "volume_reopened"), ("private-returned", "raw_read_blocked"),
                            ("legacy-zeros", "legacy_read_blocked"), ("clearable-locks", "locks_cannot_clear")]:
        machine.succeed("dd if=/var/lib/device-secret-created.img of=/dev/vdb bs=1M conv=fsync status=none")
        machine.succeed("rm -f /run/kaiba-device-secret-attempted")
        machine.succeed(f"printf 'KAIBA_TEST_FAULT={fault}\\n' > /run/device-secret-test-environment")
        machine.fail("systemctl start device-secret-fixture.service")
        output = machine.succeed("cat /run/target-events")
        failed = [json.loads(line.split("=", 1)[1]) for line in output.splitlines() if line.startswith("KAIBA_DEVICE_SECRET_TEST_EVENT=")]
        assert failed[-1]["check"] == expected and not failed[-1]["passed"], output
        assert not any(v["check"] == "complete" for v in failed)
        assert "5a"*32 not in output
        machine.succeed("test ! -e /dev/mapper/kaiba-secret-experiment-open")
        machine.succeed("test ! -e /dev/mapper/kaiba-secret-experiment-container")
        machine.succeed("sha256sum /dev/vdb > /run/failed.sha256")
        # Even after an explicitly reset boot-local marker, the on-media intent
        # prevents a retry and preserves the failed candidate byte-for-byte.
        machine.succeed("rm -f /run/kaiba-device-secret-attempted")
        machine.fail("systemctl start device-secret-fixture.service")
        machine.succeed("sha256sum --check /run/failed.sha256")
        machine.succeed("grep -F storage-prestate /run/target-errors")
    machine.succeed("dd if=/var/lib/device-secret-created.img of=/dev/vdb bs=1M conv=fsync status=none")
    machine.succeed("rm -f /run/kaiba-device-secret-attempted /run/device-secret-test-environment")
    machine.succeed("python3 -c \"import os; f=os.open('/dev/vdb', os.O_RDWR); os.pwrite(f, b'X', 0); os.fsync(f); os.close(f)\"")
    machine.succeed("sha256sum /dev/vdb > /run/corrupt-journal.sha256")
    machine.fail("systemctl start device-secret-fixture.service")
    machine.succeed("sha256sum --check /run/corrupt-journal.sha256")
    machine.succeed("grep -F storage-prestate /run/target-errors")
  '';
}
