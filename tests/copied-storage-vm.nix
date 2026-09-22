{ pkgs }:
let
  storage = import ../nix/device-secret-storage-development.nix { inherit pkgs; };
  comparison = import ../nix/copied-storage.nix { inherit pkgs; };
  config = (import ./device-secret-target/fixture-config.nix) // {
    schema_version = "kaiba.device-secret-storage-development/v1alpha1";
  };
  sourceConfig = pkgs.writeText "comparison-source.json" (builtins.toJSON config);
  vm = pkgs.testers.runNixOSTest {
    name = "kaiba-copied-storage";
    nodes.machine = { ... }: {
      virtualisation.memorySize = 1536;
      virtualisation.emptyDiskImages = [ 67 ];
      swapDevices = [ ];
      systemd.coredump.enable = false;
      boot.kernelModules = [
        "dm_mod"
        "dm_crypt"
        "loop"
      ];
      environment.systemPackages = [
        pkgs.python3
        pkgs.util-linux
        pkgs.lvm2
      ];
    };
    testScript = ''
      import json
      machine.start(allow_reboot=True)
      machine.wait_for_unit("multi-user.target")
      for held in ["transient", "persistent"]:
          machine.succeed("${comparison.cleanupFixture}/bin/kaiba-copied-storage " + held)
      machine.succeed("printf 'label: gpt\\nstart=2048,size=133120,type=linux,uuid=${config.partition_uuid}\\n' | sfdisk /dev/vdb")
      machine.succeed("udevadm settle")
      helper = "${storage.fixture}/bin/kaiba-device-secret-storage-development"
      def boot(): return machine.succeed("cat /proc/sys/kernel/random/boot_id").strip()
      def storage_run(phase):
          return json.loads(machine.succeed(f"ulimit -l unlimited; {helper} {phase} ${sourceConfig} --expected-boot-id {boot()}"))
      storage_run("create")
      machine.succeed("cp /dev/vdb1 /var/lib/incomplete.img")
      machine.reboot()
      machine.wait_for_unit("multi-user.target")
      storage_run("reopen")
      machine.succeed("cp /dev/vdb1 /var/lib/complete.img; chmod 600 /var/lib/*.img")
      original_hash = machine.succeed("sha256sum /dev/vdb1").split()[0]
      request = dict(schema_version="kaiba.copied-storage-comparison/v1alpha1", scheme="kaiba-firmware-hmac-counter-v1",
                     role="original", board_serial_sha256="${config.board_serial_sha256}", kernel_release="synthetic",
                     firmware_version="f"*40, image_sha256=original_hash, source_boot_image_sha256="b"*64,
                     source_verity_root_hash="c"*64, challenge_hex="e"*64, expected_usage=8)
      helper = "${comparison.fixture}/bin/kaiba-copied-storage"

      def run(role="original", fault=None, expected=True, image="complete", reset=True, bind_hash=True):
          # Resets exist in synthetic fixture setup only, never in the shipped helper.
          if reset:
              machine.succeed("rm -f /run/kaiba-copied-storage-attempted")
          machine.succeed(f"cp /var/lib/{image}.img /dev/shm/comparison.img; chmod 600 /dev/shm/comparison.img")
          value = request | dict(role=role, board_serial_sha256=("2"*64 if role == "comparison" else "${config.board_serial_sha256}"))
          if bind_hash:
              value["image_sha256"] = machine.succeed("sha256sum /dev/shm/comparison.img").split()[0]
          machine.succeed("printf '%s' '" + json.dumps(value) + "' > /run/comparison.json")
          env = f"KAIBA_TEST_FAULT={fault} " if fault else ""
          status, raw = machine.execute(f"ulimit -l unlimited; {env}{helper} run /run/comparison.json ${sourceConfig} /dev/shm/comparison.img --expected-boot-id {boot()} 2>/run/comparison.stderr")
          diagnostic = machine.succeed("cat /run/comparison.stderr")
          result = json.loads(raw)
          assert (status == 0) is expected and result["passed"] is expected, result
          assert result["mode"] == "synthetic-development" and not result["hardware_qualified"], result
          assert result["storage_closed"], result
          assert "KAIBA_PRIVATE_RECORD" not in raw + diagnostic and "42"*32 not in raw + diagnostic
          failures = {"hmac-einval": (0, 0, "true", 6), "canary-einval": (0, 0, "true", 6),
                      "error-query-eio": (2, 5, "false", 0), "error-query-malformed": (3, 0, "false", 0)}
          if fault in failures:
              outcome, error, available, value = failures[fault]
              assert diagnostic == f"KAIBA_COPIED_STORAGE_LAST_ERROR query_outcome={outcome} query_errno={error} available={available} value={value} transaction_correlated=false\n", diagnostic
              assert (result["last_firmware_outcome"], result["last_mailbox_tag"], result["last_mailbox_errno"]) == (2, 0x30092, 22), result
              assert not result["local_control_verified"] and not result["copied_fixture_rejected"] and result["runtime_locks_closed"], result
          else:
              assert diagnostic == "", diagnostic
          machine.succeed("test ! -e /dev/shm/kaiba-copied-storage-control.img")
          names = machine.succeed("dmsetup info --columns --noheadings -o name")
          assert "kaiba-copied-storage" not in names, names
          assert machine.succeed("sha256sum /dev/vdb1").split()[0] == original_hash
          return result

      first = run()
      assert first["source_record_verified"] and len(first["fixture_signature_hex"]) == 128
      assert run(reset=False, expected=False)["stop"] == "same-boot-repeat"
      again = run()
      assert first["fixture_public_key_hex"] == again["fixture_public_key_hex"]
      assert first["fixture_signature_hex"] == again["fixture_signature_hex"]
      other = run("comparison", "other-board")
      assert other["local_control_verified"] and other["copied_fixture_rejected"]
      assert other["source_unlock_return_code"] == -1 and other["fixture_signature_hex"] == ""
      assert run("comparison", expected=False)["stop"] == "unexpected-source-key"
      assert run(image="incomplete", expected=False)["stop"] == "source-copy"
      for fault, stop in [("preclosed", "firmware-metadata"), ("wrong-usage", "firmware-metadata"),
                          ("hmac-einval", "luks-derivation"), ("canary-einval", "canary-derivation"),
                          ("error-query-eio", "luks-derivation"), ("error-query-malformed", "luks-derivation"),
                          ("hmac-short", "luks-derivation"),
                          ("hmac-constant", "hmac-positive-control"), ("hmac-zero", "hmac-positive-control"),
                          ("hmac-repeat-mismatch", "hmac-positive-control"),
                          ("control-reopen", "local-positive-control"), ("cleanup", "cleanup-locks"),
                          ("interrupted", "interrupted")]:
          assert run(fault=fault, expected=False)["stop"] == stop
      machine.succeed("cp /var/lib/complete.img /var/lib/bad-record.img")
      machine.succeed("python3 -c \"import json; f=open('/var/lib/bad-record.img','r+b'); f.seek(1048576+4096); j=json.loads(f.read(12288).split(bytes([0]))[0]); p=1048576+int(j['segments']['0']['offset'])+512; f.seek(p); b=f.read(1); f.seek(p); f.write(bytes([b[0]^1]))\"")
      damaged = run(image="bad-record", expected=False)
      assert damaged["stop"] == "source-record" and damaged["fixture_signature_hex"] == ""
      machine.succeed("cp /var/lib/complete.img /var/lib/bad-header.img; printf 'BAD!' | dd of=/var/lib/bad-header.img bs=1 seek=1048576 conv=notrunc status=none")
      # LUKS has two metadata headers; corrupt both magic fields.
      machine.succeed("printf 'BAD!' | dd of=/var/lib/bad-header.img bs=1 seek=1064960 conv=notrunc status=none")
      invalid = run(image="bad-header", expected=False)
      assert invalid["stop"] == "storage-prestate" and invalid["last_mailbox_tag"] == 0
      mismatch = run(image="bad-header", expected=False, bind_hash=False)
      assert mismatch["stop"] == "source-copy" and mismatch["last_mailbox_tag"] == 0
      machine.succeed("modprobe -r dm_crypt")
      missing = run(expected=False)
      assert missing["stop"] == "storage-drivers" and missing["last_mailbox_tag"] == 0
    '';
  };
in
if pkgs.stdenv.hostPlatform.system == "aarch64-linux" then
  vm.overrideTestDerivation (_: {
    requiredSystemFeatures = [ "nixos-test" ];
  })
else
  vm
