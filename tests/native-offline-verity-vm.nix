{ pkgs }:
let
  fixture =
    pkgs.runCommand "kaiba-native-offline-verity-fixtures"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.cryptsetup
          pkgs.e2fsprogs
          pkgs.python3
        ];
      }
      ''
        set -euo pipefail
        mkdir -p "$out" contents/etc
        printf '%s\n' 'ID=kaiba-offline-test' > contents/etc/os-release
        python3 - <<'PY'
        from pathlib import Path
        Path('contents/kaiba-offline-read-probe').write_bytes(bytes(range(256)) * 64)
        PY
        truncate -s 32M "$out/pristine.img"
        mkfs.ext4 -q -F -b 4096 -d contents "$out/pristine.img"
        veritysetup format "$out/pristine.img" "$out/hash.img" > format.txt
        sed -n 's/^Root hash:[[:space:]]*//p' format.txt > "$out/root-hash"
        sha256sum contents/etc/os-release | cut -d ' ' -f 1 > "$out/os-release.sha256"
        sha256sum contents/kaiba-offline-read-probe | cut -d ' ' -f 1 > "$out/probe.sha256"
        python3 ${../scripts/native-offline/root-probe-plan.py} "$out/pristine.img" > "$out/probes.json"
        python3 - "$out" <<'PY'
        import json, shutil, sys
        from pathlib import Path
        root = Path(sys.argv[1])
        plan = json.loads((root / 'probes.json').read_text())
        for case in plan['cases']:
            path = root / (case['purpose'] + '.img')
            shutil.copyfile(root / 'pristine.img', path)
            with path.open('r+b') as image:
                image.seek(case['byte_offset'])
                value = image.read(1)[0] ^ case['xor_mask']
                image.seek(case['byte_offset'])
                image.write(bytes([value]))
        PY
      '';
in
pkgs.testers.runNixOSTest {
  name = "kaiba-native-offline-verity";
  nodes.machine = { lib, ... }: {
    virtualisation.vlans = [ ];
    virtualisation.qemu.networkingOptions = lib.mkForce [ "-nic none" ];
    networking.useDHCP = false;
    services.timesyncd.enable = false;
    boot.kernelModules = [
      "dm_verity"
      "loop"
    ];
    environment.systemPackages = [
      pkgs.cryptsetup
      pkgs.util-linux
      pkgs.coreutils
    ];
    environment.etc."offline-fixture".source = fixture;
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("test -z \"$(ls /sys/class/net | grep -v '^lo$')\"")
    machine.fail("systemctl is-active systemd-timesyncd.service")
    machine.succeed("mkdir -p /mnt/candidate")
    root_hash = machine.succeed("cat /etc/offline-fixture/root-hash").strip()

    def attach(case):
        machine.succeed("dmesg -c > /dev/null")
        machine.succeed(f"veritysetup open /etc/offline-fixture/{case}.img candidate /etc/offline-fixture/hash.img {root_hash}")

    def close():
        machine.succeed("veritysetup close candidate")

    attach("pristine")
    machine.succeed("mount -o ro /dev/mapper/candidate /mnt/candidate")
    machine.succeed("test $(sha256sum /mnt/candidate/etc/os-release | cut -d' ' -f1) = $(cat /etc/offline-fixture/os-release.sha256)")
    machine.succeed("test $(sha256sum /mnt/candidate/kaiba-offline-read-probe | cut -d' ' -f1) = $(cat /etc/offline-fixture/probe.sha256)")
    machine.succeed("umount /mnt/candidate")
    close()

    attach("startup-superblock")
    machine.fail("mount -o ro /dev/mapper/candidate /mnt/candidate")
    machine.succeed("dmesg | grep -E 'verity.*(corrupt|verification failed)'")
    close()

    # Start a fresh kernel for the second negative case. dm-verity's shared
    # diagnostic rate limiter may have been exhausted by mount's repeated
    # superblock reads; a missing later diagnostic must not become a flaky
    # assertion or be mistaken for evidence from the previous experiment.
    machine.shutdown()
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mkdir -p /mnt/candidate")
    attach("first-read-after-mount")
    machine.succeed("mount -o ro /dev/mapper/candidate /mnt/candidate")
    machine.succeed("test $(sha256sum /mnt/candidate/etc/os-release | cut -d' ' -f1) = $(cat /etc/offline-fixture/os-release.sha256)")
    # The first access to these data blocks happens after mounting and the
    # successful local action. Original data was never read into this mapping.
    machine.fail("cat /mnt/candidate/kaiba-offline-read-probe > /dev/null")
    machine.succeed("dmesg | grep -E 'verity.*(corrupt|verification failed)'")
    machine.succeed("umount /mnt/candidate")
    close()
  '';
}
