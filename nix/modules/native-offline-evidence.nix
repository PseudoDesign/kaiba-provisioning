{
  config,
  lib,
  pkgs,
  ...
}:
let
  probe = pkgs.writeText "kaiba-offline-read-probe" (
    lib.concatStrings (builtins.genList (index: "kaiba-offline-verity-probe-${toString index}\n") 512)
  );
  expected =
    pkgs.runCommand "kaiba-offline-expected-digests" { nativeBuildInputs = [ pkgs.coreutils ]; }
      ''
        mkdir -p "$out"
        sha256sum ${config.environment.etc."os-release".source} | cut -d ' ' -f 1 > "$out/os-release.sha256"
        sha256sum ${probe} | cut -d ' ' -f 1 > "$out/probe.sha256"
      '';
  evidence = pkgs.writeShellApplication {
    name = "kaiba-native-offline-evidence";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.util-linux
      pkgs.lvm2
      pkgs.gawk
      pkgs.gnugrep
    ];
    text = ''
      set -euo pipefail
      fail() { printf 'KAIBA_NATIVE_OFFLINE=fail reason=%s\n' "$1" >&2; exit 1; }
      test "$(findmnt -nro SOURCE /)" = /dev/mapper/root || fail root-source
      case ",$(findmnt -nro OPTIONS /)," in *,ro,*) ;; *) fail root-not-read-only ;; esac
      # The mapping name and mount flag alone do not establish dm-verity.
      table="$(dmsetup table root)" || fail mapper-unavailable
      printf '%s\n' "$table" | awk 'NF >= 13 && $1 == 0 && $3 == "verity" { good++ } END { exit !(NR == 1 && good == 1) }' || fail mapper-not-verity
      read -r expected_os < ${expected}/os-release.sha256
      actual_os="$(sha256sum /etc/os-release | cut -d ' ' -f 1)" || fail local-read
      test "$actual_os" = "$expected_os" || fail local-digest
      printf 'KAIBA_NATIVE_OFFLINE=pass schema=v1 os_release_sha256=sha256:%s root=/dev/mapper/root fleet_admission=unevaluated\n' "$actual_os"
      # This is deliberately the first read of the probe file in this boot.
      # A read failure needs accompanying kernel verity diagnostics to count
      # as a physical negative result; this marker alone is not sufficient.
      if ! actual_probe="$(sha256sum /kaiba-offline-read-probe | cut -d ' ' -f 1)"; then
        printf 'KAIBA_NATIVE_OFFLINE_PROBE=read_failed require_kernel_verity_evidence=true\n' >&2
        exit 1
      fi
      read -r expected_probe < ${expected}/probe.sha256
      test "$actual_probe" = "$expected_probe" || fail probe-digest
      printf 'KAIBA_NATIVE_OFFLINE_PROBE=pass sha256=sha256:%s\n' "$actual_probe"
    '';
  };
in
{
  system.build = {
    kaibaOfflineProbe = probe;
    kaibaOfflineExpected = expected;
  };
  systemd.services.kaiba-native-offline-evidence = {
    description = "Observe the native offline candidate and explicit late root read";
    wantedBy = [ "multi-user.target" ];
    after = [ "kaiba-secure-boot-evidence.service" ];
    requires = [ "kaiba-secure-boot-evidence.service" ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = lib.getExe evidence;
      StandardOutput = "journal+console";
      StandardError = "journal+console";
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      # DM_TABLE_STATUS requires CAP_SYS_ADMIN; no device writes are issued.
      CapabilityBoundingSet = [ "CAP_SYS_ADMIN" ];
      RestrictAddressFamilies = [ "AF_UNIX" ];
      RestrictNamespaces = true;
      TimeoutStartSec = 30;
    };
  };
}
