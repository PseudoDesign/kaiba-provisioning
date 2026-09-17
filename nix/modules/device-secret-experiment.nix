{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.kaiba.deviceSecretExperiment;
  target = (import ../device-secret-target.nix { inherit pkgs; }).package;
  supplied = pkgs.writeText "kaiba-device-secret-experiment.json" (builtins.toJSON cfg.experiment);
  checked = pkgs.runCommand "kaiba-device-secret-checked-config" { } ''
    ${target}/bin/kaiba-device-secret-target --check-config ${supplied}
    mkdir -p "$out"
    cp ${supplied} "$out/experiment.json"
  '';
in
{
  options.kaiba.deviceSecretExperiment = {
    enable = lib.mkEnableOption "the bounded, separately authorized device-secret experiment";
    experiment = lib.mkOption {
      type = lib.types.attrs;
      default = { };
      description = "Exact public experiment bindings; no secret or execution authority. Validated by the packaged helper.";
    };
  };
  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          config.kaiba.secureBootTarget.enable && !config.kaiba.secureBootTarget.developmentAccess.enable;
        message = "device-secret experiments require the signed, verified-root profile with development access disabled";
      }
      {
        assertion = (cfg.experiment.source_revision or "") == config.kaiba.secureBootTarget.sourceRevision;
        message = "device-secret experiment source must match its image source";
      }
      {
        assertion = config.swapDevices == [ ] && !config.zramSwap.enable && !config.systemd.coredump.enable;
        message = "device-secret experiments require swap and core dumps disabled";
      }
      {
        assertion =
          !config.services.openssh.enable
          && !config.services.timesyncd.enable
          && !config.services.chrony.enable
          && !config.services.ntp.enable;
        message = "device-secret experiments require offline execution without remote login or network time";
      }
    ];
    hardware.raspberry-pi.config.all.options = {
      lock_device_private_key = {
        enable = true;
        value = 1;
      };
      lock_device_key_write = {
        enable = true;
        value = 1;
      };
    };
    boot.kernelModules = [ "dm_crypt" ];
    services.getty.autologinUser = lib.mkForce null;
    services.journald.extraConfig = lib.mkAfter ''
      Storage=volatile
      ForwardToConsole=no
    '';
    systemd.services = {
      kaiba-native-offline-evidence.enable = lib.mkForce false;
      "serial-getty@serial0".enable = lib.mkForce false;
      "serial-getty@ttyAMA10".enable = lib.mkForce false;
      kaiba-device-secret-experiment = {
        description = "Run the bounded two-boot device-secret experiment";
        wantedBy = [ "multi-user.target" ];
        before = [ "multi-user.target" ];
        after = [ "kaiba-secure-boot-evidence.service" ];
        requires = [ "kaiba-secure-boot-evidence.service" ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${target}/bin/kaiba-device-secret-target --run-reviewed-experiment ${checked}/experiment.json";
          Restart = "no";
          RemainAfterExit = true;
          TimeoutStartSec = 200;
          LimitMEMLOCK = "infinity";
          LimitCORE = 0;
          UMask = "0077";
          StandardOutput = "null";
          StandardError = "journal+console";
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          ReadWritePaths = [
            "/run"
            "/dev"
          ];
          RestrictAddressFamilies = [
            "AF_UNIX"
            "AF_NETLINK"
          ];
          RestrictNamespaces = true;
          LockPersonality = true;
          CapabilityBoundingSet = [
            "CAP_SYS_ADMIN"
            "CAP_IPC_LOCK"
            "CAP_SYSLOG"
          ];
        };
      };
    };
    system.build.kaibaDeviceSecretExperimentConfig = checked;
  };
}
