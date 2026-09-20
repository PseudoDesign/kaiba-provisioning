{
  config,
  lib,
  pkgs,
  utils,
  ...
}:
let
  cfg = config.kaiba.deviceSecretOfflineStorage;
  partitionUnit = "${utils.escapeSystemdPath "/dev/disk/by-partuuid/${cfg.experiment.partition_uuid}"}.device";
  target = (import ../device-secret-storage-development.nix { inherit pkgs; }).offlineHelper;
  supplied = pkgs.writeText "kaiba-device-secret-offline-storage.json" (
    builtins.toJSON cfg.experiment
  );
  checked = pkgs.runCommand "kaiba-device-secret-checked-config" { } ''
    ${target}/bin/kaiba-device-secret-storage-development --check-config ${supplied}
    mkdir -p "$out"
    cp ${supplied} "$out/experiment.json"
  '';
in
{
  options.kaiba.deviceSecretOfflineStorage = {
    enable = lib.mkEnableOption "the bounded, separately authorized offline storage development experiment";
    experiment = lib.mkOption {
      type = lib.types.attrs;
      default = { };
      description = "Exact public experiment bindings; no secret or execution authority. Validated by the packaged helper.";
    };
  };
  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !(config.kaiba.deviceSecretExperiment.enable or false);
        message = "offline storage development and qualification experiments are mutually exclusive";
      }
      {
        assertion =
          config.kaiba.secureBootTarget.enable && !config.kaiba.secureBootTarget.developmentAccess.enable;
        message = "offline storage development experiments require the signed, verified-root profile with development access disabled";
      }
      {
        assertion = (cfg.experiment.source_revision or "") == config.kaiba.secureBootTarget.sourceRevision;
        message = "device-secret experiment source must match its image source";
      }
      {
        assertion = config.swapDevices == [ ] && !config.zramSwap.enable && !config.systemd.coredump.enable;
        message = "offline storage development experiments require swap and core dumps disabled";
      }
      {
        assertion =
          !config.services.openssh.enable
          && !config.services.timesyncd.enable
          && !config.services.chrony.enable
          && !config.services.ntp.enable;
        message = "offline storage development experiments require offline execution without remote login or network time";
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
      kaiba-device-secret-offline-storage = {
        description = "Run the bounded two-boot offline storage development experiment";
        wantedBy = [ "multi-user.target" ];
        before = [ "multi-user.target" ];
        after = [
          "kaiba-secure-boot-evidence.service"
          partitionUnit
        ];
        requires = [
          "kaiba-secure-boot-evidence.service"
          partitionUnit
        ];
        unitConfig.JobTimeoutSec = 90;
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${target}/bin/kaiba-device-secret-storage-development --run-reviewed-experiment ${checked}/experiment.json";
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
    system.build.kaibaDeviceSecretOfflineStorageConfig = checked;
  };
}
