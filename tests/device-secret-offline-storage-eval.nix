{
  pkgs,
  lib,
  candidate,
  baseline,
}:
let
  c = candidate.nixosSystem.config;
  service = c.systemd.services.kaiba-device-secret-offline-storage.serviceConfig;
in
assert lib.assertMsg (lib.all (
  a: a.assertion
) c.assertions) "device-secret image assertions failed";
assert c.nixpkgs.buildPlatform.system == "aarch64-linux";
assert c.nixpkgs.hostPlatform.system == "aarch64-linux";
assert c.hardware.raspberry-pi.config.all.options.lock_device_private_key.value == 1;
assert c.hardware.raspberry-pi.config.all.options.lock_device_key_write.value == 1;
assert service.Restart == "no" && service.LimitMEMLOCK == "infinity";
assert !c.services.openssh.enable && !c.services.timesyncd.enable;
assert !c.kaiba.secureBootTarget.developmentAccess.enable;
assert c.swapDevices == [ ] && !c.zramSwap.enable && !c.systemd.coredump.enable;
assert c.fileSystems."/".device == "/dev/mapper/root";
assert !c.systemd.services.kaiba-native-offline-evidence.enable;
assert !(baseline.nixosSystem.config.systemd.services ? kaiba-device-secret-offline-storage);
assert candidate.unsignedArtifacts.kaibaUnsignedArtifacts.rootDeviceBinding == "gpt-partuuid";
assert
  c.boot.kernelPackages.kernel.drvPath
  == baseline.nixosSystem.config.boot.kernelPackages.kernel.drvPath;
assert !c.services.chrony.enable && !c.services.ntp.enable;
assert service.Restart == "no" && service.TimeoutStartSec == 200;
assert c.systemd.services.kaiba-device-secret-offline-storage.unitConfig.JobTimeoutSec == 90;
assert lib.any (lib.hasSuffix ".device")
  c.systemd.services.kaiba-device-secret-offline-storage.requires;
assert !c.systemd.services."serial-getty@serial0".enable;
pkgs.runCommand "kaiba-device-secret-offline-storage-eval" { } ''
  mkdir -p "$out"
  printf '%s\n' 'experimental image wiring evaluated; hardware execution and qualification pending' > "$out/result"
''
