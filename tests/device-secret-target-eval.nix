{
  pkgs,
  lib,
  candidate,
  baseline,
}:
let
  c = candidate.nixosSystem.config;
  service = c.systemd.services.kaiba-device-secret-experiment.serviceConfig;
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
assert !(baseline.nixosSystem.config.systemd.services ? kaiba-device-secret-experiment);
assert candidate.unsignedArtifacts.kaibaUnsignedArtifacts.rootDeviceBinding == "gpt-partuuid";
pkgs.runCommand "kaiba-device-secret-target-eval" { } ''
  mkdir -p "$out"
  printf '%s\n' 'experimental image wiring evaluated; hardware execution and qualification pending' > "$out/result"
''
