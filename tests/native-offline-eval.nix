{
  pkgs,
  lib,
  candidate,
}:
let
  c = candidate.nixosSystem.config;
in
assert lib.assertMsg (lib.all (a: a.assertion) c.assertions) "offline candidate assertions failed";
assert c.nixpkgs.buildPlatform.system == "aarch64-linux";
assert c.nixpkgs.hostPlatform.system == "aarch64-linux";
assert !c.kaiba.secureBootTarget.developmentAccess.enable;
assert !c.services.openssh.enable && !c.services.timesyncd.enable;
assert !c.networking.useDHCP && !c.networking.useNetworkd;
assert !c.networking.networkmanager.enable && !c.networking.wireless.enable;
assert !c.systemd.network.wait-online.enable;
assert !c.services.chrony.enable && !c.services.ntp.enable;
assert c.fileSystems."/".device == "/dev/mapper/root";
assert c.swapDevices == [ ] && !c.zramSwap.enable;
assert !c.systemd.coredump.enable;
assert !(c.fileSystems ? "/boot/firmware");
assert candidate.unsignedArtifacts.kaibaUnsignedArtifacts.rootDeviceBinding == "gpt-partuuid";
assert
  candidate.unsignedArtifacts.kaibaUnsignedArtifacts.dataDevice
  == "PARTUUID=${candidate.rootDataPartitionGUID}";
assert
  candidate.unsignedArtifacts.kaibaUnsignedArtifacts.hashDevice
  == "PARTUUID=${candidate.rootHashPartitionGUID}";
pkgs.runCommand "kaiba-native-offline-eval" { } ''
  mkdir -p "$out"
  printf '%s\n' 'offline candidate configuration: pass; hardware pending' > "$out/result.txt"
''
