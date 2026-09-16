{
  lib,
  pkgs,
  tool,
  planValidator,
}:
{
  descriptor,
  sourceRevision,
}:
let
  data = builtins.fromJSON (builtins.readFile descriptor);
  configurationPath = data.configuration.path;
in
assert lib.assertMsg (
  pkgs.stdenv.buildPlatform.system == "aarch64-linux"
  && pkgs.stdenv.hostPlatform.system == "aarch64-linux"
) "staging native components require native aarch64-linux construction";
assert lib.assertMsg (
  builtins.match "[0-9a-f]{40}" sourceRevision != null
) "staging native components require an exact source revision";
assert lib.assertMsg (
  builtins.isString configurationPath
  &&
    builtins.match "/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+" configurationPath
    != null
) "staging component requires a fixed top-level configuration store path";
tool.overrideAttrs (old: {
  pname = "kaiba-pi-local-nvme-staging-native-component";
  nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.python3 ];
  descriptorInput = descriptor;
  componentSourceRevision = sourceRevision;
  # The descriptor is committed public metadata: its path strings have no
  # configuration/payload derivation context. This output is deliberately an
  # incomplete native component; assembly restores all real runtime references.
  ldflags = (old.ldflags or [ ]) ++ [ "-X main.configurationPath=${configurationPath}" ];
  preBuild = (old.preBuild or "") + ''
    python3 ${./campaign-staging-inputs.py} validate --descriptor "$descriptorInput" \
      --plan-validator ${planValidator}/bin/kaiba-rpi5-stable-campaign-staging-plan-check
  '';
  postInstall = (old.postInstall or "") + ''
    mkdir -p "$out/share/kaiba"
    cp "$descriptorInput" "$out/share/kaiba/descriptor.json"
    python3 ${./campaign-staging-inputs.py} component \
      --plan-validator ${planValidator}/bin/kaiba-rpi5-stable-campaign-staging-plan-check \
      --descriptor "$descriptorInput" --binary "$out/bin/kaiba-rpi5-stable-campaign-stage" \
      --source-revision "$componentSourceRevision" > "$out/share/kaiba/component.json"
  '';
  passthru = (builtins.removeAttrs (old.passthru or { }) [ "kaibaRpi5StableCampaignStaging" ]) // {
    kaibaRpi5StableCampaignStagingNativeComponent = {
      inherit sourceRevision configurationPath;
      leg = "pi-local-nvme";
      targetSystem = "aarch64-linux";
      completeRuntimeClosure = false;
      requiresAssembly = true;
      hardwareQualified = false;
      productionReady = false;
    };
  };
})
