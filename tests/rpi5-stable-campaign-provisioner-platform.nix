{
  lib,
  pkgs,
  self,
  nativeProvisioner,
}:

let
  cleanSource = self ? rev;
  armPackages = self.packages.aarch64-linux;
  x86Packages = self.packages.x86_64-linux;
  unsignedName = "kaiba-rpi5-stable-campaign-provisioner-unsigned";
  planName = "kaiba-rpi5-stable-campaign-provisioner-signing-plan";
  runtimeName = "kaiba-rpi5-stable-campaign-development-signing";
  checks = {
    defaultBuildIsNativeARM = lib.all (system: system == "aarch64-linux") [
      nativeProvisioner.nixosSystem.pkgs.stdenv.buildPlatform.system
      nativeProvisioner.nixosSystem.pkgs.stdenv.hostPlatform.system
      nativeProvisioner.inspectorPackage.stdenv.buildPlatform.system
      nativeProvisioner.inspectorPackage.stdenv.hostPlatform.system
      nativeProvisioner.rootImage.system
      nativeProvisioner.firmwareTree.system
      nativeProvisioner.unsignedArtifacts.system
    ];
    noPublicRevisionOverrides =
      !(self.lib ? mkRpi5StableCampaignProvisioner)
      && !(self.lib ? mkRpi5StableCampaignProvisionerSystem);
    noX86ArtifactLineage = !(x86Packages ? ${unsignedName}) && !(x86Packages ? ${planName});
    armArtifactsRequireCleanSource =
      (armPackages ? ${unsignedName}) == cleanSource && (armPackages ? ${planName}) == cleanSource;
    signingWorkstationsRequireCleanSource =
      (x86Packages ? ${runtimeName}) == cleanSource && (armPackages ? ${runtimeName}) == cleanSource;
    publishedArtifactsMatchNativeBuild =
      !cleanSource || armPackages.${unsignedName}.drvPath == nativeProvisioner.unsignedArtifacts.drvPath;
    signingPlanUsesPublishedArtifacts =
      !cleanSource
      || (
        armPackages.${planName}.system == "aarch64-linux"
        &&
          armPackages.${planName}.kaibaStableCampaignSigningPlan.unsignedArtifacts.drvPath
          == armPackages.${unsignedName}.drvPath
        && armPackages.${planName}.kaibaStableCampaignSigningPlan.sourceRevision == self.rev
      );
    signingRuntimesMatchWorkstations =
      !cleanSource
      || (
        x86Packages.${runtimeName}.system == "x86_64-linux"
        && armPackages.${runtimeName}.system == "aarch64-linux"
      );
  };
in
assert lib.assertMsg (lib.all (passed: passed) (
  builtins.attrValues checks
)) "stable-campaign native ARM platform regression: ${builtins.toJSON checks}";
pkgs.runCommand "kaiba-stable-campaign-provisioner-platform-check"
  {
    preferLocalBuild = true;
    passthru = { inherit checks; };
  }
  ''
    mkdir "$out"
    printf '%s\n' ${lib.escapeShellArg (builtins.toJSON checks)} > "$out/results.json"
  ''
