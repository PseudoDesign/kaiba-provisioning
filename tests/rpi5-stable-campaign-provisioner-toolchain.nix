{
  lib,
  pkgs,
  nixosRaspberryPi,
  provisionerPkgs,
}:

let
  # Retain the old allocator configuration as the target-side reference.
  previousPkgs = import nixosRaspberryPi.inputs.nixpkgs {
    localSystem = provisionerPkgs.stdenv.buildPlatform;
    crossSystem = provisionerPkgs.stdenv.hostPlatform;
    overlays = [ nixosRaspberryPi.overlays.jemalloc-page-size-16k ];
  };
  stockBuildPkgs = import nixosRaspberryPi.inputs.nixpkgs {
    system = provisionerPkgs.stdenv.buildPlatform.system;
  };
  # Native AArch64 builds still need the Pi allocator setting in their tools.
  expectedBuildPkgs =
    if provisionerPkgs.stdenv.buildPlatform.isAarch64 then
      previousPkgs.pkgsBuildBuild
    else
      stockBuildPkgs;
  checks = {
    targetAllocatorUnchanged = provisionerPkgs.jemalloc.drvPath == previousPkgs.jemalloc.drvPath;
    buildAllocatorMatchesPlatform =
      provisionerPkgs.pkgsBuildBuild.jemalloc.drvPath == expectedBuildPkgs.jemalloc.drvPath;
    buildRustMatchesPlatform =
      provisionerPkgs.pkgsBuildBuild.rustc.unwrapped.drvPath == expectedBuildPkgs.rustc.unwrapped.drvPath;
    initrdBuilderMatchesPlatform =
      provisionerPkgs.buildPackages.makeInitrdNGTool.drvPath
      == expectedBuildPkgs.makeInitrdNGTool.drvPath;
  };
in
assert lib.assertMsg (lib.all (passed: passed) (
  builtins.attrValues checks
)) "stable-campaign provisioner toolchain regression: ${builtins.toJSON checks}";
pkgs.runCommand "kaiba-stable-campaign-provisioner-toolchain-check"
  {
    preferLocalBuild = true;
    passthru = { inherit checks; };
  }
  ''
    mkdir "$out"
    printf '%s\n' ${lib.escapeShellArg (builtins.toJSON checks)} > "$out/results.json"
  ''
