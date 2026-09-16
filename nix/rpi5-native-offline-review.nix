{
  pkgs,
  candidate,
  platformRevision,
  platformNarHash,
  lockFile,
}:
pkgs.runCommand "kaiba-rpi5-native-offline-review"
  {
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.e2fsprogs
      pkgs.jq
      pkgs.python3
    ];
  }
  ''
    set -euo pipefail
    mkdir -p "$out"
    cp ${candidate.unsignedArtifacts}/manifest.json "$out/unsigned-artifacts.json"
    cp ${lockFile} "$out/flake.lock"
    cp ${candidate.nixosSystem.config.system.build.kaibaOfflineExpected}/* "$out/"
    python3 ${../scripts/native-offline/root-probe-plan.py} \
      ${candidate.unsignedArtifacts}/nvme/root-data.img > "$out/root-probe-plan.json"
    jq -n --slurpfile artifacts "$out/unsigned-artifacts.json" \
      --arg platform_revision '${platformRevision}' \
      --arg platform_nar_hash '${platformNarHash}' \
      --arg os_release "sha256:$(cat "$out/os-release.sha256")" \
      --arg probe "sha256:$(cat "$out/probe.sha256")" \
      --arg kernel '${candidate.nixosSystem.config.boot.kernelPackages.kernel.version}' \
      '{schema_version: "provisioning.kaiba.network/native-offline-review/v1alpha1",
        source_revision: $artifacts[0].source_revision,
        platform_revision: $platform_revision, platform_nar_hash: $platform_nar_hash,
        kernel_version: $kernel, artifact_bundle_digest: $artifacts[0].bundle_digest,
        os_release_digest: $os_release, late_read_probe_digest: $probe,
        normal_boot_medium: "nvme", system_root_medium: "nvme",
        sd_role: "separate-development-provisioner-or-recovery",
        signing_status: "unsigned", physical_staging_ready: false,
        hardware_observed: false, fleet_admission: "unevaluated",
        device_secret_feasibility: "pending"}' > "$out/review.json"
  ''
