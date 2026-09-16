{
  pkgs,
  candidate,
  review,
}:
pkgs.runCommand "kaiba-native-offline-artifacts-check"
  {
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.cryptsetup
      pkgs.jq
      pkgs.mtools
      pkgs.gnugrep
    ];
  }
  ''
    set -euo pipefail
    bundle=${candidate.unsignedArtifacts}
    manifest="$bundle/manifest.json"
    for role in boot_image root_data root_hash_tree; do
      path="$(jq -r --arg role "$role" '.artifacts[$role].path' "$manifest")"
      expected="$(jq -r --arg role "$role" '.artifacts[$role].digest' "$manifest")"
      test "sha256:$(sha256sum "$bundle/$path" | cut -d ' ' -f 1)" = "$expected"
    done
    root_hash="$(jq -r '.root_integrity_digest | sub("^sha256:"; "")' "$manifest")"
    veritysetup verify "$bundle/nvme/root-data.img" "$bundle/nvme/root-hash.img" "$root_hash"
    mcopy -i "$bundle/unsigned/boot.img" ::nixos/default/cmdline.txt cmdline.txt
    grep -F 'roothash='"$root_hash" cmdline.txt
    grep -F 'systemd.verity_root_data=PARTUUID=${candidate.rootDataPartitionGUID}' cmdline.txt
    grep -F 'systemd.verity_root_hash=PARTUUID=${candidate.rootHashPartitionGUID}' cmdline.txt
    mcopy -i "$bundle/unsigned/boot.img" ::config.txt config.txt
    ! grep -E 'dtoverlay=dwc2|dr_mode=peripheral' config.txt
    jq -e '.hardware_observed == false and .physical_staging_ready == false and .signing_status == "unsigned"' ${review}/review.json
    jq -e '.cases | length == 2' ${review}/root-probe-plan.json
    mkdir -p "$out"
    printf '%s\n' 'native ARM candidate artifact checks: pass; hardware pending' > "$out/result.txt"
  ''
