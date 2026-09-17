{ pkgs, candidate }:
pkgs.runCommand "kaiba-device-secret-experiment-artifacts"
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
    for role in boot_image root_data root_hash_tree; do
      path="$(jq -r --arg role "$role" '.artifacts[$role].path' "$bundle/manifest.json")"
      expected="$(jq -r --arg role "$role" '.artifacts[$role].digest' "$bundle/manifest.json")"
      test "sha256:$(sha256sum "$bundle/$path" | cut -d ' ' -f 1)" = "$expected"
    done
    root_hash="$(jq -r '.root_integrity_digest | sub("^sha256:"; "")' "$bundle/manifest.json")"
    veritysetup verify "$bundle/nvme/root-data.img" "$bundle/nvme/root-hash.img" "$root_hash"
    mcopy -i "$bundle/unsigned/boot.img" ::config.txt config.txt
    grep -x 'lock_device_private_key=1' config.txt
    grep -x 'lock_device_key_write=1' config.txt
    mcopy -i "$bundle/unsigned/boot.img" ::nixos/default/cmdline.txt cmdline.txt
    grep -F 'roothash='"$root_hash" cmdline.txt
    test -f ${candidate.nixosSystem.config.system.build.kaibaDeviceSecretExperimentConfig}/experiment.json
    mkdir -p "$out"
    printf '%s\n' 'synthetic-bound unsigned experiment image built natively; hardware pending' > "$out/result"
  ''
