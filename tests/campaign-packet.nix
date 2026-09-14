{
  lib,
  pkgs,
  baselineMedia,
  run1,
  run2,
}:

let
  contract = baselineMedia.kaibaRpi5StableVerifierCampaignMedia;
  source = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../internal/provisioning
      ../cmd/kaiba-rpi5-stable-campaign-packet
    ];
  };
in
pkgs.runCommand "kaiba-stable-campaign-packet-integration"
  {
    baselineMediaInput = baselineMedia;
    campaignPlanInput = contract.campaignPlan;
    campaignMutationInputsInput = contract.campaignMutationInputs;
    verifiedSignedBootInput = contract.verifiedSignedBoot;
    delegatedReleaseInput = contract.delegatedRelease;
    run1Input = run1;
    run2Input = run2;
    nativeBuildInputs = [
      pkgs.go
      pkgs.coreutils
      pkgs.jq
      pkgs.mtools
      pkgs.gnugrep
    ];
    CGO_ENABLED = "0";
    preferLocalBuild = true;
  }
  ''
    set -euo pipefail
    export GOCACHE="$TMPDIR/go-cache"
    export GOPATH="$TMPDIR/go-path"
    export LC_ALL=C
    export KAIBA_PACKET_INTEGRATION=1
    export KAIBA_PACKET_BASELINE="$baselineMediaInput"
    export KAIBA_PACKET_PLAN="$campaignPlanInput"
    export KAIBA_PACKET_RUN1="$run1Input/materialization.json"
    export KAIBA_PACKET_RUN2="$run2Input/materialization.json"
    export KAIBA_PACKET_PUBLIC_INPUTS="$TMPDIR/public-inputs"
    export KAIBA_PACKET_TARGETS="$TMPDIR/targets"
    mkdir "$KAIBA_PACKET_PUBLIC_INPUTS" "$KAIBA_PACKET_TARGETS"
    install -m 0444 "$verifiedSignedBootInput/boot.img" \
      "$KAIBA_PACKET_PUBLIC_INPUTS/unsigned-verifier-boot"
    install -m 0444 "$verifiedSignedBootInput/public.pem" \
      "$KAIBA_PACKET_PUBLIC_INPUTS/customer-boot-public-key"
    install -m 0444 "$delegatedReleaseInput/nvme-release/release-manifest.json" \
      "$KAIBA_PACKET_PUBLIC_INPUTS/positive-release-manifest"
    mcopy -i "$verifiedSignedBootInput/boot.img" \
      '::/kaiba/stable-verifier-policy.json' "$KAIBA_PACKET_PUBLIC_INPUTS/stable-verifier-policy"
    mcopy -i "$verifiedSignedBootInput/boot.img" \
      '::/kaiba/root-public.pem' "$KAIBA_PACKET_PUBLIC_INPUTS/release-policy-root-public-key"
    mcopy -i "$verifiedSignedBootInput/boot.img" \
      '::/kaiba/authority-ca.pem' "$KAIBA_PACKET_PUBLIC_INPUTS/authorization-trust-anchor"
    jq -cS '.release.files' "$baselineMediaInput/manifest.json" > "$TMPDIR/release-files.json"
    {
      printf '%s\0' 'kaiba.provisioning.rpi5-stable-verifier-campaign-release-tree.v1alpha1'
      printf '%s' "$(< "$TMPDIR/release-files.json")"
    } > "$KAIBA_PACKET_PUBLIC_INPUTS/positive-release-tree"
    jq -r '.bound_replacements[].replacement_input' "$campaignPlanInput" | sort -u \
      | while IFS= read -r name; do
        install -m 0444 "$campaignMutationInputsInput/$name.json" "$KAIBA_PACKET_PUBLIC_INPUTS/$name"
      done
    jq -r '.byte_xor_mutations[].target' "$campaignPlanInput" \
      | while IFS= read -r target; do
        case "$target" in
          release/*) input="$delegatedReleaseInput/nvme-release/''${target#release/}" ;;
          media/root-data) input="$baselineMediaInput/sd/root-data.img" ;;
          media/root-hash) input="$baselineMediaInput/sd/root-hash.img" ;;
          *) exit 1 ;;
        esac
        mkdir -p "$(dirname "$KAIBA_PACKET_TARGETS/$target")"
        cp --reflink=auto --sparse=always "$input" "$KAIBA_PACKET_TARGETS/$target"
      done
    mkdir "$out"
    cd ${source}
    go test ./cmd/kaiba-rpi5-stable-campaign-packet \
      -run '^TestPublicCampaignPacketIntegration$' -count=1 -v -timeout=15m \
      | tee "$out/test-results.txt"
    grep -F -- '--- PASS: TestPublicCampaignPacketIntegration (' "$out/test-results.txt" > /dev/null
    touch "$out/passed"
  ''
