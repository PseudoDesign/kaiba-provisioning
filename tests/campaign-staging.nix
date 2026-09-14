{
  lib,
  pkgs,
  built,
}:

let
  plan = pkgs.writeText "invalid-campaign-plan.json" "{}";
  payload = pkgs.writeText "synthetic-campaign-payload" "synthetic";
  configured = built.mkRpi5StableCampaignStaging {
    leg = "malak-sd";
    stagingPlan = plan;
    payloads = {
      boot-filesystem = payload;
      root-data = payload;
      root-hash = payload;
    };
  };
  refuses = args: !(builtins.tryEval ((built.mkRpi5StableCampaignStaging args).drvPath)).success;
in
assert !(built.stableCampaignStagingTool.kaibaRpi5StableCampaignStaging.configured);
assert configured.kaibaRpi5StableCampaignStaging.configured;
assert refuses {
  leg = "arbitrary";
  stagingPlan = plan;
  payloads = { };
};
assert refuses {
  leg = "malak-sd";
  stagingPlan = plan;
  payloads = {
    boot-filesystem = payload;
  };
};
assert refuses {
  leg = "pi-local-nvme";
  stagingPlan = "/tmp/plan.json";
  payloads.release-filesystem = payload;
};
pkgs.runCommand "kaiba-campaign-staging-contract" { nativeBuildInputs = [ pkgs.jq ]; } ''
  set -euo pipefail
  stage=${built.stableCampaignStagingTool}/bin/kaiba-rpi5-stable-campaign-stage
  "$stage" --help > help.stdout 2> help.stderr
  test ! -s help.stdout
  grep -F 'Nix-configured candidate' help.stderr
  if "$stage" execute --directory /does-not-exist --approval /does-not-exist \
    --requirements /does-not-exist --sd-envelope /does-not-exist --nvme-envelope /does-not-exist \
    > generic.stdout 2> generic.stderr; then
    echo 'Generic staging binary unexpectedly accepted device execution' >&2
    exit 1
  fi
  test ! -s generic.stdout
  grep -F 'generic build has no linker-fixed candidate configuration' generic.stderr
  if "$stage" verify --device /dev/null > override.stdout 2> override.stderr; then
    echo 'Runtime device override unexpectedly accepted' >&2
    exit 1
  fi
  test ! -s override.stdout
  jq --exit-status \
    --arg plan '${plan}' --arg payload '${payload}' \
    '.leg == "malak-sd" and .staging_plan_path == $plan and
     (.payload_paths | length) == 3 and (.payload_paths | all(. == $payload))' \
    ${configured.kaibaRpi5StableCampaignStaging.configuration}
  # The configured candidate must consume its pinned invalid plan and fail
  # before any device access, rather than falling back to a generic binary.
  if ${configured}/bin/kaiba-rpi5-stable-campaign-stage verify \
    --requirements /does-not-exist --sd-envelope /does-not-exist --nvme-envelope /does-not-exist \
    > configured.stdout 2> configured.stderr; then
    echo 'Invalid configured plan unexpectedly accepted' >&2
    exit 1
  fi
  test ! -s configured.stdout
  ! grep -F 'generic build has no linker-fixed' configured.stderr
  ! grep -F 'candidate configuration is not canonical' configured.stderr
  ${built.stableCampaignPacketTool}/bin/kaiba-rpi5-stable-campaign-packet --help > packet.stdout 2> packet.stderr
  test ! -s packet.stdout
  mkdir -p "$out"
  cp *.stderr "$out/"
''
