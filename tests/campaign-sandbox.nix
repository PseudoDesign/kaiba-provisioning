{
  pkgs,
  source,
}:

# Exercise the public contract-to-files workflow at the fixed campaign disk
# geometries. The ordinary unit suite skips this larger fixture; this separate
# mandatory flake check opts in and rejects a skipped or missing test.
pkgs.runCommand "kaiba-stable-campaign-sandbox-integration"
  {
    nativeBuildInputs = [
      pkgs.go
      pkgs.gnugrep
    ];
    CGO_ENABLED = "0";
    KAIBA_CAMPAIGN_SANDBOX_INTEGRATION = "1";
    preferLocalBuild = true;
  }
  ''
    set -euo pipefail
    export GOCACHE="$TMPDIR/go-cache"
    export GOPATH="$TMPDIR/go-path"
    export LC_ALL=C
    mkdir -p "$out"
    cd ${source}
    go test ./internal/provisioning/campaignsandbox \
      -run '^TestPublicCampaignSandboxIntegration$' -count=1 -v -timeout=15m \
      | tee "$out/test-results.txt"
    grep -F -- '--- PASS: TestPublicCampaignSandboxIntegration (' "$out/test-results.txt" > /dev/null
    touch "$out/passed"
  ''
