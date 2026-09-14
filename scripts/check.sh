#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$repository_root"

usage() {
  cat <<'EOF'
Usage: scripts/check.sh COMMAND [ARGUMENTS...]

Run inside `nix develop` for the pinned toolchain.
  go PACKAGE... [GO_TEST_FLAGS...]  Focused Go tests; keep Go's local cache
  unit                             All Go tests
  ui                               Station Python and JavaScript tests
  format                           Check Nix formatting without editing
  deployment                       Inert signing-gate deployment smoke test
  fast                             Format, unit, UI, and deployment checks
  contracts CHECK...               Named Nix checks on this host's architecture
  full                             Complete native Nix check suite

Examples:
  scripts/check.sh go ./internal/provisioning/campaignmedia
  scripts/check.sh contracts unit-static stable-verifier-campaign-media
EOF
}

require_no_arguments() {
  if (( $# != 0 )); then
    usage >&2
    exit 2
  fi
}

run_ui() {
  python3 -B tests/station-ui/test_validate.py
  # The transport tests consume the real generated graph/runtime config.
  # Realize only the Pages bundle, without VM or image qualification.
  local pages
  pages="$(nix --accept-flake-config build --no-link --print-out-paths .#kaiba-provision-station-pages)"
  KAIBA_STATION_PAGES="$pages" node --test \
    tests/station-ui/transport.test.mjs internal/provisioning/livestation/web/app.test.cjs
}

command="${1:-help}"
if (( $# > 0 )); then shift; fi
case "$command" in
  help|--help|-h)
    usage
    ;;
  go)
    if (( $# == 0 )); then usage >&2; exit 2; fi
    go test "$@"
    ;;
  unit)
    require_no_arguments "$@"
    go test ./...
    ;;
  ui)
    require_no_arguments "$@"
    run_ui
    ;;
  format)
    require_no_arguments "$@"
    nix --accept-flake-config fmt -- --ci
    ;;
  deployment)
    require_no_arguments "$@"
    tests/deployment/ubuntu_signing_gate_test.sh
    ;;
  fast)
    require_no_arguments "$@"
    nix --accept-flake-config fmt -- --ci
    go test ./...
    run_ui
    tests/deployment/ubuntu_signing_gate_test.sh
    git diff --exit-code -- flake.lock
    ;;
  contracts)
    if (( $# == 0 )); then usage >&2; exit 2; fi
    for check in "$@"; do
      if [[ ! "$check" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
        printf 'Invalid check name: %s\n' "$check" >&2
        exit 2
      fi
    done
    system="$(nix eval --impure --raw --expr builtins.currentSystem)"
    case "$system" in
      x86_64-linux|aarch64-linux) ;;
      *) printf 'Unsupported native development system: %s\n' "$system" >&2; exit 2 ;;
    esac
    checks=()
    for check in "$@"; do checks+=(".#checks.$system.$check"); done
    nix --accept-flake-config build -L --no-link "${checks[@]}"
    ;;
  full)
    require_no_arguments "$@"
    nix --accept-flake-config flake check -L
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
