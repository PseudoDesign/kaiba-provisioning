#!/usr/bin/env bash
# Run only from a new owner-created /tmp/kaiba-ace-smoke-stage.XXXXXXXX directory.
# This wrapper deletes that staging directory, including itself, on exit.
set -euo pipefail
umask 077
[[ $(uname -m) == aarch64 && ${HOSTNAME%%.*} == ace && $(id -u) != 0 ]]
smoke_stage=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ $smoke_stage =~ ^/tmp/kaiba-ace-smoke-stage\.[A-Za-z0-9]+$ ]]
[[ $(stat -c %u -- "$smoke_stage") == "$(id -u)" && $(stat -c %a -- "$smoke_stage") == 700 ]]
smoke_child=""
# shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap.
cleanup() {
  trap - EXIT INT TERM HUP
  if [[ -n $smoke_child ]]; then
    kill -TERM "$smoke_child" 2>/dev/null || true
    wait "$smoke_child" 2>/dev/null || true
  fi
  rm -rf -- "$smoke_stage"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
/nix/store/41m77i1296n33p6liin8ynr6wh3h6b7m-python3-3.14.6/bin/python3 \
  "$smoke_stage/run-remote.py" --probe "$smoke_stage/kaiba-spiffe-probe" \
  --probe-sha256 aa904426645638e2a3c455230d047df971614e8cdf74842c6300e983328c91d0 &
smoke_child=$!
set +e
wait "$smoke_child"
smoke_result=$?
set -e
smoke_child=""
exit "$smoke_result"
