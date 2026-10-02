#!/usr/bin/env bash
# One-time public receipt export. Never invoke staging, signing or ownership.
set -euo pipefail
umask 077
test "$#" -eq 0
test "$(id -u)" -eq 0

destination=/home/codex-remote/kaiba-private/task1-physical-acceptance-20261002/historical-media
test ! -e "$destination"
test ! -L "$destination"
mkdir -m 0700 "$destination"

for transaction in transaction-rpi5-sacrificial-v0.1.5-sd-1-attempt-2 transaction-rpi5-sacrificial-v0.1.6-sd-1; do
  mkdir -m 0700 "$destination/$transaction"
  files=(stage.json verification.json)
  if test "$transaction" = transaction-rpi5-sacrificial-v0.1.6-sd-1; then
    files+=(device-preflight.json)
  fi
  for name in "${files[@]}"; do
    source=/var/lib/kaiba-provisioning/evidence/$transaction/$name
    copy=$destination/$transaction/$name
    test -f "$source"
    test ! -L "$source"
    install -m 0600 "$source" "$copy"
    cmp "$source" "$copy"
    sha256sum "$source" "$copy" >> "$destination/source-copy.sha256"
    sync -f "$copy"
  done
  sync -f "$destination/$transaction"
done
sync -f "$destination/source-copy.sha256"
sync -f "$destination"
chown -R codex-remote:codex-remote "$destination"
printf '%s\n' "Public media receipts exported to $destination"
