#!/usr/bin/env bash

set -euo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
script="$script_dir/kaiba-rpi5-self-kexec-diagnostic.sh"

fail() {
  printf 'test failure: %s\n' "$*" >&2
  exit 1
}

array_contains() {
  local expected="$1"
  shift
  local value
  for value in "$@"; do
    [[ "$value" == "$expected" ]] && return 0
  done
  return 1
}

array_has_prefix() {
  local prefix="$1"
  shift
  local value
  for value in "$@"; do
    [[ "$value" == "$prefix"* ]] && return 0
  done
  return 1
}

reset_argument_state() {
  work_dir=''
  kernel_argument=''
  busybox_argument=''
  kexec_argument=''
  mode="$legacy_mode"
  mode_was_explicit=false
  execute=false
  confirmation=''
}

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

# Sourcing the implementation must not prepare or execute anything.
# shellcheck source=kaiba-rpi5-self-kexec-diagnostic.sh
source "$script"

help="$work/help"
bash "$script" --help >/dev/null 2>"$help"
grep -F 'Without --execute' "$help" >/dev/null || fail 'help does not describe the safe default'
grep -F -- '--confirm EXECUTE-DEVELOPMENT-RPI5-SELF-KEXEC' "$help" >/dev/null ||
  fail 'help omits the legacy execution confirmation boundary'
grep -F -- '--confirm EXECUTE-DEVELOPMENT-RPI5-FILE-LIVE-FDT-SELF-KEXEC' "$help" >/dev/null ||
  fail 'help omits the file-live-fdt execution confirmation boundary'
grep -F -- '--mode legacy-explicit-dtb|file-live-fdt' "$help" >/dev/null ||
  fail 'help omits the preparation-time mode selection'

busybox="${KAIBA_SELF_KEXEC_TEST_BUSYBOX:-${KAIBA_RPI5_SELF_KEXEC_BUSYBOX:-}}"
if [[ -z "$busybox" ]]; then
  busybox="$(command -v busybox)"
fi
busybox="$(readlink -e -- "$busybox")"
require_busybox_applets "$busybox"
for beacon_applet in dmesg grep tail timeout; do
  "$busybox" --list | grep -Fx -- "$beacon_applet" >/dev/null ||
    fail "BusyBox lacks CPU-diagnostic applet: $beacon_applet"
done
grep -F '"$busybox" chroot "$initramfs_root" /bin/busybox true' "$script" >/dev/null ||
  fail 'static BusyBox is not behaviorally checked inside the library-free initramfs'
grep -F '"$busybox" zcat "$config_path"' "$script" >/dev/null ||
  fail 'compressed kernel config is not read with the verified static BusyBox'
if grep -F 'require_command gzip' "$script" >/dev/null; then
  fail 'kernel config preflight still depends on a host gzip executable'
fi
grep -F '      busybox-source-path.txt \' "$script" >/dev/null ||
  fail 'prepared payload hashes omit the BusyBox path'
grep -F '      busybox.sha256 \' "$script" >/dev/null ||
  fail 'prepared payload hashes omit the BusyBox digest'
grep -F '      mode.txt >PAYLOAD_SHA256SUMS' "$script" >/dev/null ||
  fail 'prepared payload hashes omit the selected mode'

prepare_preflight_line="$(grep -nF '  require_mode_capability "$mode" "$busybox"' "$script" | cut -d: -f1)"
prepare_create_line="$(grep -nF '  mkdir -m 0700 -- "$work_dir"' "$script" | cut -d: -f1)"
[[ "$prepare_preflight_line" =~ ^[0-9]+$ && "$prepare_create_line" =~ ^[0-9]+$ &&
  "$prepare_preflight_line" -lt "$prepare_create_line" ]] ||
  fail 'preparation does not preflight the selected kexec mode before creating its bundle'
execute_preflight_line="$(grep -nF '  require_mode_capability "$selected_mode" "$busybox"' "$script" | cut -d: -f1)"
execution_claim_line="$(grep -nF '  mkdir -m 0700 -- "$work_dir/EXECUTION_CLAIM"' "$script" | cut -d: -f1)"
[[ "$execute_preflight_line" =~ ^[0-9]+$ && "$execution_claim_line" =~ ^[0-9]+$ &&
  "$execute_preflight_line" -lt "$execution_claim_line" ]] ||
  fail 'execution does not preflight the selected kexec mode before claiming the bundle'

if [[ "${KAIBA_SELF_KEXEC_EXPECT_GNU_TOOLS:-}" == 1 ]]; then
  cpio --version | grep -F 'GNU cpio' >/dev/null ||
    fail 'packaged runtime PATH does not select GNU cpio'
  realpath --version | grep -F 'GNU coreutils' >/dev/null ||
    fail 'packaged runtime PATH does not select GNU realpath'
fi

archive_a="$work/a.cpio"
archive_b="$work/b.cpio"
build_initramfs "$busybox" "$script_dir/beacon-init" "$archive_a" "$work/scratch-a"
build_initramfs "$busybox" "$script_dir/beacon-init" "$archive_b" "$work/scratch-b"
cmp --silent -- "$archive_a" "$archive_b" || fail 'beacon initramfs is not reproducible'

archive_listing="$work/archive-listing"
cpio --list --quiet <"$archive_a" | LC_ALL=C sort >"$archive_listing"
expected_listing="$work/expected-listing"
printf '%s\n' . bin bin/busybox dev init proc sys | LC_ALL=C sort >"$expected_listing"
cmp --silent -- "$expected_listing" "$archive_listing" || fail 'beacon initramfs contains unexpected paths'

extract="$work/extract"
mkdir "$extract"
(
  cd "$extract"
  cpio --extract --quiet <"$archive_a"
)
grep -F 'KAIBA_RPI5_SELF_KEXEC_BEACON:v1' "$extract/init" >/dev/null ||
  fail 'beacon marker is absent from init'
[[ "$(sed -n '1p' "$extract/init")" == '#!/bin/busybox sh' ]] ||
  fail 'beacon initramfs interpreter is not the embedded static BusyBox'
"$busybox" sh -n "$extract/init" || fail 'beacon init has invalid BusyBox shell syntax'
grep -F '/dev/ttyAMA10' "$extract/init" >/dev/null || fail 'beacon does not target ttyAMA10'
for marker in \
  KAIBA_RPI5_SELF_KEXEC_CPU_DIAGNOSTIC:v1 \
  KAIBA_RPI5_SELF_KEXEC_CPU_ONLINE_ATTEMPT: \
  KAIBA_RPI5_SELF_KEXEC_CPU_ONLINE_SUCCESS: \
  KAIBA_RPI5_SELF_KEXEC_CPU_ONLINE_FAILURE: \
  KAIBA_RPI5_SELF_KEXEC_CPU_DMESG_BEGIN \
  KAIBA_RPI5_SELF_KEXEC_CPU_DMESG: \
  KAIBA_RPI5_SELF_KEXEC_CPU_DMESG_END; do
  grep -F "$marker" "$extract/init" >/dev/null || fail "beacon omits UART contract marker: $marker"
done
grep -F 'KAIBA_RPI5_SELF_KEXEC_CPU_${label}:$value' "$extract/init" >/dev/null ||
  fail 'beacon omits the CPU-set UART marker template'
for cpu_set_call in \
  'emit_cpu_set PRESENT present' \
  'emit_cpu_set ONLINE_BEFORE online' \
  'emit_cpu_set OFFLINE_BEFORE offline' \
  'emit_cpu_set ONLINE_AFTER online' \
  'emit_cpu_set OFFLINE_AFTER offline'; do
  grep -Fx "$cpu_set_call" "$extract/init" >/dev/null ||
    fail "beacon omits CPU-set snapshot call: $cpu_set_call"
done
grep -F 'cpu_online_timeout_seconds=10' "$extract/init" >/dev/null ||
  fail 'secondary CPU online best-effort kill deadline is not ten seconds'
grep -F '"$bb" timeout -s KILL "$cpu_online_timeout_seconds"' "$extract/init" >/dev/null ||
  fail 'secondary CPU sysfs online write does not use its best-effort timeout'
grep -F 'cpu_dmesg_tail_lines=80' "$extract/init" >/dev/null ||
  fail 'CPU dmesg evidence does not have the expected line bound'
grep -F '| "$bb" tail -n "$cpu_dmesg_tail_lines" \' "$extract/init" >/dev/null ||
  fail 'CPU dmesg evidence does not enforce its line bound'
result_line="$(grep -nF "emit 'KAIBA_RPI5_SELF_KEXEC_RESULT:second-stage-init-reached'" "$extract/init" | cut -d: -f1)"
attempts_line="$(grep -nF 'online_offline_secondary_cpus' "$extract/init" | tail -n 1 | cut -d: -f1)"
poweroff_line="$(grep -nF '"$bb" poweroff -f' "$extract/init" | cut -d: -f1)"
poweroff_returned_line="$(grep -nF "emit 'KAIBA_RPI5_SELF_KEXEC_POWEROFF_RETURNED'" "$extract/init" | cut -d: -f1)"
[[ "$result_line" =~ ^[0-9]+$ && "$attempts_line" =~ ^[0-9]+$ && "$poweroff_line" =~ ^[0-9]+$ &&
  "$poweroff_returned_line" =~ ^[0-9]+$ && "$result_line" -lt "$attempts_line" &&
  "$attempts_line" -lt "$poweroff_line" && "$poweroff_line" -lt "$poweroff_returned_line" ]] ||
  fail 'CPU diagnostics are not bracketed by init-reached and fail-safe poweroff behavior'
if grep -Eq '^[[:space:]]+--serial=' "$script"; then
  fail 'diagnostic enables the unsafe kexec-tools Pi 5 purgatory serial parser'
fi
grep -F 'EXECUTION_CLAIM' "$script" >/dev/null || fail 'execution claim is not atomic'
grep -F "execution_lock_path='/run/kaiba-rpi5-self-kexec-diagnostic.lock'" "$script" >/dev/null ||
  fail 'execution does not use a host-wide lock path'
grep -F 'flock --exclusive --nonblock "$execution_lock_fd"' "$script" >/dev/null ||
  fail 'execution does not take the host-wide lock'

legacy_load_arguments=()
build_kexec_load_arguments "$legacy_mode" /prepared legacy_load_arguments
array_contains --kexec-syscall "${legacy_load_arguments[@]}" ||
  fail 'legacy load does not force the legacy syscall'
array_contains --dtb=/prepared/inputs/live.dtb "${legacy_load_arguments[@]}" ||
  fail 'legacy load does not pass the captured live DTB'
array_has_prefix --kexec-file-syscall "${legacy_load_arguments[@]}" &&
  fail 'legacy load unexpectedly selects the file syscall'

file_load_arguments=()
build_kexec_load_arguments "$file_live_fdt_mode" /prepared file_load_arguments
array_contains --kexec-file-syscall "${file_load_arguments[@]}" ||
  fail 'file-live-fdt load does not force the file syscall'
if array_has_prefix --dtb "${file_load_arguments[@]}"; then
  fail 'file-live-fdt load passes a DTB that kexec-tools would ignore'
fi
array_contains --initrd=/prepared/inputs/beacon-initramfs.cpio "${file_load_arguments[@]}" ||
  fail 'file-live-fdt load omits the prepared initramfs'
array_contains --command-line="$command_line" "${file_load_arguments[@]}" ||
  fail 'file-live-fdt load omits the fixed command line'

legacy_unload_arguments=()
build_kexec_unload_arguments "$legacy_mode" legacy_unload_arguments
[[ "${legacy_unload_arguments[*]}" == '--kexec-syscall --unload' ]] ||
  fail 'legacy cleanup does not force legacy kexec unload'
file_unload_arguments=()
build_kexec_unload_arguments "$file_live_fdt_mode" file_unload_arguments
[[ "${file_unload_arguments[*]}" == '--kexec-file-syscall --unload' ]] ||
  fail 'file-live-fdt cleanup does not force file-syscall unload'
file_exec_arguments=()
build_kexec_exec_arguments "$file_live_fdt_mode" file_exec_arguments
array_contains --kexec-file-syscall "${file_exec_arguments[@]}" ||
  fail 'file-live-fdt execution does not preserve explicit syscall selection'

command_log="$work/command.log"
run_logged "$command_log" true || fail 'run_logged rejected a successful command and log write'
tee() {
  return 23
}
if (run_logged "$command_log" true) 2>/dev/null; then
  fail 'run_logged ignored a failed diagnostic log write'
fi
unset -f tee

confirmation=''
if (require_execution_confirmation "$legacy_mode") 2>/dev/null; then
  fail 'empty execution confirmation was accepted'
fi
confirmation='wrong-token'
if (require_execution_confirmation "$legacy_mode") 2>/dev/null; then
  fail 'wrong execution confirmation was accepted'
fi
confirmation="$legacy_execution_confirmation"
require_execution_confirmation "$legacy_mode" || fail 'exact legacy execution confirmation was rejected'
if (require_execution_confirmation "$file_live_fdt_mode") 2>/dev/null; then
  fail 'legacy confirmation was accepted for file-live-fdt execution'
fi
confirmation="$file_live_fdt_execution_confirmation"
require_execution_confirmation "$file_live_fdt_mode" ||
  fail 'exact file-live-fdt execution confirmation was rejected'
if (require_execution_confirmation "$legacy_mode") 2>/dev/null; then
  fail 'file-live-fdt confirmation was accepted for legacy execution'
fi

good_config=$'CONFIG_KEXEC=y\nCONFIG_KEXEC_FILE=y\n# CONFIG_KEXEC_SIG is not set\n'
kernel_config_supports_legacy "$good_config" ||
  fail 'compatible legacy-kexec kernel configuration was rejected'
kernel_config_supports_legacy $'# CONFIG_KEXEC is not set\n' &&
  fail 'kernel without legacy kexec was accepted'
kernel_config_supports_file_live_fdt "$good_config" ||
  fail 'compatible file-kexec kernel configuration was rejected'
kernel_config_supports_file_live_fdt $'CONFIG_KEXEC_FILE=y\nCONFIG_KEXEC_SIG=y\n' &&
  fail 'signature-enforcing kernel configuration was accepted'
kernel_config_supports_file_live_fdt $'# CONFIG_KEXEC_FILE is not set\n# CONFIG_KEXEC_SIG is not set\n' &&
  fail 'kernel without file-kexec was accepted'
kexec_load_disabled_value_allows_load 0 || fail 'enabled kexec sysctl was rejected'
kexec_load_disabled_value_allows_load 1 && fail 'disabled kexec sysctl was accepted'
kexec_reboot_limit_allows_load_and_unload -1 || fail 'unlimited kexec load limit was rejected'
kexec_reboot_limit_allows_load_and_unload 2 || fail 'two-operation kexec load limit was rejected'
kexec_reboot_limit_allows_load_and_unload 1 && fail 'unsafe one-operation kexec load limit was accepted'
cap_eff_has_sys_boot 0000000000400000 || fail 'CAP_SYS_BOOT was not recognized'
cap_eff_has_sys_boot 0000000000000000 && fail 'missing CAP_SYS_BOOT was accepted'

config_fixture="$work/kernel.config"
disabled_fixture="$work/kexec_load_disabled"
status_fixture="$work/status"
limit_fixture="$work/kexec_load_limit_reboot"
printf '%s' "$good_config" >"$config_fixture"
printf '0\n' >"$disabled_fixture"
printf 'Name:\ttest\nCapEff:\t0000000000400000\n' >"$status_fixture"
printf -- '-1\n' >"$limit_fixture"
[[ "$(read_kernel_config_file "$busybox" "$config_fixture")" == "${good_config%$'\n'}" ]] ||
  fail 'verified BusyBox did not read the plain kernel config fixture'
if "$busybox" --list | grep -Fx gzip >/dev/null; then
  compressed_config_fixture="$work/kernel.config.gz"
  "$busybox" gzip -c "$config_fixture" >"$compressed_config_fixture"
  [[ "$(read_kernel_config_file "$busybox" "$compressed_config_fixture")" == "${good_config%$'\n'}" ]] ||
    fail 'verified BusyBox zcat did not read the compressed kernel config fixture'
fi
require_mode_capability \
  "$legacy_mode" "$busybox" \
  "$config_fixture" "$disabled_fixture" "$status_fixture" "$limit_fixture" ||
  fail 'fixture-backed legacy capability preflight failed'
require_mode_capability \
  "$file_live_fdt_mode" "$busybox" \
  "$config_fixture" "$disabled_fixture" "$status_fixture" "$limit_fixture" ||
  fail 'fixture-backed file-live-fdt capability preflight failed'
printf '1\n' >"$disabled_fixture"
if (require_mode_capability \
  "$legacy_mode" "$busybox" \
  "$config_fixture" "$disabled_fixture" "$status_fixture" "$limit_fixture") 2>/dev/null; then
  fail 'fixture-backed legacy preflight ignored kexec_load_disabled'
fi
if (require_mode_capability \
  "$file_live_fdt_mode" "$busybox" \
  "$config_fixture" "$disabled_fixture" "$status_fixture" "$limit_fixture") 2>/dev/null; then
  fail 'fixture-backed capability preflight ignored kexec_load_disabled'
fi
printf '0\n' >"$disabled_fixture"

# Argument parsing defaults to preparation and rejects a confirmation token
# unless --execute is present.
reset_argument_state
parse_arguments --work-dir /tmp/kaiba-self-kexec-test
[[ "$execute" == false ]] || fail 'default argument path selected execution'
[[ "$mode" == "$legacy_mode" ]] || fail 'default argument path did not select legacy explicit-DTB mode'
reset_argument_state
parse_arguments --work-dir /tmp/kaiba-self-kexec-test --mode file-live-fdt
[[ "$mode" == "$file_live_fdt_mode" ]] || fail 'explicit file-live-fdt preparation mode was not selected'
[[ "$mode_was_explicit" == true ]] || fail 'explicit preparation mode was not recorded'
if (
  reset_argument_state
  parse_arguments --work-dir /tmp/kaiba-self-kexec-test --confirm "$legacy_execution_confirmation"
) 2>/dev/null; then
  fail 'confirmation without --execute was accepted'
fi
if (
  reset_argument_state
  parse_arguments --work-dir /tmp/kaiba-self-kexec-test --mode unsupported
) 2>/dev/null; then
  fail 'unsupported preparation mode was accepted'
fi
if (
  reset_argument_state
  parse_arguments \
    --work-dir /tmp/kaiba-self-kexec-test \
    --mode file-live-fdt \
    --execute \
    --confirm "$file_live_fdt_execution_confirmation"
) 2>/dev/null; then
  fail 'execution-time mode selection was accepted'
fi

printf 'rpi5 self-kexec diagnostic shell tests: PASS\n'
