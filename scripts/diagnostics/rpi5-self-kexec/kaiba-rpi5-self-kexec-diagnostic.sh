#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail
umask 077

readonly command_line='console=ttyAMA10,115200n8 earlycon=pl011,0x107d001000,115200n8 ignore_loglevel keep_bootcon loglevel=8 initcall_debug nokaslr rdinit=/init kaiba.self_kexec_beacon=1'
readonly debug_uart_iomem='0x107d001000'
readonly legacy_mode='legacy-explicit-dtb'
readonly file_live_fdt_mode='file-live-fdt'
readonly legacy_execution_confirmation='EXECUTE-DEVELOPMENT-RPI5-SELF-KEXEC'
readonly file_live_fdt_execution_confirmation='EXECUTE-DEVELOPMENT-RPI5-FILE-LIVE-FDT-SELF-KEXEC'
readonly execution_lock_path='/run/kaiba-rpi5-self-kexec-diagnostic.lock'
readonly prepared_marker='kaiba.provisioning.rpi5-self-kexec-diagnostic/v1alpha2'
readonly packaged_busybox_default="${KAIBA_RPI5_SELF_KEXEC_BUSYBOX:-}"

work_dir=''
kernel_argument=''
busybox_argument=''
kexec_argument=''
mode="$legacy_mode"
mode_was_explicit=false
execute=false
confirmation=''
verified_kexec=''
verified_busybox=''
verified_mode=''

usage() {
  cat >&2 <<'EOF'
usage:
  sudo kaiba-rpi5-self-kexec-diagnostic \
    --work-dir NEW_ABSOLUTE_DIRECTORY \
    [--kernel ABSOLUTE_RUNNING_KERNEL] \
    [--busybox ABSOLUTE_STATIC_BUSYBOX] \
    [--kexec ABSOLUTE_KEXEC] \
    [--mode legacy-explicit-dtb|file-live-fdt]

  sudo kaiba-rpi5-self-kexec-diagnostic \
    --work-dir EXISTING_PREPARED_DIRECTORY \
    --execute \
    --confirm EXECUTE-DEVELOPMENT-RPI5-SELF-KEXEC

  sudo kaiba-rpi5-self-kexec-diagnostic \
    --work-dir EXISTING_FILE_LIVE_FDT_DIRECTORY \
    --execute \
    --confirm EXECUTE-DEVELOPMENT-RPI5-FILE-LIVE-FDT-SELF-KEXEC

Without --execute, the tool only inspects the running Raspberry Pi 5 and
prepares a hashed self-kexec bundle. It never loads or executes a kernel.

--execute is development-only and transfers control away from the running
system. Legacy explicit-DTB loading is the default. The file-live-fdt
differential must be selected during preparation with --mode file-live-fdt;
it cannot be selected at execution time. Execution is accepted only for a
pristine bundle prepared during the same boot, with the confirmation token
bound to its hashed mode. The beacon initramfs prints to ttyAMA10 and powers
the board off after five seconds.
EOF
}

fail() {
  printf 'STOP: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v -- "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

require_root() {
  [[ "$(id -u)" == 0 ]] || fail 'run this diagnostic as root'
}

require_clean_absolute_path() {
  local label="$1"
  local path="$2"
  [[ "$path" == /* && "$path" != / ]] || fail "$label must be an absolute path other than /"
  [[ "$(realpath -ms -- "$path")" == "$path" ]] || fail "$label must be a clean absolute path"
}

resolve_regular_file() {
  local label="$1"
  local path="$2"
  require_clean_absolute_path "$label" "$path"
  local resolved
  resolved="$(readlink -e -- "$path")" || fail "$label does not resolve"
  [[ -f "$resolved" && ! -L "$resolved" && -r "$resolved" ]] ||
    fail "$label must resolve to a readable regular file"
  printf '%s\n' "$resolved"
}

resolve_command_path() {
  local label="$1"
  local argument="$2"
  local name="$3"
  local path="$argument"
  if [[ -z "$path" ]]; then
    path="$(command -v -- "$name" 2>/dev/null)" || fail "$label is unavailable; pass its absolute path"
  fi
  path="$(resolve_regular_file "$label" "$path")"
  [[ -x "$path" ]] || fail "$label is not executable"
  printf '%s\n' "$path"
}

require_pi5_runtime() {
  [[ "$(uname -m)" == aarch64 ]] || fail 'this development diagnostic runs only on aarch64'
  [[ -r /proc/device-tree/model ]] || fail 'device-tree model is unavailable'
  local model
  model="$(tr -d '\000' </proc/device-tree/model)"
  [[ "$model" == Raspberry\ Pi\ 5\ Model\ B* ]] ||
    fail "hardware is not a Raspberry Pi 5 Model B: $model"
  [[ -r /sys/firmware/fdt ]] || fail 'live firmware device tree is unavailable'
  [[ -r /proc/sys/kernel/random/boot_id ]] || fail 'kernel boot ID is unavailable'
  [[ -r /sys/class/tty/ttyAMA10/iomem_base ]] ||
    fail 'ttyAMA10 MMIO base is unavailable'
  local uart_iomem
  uart_iomem="$(tr -d '[:space:]' </sys/class/tty/ttyAMA10/iomem_base)"
  [[ "$uart_iomem" =~ ^0x[0-9a-fA-F]+$ ]] ||
    fail "ttyAMA10 MMIO base is malformed: $uart_iomem"
  ((uart_iomem == debug_uart_iomem)) ||
    fail "ttyAMA10 MMIO base is $uart_iomem, want $debug_uart_iomem"
}

require_valid_mode() {
  case "$1" in
    "$legacy_mode" | "$file_live_fdt_mode") ;;
    *) fail "unsupported self-kexec mode: $1" ;;
  esac
}

execution_confirmation_for_mode() {
  case "$1" in
    "$legacy_mode") printf '%s\n' "$legacy_execution_confirmation" ;;
    "$file_live_fdt_mode") printf '%s\n' "$file_live_fdt_execution_confirmation" ;;
    *) fail "cannot select an execution confirmation for unsupported mode: $1" ;;
  esac
}

resolve_running_kernel() {
  if [[ -n "$kernel_argument" ]]; then
    resolve_regular_file 'running kernel' "$kernel_argument"
    return
  fi

  local release
  release="$(uname -r)"
  local candidate resolved
  local -a candidates=(
    /run/booted-system/kernel
    "/boot/vmlinuz-$release"
    "/boot/Image-$release"
  )
  local -a matches=()
  for candidate in "${candidates[@]}"; do
    if [[ -e "$candidate" ]]; then
      resolved="$(readlink -e -- "$candidate")" || continue
      [[ -f "$resolved" && -r "$resolved" ]] || continue
      matches+=("$resolved")
    fi
  done
  ((${#matches[@]} > 0)) ||
    fail 'could not identify the running kernel; pass --kernel with the exact running Image/vmlinuz'

  # Multiple conventional links are acceptable only when their bytes agree.
  local first_hash other_hash
  first_hash="$(sha256sum -- "${matches[0]}" | cut -d ' ' -f 1)"
  for candidate in "${matches[@]:1}"; do
    other_hash="$(sha256sum -- "$candidate" | cut -d ' ' -f 1)"
    [[ "$other_hash" == "$first_hash" ]] ||
      fail 'conventional running-kernel paths disagree; pass --kernel explicitly'
  done
  printf '%s\n' "${matches[0]}"
}

require_busybox_applets() {
  local busybox="$1"
  "$busybox" true || fail 'BusyBox executable failed its self-check'
  local applet
  for applet in cat chroot cut dmesg grep mkdir mount poweroff printf sha256sum sh sleep sync tail test timeout tr uname zcat; do
    "$busybox" --list | grep -Fx -- "$applet" >/dev/null ||
      fail "BusyBox lacks required applet: $applet"
  done
}

require_self_contained_busybox() {
  local busybox="$1"
  local initramfs_root="$2"
  [[ -d "$initramfs_root" && ! -L "$initramfs_root" ]] ||
    fail 'initramfs root for the BusyBox self-containment check is invalid'
  "$busybox" chroot "$initramfs_root" /bin/busybox true ||
    fail 'BusyBox cannot execute inside the library-free standalone initramfs'
}

build_initramfs() {
  local busybox="$1"
  local init_source="$2"
  local output="$3"
  local scratch="$4"
  local root="$scratch/root"

  mkdir -m 0700 -- "$scratch"
  mkdir -p -- "$root/bin" "$root/dev" "$root/proc" "$root/sys"
  install -m 0555 -- "$busybox" "$root/bin/busybox"
  install -m 0555 -- "$init_source" "$root/init"
  find "$root" -exec touch -h --date=@1 '{}' +
  (
    cd "$root"
    find . -print0 \
      | LC_ALL=C sort -z \
      | cpio --null --create --format=newc --owner=0:0 --reproducible --quiet
  ) >"$output"
  chmod 0600 -- "$output"
}

write_text_file() {
  local destination="$1"
  shift
  printf '%s\n' "$*" >"$destination"
  chmod 0600 -- "$destination"
}

copy_observation() {
  local source="$1"
  local destination="$2"
  if [[ -r "$source" ]]; then
    cp --no-preserve=mode,ownership,timestamps -- "$source" "$destination"
    chmod 0600 -- "$destination"
  fi
}

prepare_bundle() {
  require_root
  require_pi5_runtime
  require_valid_mode "$mode"
  require_command cpio
  require_command find
  require_command grep
  require_command install
  require_command sha256sum
  require_command sort

  require_clean_absolute_path 'work directory' "$work_dir"
  [[ ! -e "$work_dir" && ! -L "$work_dir" ]] ||
    fail 'preparation work directory already exists; use a fresh path'

  local kernel busybox busybox_selector kexec script_path script_dir init_source
  kernel="$(resolve_running_kernel)"
  busybox_selector="$busybox_argument"
  if [[ -z "$busybox_selector" ]]; then
    busybox_selector="$packaged_busybox_default"
  fi
  busybox="$(resolve_command_path 'static BusyBox' "$busybox_selector" busybox)"
  kexec="$(resolve_command_path 'kexec tool' "$kexec_argument" kexec)"
  require_busybox_applets "$busybox"
  require_mode_capability "$mode" "$busybox"
  script_path="$(readlink -e -- "${BASH_SOURCE[0]}")" ||
    fail 'diagnostic implementation path does not resolve'
  script_dir="$(dirname -- "$script_path")"
  init_source="$(resolve_regular_file 'beacon init' "$script_dir/beacon-init")"

  mkdir -m 0700 -- "$work_dir"
  mkdir -m 0700 -- "$work_dir/inputs" "$work_dir/observations" "$work_dir/scratch"
  printf 'Preparation is incomplete; do not execute this directory.\n' >"$work_dir/INCOMPLETE"
  chmod 0600 -- "$work_dir/INCOMPLETE"

  install -m 0600 -- "$kernel" "$work_dir/inputs/kernel"
  cp --no-preserve=mode,ownership,timestamps -- /sys/firmware/fdt "$work_dir/inputs/live.dtb"
  chmod 0600 -- "$work_dir/inputs/live.dtb"
  [[ -s "$work_dir/inputs/kernel" ]] || fail 'captured kernel is empty'
  [[ -s "$work_dir/inputs/live.dtb" ]] || fail 'captured live device tree is empty'

  build_initramfs \
    "$busybox" \
    "$init_source" \
    "$work_dir/inputs/beacon-initramfs.cpio" \
    "$work_dir/scratch/initramfs"
  require_self_contained_busybox \
    "$busybox" \
    "$work_dir/scratch/initramfs/root"

  write_text_file "$work_dir/command-line.txt" "$command_line"
  write_text_file "$work_dir/mode.txt" "$mode"
  copy_observation /proc/cmdline "$work_dir/observations/first-kernel-command-line.txt"
  copy_observation /proc/iomem "$work_dir/observations/iomem.txt"
  copy_observation \
    /sys/class/tty/ttyAMA10/iomem_base \
    "$work_dir/observations/ttyAMA10-iomem-base.txt"
  copy_observation /sys/kernel/kexec_loaded "$work_dir/observations/kexec-loaded.txt"
  tr -d '\000' </proc/device-tree/model >"$work_dir/observations/model.txt"
  chmod 0600 -- "$work_dir/observations/model.txt"
  uname -a >"$work_dir/observations/uname.txt"
  chmod 0600 -- "$work_dir/observations/uname.txt"
  if command -v dtc >/dev/null 2>&1; then
    dtc -I dtb -O dts \
      -o "$work_dir/observations/live-device-tree.dts" \
      "$work_dir/inputs/live.dtb" 2>"$work_dir/observations/dtc-stderr.txt" ||
      fail 'dtc could not decode the captured live device tree'
    chmod 0600 -- \
      "$work_dir/observations/live-device-tree.dts" \
      "$work_dir/observations/dtc-stderr.txt"
  else
    write_text_file "$work_dir/observations/dtc-status.txt" 'dtc was unavailable; raw live.dtb was retained'
  fi

  write_text_file "$work_dir/boot-id.txt" "$(tr -d '\n' </proc/sys/kernel/random/boot_id)"
  write_text_file "$work_dir/kernel-release.txt" "$(uname -r)"
  write_text_file "$work_dir/machine.txt" "$(uname -m)"
  write_text_file "$work_dir/kernel-source-path.txt" "$kernel"
  write_text_file "$work_dir/busybox-source-path.txt" "$busybox"
  write_text_file "$work_dir/kexec-path.txt" "$kexec"
  write_text_file "$work_dir/busybox.sha256" "$(sha256sum -- "$busybox" | cut -d ' ' -f 1)"
  write_text_file "$work_dir/kexec.sha256" "$(sha256sum -- "$kexec" | cut -d ' ' -f 1)"
  "$busybox" 2>&1 | sed -n '1p' >"$work_dir/observations/busybox-version.txt"
  chmod 0600 -- "$work_dir/observations/busybox-version.txt"
  "$kexec" --version >"$work_dir/observations/kexec-version.txt" 2>&1
  chmod 0600 -- "$work_dir/observations/kexec-version.txt"
  date --utc +%Y-%m-%dT%H:%M:%SZ >"$work_dir/prepared-at.txt"
  chmod 0600 -- "$work_dir/prepared-at.txt"

  (
    cd "$work_dir"
    sha256sum -- \
      busybox-source-path.txt \
      busybox.sha256 \
      command-line.txt \
      inputs/beacon-initramfs.cpio \
      inputs/kernel \
      inputs/live.dtb \
      kexec-path.txt \
      kexec.sha256 \
      mode.txt >PAYLOAD_SHA256SUMS
  )
  chmod 0600 -- "$work_dir/PAYLOAD_SHA256SUMS"
  write_text_file "$work_dir/INCOMPLETE" "$prepared_marker"
  mv --no-clobber -- "$work_dir/INCOMPLETE" "$work_dir/PREPARED"

  # Scratch contains only files already represented in the cpio. Keeping it
  # makes the prepared evidence directly inspectable without unpacking.
  chmod -R u=rwX,go= -- "$work_dir"
  printf 'Prepared only; no kexec operation was attempted.\n'
  printf 'Bundle: %s\n' "$work_dir"
  printf 'Payload hashes:\n'
  sed 's/^/  /' "$work_dir/PAYLOAD_SHA256SUMS"
  printf 'Command line:\n  %s\n' "$command_line"
  printf 'Mode:\n  %s\n' "$mode"
  printf 'Inspect the bundle and UART capture setup before using --execute.\n'
}

read_single_line() {
  local label="$1"
  local path="$2"
  [[ -f "$path" && ! -L "$path" ]] || fail "$label is absent or not a regular file"
  [[ "$(wc -l <"$path")" == 1 ]] || fail "$label must contain exactly one line"
  local value
  IFS= read -r value <"$path" || fail "$label cannot be read"
  [[ -n "$value" ]] || fail "$label is empty"
  printf '%s\n' "$value"
}

require_execution_confirmation() {
  local selected_mode="$1"
  local expected_confirmation
  expected_confirmation="$(execution_confirmation_for_mode "$selected_mode")"
  [[ "$confirmation" == "$expected_confirmation" ]] ||
    fail "--execute for mode $selected_mode also requires --confirm $expected_confirmation"
}

verify_prepared_bundle() {
  require_clean_absolute_path 'work directory' "$work_dir"
  [[ -d "$work_dir" && ! -L "$work_dir" ]] || fail 'prepared work directory is absent or is a symlink'
  [[ "$(stat -c '%u:%a' -- "$work_dir")" == '0:700' ]] ||
    fail 'prepared work directory must be owned by root with mode 0700'
  [[ ! -e "$work_dir/INCOMPLETE" && ! -L "$work_dir/INCOMPLETE" ]] ||
    fail 'bundle preparation did not complete'
  [[ "$(read_single_line 'prepared marker' "$work_dir/PREPARED")" == "$prepared_marker" ]] ||
    fail 'prepared marker has an unsupported schema'

  local path
  for path in \
    "$work_dir/PAYLOAD_SHA256SUMS" \
    "$work_dir/boot-id.txt" \
    "$work_dir/busybox-source-path.txt" \
    "$work_dir/busybox.sha256" \
    "$work_dir/command-line.txt" \
    "$work_dir/kernel-release.txt" \
    "$work_dir/kexec-path.txt" \
    "$work_dir/kexec.sha256" \
    "$work_dir/machine.txt" \
    "$work_dir/mode.txt" \
    "$work_dir/inputs/beacon-initramfs.cpio" \
    "$work_dir/inputs/kernel" \
    "$work_dir/inputs/live.dtb"; do
    [[ -f "$path" && ! -L "$path" ]] || fail "prepared input is absent or not a regular file: $path"
    [[ "$(stat -c '%u' -- "$path")" == 0 ]] || fail "prepared input is not root-owned: $path"
  done

  (
    cd "$work_dir"
    sha256sum --check --strict PAYLOAD_SHA256SUMS >/dev/null
  ) || fail 'prepared payload hash verification failed'

  [[ "$(read_single_line 'boot ID' "$work_dir/boot-id.txt")" == "$(tr -d '\n' </proc/sys/kernel/random/boot_id)" ]] ||
    fail 'prepared bundle belongs to a different boot'
  [[ "$(read_single_line 'kernel release' "$work_dir/kernel-release.txt")" == "$(uname -r)" ]] ||
    fail 'running kernel release changed after preparation'
  [[ "$(read_single_line 'machine architecture' "$work_dir/machine.txt")" == "$(uname -m)" ]] ||
    fail 'machine architecture changed after preparation'
  [[ "$(read_single_line 'command line' "$work_dir/command-line.txt")" == "$command_line" ]] ||
    fail 'prepared second-kernel command line changed'
  local prepared_mode
  prepared_mode="$(read_single_line 'self-kexec mode' "$work_dir/mode.txt")"
  require_valid_mode "$prepared_mode"
  [[ "$(sha256sum /sys/firmware/fdt | cut -d ' ' -f 1)" == \
    "$(sha256sum "$work_dir/inputs/live.dtb" | cut -d ' ' -f 1)" ]] ||
    fail 'live firmware device tree changed after preparation'

  [[ -r /sys/kernel/kexec_loaded ]] || fail 'kernel does not expose kexec loaded state'
  [[ "$(tr -d '\n' </sys/kernel/kexec_loaded)" == 0 ]] ||
    fail 'a kexec image is already loaded; this tool will not replace it'

  local busybox expected_busybox_hash
  busybox="$(read_single_line 'BusyBox path' "$work_dir/busybox-source-path.txt")"
  busybox="$(resolve_regular_file 'recorded static BusyBox' "$busybox")"
  [[ -x "$busybox" ]] || fail 'recorded static BusyBox is not executable'
  expected_busybox_hash="$(read_single_line 'BusyBox hash' "$work_dir/busybox.sha256")"
  [[ "$expected_busybox_hash" =~ ^[0-9a-f]{64}$ ]] || fail 'recorded BusyBox hash is malformed'
  [[ "$(sha256sum -- "$busybox" | cut -d ' ' -f 1)" == "$expected_busybox_hash" ]] ||
    fail 'recorded static BusyBox changed after preparation'

  local kexec expected_kexec_hash
  kexec="$(read_single_line 'kexec path' "$work_dir/kexec-path.txt")"
  kexec="$(resolve_regular_file 'recorded kexec tool' "$kexec")"
  [[ -x "$kexec" ]] || fail 'recorded kexec tool is not executable'
  expected_kexec_hash="$(read_single_line 'kexec hash' "$work_dir/kexec.sha256")"
  [[ "$expected_kexec_hash" =~ ^[0-9a-f]{64}$ ]] || fail 'recorded kexec hash is malformed'
  [[ "$(sha256sum -- "$kexec" | cut -d ' ' -f 1)" == "$expected_kexec_hash" ]] ||
    fail 'recorded kexec executable changed after preparation'
  verified_busybox="$busybox"
  verified_kexec="$kexec"
  verified_mode="$prepared_mode"
}

run_logged() {
  local log="$1"
  shift
  set +e
  "$@" 2>&1 | tee -a "$log"
  local -a statuses=("${PIPESTATUS[@]}")
  set -e
  if ((statuses[1] != 0)); then
    printf 'STOP: could not persist diagnostic command output to %s\n' "$log" >&2
    return 125
  fi
  return "${statuses[0]}"
}

kernel_config_supports_file_live_fdt() {
  local config="$1"
  grep -Fqx 'CONFIG_KEXEC_FILE=y' <<<"$config" &&
    grep -Fqx '# CONFIG_KEXEC_SIG is not set' <<<"$config"
}

kernel_config_supports_legacy() {
  grep -Fqx 'CONFIG_KEXEC=y' <<<"$1"
}

kexec_load_disabled_value_allows_load() {
  [[ "$1" == 0 ]]
}

kexec_reboot_limit_allows_load_and_unload() {
  local value="$1"
  [[ "$value" == -1 ]] || [[ "$value" =~ ^[0-9]+$ && "$value" -ge 2 ]]
}

cap_eff_has_sys_boot() {
  local cap_eff="${1,,}"
  [[ "$cap_eff" =~ ^[0-9a-f]+$ ]] || return 1
  local low_word="$cap_eff"
  if ((${#low_word} > 8)); then
    low_word="${low_word: -8}"
  fi
  (( (16#$low_word & 16#00400000) != 0 ))
}

find_running_kernel_config() {
  local release
  release="$(uname -r)"
  local candidate
  for candidate in \
    /proc/config.gz \
    "/boot/config-$release" \
    "/lib/modules/$release/build/.config" \
    "/run/booted-system/kernel-modules/lib/modules/$release/build/.config"; do
    if [[ -f "$candidate" && -r "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

read_kernel_config_file() {
  local busybox="$1"
  local config_path="$2"
  [[ -f "$busybox" && -x "$busybox" ]] || return 1
  [[ -f "$config_path" && -r "$config_path" ]] || return 1
  if [[ "$config_path" == *.gz ]]; then
    "$busybox" zcat "$config_path"
  else
    "$busybox" cat "$config_path"
  fi
}

read_effective_capabilities() {
  local status_path="$1"
  [[ -f "$status_path" && -r "$status_path" ]] || return 1
  local key value remainder
  while read -r key value remainder; do
    if [[ "$key" == CapEff: ]]; then
      [[ -n "$value" && -z "${remainder:-}" ]] || return 1
      printf '%s\n' "$value"
      return 0
    fi
  done <"$status_path"
  return 1
}

read_single_trimmed_value() {
  local path="$1"
  [[ -f "$path" && -r "$path" ]] || return 1
  local value
  value="$(tr -d '[:space:]' <"$path")"
  [[ -n "$value" ]] || return 1
  printf '%s\n' "$value"
}

require_mode_capability() {
  local selected_mode="$1"
  local busybox="$2"
  local config_path="${3:-}"
  local disabled_path="${4:-/proc/sys/kernel/kexec_load_disabled}"
  local status_path="${5:-/proc/self/status}"
  local reboot_limit_path="${6:-/proc/sys/kernel/kexec_load_limit_reboot}"
  require_valid_mode "$selected_mode"
  if [[ -z "$config_path" ]]; then
    config_path="$(find_running_kernel_config)" ||
      fail "cannot inspect the running kernel configuration for $selected_mode mode"
  fi

  local config
  config="$(read_kernel_config_file "$busybox" "$config_path")" ||
    fail "cannot read the running kernel configuration: $config_path"
  case "$selected_mode" in
    "$legacy_mode")
      kernel_config_supports_legacy "$config" ||
        fail 'legacy-explicit-dtb requires CONFIG_KEXEC=y'
      ;;
    "$file_live_fdt_mode")
      kernel_config_supports_file_live_fdt "$config" ||
        fail 'file-live-fdt requires CONFIG_KEXEC_FILE=y and CONFIG_KEXEC_SIG unset'
      ;;
  esac

  local disabled_value
  disabled_value="$(read_single_trimmed_value "$disabled_path")" ||
    fail "cannot read the kexec disable sysctl: $disabled_path"
  kexec_load_disabled_value_allows_load "$disabled_value" ||
    fail "kernel.kexec_load_disabled prevents the $selected_mode diagnostic"

  if [[ -e "$reboot_limit_path" ]]; then
    local reboot_limit
    reboot_limit="$(read_single_trimmed_value "$reboot_limit_path")" ||
      fail "cannot read the kexec reboot-load limit: $reboot_limit_path"
    kexec_reboot_limit_allows_load_and_unload "$reboot_limit" ||
      fail 'kexec reboot-load limit does not leave capacity for both load and fail-closed unload'
  fi

  local cap_eff
  cap_eff="$(read_effective_capabilities "$status_path")" ||
    fail "cannot read effective capabilities from: $status_path"
  cap_eff_has_sys_boot "$cap_eff" ||
    fail "$selected_mode requires CAP_SYS_BOOT in the effective capability set"
}

build_kexec_load_arguments() {
  local selected_mode="$1"
  local bundle="$2"
  local output_name="$3"
  local -n output="$output_name"
  case "$selected_mode" in
    "$legacy_mode")
      output=(
        --debug
        --kexec-syscall
        --load "$bundle/inputs/kernel"
        --initrd="$bundle/inputs/beacon-initramfs.cpio"
        --dtb="$bundle/inputs/live.dtb"
        --command-line="$command_line"
      )
      ;;
    "$file_live_fdt_mode")
      output=(
        --debug
        --kexec-file-syscall
        --load "$bundle/inputs/kernel"
        --initrd="$bundle/inputs/beacon-initramfs.cpio"
        --command-line="$command_line"
      )
      ;;
    *) fail "cannot build load arguments for unsupported mode: $selected_mode" ;;
  esac
}

build_kexec_unload_arguments() {
  local selected_mode="$1"
  local output_name="$2"
  local -n output="$output_name"
  case "$selected_mode" in
    "$legacy_mode") output=(--kexec-syscall --unload) ;;
    "$file_live_fdt_mode") output=(--kexec-file-syscall --unload) ;;
    *) fail "cannot build unload arguments for unsupported mode: $selected_mode" ;;
  esac
}

build_kexec_exec_arguments() {
  local selected_mode="$1"
  local output_name="$2"
  local -n output="$output_name"
  case "$selected_mode" in
    "$legacy_mode") output=(--debug --exec) ;;
    "$file_live_fdt_mode") output=(--debug --kexec-file-syscall --exec) ;;
    *) fail "cannot build execution arguments for unsupported mode: $selected_mode" ;;
  esac
}

execute_bundle() {
  require_root
  require_pi5_runtime
  require_command flock
  require_command sha256sum
  require_command tee

  verify_prepared_bundle
  local kexec="$verified_kexec"
  local busybox="$verified_busybox"
  local selected_mode="$verified_mode"
  require_execution_confirmation "$selected_mode"
  local execution_lock_fd
  exec {execution_lock_fd}>"$execution_lock_path"
  chmod 0600 -- "$execution_lock_path"
  flock --exclusive --nonblock "$execution_lock_fd" ||
    fail 'another self-kexec diagnostic holds the host-wide execution lock'
  [[ "$(tr -d '\n' </sys/kernel/kexec_loaded)" == 0 ]] ||
    fail 'a kexec image appeared after validation; refusing to replace it'
  require_mode_capability "$selected_mode" "$busybox"
  local execution_log="$work_dir/execution.log"
  [[ ! -e "$execution_log" && ! -L "$execution_log" ]] ||
    fail 'this prepared bundle already has an execution attempt; prepare a fresh bundle'
  mkdir -m 0700 -- "$work_dir/EXECUTION_CLAIM" 2>/dev/null ||
    fail 'this prepared bundle is already claimed by another execution attempt'
  : >"$execution_log"
  chmod 0600 -- "$execution_log"
  printf 'execution_started_at=%s\n' "$(date --utc +%Y-%m-%dT%H:%M:%SZ)" >>"$execution_log"
  printf 'boot_id=%s\n' "$(tr -d '\n' </proc/sys/kernel/random/boot_id)" >>"$execution_log"
  printf 'kexec=%s\n' "$kexec" >>"$execution_log"
  printf 'mode=%s\n' "$selected_mode" >>"$execution_log"
  printf 'command_line=%s\n' "$command_line" >>"$execution_log"

  local load_attempted=false
  local -a unload_arguments=()
  build_kexec_unload_arguments "$selected_mode" unload_arguments
  unload_on_failure() {
    local status=$?
    set +e
    if [[ "$load_attempted" == true && -r /sys/kernel/kexec_loaded &&
      "$(tr -d '\n' </sys/kernel/kexec_loaded)" == 1 ]]; then
      printf 'kexec returned or was interrupted; attempting to unload the diagnostic image\n' \
        | tee -a "$execution_log" >&2 || true
      "$kexec" "${unload_arguments[@]}" >>"$execution_log" 2>&1
      if [[ "$(tr -d '\n' </sys/kernel/kexec_loaded)" != 0 ]]; then
        printf 'STOP: diagnostic kexec image remains loaded after the unload attempt\n' \
          | tee -a "$execution_log" >&2 || true
      fi
    fi
    return "$status"
  }
  trap unload_on_failure EXIT

  printf 'Loading the hashed development self-kexec diagnostic.\n' | tee -a "$execution_log"
  load_attempted=true
  local -a load_arguments=()
  build_kexec_load_arguments "$selected_mode" "$work_dir" load_arguments
  run_logged "$execution_log" "$kexec" "${load_arguments[@]}" ||
    fail 'kexec rejected the diagnostic load-only phase'
  [[ "$(tr -d '\n' </sys/kernel/kexec_loaded)" == 1 ]] ||
    fail 'kexec load returned success but the kernel reports no loaded image'
  printf 'Load-only phase succeeded and kexec_loaded=1.\n' | tee -a "$execution_log"

  sync
  printf 'KAIBA_RPI5_SELF_KEXEC_EXECUTING: watch trusted UART now\n' | tee -a "$execution_log"
  local -a exec_arguments=()
  build_kexec_exec_arguments "$selected_mode" exec_arguments
  run_logged "$execution_log" "$kexec" "${exec_arguments[@]}" ||
    fail 'kexec execution returned an error'
  fail 'kexec execution returned without transferring control'
}

parse_arguments() {
  while (($# > 0)); do
    case "$1" in
      --work-dir)
        (($# >= 2)) || fail '--work-dir requires a value'
        work_dir="$2"
        shift 2
        ;;
      --kernel)
        (($# >= 2)) || fail '--kernel requires a value'
        kernel_argument="$2"
        shift 2
        ;;
      --busybox)
        (($# >= 2)) || fail '--busybox requires a value'
        busybox_argument="$2"
        shift 2
        ;;
      --kexec)
        (($# >= 2)) || fail '--kexec requires a value'
        kexec_argument="$2"
        shift 2
        ;;
      --mode)
        (($# >= 2)) || fail '--mode requires a value'
        mode="$2"
        mode_was_explicit=true
        shift 2
        ;;
      --execute)
        execute=true
        shift
        ;;
      --confirm)
        (($# >= 2)) || fail '--confirm requires a value'
        confirmation="$2"
        shift 2
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) fail "unknown argument: $1" ;;
    esac
  done
  [[ -n "$work_dir" ]] || fail '--work-dir is required'
  require_valid_mode "$mode"
  if [[ "$execute" == true ]]; then
    [[ -z "$kernel_argument" && -z "$busybox_argument" && -z "$kexec_argument" &&
      "$mode_was_explicit" == false ]] ||
      fail '--kernel, --busybox, --kexec, and --mode are preparation-only options'
  else
    [[ -z "$confirmation" ]] || fail '--confirm is valid only with --execute'
  fi
}

main() {
  parse_arguments "$@"
  if [[ "$execute" == true ]]; then
    execute_bundle
  else
    prepare_bundle
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
