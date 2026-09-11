{
  pkgs,
  lib ? pkgs.lib,
  releaseTree,
  aarch64Busybox,
  qemuPackage ? pkgs.qemu,
  timeoutSeconds ? 120,
  # False preserves an explicit negative differential as a Nix result.
  requireBeacon ? true,
  name ? "kaiba-rpi5-kernel-qemu-virt-beacon",
}:

assert lib.assertMsg pkgs.stdenv.hostPlatform.isLinux
  "the Raspberry Pi kernel QEMU beacon diagnostic requires a Linux host";
assert lib.assertMsg (builtins.isBool requireBeacon) "requireBeacon must be a Boolean";
assert lib.assertMsg (
  builtins.isInt timeoutSeconds && timeoutSeconds >= 10 && timeoutSeconds <= 600
) "timeoutSeconds must be an integer from 10 through 600";
assert lib.assertMsg (
  let
    value = toString releaseTree;
  in
  lib.hasPrefix "${builtins.storeDir}/" value && value != "${builtins.storeDir}/"
) "releaseTree must be one fixed Nix-store path";
assert lib.assertMsg (
  let
    value = toString aarch64Busybox;
  in
  lib.hasPrefix "${builtins.storeDir}/" value && value != "${builtins.storeDir}/"
) "aarch64Busybox must be one fixed Nix-store package path";

let
  marker = "KAIBA_RPI5_QEMU_KERNEL_BEACON";
  busybox = "${aarch64Busybox}/bin/busybox";
  commandLine = lib.concatStringsSep " " [
    "console=ttyAMA0,115200n8"
    "earlycon=pl011,0x09000000,115200n8"
    "ignore_loglevel"
    "keep_bootcon"
    "panic=-1"
    "rdinit=/init"
  ];

  beaconInit = pkgs.writeText "kaiba-rpi5-qemu-kernel-beacon-init" ''
    #!/bin/busybox sh
    set -eu
    bb=/bin/busybox

    # Do not treat a marker written to an unconnected initramfs fd as console
    # evidence.  Establish and verify the kernel console first, then bind all
    # subsequent init output to it explicitly.
    "$bb" mount -t devtmpfs devtmpfs /dev
    "$bb" test -c /dev/console
    exec </dev/console >/dev/console 2>&1

    "$bb" echo ${marker}
    "$bb" sync
    "$bb" poweroff -f
    "$bb" echo KAIBA_RPI5_QEMU_KERNEL_BEACON_POWEROFF_RETURNED
    while "$bb" true; do
      "$bb" sleep 1
    done
  '';

  beaconInitramfs =
    pkgs.runCommand "kaiba-rpi5-qemu-kernel-beacon-initramfs"
      {
        busyboxInput = busybox;
        nativeBuildInputs = [
          pkgs.binutils
          pkgs.coreutils
          pkgs.cpio
          pkgs.findutils
          pkgs.gnugrep
          qemuPackage
        ];
        passthru.kaibaRpi5QemuKernelBeaconInitramfs = {
          architecture = "aarch64-linux";
          staticBusybox = true;
          init = "/init";
          inherit marker;
          productionReady = false;
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        export TZ=UTC

        test -f "$busyboxInput"
        test ! -L "$busyboxInput"
        test -x "$busyboxInput"
        readelf --file-header "$busyboxInput" \
          | grep -E 'Machine:[[:space:]]+AArch64$' > /dev/null
        if readelf --program-headers "$busyboxInput" | grep -F ' INTERP ' > /dev/null; then
          echo "aarch64Busybox must be statically linked" >&2
          exit 1
        fi

        # The caller supplies the AArch64 BusyBox package, so validate its
        # applet set through the host QEMU user-mode emulator.  Merely finding
        # a static binary is insufficient: reduced BusyBox builds can contain
        # only `sh`, which would otherwise look like a kernel/console failure.
        qemu-aarch64 "$busyboxInput" --list > "$TMPDIR/busybox-applets"
        for applet in sh mount test echo sync poweroff true sleep; do
          if ! grep -F -x -- "$applet" "$TMPDIR/busybox-applets" > /dev/null; then
            echo "aarch64Busybox is missing required applet: $applet" >&2
            exit 1
          fi
        done

        root="$TMPDIR/root"
        mkdir -p "$root/bin" "$root/dev" "$root/proc" "$root/sys"
        install -m 0555 "$busyboxInput" "$root/bin/busybox"
        install -m 0555 ${beaconInit} "$root/init"
        find "$root" -exec touch --date=@1 '{}' +
        (
          cd "$root"
          find . -print0 | sort -z \
            | cpio --null --create --format=newc --owner=0:0 --reproducible --quiet
        ) > "$out"
        test -s "$out"
      '';

  # Rebind only the initramfs. The original campaign manifest remains the
  # source of truth for the exact kernel digest and size, while this synthetic
  # diagnostic manifest binds the generated beacon archive passed to QEMU.
  beaconRelease =
    pkgs.runCommand "kaiba-rpi5-qemu-kernel-beacon-release"
      {
        releaseTreeInput = releaseTree;
        beaconInitramfsInput = beaconInitramfs;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
        ];
        passthru.kaibaRpi5QemuKernelBeaconRelease = {
          originalRelease = releaseTree;
          initramfsReplacedForDiagnostic = true;
          kernelByteIdenticalToOriginalRelease = true;
          inherit beaconInitramfs marker;
          productionReady = false;
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C

        original_manifest="$releaseTreeInput/release-manifest.json"
        original_kernel="$releaseTreeInput/kernel"
        test -f "$original_manifest"
        test -f "$original_kernel"
        test ! -L "$original_kernel"
        test -s "$original_kernel"

        test "$(jq '[.components[] | select(.role == "kernel")] | length' "$original_manifest")" -eq 1
        expected_kernel_digest="$(
          jq --exit-status --raw-output \
            '.components[] | select(.role == "kernel") | .digest' \
            "$original_manifest"
        )"
        expected_kernel_size="$(
          jq --exit-status --raw-output \
            '.components[] | select(.role == "kernel") | .size_bytes' \
            "$original_manifest"
        )"
        actual_kernel_digest="sha256:$(sha256sum "$original_kernel" | cut -d ' ' -f 1)"
        actual_kernel_size="$(stat --format=%s "$original_kernel")"
        test "$actual_kernel_digest" = "$expected_kernel_digest"
        test "$actual_kernel_size" = "$expected_kernel_size"

        beacon_initramfs_digest="sha256:$(sha256sum "$beaconInitramfsInput" | cut -d ' ' -f 1)"
        beacon_initramfs_size="$(stat --format=%s "$beaconInitramfsInput")"
        original_manifest_digest="sha256:$(sha256sum "$original_manifest" | cut -d ' ' -f 1)"

        mkdir -p "$out"
        install -m 0444 "$original_kernel" "$out/kernel"
        install -m 0444 "$beaconInitramfsInput" "$out/initramfs"
        jq --null-input --sort-keys \
          --arg schema_version 'kaiba.provisioning.rpi5-qemu-kernel-beacon-release/v1alpha1' \
          --arg original_manifest_digest "$original_manifest_digest" \
          --arg kernel_digest "$actual_kernel_digest" \
          --argjson kernel_size "$actual_kernel_size" \
          --arg initramfs_digest "$beacon_initramfs_digest" \
          --argjson initramfs_size "$beacon_initramfs_size" \
          '{
            schema_version: $schema_version,
            source_release_manifest_digest: $original_manifest_digest,
            components: [
              {role: "kernel", digest: $kernel_digest, size_bytes: $kernel_size},
              {role: "initramfs", digest: $initramfs_digest, size_bytes: $initramfs_size}
            ],
            diagnostic_only: true,
            production_ready: false
          }' > "$out/release-manifest.json"
      '';

  payloadEvidence = import ./rpi5-release-payload-qemu-virt.nix {
    inherit
      lib
      pkgs
      qemuPackage
      timeoutSeconds
      ;
    releaseTree = beaconRelease;
    # The outer differential preserves negative evidence and applies its own
    # strict conjunction of the QMP result and the unique PL011 marker.
    requireGuestPoweroff = false;
    diagnosticCommandLineOverride = commandLine;
    witnessExpectedSource = "static-busybox-beacon-init";
    witnessInferenceBasis = "rdinit=/init selected the generated static BusyBox beacon, whose final action is poweroff -f; panic=-1 makes a kernel panic produce guest-reset, and QMP reported guest-shutdown";
    witnessInferenceLimitation = "QMP identifies a guest shutdown request but does not attest which guest instruction issued it; the separate PL011 marker is required by this differential";
    name = "${name}-payload-evidence";
  };
in
pkgs.runCommand name
  {
    payloadEvidenceInput = payloadEvidence;
    beaconInitramfsInput = beaconInitramfs;
    beaconReleaseInput = beaconRelease;
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.jq
    ];
    passthru.kaibaRpi5KernelQemuVirtBeacon = {
      architecture = "aarch64-linux";
      emulatedMachine = "qemu-virt";
      exactReleaseKernel = true;
      generatedBeaconInitramfs = true;
      explicitPL011 = {
        deviceTreeNode = "/pl011@9000000";
        address = "0x09000000";
        console = "ttyAMA0";
      };
      consoleMarkerStrategy = marker;
      qmpGuestShutdownStrategy = true;
      positiveResultRequiresMarkerAndCleanQemuExit = true;
      inherit requireBeacon timeoutSeconds;
      productionReady = false;
      hardwareObserved = false;
    };
    preferLocalBuild = true;
  }
  ''
    set -euo pipefail
    export LC_ALL=C

    mkdir -p "$out"
    cp -R --no-preserve=mode,ownership "$payloadEvidenceInput"/. "$out/"
    install -m 0444 "$beaconInitramfsInput" "$out/beacon-initramfs"
    install -m 0444 "$beaconReleaseInput/release-manifest.json" \
      "$out/beacon-release-manifest.json"
    install -m 0444 "$payloadEvidenceInput/result.json" \
      "$out/payload-result.json"

    pl011_marker_observed=false
    tr -d '\r' < "$out/console.log" > "$TMPDIR/console-normalized.log"
    if grep -F -x -- ${lib.escapeShellArg marker} \
      "$TMPDIR/console-normalized.log" > /dev/null
    then
      pl011_marker_observed=true
    fi
    qmp_and_clean_exit_observed="$(
      jq --raw-output '.requirement.satisfied' "$out/payload-result.json"
    )"
    source_release_manifest_digest="$(
      jq --exit-status --raw-output '.source_release_manifest_digest' \
        "$out/beacon-release-manifest.json"
    )"
    test "$qmp_and_clean_exit_observed" = true \
      || test "$qmp_and_clean_exit_observed" = false

    differential_accepted=false
    if test "$pl011_marker_observed" = true \
      && test "$qmp_and_clean_exit_observed" = true
    then
      differential_accepted=true
    fi

    jq --sort-keys \
      --arg schema_version 'kaiba.provisioning.rpi5-kernel-qemu-beacon-diagnostic/v1alpha1' \
      --arg marker ${lib.escapeShellArg marker} \
      --arg source_release_manifest_digest "$source_release_manifest_digest" \
      --argjson pl011_marker_observed "$pl011_marker_observed" \
      --argjson qmp_and_clean_exit_observed "$qmp_and_clean_exit_observed" \
      --argjson differential_accepted "$differential_accepted" \
      --argjson require_beacon ${lib.boolToString requireBeacon} \
      '. as $payload
       | {
          schema_version: $schema_version,
          status: (
            if $differential_accepted then "kernel-beacon-observed"
            elif $pl011_marker_observed then "kernel-beacon-observed-qmp-failed"
            elif $qmp_and_clean_exit_observed then "kernel-beacon-console-not-observed"
            else "kernel-beacon-not-observed"
            end
          ),
          source_release_manifest_digest: $source_release_manifest_digest,
          kernel: ($payload.payload.kernel + {
            byte_identical_to_source_release: true
          }),
          initramfs: {
            role: "generated-static-busybox-beacon",
            digest: $payload.payload.initramfs.digest,
            size_bytes: $payload.payload.initramfs.size_bytes,
            marker: $marker
          },
          environment: $payload.environment,
          observations: {
            pl011_marker_observed: $pl011_marker_observed,
            qmp_guest_shutdown_and_clean_exit_observed: $qmp_and_clean_exit_observed
          },
          requirement: {
            beacon_required: $require_beacon,
            positive_result_requires_marker_and_clean_qemu_exit: true,
            satisfied: $differential_accepted
          },
          payload_diagnostic: $payload,
          hardware_observed: false,
          production_ready: false
        }' "$out/payload-result.json" > "$out/result.json.tmp"
    mv "$out/result.json.tmp" "$out/result.json"
    chmod 0444 "$out"/*

    if test ${lib.boolToString requireBeacon} = true \
      && test "$differential_accepted" != true
    then
      jq . "$out/result.json" >&2
      echo "strict QEMU kernel beacon diagnostic requires its PL011 marker and clean guest shutdown" >&2
      exit 1
    fi
  ''
