{
  pkgs,
  lib ? pkgs.lib,
  releaseTree,
  qemuPackage ? pkgs.qemu,
  timeoutSeconds ? 120,
  # False is an evidence-collection mode: the derivation succeeds after a
  # negative runtime observation, but result.json still records failure.
  requireGuestPoweroff ? true,
  diagnosticCommandLineOverride ? null,
  witnessExpectedSource ? null,
  witnessInferenceBasis ? null,
  witnessInferenceLimitation ? null,
  name ? "kaiba-rpi5-release-payload-qemu-virt",
}@args:

assert lib.assertMsg pkgs.stdenv.hostPlatform.isLinux
  "the Raspberry Pi release-payload QEMU diagnostic requires a Linux host";
assert lib.assertMsg (
  builtins.isInt timeoutSeconds && timeoutSeconds >= 10 && timeoutSeconds <= 600
) "timeoutSeconds must be an integer from 10 through 600";
assert lib.assertMsg (builtins.isBool requireGuestPoweroff)
  "requireGuestPoweroff must be a Boolean";
assert lib.assertMsg (
  diagnosticCommandLineOverride == null
  || (
    builtins.isString diagnosticCommandLineOverride
    && diagnosticCommandLineOverride != ""
    && !(lib.hasInfix "\n" diagnosticCommandLineOverride)
    && builtins.stringLength diagnosticCommandLineOverride <= 4096
  )
) "diagnosticCommandLineOverride must be null or one non-empty line of at most 4096 bytes";
assert lib.assertMsg
  (
    diagnosticCommandLineOverride == null
    || (
      args ? witnessExpectedSource && args ? witnessInferenceBasis && args ? witnessInferenceLimitation
    )
  )
  "a diagnosticCommandLineOverride requires explicit witnessExpectedSource, witnessInferenceBasis, and witnessInferenceLimitation values";
assert lib.assertMsg
  (
    if diagnosticCommandLineOverride == null then
      witnessExpectedSource == null && witnessInferenceBasis == null && witnessInferenceLimitation == null
    else
      builtins.isString witnessExpectedSource
      && witnessExpectedSource != ""
      && builtins.isString witnessInferenceBasis
      && witnessInferenceBasis != ""
      && builtins.isString witnessInferenceLimitation
      && witnessInferenceLimitation != ""
  )
  "a command-line override requires explicit witnessExpectedSource, witnessInferenceBasis, and witnessInferenceLimitation; witness metadata without an override is not accepted";
assert lib.assertMsg (
  let
    value = toString releaseTree;
  in
  lib.hasPrefix "${builtins.storeDir}/" value && value != "${builtins.storeDir}/"
) "releaseTree must be one fixed Nix-store path";

let
  # This is intentionally different from the authenticated Pi command line.
  # It isolates whether the exact release kernel and initramfs can enter their
  # bundled systemd under QEMU's virt machine and runtime-generated DTB. The
  # poweroff target makes the witness independent of serial-console output:
  # QEMU must report a guest-initiated PSCI shutdown over QMP. An immediate
  # panic reboot is selected so a pre-userspace kernel panic is reported as
  # guest-reset (and rejected), rather than resembling the requested poweroff.
  diagnosticCommandLine =
    if diagnosticCommandLineOverride == null then
      lib.concatStringsSep " " [
        "console=ttyAMA0,115200n8"
        "earlycon=pl011,0x09000000,115200n8"
        "ignore_loglevel"
        "keep_bootcon"
        "panic=-1"
        "rdinit=/init"
        "rd.systemd.unit=poweroff.target"
      ]
    else
      diagnosticCommandLineOverride;
  effectiveWitnessExpectedSource =
    if witnessExpectedSource == null then
      "release-initramfs-systemd-poweroff-target"
    else
      witnessExpectedSource;
  effectiveWitnessInferenceBasis =
    if witnessInferenceBasis == null then
      "rdinit=/init selected the release initramfs, rd.systemd.unit=poweroff.target requested its bundled systemd to power off, panic=-1 makes a kernel panic produce guest-reset, and QMP reported guest-shutdown"
    else
      witnessInferenceBasis;
  effectiveWitnessInferenceLimitation =
    if witnessInferenceLimitation == null then
      "QMP reports that the guest requested shutdown; it does not attest the identity of the guest code that issued the request"
    else
      witnessInferenceLimitation;

  qmpRunner = pkgs.writeText "kaiba-rpi5-payload-qmp-runner.py" ''
    import argparse
    import json
    import os
    import socket
    import subprocess
    import sys
    import time


    def emit_console_tail(path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as source:
                lines = source.readlines()
        except FileNotFoundError:
            return
        if lines:
            sys.stderr.write("--- QEMU PL011 console tail (diagnostic only) ---\n")
            sys.stderr.writelines(lines[-120:])


    parser = argparse.ArgumentParser()
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--initramfs", required=True)
    parser.add_argument("--dtb", required=True)
    parser.add_argument("--command-line", required=True)
    parser.add_argument("--console-log", required=True)
    parser.add_argument("--qemu-log", required=True)
    parser.add_argument("--qmp-log", required=True)
    parser.add_argument("--witness", required=True)
    parser.add_argument("--failure", required=True)
    parser.add_argument("--timeout", required=True, type=int)
    arguments = parser.parse_args()

    qmp_socket = os.path.join(os.path.dirname(arguments.qmp_log), "qmp.sock")
    try:
        os.unlink(qmp_socket)
    except FileNotFoundError:
        pass

    command = [
        arguments.qemu,
        "-machine", "virt,gic-version=2,secure=off,virtualization=off",
        "-accel", "tcg,thread=multi",
        "-cpu", "max",
        "-smp", "2",
        "-m", "1536M",
        "-display", "none",
        "-monitor", "none",
        "-nodefaults",
        "-no-reboot",
        "-chardev", f"file,id=kaiba-serial,path={arguments.console_log}",
        "-serial", "chardev:kaiba-serial",
        "-qmp", f"unix:{qmp_socket},server=on,wait=off",
        "-kernel", arguments.kernel,
        "-initrd", arguments.initramfs,
        "-dtb", arguments.dtb,
        "-append", arguments.command_line,
    ]

    started_at = time.monotonic()
    qemu_log = None
    process = None
    connection = None
    qmp_messages = []
    deadline = started_at + arguments.timeout
    witnessed_shutdown = None
    capabilities_sent = False
    capabilities_accepted = False
    failure = None

    try:
        qemu_log = open(arguments.qemu_log, "wb")
        process = subprocess.Popen(command, stdout=qemu_log, stderr=subprocess.STDOUT)
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    f"QEMU exited with status {process.returncode} before QMP connected"
                )
            candidate = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                candidate.connect(qmp_socket)
            except (FileNotFoundError, ConnectionRefusedError):
                candidate.close()
                time.sleep(0.05)
                continue
            except Exception:
                candidate.close()
                raise
            connection = candidate
            break
        if connection is None:
            raise RuntimeError("timed out connecting to QMP")

        connection.settimeout(0.25)
        buffer = b""
        while time.monotonic() < deadline:
            try:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                buffer += chunk
            except socket.timeout:
                continue

            while b"\n" in buffer:
                raw_message, buffer = buffer.split(b"\n", 1)
                if not raw_message.strip():
                    continue
                message = json.loads(raw_message)
                qmp_messages.append(message)

                if "QMP" in message and not capabilities_sent:
                    connection.sendall(b'{"execute":"qmp_capabilities"}\r\n')
                    capabilities_sent = True
                    continue
                if capabilities_sent and "return" in message:
                    capabilities_accepted = True
                    continue
                if message.get("event") != "SHUTDOWN":
                    continue

                data = message.get("data", {})
                if data.get("guest") is True and data.get("reason") == "guest-shutdown":
                    witnessed_shutdown = message
                    # Preserve the event before waiting for QEMU to exit. A
                    # later emulator hang or non-zero exit is a separate
                    # failure and must not erase the guest observation.
                    with open(arguments.witness, "w", encoding="utf-8") as destination:
                        json.dump(witnessed_shutdown, destination, sort_keys=True)
                        destination.write("\n")
                    break
            if witnessed_shutdown is not None:
                break

        if not capabilities_accepted:
            raise RuntimeError("QMP capabilities negotiation did not complete")
        if witnessed_shutdown is None:
            raise RuntimeError(
                "no guest-initiated SHUTDOWN event arrived over QMP before timeout"
            )

        remaining = max(0.1, min(10.0, deadline - time.monotonic()))
        return_code = process.wait(timeout=remaining)
        if return_code != 0:
            raise RuntimeError(f"QEMU exited with status {return_code} after guest shutdown")

    except Exception as error:
        failed_at = time.monotonic()
        return_code_before_cleanup = process.poll() if process is not None else None
        terminated_by_runner = process is not None and return_code_before_cleanup is None
        if terminated_by_runner:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        emit_console_tail(arguments.console_log)
        failure = {
            "schema_version": "kaiba.provisioning.rpi5-release-payload-qemu-diagnostic-failure/v1alpha1",
            "status": (
                "guest-poweroff-observed-qemu-exit-failed"
                if witnessed_shutdown is not None
                else "guest-poweroff-not-observed"
            ),
            "error_type": type(error).__name__,
            "error": str(error),
            "timed_out": failed_at >= deadline,
            "timeout_seconds": arguments.timeout,
            "elapsed_seconds": round(failed_at - started_at, 3),
            "qemu_started": process is not None,
            "qemu_return_code_before_cleanup": return_code_before_cleanup,
            "qemu_return_code_after_cleanup": (
                process.returncode if process is not None else None
            ),
            "qemu_terminated_by_runner": terminated_by_runner,
            "qmp_connected": connection is not None,
            "qmp_capabilities_sent": capabilities_sent,
            "qmp_capabilities_accepted": capabilities_accepted,
            "qmp_messages_seen": len(qmp_messages),
            "guest_shutdown_event_observed": witnessed_shutdown is not None,
            "guest_shutdown_event": witnessed_shutdown,
            "console_log_has_bytes": (
                os.path.exists(arguments.console_log)
                and os.path.getsize(arguments.console_log) > 0
            ),
        }
        with open(arguments.failure, "w", encoding="utf-8") as destination:
            json.dump(failure, destination, sort_keys=True)
            destination.write("\n")
        sys.stderr.write(f"QEMU payload diagnostic failed: {error}\n")
    finally:
        if connection is not None:
            connection.close()
        if qemu_log is not None:
            qemu_log.close()
        with open(arguments.qmp_log, "w", encoding="utf-8") as destination:
            for message in qmp_messages:
                destination.write(json.dumps(message, sort_keys=True) + "\n")

    if failure is not None:
        raise SystemExit(1)
  '';
in
pkgs.runCommand name
  {
    releaseTreeInput = releaseTree;
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.dtc
      pkgs.gnugrep
      pkgs.jq
      pkgs.python3
      qemuPackage
    ];
    passthru.kaibaRpi5ReleasePayloadQemuVirt = {
      architecture = "aarch64-linux";
      emulatedMachine = "qemu-virt";
      emulatedInterruptController = "gicv2";
      kernelByteIdenticalToRelease = true;
      initramfsByteIdenticalToRelease = true;
      manifestComponentDigestsChecked = true;
      qemuRuntimeDeviceTree = true;
      releaseDeviceTreeUsed = false;
      explicitPL011 = {
        deviceTreeNode = "/pl011@9000000";
        address = "0x09000000";
        console = "ttyAMA0";
      };
      consoleRequiredForSuccess = false;
      qmpGuestShutdownWitnessMechanism = true;
      userspaceEntryInferenceAvailableOnObservedPoweroff = true;
      inherit requireGuestPoweroff;
      verifierHandoffExercised = false;
      raspberryPiFirmwareObserved = false;
      bcm2712Observed = false;
      rp1Observed = false;
      productionReady = false;
      witnessExpectedSource = effectiveWitnessExpectedSource;
      witnessInferenceBasis = effectiveWitnessInferenceBasis;
      witnessInferenceLimitation = effectiveWitnessInferenceLimitation;
      inherit diagnosticCommandLine timeoutSeconds;
    };
    preferLocalBuild = true;
  }
  ''
    set -euo pipefail
    export LC_ALL=C
    export TZ=UTC

    readonly release="$releaseTreeInput"
    readonly manifest="$release/release-manifest.json"
    readonly kernel="$release/kernel"
    readonly initramfs="$release/initramfs"
    readonly runtime_dtb="$TMPDIR/qemu-virt-runtime.dtb"
    readonly console_log="$TMPDIR/console.log"
    readonly qemu_log="$TMPDIR/qemu.log"
    readonly qmp_log="$TMPDIR/qmp.ndjson"
    readonly witness="$TMPDIR/qmp-shutdown-witness.json"
    readonly failure_artifact="$TMPDIR/failure.json"

    for input in "$manifest" "$kernel" "$initramfs"; do
      test -f "$input"
      test ! -L "$input"
      test -s "$input"
    done

    kernel_components="$(
      jq '[.components[] | select(.role == "kernel")] | length' "$manifest"
    )"
    initramfs_components="$(
      jq '[.components[] | select(.role == "initramfs")] | length' "$manifest"
    )"
    test "$kernel_components" -eq 1
    test "$initramfs_components" -eq 1

    expected_kernel_digest="$(
      jq --exit-status --raw-output '.components[] | select(.role == "kernel") | .digest' "$manifest"
    )"
    expected_kernel_size="$(
      jq --exit-status --raw-output '.components[] | select(.role == "kernel") | .size_bytes' "$manifest"
    )"
    expected_initramfs_digest="$(
      jq --exit-status --raw-output '.components[] | select(.role == "initramfs") | .digest' "$manifest"
    )"
    expected_initramfs_size="$(
      jq --exit-status --raw-output '.components[] | select(.role == "initramfs") | .size_bytes' "$manifest"
    )"

    case "$expected_kernel_digest" in
      sha256:[0-9a-f][0-9a-f]*) ;;
      *) echo "release manifest has a non-canonical kernel digest" >&2; exit 1 ;;
    esac
    case "$expected_initramfs_digest" in
      sha256:[0-9a-f][0-9a-f]*) ;;
      *) echo "release manifest has a non-canonical initramfs digest" >&2; exit 1 ;;
    esac
    test "''${#expected_kernel_digest}" -eq 71
    test "''${#expected_initramfs_digest}" -eq 71

    actual_kernel_digest="sha256:$(sha256sum "$kernel" | cut -d ' ' -f 1)"
    actual_initramfs_digest="sha256:$(sha256sum "$initramfs" | cut -d ' ' -f 1)"
    actual_kernel_size="$(stat --format=%s "$kernel")"
    actual_initramfs_size="$(stat --format=%s "$initramfs")"
    test "$actual_kernel_digest" = "$expected_kernel_digest"
    test "$actual_initramfs_digest" = "$expected_initramfs_digest"
    test "$actual_kernel_size" = "$expected_kernel_size"
    test "$actual_initramfs_size" = "$expected_initramfs_size"

    # The arm64 Image header magic at byte offset 56 is "ARM\x64". Checking
    # it here turns an accidental non-kernel payload into a clear build error.
    test "$(od --address-radix=n --skip-bytes=56 --read-bytes=4 --format=x1 "$kernel" | tr -d ' \n')" = \
      41524d64

    # Generate the DTB from exactly the QEMU machine used below, then pass it
    # back explicitly. This avoids reusing the Pi DTB while still making the
    # PL011 chosen for earlycon an inspectable test input.
    qemu-system-aarch64 \
      -machine virt,gic-version=2,secure=off,virtualization=off,dumpdtb="$runtime_dtb" \
      -accel tcg,thread=multi \
      -cpu max \
      -smp 2 \
      -m 1536M \
      -display none \
      -monitor none \
      -nodefaults \
      -serial null
    test -s "$runtime_dtb"
    fdtget "$runtime_dtb" /pl011@9000000 compatible \
      | grep -F 'arm,pl011' > /dev/null
    fdtget -t x "$runtime_dtb" /pl011@9000000 reg \
      | grep -E '(^|[[:space:]])9000000([[:space:]]|$)' > /dev/null

    # Create the log paths up front. QEMU is allowed to leave either log empty;
    # absence of console output is itself useful diagnostic evidence.
    : > "$console_log"
    : > "$qemu_log"
    : > "$qmp_log"

    set +e
    python3 ${qmpRunner} \
      --qemu "$(command -v qemu-system-aarch64)" \
      --kernel "$kernel" \
      --initramfs "$initramfs" \
      --dtb "$runtime_dtb" \
      --command-line ${lib.escapeShellArg diagnosticCommandLine} \
      --console-log "$console_log" \
      --qemu-log "$qemu_log" \
      --qmp-log "$qmp_log" \
      --witness "$witness" \
      --failure "$failure_artifact" \
      --timeout ${toString timeoutSeconds}
    runner_status="$?"
    set -e

    guest_poweroff_event_observed=false
    if jq --exit-status '
        .event == "SHUTDOWN"
        and .data.guest == true
        and .data.reason == "guest-shutdown"
      ' "$witness" > /dev/null
    then
      guest_poweroff_event_observed=true
    else
      jq --null-input --sort-keys \
        '{
          status: "not-observed",
          event: null,
          data: {guest: null, reason: null}
        }' > "$witness"
    fi

    diagnostic_accepted=false
    if test "$runner_status" -eq 0 \
      && test "$guest_poweroff_event_observed" = true
    then
      diagnostic_accepted=true
      jq --null-input --sort-keys \
        --arg schema_version 'kaiba.provisioning.rpi5-release-payload-qemu-diagnostic-failure/v1alpha1' \
        '{
          schema_version: $schema_version,
          status: "not-applicable",
          error: null
        }' > "$failure_artifact"
    else
      # A runner crash can occur before Python has enough state to serialize
      # its own error. Preserve that case as a structured negative result too.
      if test "$guest_poweroff_event_observed" = true; then
        expected_failure_status=guest-poweroff-observed-qemu-exit-failed
      else
        expected_failure_status=guest-poweroff-not-observed
      fi
      if ! jq --exit-status --arg expected_status "$expected_failure_status" '
          .schema_version == "kaiba.provisioning.rpi5-release-payload-qemu-diagnostic-failure/v1alpha1"
          and .status == $expected_status
          and (.error | type == "string")
        ' "$failure_artifact" > /dev/null 2>&1
      then
        jq --null-input --sort-keys \
          --arg schema_version 'kaiba.provisioning.rpi5-release-payload-qemu-diagnostic-failure/v1alpha1' \
          --arg status "$expected_failure_status" \
          --argjson runner_status "$runner_status" \
          '{
            schema_version: $schema_version,
            status: $status,
            error_type: "runner-exit",
            error: "QMP runner exited without a valid failure artifact",
            runner_status: $runner_status
          }' > "$failure_artifact"
      fi
    fi

    mkdir -p "$out"
    install -m 0444 "$runtime_dtb" "$out/qemu-virt-runtime.dtb"
    install -m 0444 "$console_log" "$out/console.log"
    install -m 0444 "$qemu_log" "$out/qemu.log"
    install -m 0444 "$qmp_log" "$out/qmp.ndjson"
    install -m 0444 "$witness" "$out/qmp-shutdown-witness.json"
    install -m 0444 "$failure_artifact" "$out/failure.json"

    runtime_dtb_digest="sha256:$(sha256sum "$runtime_dtb" | cut -d ' ' -f 1)"
    jq --null-input --sort-keys \
      --arg schema_version 'kaiba.provisioning.rpi5-release-payload-qemu-diagnostic/v1alpha1' \
      --arg kernel_digest "$actual_kernel_digest" \
      --argjson kernel_size "$actual_kernel_size" \
      --arg initramfs_digest "$actual_initramfs_digest" \
      --argjson initramfs_size "$actual_initramfs_size" \
      --arg runtime_dtb_digest "$runtime_dtb_digest" \
      --arg command_line ${lib.escapeShellArg diagnosticCommandLine} \
      --arg witness_expected_source ${lib.escapeShellArg effectiveWitnessExpectedSource} \
      --arg witness_inference_basis ${lib.escapeShellArg effectiveWitnessInferenceBasis} \
      --arg witness_inference_limitation ${lib.escapeShellArg effectiveWitnessInferenceLimitation} \
      --argjson guest_poweroff_event_observed "$guest_poweroff_event_observed" \
      --argjson diagnostic_accepted "$diagnostic_accepted" \
      --argjson require_guest_poweroff ${lib.boolToString requireGuestPoweroff} \
      --slurpfile failure "$failure_artifact" \
      '{
        schema_version: $schema_version,
        status: (
          if $diagnostic_accepted
          then "guest-poweroff-observed"
          elif $guest_poweroff_event_observed
          then "guest-poweroff-observed-qemu-exit-failed"
          else "guest-poweroff-not-observed"
          end
        ),
        payload: {
          kernel: {digest: $kernel_digest, size_bytes: $kernel_size},
          initramfs: {digest: $initramfs_digest, size_bytes: $initramfs_size},
          byte_identical_to_release: true
        },
        environment: {
          machine: "qemu-virt",
          interrupt_controller: "gicv2",
          device_tree_digest: $runtime_dtb_digest,
          release_device_tree_used: false,
          command_line: $command_line,
          pl011: {device: "ttyAMA0", address: "0x09000000"}
        },
        witness: {
          transport: "qmp",
          observed: $guest_poweroff_event_observed,
          event: (if $guest_poweroff_event_observed then "SHUTDOWN" else null end),
          guest: (if $guest_poweroff_event_observed then true else null end),
          reason: (if $guest_poweroff_event_observed then "guest-shutdown" else null end),
          console_required: false,
          userspace_entry_inferred: $guest_poweroff_event_observed,
          expected_source: $witness_expected_source,
          inference_basis: $witness_inference_basis,
          limitation: $witness_inference_limitation
        },
        qemu: {
          clean_exit_after_witness: (
            if $guest_poweroff_event_observed then $diagnostic_accepted else null end
          )
        },
        requirement: {
          guest_poweroff_required: $require_guest_poweroff,
          clean_qemu_exit_required: true,
          satisfied: $diagnostic_accepted
        },
        failure: (if $diagnostic_accepted then null else $failure[0] end),
        hardware_observed: false,
        production_ready: false
      }' > "$out/result.json"

    if test ${lib.boolToString requireGuestPoweroff} = true \
      && test "$diagnostic_accepted" != true
    then
      jq . "$failure_artifact" >&2
      echo "strict QEMU payload diagnostic requires a guest shutdown and clean QEMU exit" >&2
      exit 1
    fi
  ''
