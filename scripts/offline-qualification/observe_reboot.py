#!/usr/bin/env python3
"""Read-only Ace identity observations and bounded before/after reboot comparison."""
import argparse
import base64
import datetime as dt
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading


INVENTORY = Path(os.environ.get("KAIBA_OFFLINE_INVENTORY", str(Path(__file__).with_name("inventory.py"))))
spec = importlib.util.spec_from_file_location("inventory", INVENTORY)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)
SCHEMA = "kaiba.identity-reboot-observation/v1alpha1"
COMPARISON_SCHEMA = "kaiba.identity-reboot-comparison/v1alpha1"
MAX_RAW = 262144
MAX_FIELD = 16384
MAX_PROBE_AGE = 420  # Five-minute timer, with bounded scheduling margin.
SERVICES = ("hydra-server", "hydra-evaluator", "hydra-queue-runner", "postgresql",
            "sshd", "spire-server", "spire-agent", "kaiba-identity-pilot-probe.timer")
FIELDS = ("boot_id", "boot_id_end", "current_system", "persistent_system", "booted_system",
          "generation", "bundle_digest", "probe_unit_before", "probe_stat_before", "probe",
          "probe_stat_after", "probe_unit_after", "enrollment", "pilot_directory", "pilot_file",
          "pilot_mount", "grant_absent", "failed_units", "ntp", "uptime", "target_utc",
          *["service_" + unit for unit in SERVICES])
UNIT_KEYS = {"InvocationID", "ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic",
             "ExecMainStatus", "Result", "ActiveState"}

# No service activation, SPIRE admin calls, key/database reads, boot-mount
# triggering, grant generation or reboot. The existing client's status command
# emits public enrollment metadata only. root is needed for protected public
# bundle/output files and to invoke that client as its existing service user.
REMOTE_SCRIPT = r'''set -eu
export LC_ALL=C
emit() {
    field=$1
    shift
    set +e
    value=$("$@" 2>/dev/null)
    status=$?
    set -e
    printf '%s|%s|' "$field" "$status"
    printf '%s' "$value" | head -c 16385 | base64 -w 0
    printf '\n'
}
probe_unit() {
    systemctl show kaiba-identity-pilot-probe.service \
        --property=InvocationID,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,ExecMainStatus,Result,ActiveState
}
emit boot_id cat /proc/sys/kernel/random/boot_id
emit current_system readlink -f /run/current-system
emit persistent_system readlink -f /nix/var/nix/profiles/system
emit booted_system readlink -f /run/booted-system
emit generation readlink /nix/var/nix/profiles/system
emit bundle_digest sha256sum /var/lib/kaiba/identity/pilot-bootstrap/trust-bundle.pem
emit probe_unit_before probe_unit
emit probe_stat_before stat -c '%Y:%s:%i' /var/lib/kaiba-identity-pilot-probe/identity.jsonl
emit probe cat /var/lib/kaiba-identity-pilot-probe/identity.jsonl
emit probe_stat_after stat -c '%Y:%s:%i' /var/lib/kaiba-identity-pilot-probe/identity.jsonl
emit probe_unit_after probe_unit
emit enrollment sudo -n -u kaiba-pilot-device /var/lib/kaiba-pilot-device-tools/kaiba-pilot-device -state /var/lib/kaiba-pilot-device status
emit pilot_directory stat -c '%u:%g:%a' /var/lib/kaiba-pilot-device
emit pilot_file stat -c '%u:%g:%a:%h' /var/lib/kaiba-pilot-device/state.json
emit pilot_mount findmnt -n -o OPTIONS --mountpoint /var/lib/kaiba-pilot-device
emit grant_absent test ! -e /run/kaiba-identity-pilot-init/join-token
emit failed_units systemctl --failed --no-legend --plain
emit service_hydra-server systemctl is-active hydra-server
emit service_hydra-evaluator systemctl is-active hydra-evaluator
emit service_hydra-queue-runner systemctl is-active hydra-queue-runner
emit service_postgresql systemctl is-active postgresql
emit service_sshd systemctl is-active sshd
emit service_spire-server systemctl is-active spire-server
emit service_spire-agent systemctl is-active spire-agent
emit service_kaiba-identity-pilot-probe.timer systemctl is-active kaiba-identity-pilot-probe.timer
emit ntp timedatectl show --property=NTPSynchronized --value
emit uptime cat /proc/uptime
emit target_utc date -u +%Y-%m-%dT%H:%M:%SZ
emit boot_id_end cat /proc/sys/kernel/random/boot_id
'''


def require(condition, code):
    if not condition:
        raise ValueError(code)


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def strict_json(raw):
    def object_pairs(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "duplicate-json-key")
            value[key] = item
        return value
    def constant(_):
        raise ValueError("non-finite-json")
    return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=constant)


def timestamp(value):
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value), "timestamp")
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp()


def parse(raw):
    require(0 < len(raw) <= MAX_RAW, "transcript-size")
    fields = {}
    for line in raw.decode("ascii").splitlines():
        parts = line.split("|")
        require(len(parts) == 3, "transcript-record")
        name, status, encoded = parts
        require(name in FIELDS and name not in fields, "transcript-field")
        require(re.fullmatch(r"0|[1-9][0-9]{0,2}", status) and int(status) <= 255, "transcript-status")
        value = base64.b64decode(encoded, validate=True)
        require(len(value) <= MAX_FIELD, "field-size")
        text = value.decode("ascii")
        require(all(c in "\n\t" or 32 <= ord(c) <= 126 for c in text), "field-encoding")
        fields[name] = (int(status), text.strip())
    require(set(fields) == set(FIELDS), "transcript-incomplete")
    return fields


def project(raw, collected_at):
    fields = parse(raw)
    issues = []
    def check(condition, code):
        if not condition:
            issues.append(code)
    def value(name):
        code, text = fields[name]
        require(code == 0, "required-observation-unavailable")
        return text
    # Non-active services and a still-present grant are readiness failures,
    # rather than missing evidence. No raw service failures enter public output.
    services = {unit: fields["service_" + unit] == (0, "active") for unit in SERVICES}
    check(all(services.values()), "required-service-not-active")
    check(fields["grant_absent"] == (0, ""), "bootstrap-grant-not-absent")
    check(value("ntp") == "yes", "clock-not-synchronized")
    check(not value("failed_units"), "failed-systemd-units")
    boot_id = value("boot_id")
    require(re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id), "boot-id")
    require(boot_id == value("boot_id_end"), "boot-changed-during-observation")
    systems = {name: value(name) for name in ("current_system", "persistent_system", "booted_system")}
    for path in systems.values():
        require(re.fullmatch(r"/nix/store/[0-9a-z]{32}-nixos-system-ace-[A-Za-z0-9.+_-]+", path), "system-closure")
    match = re.fullmatch(r"(?:/nix/var/nix/profiles/)?system-([1-9][0-9]*)-link", value("generation"))
    require(match is not None, "system-generation")
    bundle = re.fullmatch(r"([0-9a-f]{64})  /var/lib/kaiba/identity/pilot-bootstrap/trust-bundle.pem", value("bundle_digest"))
    require(bundle is not None, "bundle-digest")
    unit_raw = value("probe_unit_before")
    require(unit_raw == value("probe_unit_after") and value("probe_stat_before") == value("probe_stat_after"), "probe-changed-during-observation")
    unit = {}
    for line in unit_raw.splitlines():
        key, separator, item = line.partition("=")
        require(separator and key in UNIT_KEYS and key not in unit, "probe-unit-properties")
        unit[key] = item
    require(set(unit) == UNIT_KEYS, "probe-unit-incomplete")
    check(bool(re.fullmatch(r"[0-9a-f]{32}", unit["InvocationID"])) and unit["InvocationID"] != "0" * 32, "probe-no-current-invocation")
    for key in ("ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic", "ExecMainStatus"):
        require(re.fullmatch(r"[0-9]+", unit[key]), "probe-unit-number")
    start = int(unit["ExecMainStartTimestampMonotonic"]) / 1_000_000
    end = int(unit["ExecMainExitTimestampMonotonic"]) / 1_000_000
    check(unit["Result"] == "success" and unit["ExecMainStatus"] == "0" and unit["ActiveState"] == "inactive", "probe-not-completed-successfully")
    uptime_text = value("uptime").split()
    require(len(uptime_text) == 2 and all(re.fullmatch(r"[0-9]+\.[0-9]+", item) for item in uptime_text), "uptime")
    uptime = float(uptime_text[0])
    require(math.isfinite(uptime), "uptime")
    target_at = value("target_utc")
    target_seconds = timestamp(target_at)
    check(abs(timestamp(collected_at) - target_seconds) <= 30, "station-target-clock-skew")
    check(0 < start <= end <= uptime and uptime - end <= MAX_PROBE_AGE, "probe-not-fresh-in-current-boot")
    probe_stat = value("probe_stat_before").split(":")
    require(len(probe_stat) == 3 and all(re.fullmatch(r"[0-9]+", x) for x in probe_stat), "probe-file-stat")
    modified, size, inode = map(int, probe_stat)
    check(0 < size <= MAX_FIELD and inode > 0, "probe-output-metadata")
    # Five seconds allows stat's integer seconds and capture scheduling. The
    # monotonic unit timestamps cannot be inherited from the previous boot.
    boot_seconds = target_seconds - uptime
    check(boot_seconds + start - 5 <= modified <= boot_seconds + end + 5, "probe-output-not-from-invocation")
    probe = strict_json(value("probe"))
    require(isinstance(probe, dict) and set(probe) == {"spiffe_id", "serial", "not_after", "pid"}, "probe-json")
    require(isinstance(probe["spiffe_id"], str) and re.fullmatch(r"spiffe://[a-z0-9.-]+/device/[a-z0-9_-]+/instance/[a-z0-9_-]+/workload/identity-probe", probe["spiffe_id"]), "probe-identity")
    require(isinstance(probe["serial"], str) and re.fullmatch(r"[1-9][0-9]*", probe["serial"]), "probe-serial")
    require(type(probe["pid"]) is int and probe["pid"] > 0, "probe-pid")
    check(timestamp(probe["not_after"]) > target_seconds + 30, "probe-identity-expired-or-expiring")
    enrollment = strict_json(value("enrollment"))
    require(isinstance(enrollment, dict) and enrollment.get("schema_version") == "kaiba.pilot-device-client/v1alpha1", "enrollment-status-schema")
    check(enrollment.get("phase") == "verified" and all(isinstance(enrollment.get(k), str) and enrollment[k] for k in ("spki_digest", "enrollment_id", "logical_device_id")), "enrollment-not-verified")
    check(value("pilot_directory") == "994:988:700" and value("pilot_file") == "994:988:600:1", "pilot-state-metadata")
    check({"rw", "nosuid", "nodev", "noexec"} <= set(value("pilot_mount").split(",")), "pilot-protected-mount")
    check(systems["current_system"] == systems["persistent_system"], "current-persistent-system-mismatch")
    return {
        "schema_version": SCHEMA, "target_reference": "ace", "evidence_kind": "target-self-report",
        "collected_at_station_utc": collected_at, "target_utc": target_at,
        "collector_sha256": digest(Path(__file__).read_bytes()),
        "transport_helper_sha256": digest(INVENTORY.read_bytes()), "raw_evidence_sha256": digest(raw),
        "boot_id": boot_id, "uptime_seconds": uptime, **systems, "system_generation": int(match[1]),
        "trust_bundle_sha256": "sha256:" + bundle[1], "spiffe_id": probe["spiffe_id"],
        "svid_not_after": probe["not_after"], "probe_invocation_id": unit["InvocationID"],
        "public_enrollment_sha256": digest(json.dumps(enrollment, sort_keys=True, separators=(",", ":")).encode()),
        "services_active": services, "ready_for_comparison": not issues, "readiness_issues": issues,
        "hardware_qualified": False, "boot_chain_authenticated": False,
        "offline_rollback_qualified": False, "clock_continuity_qualified": False,
        "fleet_admission": "unevaluated", "publication_authorized": False,
    }


def private_write(directory, files):
    directory.mkdir(mode=0o700)
    for filename, content in files.items():
        fd = os.open(directory / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(content)


def check_destination(directory):
    require(directory.is_absolute() and not directory.exists(), "new-private-directory-required")
    require(not directory.resolve().is_relative_to("/nix/store"), "private-evidence-not-store-input")
    script = Path(__file__).resolve()
    if script.parent.name == "offline-qualification" and script.parent.parent.name == "scripts":
        require(not directory.resolve().is_relative_to(script.parents[2]), "private-evidence-outside-checkout-required")


def collect(directory, known_hosts):
    check_destination(directory)
    args = inventory.ssh_arguments("ace", known_hosts)[:-2]
    args += ["sudo", "-n", "sh", "-s"]
    # Do not reuse another connection's authentication or lifetime.
    args[1:1] = ["-o", "ControlMaster=no", "-o", "ControlPath=none"]
    with subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        timer = threading.Timer(45, process.kill)
        timer.start()
        try:
            process.stdin.write(REMOTE_SCRIPT.encode("ascii"))
            process.stdin.close()
            raw = process.stdout.read(MAX_RAW + 1)
            if len(raw) > MAX_RAW:
                process.kill()
            code = process.wait()
        finally:
            timer.cancel()
        require(code == 0, "ssh-observation-failed")
    collected_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report = project(raw, collected_at)
    private_write(directory, {"raw.txt": raw, "observe_reboot.py": Path(__file__).read_bytes(),
                              "inventory.py": INVENTORY.read_bytes(), "observation.json": encode(report)})
    return report


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("ascii")


def read_capture(directory):
    def read(name):
        path = directory / name
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= MAX_RAW, "capture-file")
        return path.read_bytes()
    raw = read("raw.txt")
    report = strict_json(read("observation.json"))
    require(isinstance(report, dict), "capture-report")
    require(digest(read("observe_reboot.py")) == digest(Path(__file__).read_bytes()), "collector-version-mismatch")
    require(digest(read("inventory.py")) == digest(INVENTORY.read_bytes()), "transport-version-mismatch")
    regenerated = project(raw, report.get("collected_at_station_utc"))
    require(regenerated == report, "capture-projection-mismatch")
    return report


def compare(before, after, expected_system, expected_generation, expected_spiffe_id, max_interval=900):
    require(type(max_interval) is int and 1 <= max_interval <= 1800, "comparison-interval")
    require(type(expected_generation) is int and expected_generation > 0, "expected-generation")
    checks = {
        "both_observations_ready": before["ready_for_comparison"] and after["ready_for_comparison"],
        "boot_id_changed": before["boot_id"] != after["boot_id"],
        "probe_invocation_changed": before["probe_invocation_id"] != after["probe_invocation_id"],
        "same_expected_system": all(x[k] == expected_system for x in (before, after) for k in ("current_system", "persistent_system")),
        "booted_expected_system": after["booted_system"] == expected_system,
        "same_expected_generation": before["system_generation"] == after["system_generation"] == expected_generation,
        "same_expected_spiffe_identity": before["spiffe_id"] == after["spiffe_id"] == expected_spiffe_id,
        "same_trust_bundle": before["trust_bundle_sha256"] == after["trust_bundle_sha256"],
        "same_public_enrollment_status": before["public_enrollment_sha256"] == after["public_enrollment_sha256"],
    }
    elapsed = timestamp(after["collected_at_station_utc"]) - timestamp(before["collected_at_station_utc"])
    checks["bounded_observation_interval"] = 0 < elapsed <= max_interval
    # A fresh boot must fall between observations (allow capture/skew margin).
    checks["new_boot_within_observation_interval"] = 0 < after["uptime_seconds"] <= elapsed + 30
    return {"schema_version": COMPARISON_SCHEMA, "target_reference": "ace",
            "evidence_kind": "target-self-report", "before_raw_sha256": before["raw_evidence_sha256"],
            "after_raw_sha256": after["raw_evidence_sha256"], "checks": checks,
            "warm_reboot_observation_passed": all(checks.values()),
            "reboot_action_independently_verified": False,
            "physical_cold_boot_tested": False, "hardware_qualified": False,
            "boot_chain_authenticated": False, "offline_rollback_qualified": False,
            "clock_continuity_qualified": False, "fleet_admission": "unevaluated",
            "dns_publication_tested": False, "publication_authorized": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    capture = sub.add_parser("collect")
    capture.add_argument("--output-dir", type=Path, required=True)
    capture.add_argument("--known-hosts", type=Path, help="existing trusted host-key file; no new keys are accepted")
    comparison = sub.add_parser("compare")
    comparison.add_argument("--before", type=Path, required=True)
    comparison.add_argument("--after", type=Path, required=True)
    comparison.add_argument("--expected-system", required=True)
    comparison.add_argument("--expected-generation", type=int, required=True)
    comparison.add_argument("--expected-spiffe-id", required=True)
    comparison.add_argument("--max-interval-seconds", type=int, default=900)
    comparison.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "collect":
            report = collect(args.output_dir, args.known_hosts)
            passed = report["ready_for_comparison"]
            print("Private observation retained; ready_for_comparison=" + str(passed).lower())
        else:
            check_destination(args.output_dir)
            report = compare(read_capture(args.before), read_capture(args.after), args.expected_system,
                             args.expected_generation, args.expected_spiffe_id, args.max_interval_seconds)
            private_write(args.output_dir, {"comparison.json": encode(report)})
            passed = report["warm_reboot_observation_passed"]
            print("Private comparison retained; warm_reboot_observation_passed=" + str(passed).lower())
        return 0 if passed else 2
    except (OSError, ValueError, UnicodeError, TypeError, subprocess.SubprocessError):
        print("STOP: incomplete or inconsistent bounded observation; no reboot or qualification performed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
