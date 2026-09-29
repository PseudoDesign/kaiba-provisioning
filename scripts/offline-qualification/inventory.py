#!/usr/bin/env python3
"""Collect fixed, read-only host metadata; never qualify hardware or read OTP keys."""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading


SCHEMA = "kaiba.offline-qualification-inventory/v1alpha1"
MAX_FIELD = 16384
MAX_RAW = 262144
TARGETS = {"ace": "adam@ace.local", "mako": "adam@mako.local"}
SERVICES = ("nginx", "dogsitting", "crtvar", "spire-server", "spire-agent",
            "systemd-timesyncd", "chronyd")
FIELDS = ("model", "architecture", "kernel", "system_closure", "root_mount",
          "storage_types", "bootloader_version", "signed_boot_property",
          "boot_mode_property", "tpm_interfaces", "target_utc", "ntp_synchronized",
          *["service_" + unit for unit in SERVICES])

# Run the same fixed command on either existing host. No user-controlled shell
# fragments, OTP dumps, key operations, firmware updates, or state-changing
# systemctl verbs. sudo is confined to the public bootloader-version query.
REMOTE_SCRIPT = r'''set -eu
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
emit model cat /proc/device-tree/model
emit architecture uname -m
emit kernel uname -r
emit system_closure readlink /run/current-system
emit root_mount findmnt -n -o SOURCE,FSTYPE,OPTIONS /
emit storage_types lsblk -nr -o TYPE,FSTYPE
emit bootloader_version sudo -n vcgencmd bootloader_version
emit signed_boot_property od -An -tx1 /proc/device-tree/chosen/bootloader/signed
emit boot_mode_property od -An -tx1 /proc/device-tree/chosen/bootloader/boot-mode
emit tpm_interfaces sh -c 'for node in /dev/tpm0 /dev/tpmrm0; do if test -c "$node"; then printf "%s=present\n" "$node"; else printf "%s=not-observed\n" "$node"; fi; done; if test -d /sys/class/tpm; then for node in /sys/class/tpm/tpm*; do if test -e "$node"; then basename "$node"; fi; done; fi'
emit target_utc date -u +%Y-%m-%dT%H:%M:%SZ
emit ntp_synchronized timedatectl show --property=NTPSynchronized --value
emit service_nginx systemctl is-active nginx
emit service_dogsitting systemctl is-active dogsitting
emit service_crtvar systemctl is-active crtvar
emit service_spire-server systemctl is-active spire-server
emit service_spire-agent systemctl is-active spire-agent
emit service_systemd-timesyncd systemctl is-active systemd-timesyncd
emit service_chronyd systemctl is-active chronyd
'''


def require(condition, code):
    if not condition:
        raise ValueError(code)


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def parse(raw):
    """Require the complete closed transcript, including failed observations."""
    require(0 < len(raw) <= MAX_RAW, "transcript-size")
    result = {}
    for line in raw.decode("ascii").splitlines():
        parts = line.split("|")
        require(len(parts) == 3, "transcript-record")
        name, status, encoded = parts
        require(name in FIELDS and name not in result, "transcript-field")
        require(re.fullmatch(r"0|[1-9][0-9]{0,2}", status) and int(status) <= 255,
                "transcript-exit-code")
        value = base64.b64decode(encoded, validate=True)
        require(len(value) <= MAX_FIELD, "field-size")
        value = value.rstrip(b"\0") if name == "model" else value
        text = value.decode("ascii")
        require(all(character in "\n\t" or 32 <= ord(character) <= 126 for character in text),
                "field-encoding")
        result[name] = (int(status), text.strip())
    require(set(result) == set(FIELDS), "transcript-incomplete")
    return result


def observation(fields, name):
    status, value = fields[name]
    # Failure output is retained privately but never promoted to an observation.
    if status != 0 or not value:
        return {"state": "not-observed", "exit_code": status}
    return {"state": "observed", "value": value}


def project(raw, target, collected_at, collector_digest):
    require(target in TARGETS, "target")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", collector_digest), "collector-digest")
    timestamp = datetime.datetime.strptime(collected_at, "%Y-%m-%dT%H:%M:%SZ")
    require(timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") == collected_at, "timestamp")
    fields = parse(raw)
    values = {name: observation(fields, name) for name in FIELDS if not name.startswith("service_")}
    services = {}
    for unit in SERVICES:
        status, value = fields["service_" + unit]
        # systemctl uses exit 3 for non-active states. Keep that observation,
        # while distinguishing unavailable commands or unrecognized output.
        # This is an activity observation, not proof the unit is installed.
        if status in (0, 3) and value in ("active", "inactive", "activating", "deactivating", "failed"):
            services[unit] = {"state": "observed", "value": value}
        else:
            services[unit] = {"state": "not-observed", "exit_code": status}
    return {
        "schema_version": SCHEMA,
        "target_reference": target,
        "collected_at_station_utc": collected_at,
        "collector_sha256": collector_digest,
        "raw_evidence_sha256": digest(raw),
        "transport": "ssh-existing-host-key",
        "evidence_kind": "target-self-report",
        "observations": values,
        "services": services,
        "hardware_qualified": False,
        "boot_chain_authenticated": False,
        "offline_rollback_qualified": False,
        "clock_continuity_qualified": False,
        "fleet_admission": "unevaluated",
        "execution_authority": False,
        "publication_authorized": False,
    }


def ssh_arguments(target, known_hosts=None):
    require(target in TARGETS, "target")
    arguments = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                 "-o", "UpdateHostKeys=no", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
                 "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=8", "-o",
                 "ConnectionAttempts=1"]
    if known_hosts is not None:
        require(known_hosts.is_absolute() and re.fullmatch(r"[A-Za-z0-9/_.-]+", str(known_hosts)),
                "known-hosts-path")
        metadata = known_hosts.lstat()
        require(stat.S_ISREG(metadata.st_mode) and 0 < metadata.st_size <= 65536,
                "known-hosts-file")
        arguments += ["-o", "UserKnownHostsFile=" + str(known_hosts),
                      "-o", "GlobalKnownHostsFile=/dev/null"]
    return arguments + [TARGETS[target], "sh", "-s"]


def collect(target, directory, known_hosts=None):
    require(directory.is_absolute() and not directory.exists(), "new-private-directory-required")
    require(not directory.resolve().is_relative_to("/nix/store"), "private-evidence-not-store-input")
    script = Path(__file__).resolve()
    if script.parent.name == "offline-qualification" and script.parent.parent.name == "scripts":
        require(not directory.resolve().is_relative_to(script.parents[2]),
                "private-evidence-outside-checkout-required")
    # Fixed commands have bounded fields; the receiver also imposes a total
    # output ceiling before it decodes or retains a transcript.
    collector_source = Path(__file__).read_bytes()
    with subprocess.Popen(ssh_arguments(target, known_hosts), stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        process.stdin.write(REMOTE_SCRIPT.encode("ascii"))
        process.stdin.close()
        timer = threading.Timer(45, process.kill)
        timer.start()
        try:
            raw = process.stdout.read(MAX_RAW + 1)
            if len(raw) > MAX_RAW:
                process.kill()
            returncode = process.wait()
        finally:
            timer.cancel()
        require(returncode == 0, "ssh-observation-failed")
    collected_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report = project(raw, target, collected_at, digest(collector_source))
    directory.mkdir(mode=0o700)
    for filename, content in (
        ("raw.txt", raw),
        ("collector.py", collector_source),
        ("inventory.json", (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("ascii")),
    ):
        descriptor = os.open(directory / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=tuple(TARGETS), required=True)
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="new absolute private directory, outside the checkout")
    parser.add_argument("--known-hosts", type=Path,
                        help="existing absolute task-specific trusted host-key file; never accepts a new key")
    arguments = parser.parse_args()
    try:
        collect(arguments.target, arguments.output_dir, arguments.known_hosts)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        print("STOP: trusted SSH or complete bounded metadata unavailable; no qualification produced", file=sys.stderr)
        return 1
    print("Private inventory retained; hardware, rollback and clock qualification remain open.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
