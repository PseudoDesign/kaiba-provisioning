#!/usr/bin/env python3
"""Read-only inventory of the retained September 15 development candidate.

Print public digests and missing prerequisites. Never read devices, change GPT,
sign, repair artifacts, or interpret a descriptive record as physical evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def strict_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate JSON key: {name}")
        result[name] = value
    return result


def load(data):
    return json.loads(data, object_pairs_hook=strict_object)


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_descriptor(path):
    pin = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(pin)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1024 * 1024:
            raise ValueError("descriptor must be a bounded regular file")
        readable = os.open(f"/proc/self/fd/{pin}", os.O_RDONLY | os.O_CLOEXEC)
    finally:
        os.close(pin)
    with os.fdopen(readable, "rb") as source:
        encoded = source.read(1024 * 1024 + 1)
        after = os.fstat(source.fileno())
    if len(encoded) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("descriptor changed during inventory")
    return encoded


def inspect(path, expected_digest, expected_size):
    entry = {"path": str(path), "expected_sha256": expected_digest,
             "expected_size_bytes": expected_size}
    try:
        pin = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(pin)
            if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
                entry["status"] = "wrong-type-or-size"
                return entry
            readable = os.open(f"/proc/self/fd/{pin}", os.O_RDONLY | os.O_CLOEXEC)
        finally:
            os.close(pin)
        with os.fdopen(readable, "rb") as source:
            hashed = hashlib.sha256()
            for chunk in iter(lambda: source.read(128 * 1024), b""):
                hashed.update(chunk)
            after = os.fstat(source.fileno())
            stable = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            entry["actual_sha256"] = "sha256:" + hashed.hexdigest()
            entry["status"] = "bytes-match" if stable and entry["actual_sha256"] == expected_digest else "changed-or-mismatched"
    except FileNotFoundError:
        entry["status"] = "missing"
    except PermissionError:
        entry["status"] = "unreadable"
    return entry


def inventory(descriptor):
    for role in ("configuration", "staging_plan"):
        binding = descriptor[role]
        encoded = binding["json"].encode()
        if digest(encoded) != binding["sha256"] or len(encoded) != binding["size_bytes"]:
            raise ValueError(f"embedded {role} bytes differ from their descriptor binding")
    if descriptor["hardware_qualified"] or descriptor["production_ready"] or descriptor["leg"] != "pi-local-nvme":
        raise ValueError("expected the unqualified development NVMe descriptor")
    plan = load(descriptor["staging_plan"]["json"])
    config = load(descriptor["configuration"]["json"])
    if plan["plan_digest"] != descriptor["staging_plan"]["plan_digest"]:
        raise ValueError("staging plan binding differs")
    if config["staging_plan_path"] != descriptor["staging_plan"]["path"]:
        raise ValueError("configuration is detached from the staging plan")
    payload = descriptor["payloads"][0]
    run_root = Path(payload["path"]).parent.parent
    if not str(run_root).startswith("/nix/store/"):
        raise ValueError("expected an immutable store run")
    names = {"boot-filesystem": "sd/boot-filesystem.img", "root-data": "sd/root-data.img",
             "root-hash": "sd/root-hash.img", "release-filesystem": "nvme/release-filesystem.img"}
    artifacts = []
    devices = []
    for device in plan["devices"]:
        devices.append({key: device["identity"][key] for key in ("leg", "config_id", "hostname", "selector", "capacity_bytes", "disk_guid")})
        for partition in device["partitions"]:
            role = partition["role"]
            if role == "release-filesystem" and (partition["source_sha256"] != payload["sha256"] or partition["source_size_bytes"] != payload["size_bytes"] or config["payload_paths"][role] != payload["path"]):
                raise ValueError("NVMe payload descriptor differs from the embedded plan")
            entry = inspect(run_root / names[role], partition["source_sha256"], partition["source_size_bytes"])
            entry.update(role=role, expected_whole_partition_sha256=partition["expected_whole_partition_sha256"],
                         partition_capacity_bytes=partition["capacity_bytes"])
            artifacts.append(entry)
    return {"schema_version": "kaiba.provisioning.rpi5-task1-retained-inventory/v1alpha1",
            "assurance": "local-public-byte-inventory-only", "campaign": plan["campaign"],
            "staging_plan_digest": plan["plan_digest"], "devices": devices,
            "retained_files": [inspect(Path(descriptor[role]["path"]), descriptor[role]["sha256"], descriptor[role]["size_bytes"]) for role in ("configuration", "staging_plan")],
            "payloads": artifacts,
            "original_ownership_verified": False, "native_build_provenance_verified": False,
            "signatures_verified": False, "physical_execution_authorized": False,
            "hardware_qualified": False, "production_ready": False, "enrollment_ready": False,
            "outstanding": ["current-owned-board-identity-and-readback", "original-ownership-evidence",
                            "complete-retained-signed-artifacts-and-receipts", "reviewed-native-build-provenance",
                            "fresh-sd-nvme-envelopes-and-durable-recovery-backups", "qualified-power-usb-uart-topology",
                            "authority-certificate-validity-and-pi-rtc", "explicit-physical-execution-approval",
                            "independent-complete-media-readback", "33-run-37-claim-physical-campaign",
                            "signed-owned-recovery-and-repeated-owned-state-readback", "independent-final-review"]}


def main():
    default = Path(__file__).resolve().parents[1] / "reviewed-candidates/development-pi5-staging-20260915/descriptor.json"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", type=Path, default=default)
    args = parser.parse_args()
    try:
        report = inventory(load(read_descriptor(args.descriptor)))
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        print(f"task1 inventory: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
