#!/usr/bin/env python3
"""Public, regular-file boundaries for the split native staging package.

The pure Python descriptor checks are preliminary consistency checks. Every
constructor also invokes the fixed Go production parser through bounded stdin.
This helper binds exact bytes and streams the selected payload; it neither opens
devices nor treats a component manifest as authenticated build provenance.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

DESCRIPTOR_SCHEMA = "kaiba.provisioning.rpi5-stable-campaign-staging-descriptor/v1alpha1"
COMPONENT_SCHEMA = "kaiba.provisioning.rpi5-stable-campaign-staging-native-component/v1alpha1"
CONFIG_SCHEMA = "kaiba.provisioning.rpi5-stable-campaign-staging-configuration/v1alpha1"
PLAN_SCHEMA = "kaiba.provisioning.rpi5-stable-verifier-campaign-media-staging-plan/v1alpha1"
MAX_JSON = 4 * 1024 * 1024
CAPACITY = 8 * 1024 * 1024 * 1024
BINARY = "bin/kaiba-rpi5-stable-campaign-stage"
COMPONENT_FILES = {BINARY, "share/kaiba/component.json", "share/kaiba/descriptor.json"}
PRIVATE_MARKER = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected), "unexpected or missing JSON fields")


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def valid_digest(value):
    require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "invalid SHA-256 digest")


def store_path(value, top_level=False):
    require(type(value) is str and len(value) <= 4096, "invalid store path")
    require(re.fullmatch(r"/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+(?:/[A-Za-z0-9+._?=-]+)*", value), "invalid store path")
    require(str(Path(value)) == value and all(p not in (".", "..") for p in value.split("/")), "noncanonical store path")
    if top_level:
        require(len(Path(value).parts) == 4, "configuration must be a top-level store file")


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def parse(data, canonical=False):
    require(0 < len(data) <= MAX_JSON, "JSON size outside bounds")

    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result

    value = json.loads(data, object_pairs_hook=object_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON number")))

    def public(item):
        if isinstance(item, dict):
            for key, val in item.items():
                public(key)
                public(val)
        elif isinstance(item, list):
            for val in item:
                public(val)
        elif isinstance(item, str):
            require(not PRIVATE_MARKER.search(item), "private-key markers are forbidden in public metadata")
    public(value)
    if canonical:
        require(encode(value) == data, "descriptor must be canonical JSON with one LF")
    return value


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def open_regular(path, maximum):
    """Pin before readable open; a substituted FIFO/device is never activated."""
    path = str(path)
    require(os.path.isabs(path) and os.path.normpath(path) == path, "input path must be absolute and canonical")
    # Each ancestor is pinned without symlink traversal, including the final file.
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in Path(path).parts[1:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = following
        pin = os.open(Path(path).name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        before = os.fstat(pin)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, "input must be a bounded regular non-symlink file")
        fd = os.open(f"/proc/self/fd/{pin}", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        if identity(os.fstat(fd)) != identity(before):
            os.close(fd)
            raise ValueError("input changed while opening")
        return os.fdopen(fd, "rb"), before
    finally:
        os.close(pin)


def unchanged(stream, before):
    require(identity(os.fstat(stream.fileno())) == identity(before), "input changed while reading")


def read_regular(path, maximum=MAX_JSON):
    stream, before = open_regular(path, maximum)
    with stream:
        data = stream.read(maximum + 1)
        require(len(data) == before.st_size, "input size changed while reading")
        unchanged(stream, before)
        return data


def configuration(data):
    value = parse(data)
    keys(value, ("leg", "payload_paths", "schema_version", "staging_plan_path"))
    require(value["schema_version"] == CONFIG_SCHEMA and value["leg"] == "pi-local-nvme", "only the fixed NVMe leg is supported")
    keys(value["payload_paths"], ("release-filesystem",))
    store_path(value["staging_plan_path"])
    store_path(value["payload_paths"]["release-filesystem"])
    # Go's fixed configuration fields and Nix toJSON both use this key order.
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    require(data in (canonical, canonical + b"\n"), "configuration is not canonical JSON")
    return value


def partition(plan_data):
    plan = parse(plan_data)
    require(plan.get("schema_version") == PLAN_SCHEMA, "unexpected staging-plan schema")
    require(plan.get("destructive_staging_ready") is False and plan.get("initial_gpt_recovery_bound") is False, "staging plan must retain descriptive boundaries")
    valid_digest(plan.get("plan_digest"))
    require(type(plan.get("devices")) is list and len(plan["devices"]) == 2, "staging plan requires two device legs")
    require([d.get("identity", {}).get("leg") for d in plan["devices"]] == ["malak-sd", "pi-local-nvme"], "staging plan leg ordering differs")
    device = plan["devices"][1]
    require(type(device.get("partitions")) is list and len(device["partitions"]) == 1, "NVMe requires one partition")
    part = device["partitions"][0]
    require(part.get("role") == "release-filesystem" and part.get("number") == 1 and part.get("byte_start") == 1048576, "NVMe payload geometry differs")
    require(type(part.get("capacity_bytes")) is int and part["capacity_bytes"] == CAPACITY, "NVMe partition capacity differs")
    size = part.get("source_size_bytes")
    require(type(size) is int and 0 < size <= CAPACITY, "invalid source size")
    require(type(part.get("zero_tail_bytes")) is int and part["zero_tail_bytes"] == CAPACITY - size, "zero tail differs")
    valid_digest(part.get("source_sha256"))
    valid_digest(part.get("expected_whole_partition_sha256"))
    return plan, part


def embedded(record, fields):
    keys(record, fields)
    store_path(record["path"])
    require(type(record["json"]) is str, "embedded JSON must preserve exact file text")
    data = record["json"].encode()
    require(type(record["size_bytes"]) is int and record["size_bytes"] == len(data), "embedded JSON size differs")
    require(record["sha256"] == digest(data), "embedded JSON digest differs")
    return data


def validate(data):
    desc = parse(data, canonical=True)
    keys(desc, ("schema_version", "target_system", "leg", "configuration", "staging_plan", "payloads", "hardware_qualified", "production_ready"))
    require(desc["schema_version"] == DESCRIPTOR_SCHEMA and desc["target_system"] == "aarch64-linux" and desc["leg"] == "pi-local-nvme", "descriptor profile differs")
    require(desc["hardware_qualified"] is False and desc["production_ready"] is False, "descriptor cannot grant readiness")
    config_data = embedded(desc["configuration"], ("path", "sha256", "size_bytes", "json"))
    store_path(desc["configuration"]["path"], top_level=True)
    fixed = configuration(config_data)
    plan_data = embedded(desc["staging_plan"], ("path", "sha256", "size_bytes", "json", "plan_digest"))
    plan, part = partition(plan_data)
    require(fixed["staging_plan_path"] == desc["staging_plan"]["path"], "configuration plan binding differs")
    require(plan["plan_digest"] == desc["staging_plan"]["plan_digest"], "plan digest binding differs")
    require(type(desc["payloads"]) is list and len(desc["payloads"]) == 1, "descriptor requires one payload")
    payload = desc["payloads"][0]
    keys(payload, ("role", "path", "sha256", "size_bytes", "partition_size_bytes", "whole_partition_sha256"))
    require(type(payload["size_bytes"]) is int and type(payload["partition_size_bytes"]) is int, "payload sizes must be integers")
    require(payload == {"role": "release-filesystem", "path": fixed["payload_paths"]["release-filesystem"], "sha256": part["source_sha256"], "size_bytes": part["source_size_bytes"], "partition_size_bytes": part["capacity_bytes"], "whole_partition_sha256": part["expected_whole_partition_sha256"]}, "payload binding differs from the included plan")
    return desc


def verify_payload(payload):
    stream, before = open_regular(payload["path"], CAPACITY)
    source_hash, whole_hash = hashlib.sha256(), hashlib.sha256()
    with stream:
        require(before.st_size == payload["size_bytes"], "actual payload size differs")
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            source_hash.update(block)
            whole_hash.update(block)
        unchanged(stream, before)
    require("sha256:" + source_hash.hexdigest() == payload["sha256"], "actual source payload digest differs")
    remaining = payload["partition_size_bytes"] - payload["size_bytes"]
    zeros = bytes(1024 * 1024)
    while remaining:
        count = min(len(zeros), remaining)
        whole_hash.update(zeros[:count])
        remaining -= count
    require("sha256:" + whole_hash.hexdigest() == payload["whole_partition_sha256"], "complete padded partition digest differs")


def verify_inputs(desc, config_path, plan_path):
    require(str(config_path) == desc["configuration"]["path"] and str(plan_path) == desc["staging_plan"]["path"], "actual input paths differ")
    require(read_regular(config_path) == desc["configuration"]["json"].encode(), "actual configuration bytes differ")
    require(read_regular(plan_path) == desc["staging_plan"]["json"].encode(), "actual plan bytes differ")
    verify_payload(desc["payloads"][0])


def author(config_path, plan_path):
    config_data, plan_data = read_regular(config_path), read_regular(plan_path)
    fixed = configuration(config_data)
    plan, part = partition(plan_data)
    def record(path, data):
        return {"path": str(path), "sha256": digest(data), "size_bytes": len(data), "json": data.decode()}
    desc = {"schema_version": DESCRIPTOR_SCHEMA, "target_system": "aarch64-linux", "leg": "pi-local-nvme", "configuration": record(config_path, config_data), "staging_plan": dict(record(plan_path, plan_data), plan_digest=plan["plan_digest"]), "payloads": [{"role": "release-filesystem", "path": fixed["payload_paths"]["release-filesystem"], "sha256": part["source_sha256"], "size_bytes": part["source_size_bytes"], "partition_size_bytes": part["capacity_bytes"], "whole_partition_sha256": part["expected_whole_partition_sha256"]}], "hardware_qualified": False, "production_ready": False}
    data = encode(desc)
    validate(data)
    verify_inputs(desc, config_path, plan_path)
    return data


def component(data, binary_path, revision):
    desc = validate(data)
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "component source revision must be a full commit")
    binary = read_regular(binary_path, 64 * 1024 * 1024)
    require(binary[:7] == b"\x7fELF\x02\x01\x01" and binary[18:20] == b"\xb7\x00", "component must be AArch64 ELF64 little-endian")
    require(desc["configuration"]["path"].encode() in binary, "binary lacks the fixed configuration binding")
    return {"schema_version": COMPONENT_SCHEMA, "source_revision": revision, "descriptor_sha256": digest(data), "configuration_path": desc["configuration"]["path"], "configuration_sha256": desc["configuration"]["sha256"], "target_system": "aarch64-linux", "leg": "pi-local-nvme", "binary": {"path": BINARY, "sha256": digest(binary), "size_bytes": len(binary)}, "complete_runtime_closure": False, "hardware_qualified": False, "production_ready": False}


def verify_component(data, directory, revision):
    directory = Path(directory)
    actual = set()
    for root, dirs, files in os.walk(directory, followlinks=False):
        for name in dirs:
            path = Path(root) / name
            require(not path.is_symlink() and path.relative_to(directory).as_posix() in ("bin", "share", "share/kaiba"), "unexpected component directory")
        for name in files:
            actual.add((Path(root) / name).relative_to(directory).as_posix())
    require(actual == COMPONENT_FILES, "component file set differs")
    require(read_regular(directory / "share/kaiba/descriptor.json") == data, "component descriptor bytes differ")
    expected = component(data, directory / BINARY, revision)
    require(read_regular(directory / "share/kaiba/component.json") == encode(expected), "component manifest differs from actual bytes and selected source")


def validate_plan_contract(desc, validator):
    # Nix supplies the fixed same-platform production parser. Stdin is bounded
    # public data; the checker has no path or hardware interface.
    require(os.path.isabs(str(validator)), "plan validator path must be absolute")
    result = subprocess.run([str(validator)], input=desc["staging_plan"]["json"].encode(), capture_output=True, timeout=30, check=False)
    require(result.returncode == 0, "production Go staging-plan validation failed")
    report = parse(result.stdout)
    require(report == {"status": "valid", "plan_digest": desc["staging_plan"]["plan_digest"], "destructive_staging_ready": False}, "production staging-plan report differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    author_parser = sub.add_parser("author")
    author_parser.add_argument("--configuration", required=True, type=Path)
    author_parser.add_argument("--staging-plan", required=True, type=Path)
    author_parser.add_argument("--plan-validator", required=True, type=Path)
    for name in ("validate", "verify-inputs", "component", "verify-component"):
        p = sub.add_parser(name)
        p.add_argument("--descriptor", required=True, type=Path)
        p.add_argument("--plan-validator", required=True, type=Path)
        if name == "verify-inputs":
            p.add_argument("--configuration", required=True, type=Path)
            p.add_argument("--staging-plan", required=True, type=Path)
        if name in ("component", "verify-component"):
            p.add_argument("--source-revision", required=True)
            p.add_argument("--binary" if name == "component" else "--directory", required=True, type=Path)
    args = parser.parse_args()
    if args.operation == "author":
        data = author(args.configuration, args.staging_plan)
        validate_plan_contract(validate(data), args.plan_validator)
        sys.stdout.buffer.write(data)
        return
    data = read_regular(args.descriptor)
    desc = validate(data)
    validate_plan_contract(desc, args.plan_validator)
    if args.operation == "verify-inputs":
        verify_inputs(desc, args.configuration, args.staging_plan)
    elif args.operation == "component":
        sys.stdout.buffer.write(encode(component(data, args.binary, args.source_revision)))
        return
    elif args.operation == "verify-component":
        verify_component(data, args.directory, args.source_revision)
    sys.stdout.buffer.write(encode({"status": "valid", "descriptor_sha256": digest(data), "hardware_qualified": False, "production_ready": False}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print("staging inputs: " + str(exc), file=sys.stderr)
        sys.exit(1)
