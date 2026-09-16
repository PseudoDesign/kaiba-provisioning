#!/usr/bin/env python3
"""Export one incomplete native ARM staging component; never operate on media."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys


sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "release_candidate", Path(__file__).with_name("release_candidate.py")
)
candidate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(candidate)

SYSTEM = "aarch64-linux"
DESCRIPTOR_SCHEMA = "kaiba.provisioning.rpi5-stable-campaign-staging-descriptor/v1alpha1"
COMPONENT_SCHEMA = "kaiba.provisioning.rpi5-stable-campaign-staging-native-component/v1alpha1"
DESCRIPTOR_LIMIT = 4 * 1024 * 1024
BINARY_LIMIT = 32 * 1024 * 1024
CLOSURE_LIMIT = 64 * 1024 * 1024
STORE_PATH = r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+"
FILES = {
    "bin/kaiba-rpi5-stable-campaign-stage",
    "share/kaiba/component.json",
    "share/kaiba/descriptor.json",
}
DIRECTORIES = {"bin", "share", "share/kaiba"}


def exact_keys(value, keys, description):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"{description} must have its exact closed fields")


def require_digest(value):
    if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise ValueError("digest must be canonical SHA-256")


def require_store_path(value):
    if (not isinstance(value, str) or len(value) > 4096
            or re.fullmatch(STORE_PATH + r"(?:/[A-Za-z0-9+._?=-]+)*", value) is None):
        raise ValueError("descriptor paths must be canonical immutable store paths")
    if any(part in (".", "..") for part in value.split("/")):
        raise ValueError("descriptor paths must not contain traversal")
    return "/".join(value.split("/")[:4])


def require_public_strings(value):
    if isinstance(value, dict):
        for key, item in value.items():
            require_public_strings(key)
            require_public_strings(item)
    elif isinstance(value, list):
        for item in value:
            require_public_strings(item)
    elif isinstance(value, str) and re.search(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", value):
        raise ValueError("private key material is forbidden in a public descriptor")


def validate_descriptor(encoded):
    if not 0 < len(encoded) <= DESCRIPTOR_LIMIT:
        raise ValueError("descriptor is empty or too large")
    if re.search(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", encoded):
        raise ValueError("private key material is forbidden in a public descriptor")
    value = candidate.strict_json(encoded)
    require_public_strings(value)
    canonical = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
    if canonical != encoded:
        raise ValueError("descriptor must be canonical JSON with one LF")
    exact_keys(value, {
        "schema_version", "target_system", "leg", "configuration", "staging_plan",
        "payloads", "hardware_qualified", "production_ready",
    }, "staging descriptor")
    if (value["schema_version"] != DESCRIPTOR_SCHEMA or value["target_system"] != SYSTEM
            or value["leg"] != "pi-local-nvme" or value["hardware_qualified"] is not False
            or value["production_ready"] is not False):
        raise ValueError("descriptor must select the incomplete unqualified native NVMe component")
    for name, extra in (("configuration", set()), ("staging_plan", {"plan_digest"})):
        record = value[name]
        exact_keys(record, {"path", "sha256", "size_bytes", "json"} | extra, name)
        require_store_path(record["path"])
        require_digest(record["sha256"])
        if type(record["size_bytes"]) is not int or not 0 < record["size_bytes"] <= DESCRIPTOR_LIMIT:
            raise ValueError("embedded JSON size is invalid")
        if not isinstance(record["json"], str):
            raise ValueError("embedded JSON must preserve its exact bytes as a string")
        raw = record["json"].encode("utf-8")
        if (record["size_bytes"] != len(raw)
                or record["sha256"] != "sha256:" + hashlib.sha256(raw).hexdigest()):
            raise ValueError("embedded JSON digest or size differs")
        require_public_strings(candidate.strict_json(raw))
        if name == "staging_plan":
            require_digest(record["plan_digest"])
    payloads = value["payloads"]
    if not isinstance(payloads, list) or len(payloads) != 1:
        raise ValueError("NVMe descriptor requires exactly one release payload")
    payload = payloads[0]
    exact_keys(payload, {"role", "path", "sha256", "size_bytes", "partition_size_bytes",
                         "whole_partition_sha256"}, "release payload")
    require_store_path(payload["path"])
    for field in ("sha256", "whole_partition_sha256"):
        require_digest(payload[field])
    if (payload["role"] != "release-filesystem" or type(payload["size_bytes"]) is not int
            or type(payload["partition_size_bytes"]) is not int
            or payload["partition_size_bytes"] != 8589934592
            or not 0 < payload["size_bytes"] <= payload["partition_size_bytes"]):
        raise ValueError("descriptor payload role or geometry differs")
    # The constructor's descriptor helper additionally checks configuration,
    # plan and payload cross-bindings. The staging runtime remains the authority
    # for the complete typed staging contract before any device operation.
    return value


def committed_descriptor(repository, source_sha, relative):
    if (not isinstance(relative, str) or len(relative) > 255
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*\.json", relative) is None):
        raise ValueError("descriptor must be a canonical relative JSON file in the selected commit")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC
    descriptor = os.open(repository, flags)
    path = repository / relative
    try:
        for part in relative.split("/")[:-1]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        encoded = candidate.read_plain_file(path, DESCRIPTOR_LIMIT, directory_fd=descriptor)
    finally:
        os.close(descriptor)
    value = validate_descriptor(encoded)
    tree = candidate.run("git", "ls-tree", "-z", source_sha, "--", relative, cwd=repository)
    match = re.fullmatch(r"100644 blob ([0-9a-f]{40})\t" + re.escape(relative) + "\x00", tree)
    if match is None:
        raise ValueError("descriptor must be one non-executable regular committed blob")
    blob = match[1]
    if candidate.run("git", "cat-file", "-s", blob, cwd=repository) != str(len(encoded)):
        raise ValueError("descriptor size differs from the selected Git blob")
    committed = candidate.subprocess.check_output(["git", "cat-file", "blob", blob], cwd=repository)
    if committed != encoded:
        raise ValueError("descriptor bytes differ from the selected Git blob")
    return value, encoded, {"source_file": relative, "git_blob": blob,
                            "sha256": hashlib.sha256(encoded).hexdigest(), "size_bytes": len(encoded)}


def expression(flake, relative, revision):
    quote = candidate.nix_string
    return (
        f"let f = builtins.getFlake {quote(flake)}; "
        "component = f.lib.mkRpi5StableCampaignStagingNativeComponent { "
        f'system = "{SYSTEM}"; descriptor = f.outPath + {quote("/" + relative)}; '
        f"sourceRevision = {quote(revision)}; }}; "
        f"in assert f.rev == {quote(revision)}; "
        f'assert builtins.currentSystem == "{SYSTEM}"; '
        f'assert component.system == "{SYSTEM}"; component'
    )


def validate_component(directory, descriptor, encoded, revision):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("component output must be a plain directory")
    actual_files, actual_directories = set(), set()
    for path in directory.rglob("*"):
        mode = path.lstat().st_mode
        relative = path.relative_to(directory).as_posix()
        if stat.S_ISDIR(mode):
            actual_directories.add(relative)
        elif stat.S_ISREG(mode):
            actual_files.add(relative)
        else:
            raise ValueError("component output contains a symbolic or special file")
    if actual_files != FILES or actual_directories != DIRECTORIES:
        raise ValueError("component output has an unexpected file set")
    reader = lambda name, limit: candidate.read_plain_file(directory / name, limit, single_link=False)
    if reader("share/kaiba/descriptor.json", DESCRIPTOR_LIMIT) != encoded:
        raise ValueError("component retained a different descriptor")
    manifest = candidate.strict_json(reader("share/kaiba/component.json", 65536))
    exact_keys(manifest, {
        "schema_version", "source_revision", "descriptor_sha256", "configuration_path",
        "configuration_sha256", "target_system", "leg", "binary", "complete_runtime_closure",
        "hardware_qualified", "production_ready",
    }, "native component manifest")
    if (manifest["schema_version"] != COMPONENT_SCHEMA or manifest["source_revision"] != revision
            or manifest["descriptor_sha256"] != "sha256:" + hashlib.sha256(encoded).hexdigest()
            or manifest["configuration_path"] != descriptor["configuration"]["path"]
            or manifest["configuration_sha256"] != descriptor["configuration"]["sha256"]
            or manifest["target_system"] != SYSTEM or manifest["leg"] != "pi-local-nvme"
            or any(manifest[key] is not False for key in (
                "complete_runtime_closure", "hardware_qualified", "production_ready"))):
        raise ValueError("component source, configuration or incomplete status differs")
    binary = reader("bin/kaiba-rpi5-stable-campaign-stage", BINARY_LIMIT)
    # Read bytes only: the exported component is not invoked on the runner.
    if (len(binary) < 64 or binary[:7] != b"\x7fELF\x02\x01\x01"
            or int.from_bytes(binary[18:20], "little") != 183):
        raise ValueError("component binary is not native little-endian ELF64 AArch64")
    if descriptor["configuration"]["path"].encode() not in binary:
        raise ValueError("component binary lacks the fixed configuration binding")
    if manifest["binary"] != {"path": "bin/kaiba-rpi5-stable-campaign-stage",
                              "sha256": "sha256:" + hashlib.sha256(binary).hexdigest(),
                              "size_bytes": len(binary)}:
        raise ValueError("component binary digest or size differs")
    return manifest


def closure_metadata(paths, descriptor):
    if not paths or len(paths) > 32 or paths != sorted(set(paths)):
        raise ValueError("component closure must be a bounded sorted path set")
    for path in paths:
        if re.fullmatch(STORE_PATH, path) is None:
            raise ValueError("component closure contains a non-store path")
    excluded = {require_store_path(descriptor["staging_plan"]["path"]),
                *(require_store_path(p["path"]) for p in descriptor["payloads"])}
    if excluded.intersection(paths):
        raise ValueError("incomplete component closure unexpectedly includes the plan or payload")
    metadata = candidate.path_metadata(paths)
    total = 0
    records = {}
    for path in paths:
        record = metadata[path]
        size, references = record.get("narSize"), record.get("references")
        if (type(size) is not int or not 0 < size <= CLOSURE_LIMIT
                or not isinstance(references, list) or not all(isinstance(p, str) for p in references)
                or len(references) != len(set(references)) or not set(references).issubset(paths)
                or not re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", record["narHash"])):
            raise ValueError("component closure metadata is incomplete or exceeds its bounds")
        total += size
        records[path] = {"nar_hash": record["narHash"], "nar_size": size,
                         "references": sorted(references)}
    if total > CLOSURE_LIMIT:
        raise ValueError("component export must not carry a media-sized closure")
    return records


def build(args):
    repository = args.repository.resolve()
    candidate.require_clean_checkout(repository, args.source_sha)
    candidate.require_sha(args.main_sha)
    candidate.require_sha(args.workflow_sha)
    descriptor, encoded, record = committed_descriptor(repository, args.source_sha, args.descriptor)
    candidate.require_native_system(SYSTEM)
    epoch = candidate.source_epoch(repository, args.source_sha)
    output = args.output.resolve()
    if output.is_relative_to(repository):
        raise ValueError("artifact output must be outside the candidate checkout")
    output.mkdir(parents=True, exist_ok=False)
    flake = f"git+{repository.as_uri()}?rev={args.source_sha}"
    result = candidate.strict_json(candidate.run(
        "nix", "--accept-flake-config", "build", "--no-update-lock-file", "--no-write-lock-file",
        "--no-link", "--json", "-L", "--impure", "--expr", expression(flake, args.descriptor, args.source_sha),
    ))
    if (not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict)
            or not isinstance(result[0].get("outputs"), dict) or set(result[0]["outputs"]) != {"out"}):
        raise ValueError("native component must have exactly one output")
    selected = result[0]["outputs"]["out"]
    if not isinstance(selected, str) or re.fullmatch(STORE_PATH, selected) is None:
        raise ValueError("native component output is not an immutable store object")
    manifest = validate_component(Path(selected), descriptor, encoded, args.source_sha)
    paths = sorted(set(candidate.run("nix-store", "--query", "--requisites", selected).splitlines()))
    if selected not in paths:
        raise ValueError("closure omitted the selected native component")
    metadata = closure_metadata(paths, descriptor)
    archive = output / "nix-store-export.gz"
    if candidate.export_closure([selected], archive) != paths:
        raise ValueError("component closure changed during export")
    if closure_metadata(paths, descriptor) != metadata:
        raise ValueError("component closure metadata changed during export")
    candidate.require_clean_checkout(repository, args.source_sha)
    if committed_descriptor(repository, args.source_sha, args.descriptor) != (descriptor, encoded, record):
        raise ValueError("descriptor changed during export")
    (output / "descriptor.json").write_bytes(encoded)
    (output / "component.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    provenance = {
        "profile": "incomplete-native-staging-component",
        "source_revision": args.source_sha, "source_date_epoch": epoch,
        "main_revision_at_dispatch": args.main_sha, "workflow_revision": args.workflow_sha,
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "nix_version": candidate.run("nix", "--version"), "system": SYSTEM,
        "native_runner_verified": True, "descriptor": record,
        "output": {"attribute": "lib.mkRpi5StableCampaignStagingNativeComponent",
                   "path": selected, **metadata[selected]},
        "exported_store_paths": paths, "exported_store_path_metadata": metadata,
        "archive": {"file": archive.name, "sha256": candidate.file_sha256(archive),
                    "size_bytes": archive.stat().st_size},
        "export_contains_complete_component_closure": True,
        "complete_staging_runtime_closure": False, "payloads_exported": False,
        "component_executed": False, "signing_performed": False,
        "hardware_observed": False, "production_ready": False,
    }
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    summary = (
        f"Incomplete native ARM staging component from `{args.source_sha}`.\n\n"
        f"Workflow revision: `{args.workflow_sha}`.\n\n"
        f"Component: `{selected}`; NAR `{metadata[selected]['nar_hash']}`.\n\n"
        f"Archive SHA-256: `{provenance['archive']['sha256']}`.\n\n"
        "This archive contains the component's complete Nix closure, but is intentionally "
        "**not a complete staging runtime**. The locally verified plan and actual payload "
        "closure must be assembled separately. No component execution, signing, device "
        "access, recovery capture, staging approval or hardware qualification occurred.\n"
    )
    (output / "SUMMARY.md").write_text(summary)
    checksums = "".join(f"{candidate.file_sha256(path)}  {path.name}\n"
                        for path in sorted(output.iterdir()) if path.is_file())
    (output / "SHA256SUMS").write_text(checksums)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("select-source", "build"):
        command = commands.add_parser(name)
        command.add_argument("--repository", type=Path, required=True)
        command.add_argument("--source-sha", required=True)
        command.add_argument("--main-sha", required=True)
        if name == "select-source":
            command.add_argument("--workflow-ref", required=True)
        else:
            command.add_argument("--workflow-sha", required=True)
            command.add_argument("--descriptor", required=True)
            command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "select-source":
        print("source_sha=" + candidate.select_source(
            args.repository, args.source_sha, args.main_sha, args.workflow_ref))
    else:
        build(args)


if __name__ == "__main__":
    main()
