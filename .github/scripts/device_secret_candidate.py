#!/usr/bin/env python3
"""Build/export a public, unsigned device-secret experiment on native ARM."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "release_candidate", Path(__file__).with_name("release_candidate.py"))
candidate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(candidate)

SYSTEM = "aarch64-linux"
STORE = r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+"
LIMIT = 8192
KEYS = {"schema_version", "scheme", "experiment_id", "target_reference", "source_revision",
        "volume_uuid", "partition_uuid", "board_serial_sha256", "disk_serial_sha256",
        "nonce_hex", "slot_id", "expected_usage"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def validate_config(raw, revision, expected_digest):
    candidate.require_sha(revision)
    require(0 < len(raw) <= LIMIT, "experiment must be bounded public JSON")
    require(isinstance(expected_digest, str) and re.fullmatch(r"[0-9a-f]{64}", expected_digest),
            "experiment digest must be SHA-256 of the exact supplied bytes")
    require(hashlib.sha256(raw).hexdigest() == expected_digest, "experiment digest mismatch")
    value = candidate.strict_json(raw)
    require(isinstance(value, dict) and set(value) == KEYS, "experiment must have its exact fields")
    require(value["schema_version"] == "kaiba.device-secret-target/v1alpha1" and
            value["scheme"] == "kaiba-firmware-hmac-counter-v1", "unsupported experiment")
    require(value["source_revision"] == revision, "experiment source differs from selected source")
    for name in ("experiment_id", "target_reference"):
        require(isinstance(value[name], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value[name]),
                "experiment identifiers must be bounded lowercase identifiers")
    for name in ("board_serial_sha256", "disk_serial_sha256", "nonce_hex"):
        require(isinstance(value[name], str) and re.fullmatch(r"[0-9a-f]{64}", value[name]) and
                set(value[name]) != {"0"}, "invalid experiment digest or nonce")
    for name in ("volume_uuid", "partition_uuid"):
        require(isinstance(value[name], str) and re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value[name]) and
            set(value[name]) != {"0", "-"}, "invalid experiment UUID")
    require(value["volume_uuid"] != value["partition_uuid"], "volume and partition UUIDs must differ")
    require(type(value["slot_id"]) is int and value["slot_id"] == 1 and
            type(value["expected_usage"]) is int and value["expected_usage"] in (0, 8, 9, 10, 11, 12, 13, 14),
            "unsupported slot or usage")
    return value


def expression(flake, revision, epoch, config, *, paths=False):
    quote = candidate.nix_string
    ending = "builtins.mapAttrs (_: value: toString value) outputs" if paths else "builtins.attrValues outputs"
    return (
        f"let f = builtins.getFlake {quote(flake)}; "
        "reviewedSigner = builtins.fromJSON (builtins.readFile "
        '(f.outPath + "/signers/development-prototype/independent-review-2026-08-27.json")); '
        "c = f.lib.mkRpi5DeviceSecretExperiment { "
        f"experiment = builtins.fromJSON {quote(encoded(config).decode())}; "
        f"sourceRevision = {quote(revision)}; "
        "expectedCustomerKeyHash = builtins.substring 7 64 reviewedSigner.public_bindings.customer_key_hash; }; "
        's = f.lib.mkRpi5DeviceSecretSigningPlan { system = "aarch64-linux"; candidate = c; '
        f"sourceDateEpoch = {epoch}; }}; "
        "outputs = { unsigned = c.unsignedArtifacts; signing_plan = s; signing_input = s.input; "
        "review = s.kaibaNativeOffline.review; "
        "checked_config = c.nixosSystem.config.system.build.kaibaDeviceSecretExperimentConfig; }; "
        f"in assert f.rev == {quote(revision)}; "
        'assert builtins.currentSystem == "aarch64-linux"; '
        'assert c.unsignedArtifacts.system == "aarch64-linux"; '
        'assert s.system == "aarch64-linux"; ' + ending
    )


def validate_outputs(outputs, config, revision, epoch):
    require(set(outputs) == {"unsigned", "signing_plan", "signing_input", "review", "checked_config"},
            "unexpected build outputs")
    require(all(isinstance(p, str) and re.fullmatch(STORE, p) for p in outputs.values()),
            "outputs must be immutable store paths")
    paths = {key: Path(value) for key, value in outputs.items()}
    read = lambda root, name: candidate.read_plain_file(paths[root] / name, 65536, single_link=False)
    load = lambda root, name: candidate.strict_json(read(root, name))
    require(load("checked_config", "experiment.json") == config and
            read("checked_config", "experiment.json") == read("review", "experiment.json"),
            "checked experiment differs from requested bindings")
    review = load("review", "review.json")
    manifest = load("signing_input", "manifest.json")
    unsigned = load("unsigned", "manifest.json")
    intent = load("signing_plan", "release-intent.json")
    plan = load("signing_plan", "plan.json")
    digest = lambda raw: "sha256:" + hashlib.sha256(raw).hexdigest()
    require(review["device_secret_experiment_digest"] == digest(read("review", "experiment.json")) and
            review["device_secret_execution"] == "pending-separate-authority",
            "review must bind the checked experiment without execution authority")
    require(manifest["review_digest"] == digest(read("review", "review.json")) and
            manifest["unsigned_artifacts_digest"] == digest(read("unsigned", "manifest.json")) and
            intent["unsigned_manifest_digest"] == digest(read("signing_input", "manifest.json")),
            "signing input must bind the exact review and unsigned artifact manifest")
    require(all(record["source_revision"] == revision for record in (review, manifest, unsigned, intent)) and
            intent["source_date_epoch"] == plan["source_date_epoch"] == epoch, "source or epoch mismatch")
    require(intent["authorization_scope"] == "native_offline_boot" and
            intent["signing_input"]["role"] == "rpi5.boot_image", "wrong signing scope")
    require(review["signing_status"] == unsigned["signing_status"] == "unsigned" and
            review["hardware_observed"] is False and manifest["hardware_observed"] is False and
            review["fleet_admission"] == manifest["fleet_admission"] == "unevaluated",
            "build outputs must remain unsigned and unqualified")
    for role, name in (("boot_image", "unsigned/boot.img"), ("root_data", "nvme/root-data.img"),
                       ("root_hash_tree", "nvme/root-hash.img")):
        path = paths["unsigned"] / name
        require(path.is_file() and not path.is_symlink(), "artifact must be a regular file")
        observed = {"digest": "sha256:" + candidate.file_sha256(path), "size_bytes": path.stat().st_size}
        require(manifest[role] == observed and unsigned["artifacts"][role] == {
            "path": name, "digest": observed["digest"]}, "artifact bytes differ from manifest")
    boot = paths["signing_plan"] / "boot.img"
    require(boot.is_file() and not boot.is_symlink() and boot.stat().st_size == 96 * 1024 * 1024 and
            manifest["boot_image"] == {"digest": "sha256:" + candidate.file_sha256(boot),
                                      "size_bytes": boot.stat().st_size} and
            intent["signing_input"] == {"role": "rpi5.boot_image", **manifest["boot_image"]},
            "signing plan must carry the exact experiment image")


def build(args, raw, digest, *, rehearsal=False):
    repository = args.repository.resolve()
    candidate.require_clean_checkout(repository, args.source_sha)
    candidate.require_sha(args.main_sha)
    candidate.require_sha(args.workflow_sha)
    config = validate_config(raw, args.source_sha, digest)
    candidate.require_native_system(SYSTEM)
    epoch = candidate.source_epoch(repository, args.source_sha)
    output = args.output.resolve()
    require(not output.is_relative_to(repository), "export must be outside source checkout")
    output.mkdir(parents=True, exist_ok=False)
    flake = f"git+{repository.as_uri()}?rev={args.source_sha}"
    base = ("nix", "--accept-flake-config")
    flags = ("--no-update-lock-file", "--no-write-lock-file", "--impure", "--expr")
    outputs = candidate.strict_json(candidate.run(*base, "eval", "--json", *flags,
        expression(flake, args.source_sha, epoch, config, paths=True)))
    result = candidate.strict_json(candidate.run(*base, "build", "--no-link", "--json", "-L", *flags,
        expression(flake, args.source_sha, epoch, config)))
    realized = {path for record in result for path in record["outputs"].values()}
    require(realized == set(outputs.values()), "realized output selection differs from evaluated outputs")
    validate_outputs(outputs, config, args.source_sha, epoch)
    paths = sorted(set(candidate.run("nix-store", "--query", "--requisites", *outputs.values()).splitlines()))
    require(set(outputs.values()).issubset(paths) and
            all(re.fullmatch(STORE, p) for p in paths), "invalid export closure")
    metadata = candidate.path_metadata(paths)
    require(sum(record["narSize"] for record in metadata.values()) <= 8 * 1024**3,
            "export closure exceeds 8 GiB bound")
    archive = output / "nix-store-export.gz"
    require(candidate.export_closure(list(outputs.values()), archive) == paths, "closure changed during export")
    require(candidate.path_metadata(paths) == metadata, "store metadata changed during export")
    candidate.require_clean_checkout(repository, args.source_sha)
    # Retain both supplied bytes and the constructor's checked representation.
    (output / "submitted-experiment.json").write_bytes(raw)
    for role, name, destination in (("checked_config", "experiment.json", "experiment.json"),
                                  ("review", "review.json", "review.json"),
                                  ("unsigned", "manifest.json", "unsigned-manifest.json"),
                                  ("signing_input", "manifest.json", "signing-input.json"),
                                  ("signing_plan", "plan.json", "plan.json"),
                                  ("signing_plan", "release-intent.json", "release-intent.json"),
                                  ("signing_plan", "public.pem", "public.pem")):
        shutil.copyfile(Path(outputs[role]) / name, output / destination)
    provenance = {
        "profile": "device-secret-unsigned-experiment", "source_revision": args.source_sha,
        "source_date_epoch": epoch, "workflow_revision": args.workflow_sha,
        "main_revision_at_dispatch": None if rehearsal else args.main_sha,
        "purpose": "ci-rehearsal" if rehearsal else "selected-public-candidate",
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "system": SYSTEM, "native_runner_verified": True,
        "nix_version": candidate.run("nix", "--version"), "submitted_experiment_sha256": digest,
        "checked_experiment_sha256": candidate.file_sha256(output / "experiment.json"),
        "outputs": {role: {"path": path, "nar_hash": metadata[path]["narHash"]}
                    for role, path in outputs.items()},
        "exported_store_paths": paths,
        "exported_store_path_metadata": {p: {"nar_hash": metadata[p]["narHash"],
            "nar_size": metadata[p]["narSize"], "references": sorted(metadata[p]["references"])} for p in paths},
        "archive": {"file": archive.name, "sha256": candidate.file_sha256(archive),
                    "size_bytes": archive.stat().st_size},
        "signing_performed": False, "execution_authorized": False,
        "hardware_observed": False, "hardware_qualified": False, "fleet_admission": "unevaluated",
    }
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    (output / "SUMMARY.md").write_text(
        f"Unsigned device-secret experiment from `{args.source_sha}` on native ARM.\n\n"
        f"Purpose: `{provenance['purpose']}`. Input SHA-256: `{digest}`.\n\n"
        f"Archive SHA-256: `{provenance['archive']['sha256']}`.\n\n"
        "The archive retains the unsigned image/root/tree, checked configuration, review, signing plan "
        "and signing input with their Nix closures. Signing, slot/image review, staging, secret operations "
        "and physical qualification remain separate. No host selectors or execution grants are accepted.\n")
    (output / "SHA256SUMS").write_text("".join(
        f"{candidate.file_sha256(path)}  {path.name}\n" for path in sorted(output.iterdir()) if path.is_file()))


def rehearsal_config(revision):
    return {"schema_version": "kaiba.device-secret-target/v1alpha1", "scheme": "kaiba-firmware-hmac-counter-v1",
            "experiment_id": "ci-export-rehearsal", "target_reference": "synthetic-no-physical-target",
            "source_revision": revision, "volume_uuid": "11111111-1111-4111-8111-111111111111",
            "partition_uuid": "22222222-2222-4222-8222-222222222222", "board_serial_sha256": "b" * 64,
            "disk_serial_sha256": "c" * 64, "nonce_hex": "d" * 64, "slot_id": 1, "expected_usage": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("select-source", "build", "rehearse"):
        command = commands.add_parser(name)
        command.add_argument("--repository", type=Path, required=True)
        if name != "rehearse":
            command.add_argument("--source-sha", required=True)
            command.add_argument("--main-sha", required=True)
        if name == "select-source":
            command.add_argument("--workflow-ref", required=True)
        else:
            command.add_argument("--output", type=Path, required=True)
            if name == "build":
                command.add_argument("--workflow-sha", required=True)
    args = parser.parse_args()
    if args.command == "rehearse":
        args.source_sha = args.main_sha = args.workflow_sha = candidate.run(
            "git", "rev-parse", "HEAD", cwd=args.repository)
        raw = encoded(rehearsal_config(args.source_sha))
        build(args, raw, hashlib.sha256(raw).hexdigest(), rehearsal=True)
    else:
        raw = os.environ.get("EXPERIMENT_JSON", "").encode()
        digest = os.environ.get("EXPERIMENT_SHA256", "")
        validate_config(raw, args.source_sha, digest)
        if args.command == "select-source":
            print("source_sha=" + candidate.select_source(
                args.repository, args.source_sha, args.main_sha, args.workflow_ref))
        else:
            build(args, raw, digest)


if __name__ == "__main__":
    main()
