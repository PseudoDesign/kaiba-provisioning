#!/usr/bin/env python3
"""Prepare public Nix outputs for one main-history commit; never invoke a signer."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


OUTPUTS = {
    "aarch64-linux": {
        "unsigned": "kaiba-rpi5-stable-campaign-provisioner-unsigned",
        "signing-plan": "kaiba-rpi5-stable-campaign-provisioner-signing-plan",
    },
    "x86_64-linux": {
        "signing-runtime": "kaiba-rpi5-stable-campaign-development-signing",
    },
}


def run(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def require_sha(value):
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("source and workflow revisions must be full lowercase 40-hex commit SHAs")
    return value


def select_source(repository, source_sha, main_sha, workflow_ref):
    require_sha(source_sha)
    require_sha(main_sha)
    if workflow_ref != "refs/heads/main":
        raise ValueError("dispatch the release candidate workflow from main")
    for sha in (source_sha, main_sha):
        if run("git", "cat-file", "-t", sha, cwd=repository) != "commit":
            raise ValueError("candidate and main SHAs must name commit objects")
    if run("git", "rev-parse", "HEAD", cwd=repository) != main_sha:
        raise ValueError("workflow checkout does not match main at dispatch")
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", source_sha, main_sha],
        cwd=repository,
        check=True,
    )
    return source_sha


def require_clean_checkout(repository, source_sha):
    require_sha(source_sha)
    if run("git", "rev-parse", "HEAD", cwd=repository) != source_sha:
        raise ValueError("candidate checkout does not match the selected source SHA")
    if run("git", "status", "--porcelain", "--untracked-files=all", cwd=repository):
        raise ValueError("candidate checkout must be clean")


def file_sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_public_lineage(unsigned, plan, source_sha):
    manifest_bytes = (unsigned / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    intent = json.loads((plan / "release-intent.json").read_bytes())
    if manifest["source_revision"] != source_sha or intent["source_revision"] != source_sha:
        raise ValueError("built public inputs claim a different source revision")
    if intent["unsigned_manifest_digest"] != "sha256:" + hashlib.sha256(manifest_bytes).hexdigest():
        raise ValueError("signing intent does not bind the exported unsigned manifest")
    if intent["unsigned_artifact_set_digest"] != manifest["bundle_digest"]:
        raise ValueError("signing intent does not bind the exported unsigned artifact set")


def path_metadata(paths):
    records = json.loads(run("nix", "path-info", "--json", "--json-format", "1", *paths))
    # Nix versions expose either an array of path records or a path-keyed object.
    if isinstance(records, list):
        records = {record["path"]: record for record in records}
    if set(records) != set(paths) or any(not record.get("narHash") for record in records.values()):
        raise ValueError("Nix did not return a NAR hash for every requested output")
    return records


def export_closure(paths, destination):
    closure = sorted(set(run("nix-store", "--query", "--requisites", *paths).splitlines()))
    if not set(paths).issubset(closure):
        raise ValueError("Nix closure is missing a selected output")
    with subprocess.Popen(["nix-store", "--export", *closure], stdout=subprocess.PIPE) as process:
        with destination.open("xb") as stream:
            with gzip.GzipFile(filename="", fileobj=stream, mode="wb", compresslevel=1, mtime=0) as archive:
                shutil.copyfileobj(process.stdout, archive)
        if process.wait() != 0:
            raise RuntimeError("Nix store export failed")
    return closure


def build(args):
    repository = args.repository.resolve()
    require_clean_checkout(repository, args.source_sha)
    require_sha(args.main_sha)
    require_sha(args.workflow_sha)
    output = args.output.resolve()
    if output.is_relative_to(repository):
        raise ValueError("artifact output must be outside the candidate checkout")
    output.mkdir(parents=True, exist_ok=False)
    flake = f"git+file:{repository}?rev={args.source_sha}"
    selected = {}
    for role, package in OUTPUTS[args.system].items():
        attribute = f"packages.{args.system}.{package}"
        result = json.loads(run(
            "nix", "--accept-flake-config", "build", "--no-write-lock-file",
            "--no-link", "--json", "-L", f"{flake}#{attribute}",
        ))
        if len(result) != 1 or set(result[0]["outputs"]) != {"out"}:
            raise ValueError("candidate package must have exactly one output")
        selected[role] = {"attribute": attribute, "path": result[0]["outputs"]["out"]}

    if args.system == "aarch64-linux":
        unsigned = Path(selected["unsigned"]["path"])
        plan = Path(selected["signing-plan"]["path"])
        validate_public_lineage(unsigned, plan, args.source_sha)
        shutil.copyfile(unsigned / "manifest.json", output / "unsigned-manifest.json")
        for name in ("plan.json", "release-intent.json", "public.pem"):
            shutil.copyfile(plan / name, output / name)

    paths = [record["path"] for record in selected.values()]
    metadata = path_metadata(paths)
    for record in selected.values():
        record["nar_hash"] = metadata[record["path"]]["narHash"]
    archive = output / "nix-store-export.gz"
    closure = export_closure(paths, archive)
    require_clean_checkout(repository, args.source_sha)
    provenance = {
        "source_revision": args.source_sha,
        "main_revision_at_dispatch": args.main_sha,
        "workflow_revision": args.workflow_sha,
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "nix_version": run("nix", "--version"),
        "system": args.system,
        "outputs": selected,
        "exported_store_paths": closure,
        "archive": {
            "file": archive.name,
            "sha256": file_sha256(archive),
            "size_bytes": archive.stat().st_size,
        },
        "signing_performed": False,
        "hardware_observed": False,
    }
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    summary = f"Candidate `{args.source_sha}` — `{args.system}`\n\n"
    summary += f"Workflow revision: `{args.workflow_sha}`.\n\n"
    for role, record in selected.items():
        summary += f"- {role}: `{record['path']}` (NAR `{record['nar_hash']}`)\n"
    summary += f"\nExport SHA-256: `{provenance['archive']['sha256']}`.\n\n"
    summary += "The archive includes the selected outputs and their complete Nix runtime closures. "
    summary += "This is build provenance; signing approval, CI qualification, and hardware evidence remain separate.\n"
    (output / "SUMMARY.md").write_text(summary)
    checksums = "".join(
        f"{provenance['archive']['sha256'] if path == archive else file_sha256(path)}  {path.name}\n"
        for path in sorted(output.iterdir())
    )
    (output / "SHA256SUMS").write_text(checksums)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("select-source", "build"):
        subparser = commands.add_parser(command)
        subparser.add_argument("--repository", type=Path, required=True)
        subparser.add_argument("--source-sha", required=True)
        subparser.add_argument("--main-sha", required=True)
        if command == "select-source":
            subparser.add_argument("--workflow-ref", required=True)
        else:
            subparser.add_argument("--workflow-sha", required=True)
            subparser.add_argument("--system", choices=OUTPUTS, required=True)
            subparser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "select-source":
        print("source_sha=" + select_source(args.repository, args.source_sha, args.main_sha, args.workflow_ref))
    else:
        build(args)


if __name__ == "__main__":
    main()
