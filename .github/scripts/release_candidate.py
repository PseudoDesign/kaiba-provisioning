#!/usr/bin/env python3
"""Prepare public Nix outputs for one main-history commit; never invoke a signer."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
from urllib.parse import urlsplit


OUTPUTS = {
    "aarch64-linux": {
        "unsigned": "kaiba-rpi5-stable-campaign-provisioner-unsigned",
        "signing-plan": "kaiba-rpi5-stable-campaign-provisioner-signing-plan",
    },
    "x86_64-linux": {
        "signing-runtime": "kaiba-rpi5-stable-campaign-development-signing",
    },
}
PUBLIC_INPUT_LIMITS = {
    "candidate.json": 16 * 1024,
    "policy.json": 1024 * 1024,
    "root-public.pem": 16 * 1024,
    "authority-ca.pem": 64 * 1024,
}
CONFIG_SCHEMA = "kaiba.provisioning.rpi5-stable-verifier-candidate/v1alpha1"
CONFIG_IDS = ("cohort_id", "slot_id", "authority_key_id", "audience", "logical_identity")
CONFIG_INTS = ("verifier_version", "minimum_security_epoch")
CONFIG_KEYS = {"schema_version", "authority_url", *CONFIG_IDS, *CONFIG_INTS}


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


def require_native_system(system):
    machine = {"aarch64-linux": "aarch64", "x86_64-linux": "x86_64"}[system]
    if platform.system() != "Linux" or platform.machine() != machine:
        raise ValueError(f"{system} outputs require a native {machine} Linux runner")
    if run("nix", "eval", "--impure", "--raw", "--expr", "builtins.currentSystem") != system:
        raise ValueError("Nix system does not match the native candidate runner")


def source_epoch(repository, source_sha):
    value = run("git", "show", "-s", "--format=%ct", source_sha, cwd=repository)
    if not re.fullmatch(r"[1-9][0-9]*", value) or int(value) > 253402300799:
        raise ValueError("selected commit has an invalid source date epoch")
    return int(value)


def strict_json(encoded):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate JSON field: {key}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f"invalid JSON constant: {value}")

    return json.loads(encoded, object_pairs_hook=pairs, parse_constant=invalid_constant)


def validate_config(encoded):
    config = strict_json(encoded)
    if not isinstance(config, dict) or set(config) != CONFIG_KEYS or config["schema_version"] != CONFIG_SCHEMA:
        raise ValueError("candidate.json must use the closed verifier candidate schema")
    for key in CONFIG_INTS:
        if type(config[key]) is not int or not 1 <= config[key] <= 2147483647:
            raise ValueError(f"candidate {key} must be an integer between 1 and 2147483647")
    for key in CONFIG_IDS:
        if not isinstance(config[key], str) or not re.fullmatch(r"[a-z0-9][a-z0-9._:-]{0,127}", config[key]):
            raise ValueError(f"candidate {key} must be a canonical identifier")
    url = config["authority_url"]
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) <= 32 or ord(c) >= 127 for c in url):
        raise ValueError("candidate authority_url must be a bounded ASCII HTTPS URL")
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or parsed.port == 0
            or parsed.path not in ("", "/") or parsed.query):
        raise ValueError("candidate authority_url must be an HTTPS origin without credentials, query or fragment")
    return config


def read_plain_file(path, limit, *, single_link=True, directory_fd=None):
    target = path if directory_fd is None else path.name
    metadata = lambda: os.stat(target, dir_fd=directory_fd, follow_symlinks=False)
    before = metadata()
    if (not stat.S_ISREG(before.st_mode) or (single_link and before.st_nlink != 1)
            or not 0 < before.st_size <= limit):
        raise ValueError(f"{path.name} must be a bounded regular file with one link")
    descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if fields(before) != fields(opened):
            raise ValueError(f"{path.name} changed while opening")
        encoded = stream.read(limit + 1)
        if (len(encoded) != before.st_size or fields(opened) != fields(os.fstat(stream.fileno()))
                or fields(opened) != fields(metadata())):
            raise ValueError(f"{path.name} changed while reading")
    return encoded


def validate_public_inputs(repository, source_sha, relative):
    if (not isinstance(relative, str) or len(relative) > 255
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*", relative)):
        raise ValueError("public inputs must name a canonical relative directory inside the selected commit")
    directory = repository / relative
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC
    descriptor = os.open(repository, flags)
    payloads = {}
    try:
        for component in relative.split("/"):
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as error:
                raise ValueError("public input directory components must be plain directories") from error
            os.close(descriptor)
            descriptor = child
        if set(os.listdir(descriptor)) != set(PUBLIC_INPUT_LIMITS):
            raise ValueError("public input directory must contain exactly the four allowed files")
        for name, limit in PUBLIC_INPUT_LIMITS.items():
            payloads[name] = read_plain_file(directory / name, limit, directory_fd=descriptor)
        if set(os.listdir(descriptor)) != set(PUBLIC_INPUT_LIMITS):
            raise ValueError("public input directory changed while reading")
    finally:
        os.close(descriptor)
    records = {}
    for name in PUBLIC_INPUT_LIMITS:
        encoded = payloads[name]
        if re.search(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----", encoded):
            raise ValueError("private key material is forbidden in candidate public inputs")
        relative_file = relative + "/" + name
        tree = run("git", "ls-tree", "-z", source_sha, "--", relative_file, cwd=repository)
        match = re.fullmatch(r"100644 blob ([0-9a-f]{40})\t" + re.escape(relative_file) + "\x00", tree)
        if match is None:
            raise ValueError(f"{relative_file} must be one plain blob in the selected commit")
        blob = match[1]
        if run("git", "cat-file", "-s", blob, cwd=repository) != str(len(encoded)):
            raise ValueError(f"{relative_file} size differs from the selected commit")
        committed = subprocess.check_output(["git", "cat-file", "blob", blob], cwd=repository)
        if committed != encoded:
            raise ValueError(f"{relative_file} bytes differ from the selected commit")
        records[name] = {"sha256": hashlib.sha256(encoded).hexdigest(), "size_bytes": len(encoded), "git_blob": blob}
    config = validate_config(payloads["candidate.json"])
    return directory, config, records, payloads


def nix_string(value):
    # JSON quoting alone leaves Nix's ${...} interpolation active.
    return json.dumps(value, ensure_ascii=False).replace("${", "\\${")


def verifier_expression(flake, relative, revision, epoch, output):
    if output not in ("unsignedBoot", "signingPlan"):
        raise ValueError("unsupported verifier output")
    return (
        f"let f = builtins.getFlake {nix_string(flake)}; "
        "candidate = f.lib.mkRpi5StableVerifierCandidate { "
        f"publicInputs = f.outPath + {nix_string('/' + relative)}; "
        f"sourceRevision = {nix_string(revision)}; sourceDateEpoch = {epoch}; }}; "
        f"in assert f.rev == {nix_string(revision)}; "
        'assert builtins.currentSystem == "aarch64-linux"; '
        f'assert candidate.{output}.system == "aarch64-linux"; candidate.{output}'
    )


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


def validate_verifier_lineage(unsigned, plan, source_sha, epoch, flake):
    for directory, expected in (
        (unsigned, {"manifest.json", "boot.img"}),
        (plan, {"plan.json", "release-intent.json", "public.pem", "boot.img"}),
    ):
        if directory.is_symlink() or not directory.is_dir() or {p.name for p in directory.iterdir()} != expected:
            raise ValueError("verifier output does not have its closed file set")
        for name in expected:
            if not stat.S_ISREG((directory / name).lstat().st_mode):
                raise ValueError("verifier output contains a non-regular file")
    manifest_bytes = read_plain_file(unsigned / "manifest.json", 65536, single_link=False)
    manifest = strict_json(manifest_bytes)
    intent = strict_json(read_plain_file(plan / "release-intent.json", 65536, single_link=False))
    plan_json = strict_json(read_plain_file(plan / "plan.json", 65536, single_link=False))
    if any(not isinstance(value, dict) for value in (manifest, intent, plan_json)):
        raise ValueError("verifier manifest, intent and plan must be JSON objects")
    if (manifest.get("schema_version") != "kaiba.provisioning.rpi5-stable-verifier-boot-artifact/v1alpha1"
            or intent.get("schema_version") != "kaiba.provisioning.rpi5-stable-campaign-verifier-signing-intent/v1alpha1"
            or intent.get("authorization_scope") != "stable_campaign_verifier_boot"):
        raise ValueError("exported verifier has the wrong artifact or signing profile")
    if manifest.get("source_revision") != source_sha or intent.get("source_revision") != source_sha:
        raise ValueError("exported verifier source differs from the selected commit")
    if intent.get("source_date_epoch") != epoch or plan_json.get("source_date_epoch") != epoch:
        raise ValueError("exported verifier epoch differs from the selected commit")
    digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    if intent.get("unsigned_manifest_digest") != digest:
        raise ValueError("verifier intent does not bind the exact unsigned manifest")
    boot = unsigned / "boot.img"
    size = boot.stat().st_size
    if size != 96 * 1024 * 1024:
        raise ValueError("verifier candidate boot image must be exactly 96 MiB")
    boot_digest = "sha256:" + file_sha256(boot)
    if (manifest.get("boot_image") != {"path": "boot.img", "sha256": boot_digest, "size_bytes": size}
            or intent.get("signing_input") != {"role": "rpi5.boot_image", "digest": boot_digest, "size_bytes": size}
            or (plan / "boot.img").stat().st_size != size or file_sha256(plan / "boot.img") != boot_digest[7:]):
        raise ValueError("verifier plan, image and manifest do not bind the same bytes")
    reference = f"{flake}#packages.aarch64-linux.kaiba-rpi5-stable-verifier-signing"
    for arguments in (("validate-plan", "--plan", str(plan)),
                      ("validate-unsigned", "--plan", str(plan), "--manifest", str(unsigned / "manifest.json"))):
        result = strict_json(run("nix", "--accept-flake-config", "run", "--no-update-lock-file",
                                 "--no-write-lock-file", reference, "--", *arguments))
        if result.get("status") != "valid":
            raise ValueError("public verifier lineage validation did not pass")


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
    profile = getattr(args, "profile", "provisioner")
    relative = getattr(args, "public_inputs", "")
    if profile not in ("provisioner", "verifier"):
        raise ValueError("unsupported candidate profile")
    if profile == "provisioner" and relative:
        raise ValueError("the provisioner profile does not accept custom public inputs")
    inputs = None
    if profile == "verifier":
        inputs = validate_public_inputs(repository, args.source_sha, relative)
    epoch = source_epoch(repository, args.source_sha)
    require_native_system(args.system)
    output = args.output.resolve()
    if output.is_relative_to(repository):
        raise ValueError("artifact output must be outside the candidate checkout")
    output.mkdir(parents=True, exist_ok=False)
    flake = f"git+{repository.as_uri()}?rev={args.source_sha}"
    selected = {}
    packages = OUTPUTS[args.system]
    if profile == "verifier":
        packages = ({"unsigned": "unsignedBoot", "signing-plan": "signingPlan"}
                    if args.system == "aarch64-linux" else
                    {"signing-runtime": "kaiba-rpi5-stable-verifier-development-signing"})
    for role, package in packages.items():
        if profile == "verifier" and args.system == "aarch64-linux":
            attribute = f"lib.mkRpi5StableVerifierCandidate.{package}"
            selector = ("--impure", "--expr", verifier_expression(flake, relative, args.source_sha, epoch, package))
        else:
            attribute = f"packages.{args.system}.{package}"
            selector = (f"{flake}#{attribute}",)
        result = json.loads(run(
            "nix", "--accept-flake-config", "build", "--no-update-lock-file", "--no-write-lock-file",
            "--no-link", "--json", "-L", *selector,
        ))
        if len(result) != 1 or set(result[0]["outputs"]) != {"out"}:
            raise ValueError("candidate package must have exactly one output")
        selected[role] = {"attribute": attribute, "path": result[0]["outputs"]["out"]}

    if args.system == "aarch64-linux":
        unsigned = Path(selected["unsigned"]["path"])
        plan = Path(selected["signing-plan"]["path"])
        if profile == "verifier":
            validate_verifier_lineage(unsigned, plan, args.source_sha, epoch, flake)
        else:
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
    public_records = None
    if inputs is not None:
        directory, config, records, payloads = validate_public_inputs(repository, args.source_sha, relative)
        if config != inputs[1] or records != inputs[2]:
            raise ValueError("candidate public inputs changed during the build")
        public_output = output / "public-inputs"
        public_output.mkdir()
        for name in records:
            (public_output / name).write_bytes(payloads[name])
        public_records = {"source_directory": relative, "files": records, "configuration": config}
    provenance = {
        "profile": profile,
        "source_revision": args.source_sha,
        "source_date_epoch": epoch,
        "main_revision_at_dispatch": args.main_sha,
        "workflow_revision": args.workflow_sha,
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "nix_version": run("nix", "--version"),
        "system": args.system,
        "native_runner_verified": True,
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
    if public_records is not None:
        provenance["public_inputs"] = public_records
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    summary = f"Candidate `{args.source_sha}` — `{profile}` — `{args.system}`\n\n"
    summary += f"Workflow revision: `{args.workflow_sha}`.\n\n"
    for role, record in selected.items():
        summary += f"- {role}: `{record['path']}` (NAR `{record['nar_hash']}`)\n"
    summary += f"\nExport SHA-256: `{provenance['archive']['sha256']}`.\n\n"
    summary += "The archive includes the selected outputs and their complete Nix runtime closures. "
    summary += "This is build provenance; signing approval, CI qualification, and hardware evidence remain separate.\n"
    (output / "SUMMARY.md").write_text(summary)
    checksums = "".join(
        f"{provenance['archive']['sha256'] if path == archive else file_sha256(path)}  {path.relative_to(output).as_posix()}\n"
        for path in sorted(output.rglob("*")) if path.is_file()
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
            subparser.add_argument("--profile", choices=("provisioner", "verifier"), default="provisioner")
            subparser.add_argument("--public-inputs", default="", help="verifier-only relative directory in the selected commit")
            subparser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "select-source":
        print("source_sha=" + select_source(args.repository, args.source_sha, args.main_sha, args.workflow_ref))
    else:
        build(args)


if __name__ == "__main__":
    main()
