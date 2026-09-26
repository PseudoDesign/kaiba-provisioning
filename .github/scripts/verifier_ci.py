#!/usr/bin/env python3
"""Select expensive ARM64 checks by their complete Nix build inputs."""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SYSTEM = "aarch64-linux"
VERIFIER_CHECKS = (
    "stable-verifier-rpi5-hardware-eval",
    "stable-verifier-rpi5-file-live-fdt-hardware-eval",
)
HEAVY_CHECKS = (
    "stable-verifier-aarch64-kexec-vm",
    "stable-handoff-aarch64-kexec-file-vm",
    "device-secret-target-luks-vm",
    "device-secret-storage-development-vm",
    "enrollment-storage-vm",
    "copied-storage-vm",
    "device-secret-offline-storage-vm",
    "device-secret-execution-vm",
    "stable-campaign-provisioner-unsigned-artifacts",
    "device-secret-target-artifacts",
)
SELECTIVE_CHECKS = VERIFIER_CHECKS + HEAVY_CHECKS
NIX = ["nix", "--accept-flake-config"]


def identities(repository):
    fields = " ".join(f'"{name}" = checks."{name}".drvPath;' for name in SELECTIVE_CHECKS)
    result = subprocess.check_output(
        NIX + ["eval", "--json", "--no-write-lock-file",
               f"{repository}#checks.{SYSTEM}", "--apply", f"checks: {{ {fields} }}"],
        text=True,
    )
    value = json.loads(result)
    validate_identities(value)
    return value


def validate_identities(value):
    if not isinstance(value, dict) or set(value) != set(SELECTIVE_CHECKS):
        raise ValueError("selective ARM check names changed; review CI selection")
    if any(not isinstance(path, str) or re.fullmatch(
        r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+\.drv", path
    ) is None for path in value.values()):
        raise ValueError("invalid ARM derivation identity")


def changed_checks(before, after):
    validate_identities(before)
    validate_identities(after)
    return [name for name in SELECTIVE_CHECKS if before[name] != after[name]]


def plan(repository, event_name, base_sha=None):
    if event_name not in {"pull_request", "push", "workflow_dispatch"}:
        raise ValueError("unsupported CI event")
    after = identities(repository)
    if event_name != "pull_request":
        return {"checks": list(SELECTIVE_CHECKS), "before": None, "after": after}
    if not isinstance(base_sha, str) or re.fullmatch(r"[0-9a-f]{40}", base_sha) is None:
        raise ValueError("pull request base commit is required")
    # A real checkout preserves revision-dependent inputs. This evaluates
    # derivations on the x86 runner without building the ARM images.
    with tempfile.TemporaryDirectory(prefix="kaiba-verifier-ci-") as temporary:
        base = Path(temporary) / "base"
        subprocess.run(
            ["git", "-C", str(repository), "worktree", "add", "--detach", str(base), base_sha],
            check=True,
        )
        try:
            before = identities(base)
        finally:
            subprocess.run(
                ["git", "-C", str(repository), "worktree", "remove", "--force", str(base)],
                check=True,
            )
    return {"checks": changed_checks(before, after), "before": before, "after": after}


def ordinary_checks(names):
    if (not isinstance(names, list) or len(names) != len(set(names))
            or any(not isinstance(name, str) or re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) is None
                   for name in names)
            or not set(SELECTIVE_CHECKS).issubset(names)):
        raise ValueError("unexpected ARM check set; review CI partition")
    return [name for name in names if name not in SELECTIVE_CHECKS]


def build_ordinary(repository):
    if platform.machine() != "aarch64":
        raise ValueError("ARM checks must run on a native ARM runner")
    # Keep flake-wide validation and automatically include every other check,
    # including new checks, rather than maintaining an ordinary-check allowlist.
    # Selective VM/image checks are built only in their individual matrix jobs.
    subprocess.run(NIX + ["flake", "check", "--no-build"], cwd=repository, check=True)
    names = json.loads(subprocess.check_output(
        NIX + ["eval", "--json", f"{repository}#checks.{SYSTEM}",
               "--apply", "builtins.attrNames"], text=True,
    ))
    checks = ordinary_checks(names)
    subprocess.run(
        NIX + ["build", "-L", "--no-link"]
        + [f"{repository}#checks.{SYSTEM}.{name}" for name in checks], check=True,
    )


def require_results(environment):
    for name in ("CORE_RESULT", "ARM_RESULT", "DEVELOPMENT_RESULT", "PLAN_RESULT"):
        if environment.get(name) != "success":
            raise ValueError(f"{name} must succeed, got {environment.get(name)!r}")
    for lane in ("VERIFIER", "HEAVY"):
        required = environment.get(lane + "_REQUIRED")
        result = environment.get(lane + "_RESULT")
        if required not in {"true", "false"} or result != (
            "success" if required == "true" else "skipped"
        ):
            raise ValueError(f"unexpected {lane} result: required={required!r}, result={result!r}")


def write_plan(result, output, summary):
    selected = result["checks"]
    if len(selected) != len(set(selected)) or not set(selected).issubset(SELECTIVE_CHECKS):
        raise ValueError("unexpected selected checks")
    for prefix, checks in (("", VERIFIER_CHECKS), ("heavy_", HEAVY_CHECKS)):
        group = [name for name in checks if name in selected]
        output.write(f"{prefix}required={str(bool(group)).lower()}\n")
        output.write(prefix + "checks=" + json.dumps(group) + "\n")
    summary.write("### Expensive ARM64 check selection\n\n")
    summary.write("Selected checks run in individually named native ARM jobs. "
                  "Main and manual runs retain full coverage.\n\n")
    summary.write("| Check | Decision | Base derivation | Current derivation |\n")
    summary.write("| --- | --- | --- | --- |\n")
    for name in SELECTIVE_CHECKS:
        before = (result["before"] or {}).get(name, "full run")
        after = result["after"][name]
        decision = "run" if name in selected else "skip: identical inputs"
        summary.write(f"| `{name}` | {decision} | `{before}` | `{after}` |\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["plan", "build-ordinary", "require-results"])
    args = parser.parse_args()
    if args.command == "build-ordinary":
        build_ordinary(ROOT)
    elif args.command == "require-results":
        require_results(os.environ)
    else:
        event_name = os.environ["GITHUB_EVENT_NAME"]
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        base = event.get("pull_request", {}).get("base", {}).get("sha")
        result = plan(ROOT, event_name, base)
        print(json.dumps(result, indent=2))
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output, Path(
            os.environ["GITHUB_STEP_SUMMARY"]
        ).open("a") as summary:
            write_plan(result, output, summary)


if __name__ == "__main__":
    main()
