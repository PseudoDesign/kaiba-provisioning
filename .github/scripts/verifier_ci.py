#!/usr/bin/env python3
"""Select the older verifier image checks by their complete Nix build inputs."""

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
NIX = ["nix", "--accept-flake-config"]


def identities(repository):
    fields = " ".join(f'"{name}" = checks."{name}".drvPath;' for name in VERIFIER_CHECKS)
    result = subprocess.check_output(
        NIX + ["eval", "--json", "--no-write-lock-file",
               f"{repository}#checks.{SYSTEM}", "--apply", f"checks: {{ {fields} }}"],
        text=True,
    )
    value = json.loads(result)
    validate_identities(value)
    return value


def validate_identities(value):
    if not isinstance(value, dict) or set(value) != set(VERIFIER_CHECKS):
        raise ValueError("verifier check names changed; review CI selection")
    if any(not isinstance(path, str) or re.fullmatch(
        r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+\.drv", path
    ) is None for path in value.values()):
        raise ValueError("invalid verifier derivation identity")


def changed_checks(before, after):
    validate_identities(before)
    validate_identities(after)
    return [name for name in VERIFIER_CHECKS if before[name] != after[name]]


def plan(repository, event_name, base_sha=None):
    if event_name not in {"pull_request", "push", "workflow_dispatch"}:
        raise ValueError("unsupported CI event")
    after = identities(repository)
    if event_name != "pull_request":
        return {"checks": list(VERIFIER_CHECKS), "before": None, "after": after}
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
            or not set(VERIFIER_CHECKS).issubset(names)):
        raise ValueError("unexpected ARM check set; review CI partition")
    return [name for name in names if name not in VERIFIER_CHECKS]


def build_ordinary(repository):
    if platform.machine() != "aarch64":
        raise ValueError("ARM checks must run on a native ARM runner")
    # Keep flake-wide validation and automatically include every other check,
    # including new checks, rather than maintaining an ordinary-check allowlist.
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
    required = environment.get("VERIFIER_REQUIRED")
    result = environment.get("VERIFIER_RESULT")
    if required not in {"true", "false"} or result != (
        "success" if required == "true" else "skipped"
    ):
        raise ValueError(f"unexpected verifier result: required={required!r}, result={result!r}")


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
        required = bool(result["checks"])
        print(json.dumps(result, indent=2))
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
            output.write(f"required={str(required).lower()}\n")
            output.write("checks=" + json.dumps(result["checks"]) + "\n")
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary:
            summary.write("### Older verifier image checks\n\n")
            summary.write("Selected: " + (", ".join(result["checks"]) if required else
                          "none; both derivations match the PR base") + ".\n")


if __name__ == "__main__":
    main()
