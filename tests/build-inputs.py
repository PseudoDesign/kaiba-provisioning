#!/usr/bin/env python3
"""Check real package/VM derivation identities without building images or VMs.

Run from a Git checkout with Python 3 and Nix available. Temporary snapshots
have no Git revision: this tests reusable implementation inputs, independently
of the exact clean-commit provenance intentionally embedded in release images.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
PACKAGES = {
    "verifier": "kaiba-rpi5-stable-verifier",
    "inspector": "kaiba-rpi5-stable-campaign-gpt-inspect",
    "validator": "kaiba-rpi5-kexec-input-validate",
    "authority": "kaiba-rpi5-verifier-test-authority",
    "proof": "kaiba-rpi5-one-boot-prove",
}
GENERAL_PACKAGES = {
    "control": "kaiba-provision-control",
    "station": "kaiba-provision-station",
    "gate": "kaiba-provision-signing-gate-foundation",
    "campaign-plan": "kaiba-rpi5-stable-campaign-plan",
    "boot-signing": "kaiba-provision-sign-boot",
}
SYSTEMS = {"x86": "x86_64-linux", "arm": "aarch64-linux"}
VMS = {"x86-vm", "arm-verifier-vm", "arm-handoff-vm"}
VERIFIER_IMAGES = {"legacy-verifier-image", "file-verifier-image"}
GENERAL = {f"{arch}-{name}" for arch in SYSTEMS for name in GENERAL_PACKAGES}
STAGING_VM = {"staging-vm"}
RUNTIME = {f"{arch}-{name}" for arch in SYSTEMS for name in PACKAGES} | VMS | VERIFIER_IMAGES | GENERAL | STAGING_VM


def identities(source):
    attributes = [
        f'"{arch}-{name}" = flake.packages.{system}.{package}.drvPath;'
        for arch, system in SYSTEMS.items()
        for name, package in (PACKAGES | GENERAL_PACKAGES).items()
    ]
    attributes += [
        '"staging-vm" = flake.checks.x86_64-linux.stable-campaign-staging-vm.drvPath;',
        '"x86-vm" = flake.checks.x86_64-linux.stable-verifier-initramfs-vm.drvPath;',
        '"arm-verifier-vm" = flake.checks.aarch64-linux.stable-verifier-aarch64-kexec-vm.drvPath;',
        '"arm-handoff-vm" = flake.checks.aarch64-linux.stable-handoff-aarch64-kexec-file-vm.drvPath;',
        '"legacy-verifier-image" = flake.checks.aarch64-linux.stable-verifier-rpi5-hardware-eval.drvPath;',
        '"file-verifier-image" = flake.checks.aarch64-linux.stable-verifier-rpi5-file-live-fdt-hardware-eval.drvPath;',
        '"unit" = flake.checks.x86_64-linux.unit.drvPath;',
    ]
    expression = (
        'let flake = builtins.getFlake ("path:" + builtins.getEnv "KAIBA_BUILD_INPUTS_SOURCE"); '
        "in { " + " ".join(attributes) + " }"
    )
    result = subprocess.run(
        [
            "nix", "--accept-flake-config", "eval", "--impure", "--json",
            "--no-write-lock-file", "--expr", expression,
        ],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        env=os.environ | {"KAIBA_BUILD_INPUTS_SOURCE": str(source)},
    )
    return json.loads(result.stdout)


def append(source, path, text):
    with (source / path).open("a") as output:
        output.write(text)


def main():
    # Include working edits and new source files, but never .git or ignored
    # build results. Every fileset is evaluated once from a raw snapshot.
    files = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT
    ).decode().split("\0")
    with tempfile.TemporaryDirectory(prefix="kaiba-build-inputs-") as temporary:
        original = Path(temporary) / "original"
        for relative in filter(None, files):
            target = original / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target, follow_symlinks=False)
        baseline = identities(original)
        print("Evaluated baseline hardware packages and VM checks", flush=True)

        def check(name, edits, expected_runtime_changes, unit_changes=None):
            snapshot = Path(temporary) / name
            shutil.copytree(original, snapshot, symlinks=True)
            for path, text in edits:
                append(snapshot, path, text)
            actual = identities(snapshot)
            changed = {key for key in RUNTIME if actual[key] != baseline[key]}
            if changed != expected_runtime_changes:
                raise AssertionError(
                    f"{name}: expected changed derivations {sorted(expected_runtime_changes)}, "
                    f"got {sorted(changed)}"
                )
            if unit_changes is not None and (actual["unit"] != baseline["unit"]) != unit_changes:
                raise AssertionError(f"{name}: unexpected unit-test derivation identity")
            print(f"PASS {name}", flush=True)

        check("documentation", [("README.md", "\nBuild-input identity probe.\n")], set(), False)
        check(
            "remote-helper-only",
            [("tools/device-secret-development/main.c", "\n/* identity probe */\n")],
            set(), False,
        )
        check(
            "verifier-kernel-patch",
            [("nix/patches/arm64-kexec-file-require-in-place.patch", "\n")],
            VERIFIER_IMAGES | {"arm-handoff-vm"}, False,
        )
        check(
            "unrelated-ui-and-command",
            [
                ("internal/provisioning/stationui/web/styles.css", "\n/* identity probe */\n"),
                ("cmd/kaiba-provision-control/main.go", "\n// identity probe\n"),
            ],
            GENERAL, True,
        )
        check(
            "test-only",
            [("internal/provisioning/stablehandoff/archive_test.go", "\n// identity probe\n")],
            set(), True,
        )
        check(
            "signer-test-only",
            [("internal/provisioning/yubikeysigner/signer_test.go", "\n// identity probe\n")],
            set(), True,
        )
        check(
            "staging-vm-tests",
            [("internal/provisioning/campaignstaging/vm_integration_linux_test.go", "\n// identity probe\n")],
            STAGING_VM, True,
        )
        check(
            "embedded-ui-asset",
            [("internal/provisioning/livestation/web/app.js", "\n// identity probe\n")],
            GENERAL, True,
        )
        check(
            "module-definition",
            [("go.mod", "\n// identity probe\n")],
            RUNTIME, True,
        )
        check(
            "runtime-entry-points",
            [(f"cmd/{package}/main.go", "\n// identity probe\n") for package in PACKAGES.values()],
            RUNTIME - {"arm-handoff-vm"} - STAGING_VM, True,
        )
        check(
            "handoff-implementation",
            [("internal/provisioning/stablehandoff/archive.go", "\n// identity probe\n")],
            {"x86-verifier", "arm-verifier"} | VMS | VERIFIER_IMAGES | GENERAL, True,
        )
        check(
            "transitive-verifier-library",
            [("internal/provisioning/bundle/digest.go", "\n// identity probe\n")],
            {"x86-verifier", "arm-verifier", "x86-inspector", "arm-inspector", "x86-vm", "arm-verifier-vm"} | VERIFIER_IMAGES | GENERAL | STAGING_VM,
            True,
        )
        check(
            "signed-vm-fixture",
            [("tests/stable-verifier-vm-fixture/main.go", "\n// identity probe\n")],
            {"x86-vm"}, False,
        )
        check(
            "fixture-signing-helper",
            [("tests/deterministic-rsa-fixture.py", "\n# identity probe\n")],
            {"x86-vm"}, False,
        )


if __name__ == "__main__":
    main()
