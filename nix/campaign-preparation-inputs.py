"""Materialize distinct regular plan inputs from immutable public Nix outputs."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat


def copy_regular(source, target):
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
        raise ValueError("plan input must be a nonempty regular file")
    target.parent.mkdir(parents=True, exist_ok=True)
    # A real copy deliberately gives every plan role its own opened identity.
    shutil.copyfile(source, target)


def materialize(output, release, allowlist, trust, boot, mutations, roots):
    public = output / "public-inputs"
    targets = output / "mutation-targets"
    public.mkdir(parents=True)
    targets.mkdir()
    names = allowlist.read_text().splitlines()
    if names != sorted(set(names)) or not names or len(names) > 128:
        raise ValueError("release allowlist must be sorted and unique")
    fixed = {"cmdline.txt", "device-tree.dtb", "dm-verity.json", "initramfs", "kernel", "release-manifest.json", "root.img", "slot.txt"}
    if not fixed.issubset(names) or any(name not in fixed and not re.fullmatch(r"overlays/[a-z0-9][a-z0-9._-]{0,127}\.dtbo", name) for name in names):
        raise ValueError("unsupported release path")
    actual = []
    for path in release.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError("release contains a nonregular entry")
        actual.append(path.relative_to(release).as_posix())
    if sorted(actual) != names:
        raise ValueError("release bytes differ from the exact allowlist")
    manifest = json.loads((release / "release-manifest.json").read_bytes())
    if not manifest.get("overlays"):
        raise ValueError("campaign requires a real first overlay")
    overlay = "overlays/" + manifest["overlays"][0]["name"] + ".dtbo"
    if overlay not in names:
        raise ValueError("first manifest overlay is absent from the release allowlist")
    records = []
    for name in names:
        path = release / name
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        records.append({"path": name, "sha256": "sha256:" + digest, "size_bytes": path.stat().st_size})
    inventory = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    (public / "positive-release-tree").write_bytes(b"kaiba.provisioning.rpi5-stable-verifier-campaign-release-tree.v1alpha1\0" + inventory)
    sources = {
        "authorization-trust-anchor": trust / "authority-ca.pem",
        "customer-boot-public-key": boot / "public.pem",
        "positive-release-manifest": release / "release-manifest.json",
        "release-policy-root-public-key": trust / "root-public.pem",
        "stable-verifier-policy": trust / "policy.json",
        "unsigned-verifier-boot": boot / "boot.img",
    }
    for path in sorted(mutations.iterdir()):
        if path.suffix != ".json":
            raise ValueError("unexpected mutation input")
        sources[path.stem] = path
    if len(sources) != 26:
        raise ValueError("campaign requires exactly 20 mutation inputs")
    for name, source in sources.items():
        copy_regular(source, public / name)
    target_sources = {"release/" + name: release / name for name in sorted(fixed - {"release-manifest.json"})}
    target_sources["release/" + overlay] = release / overlay
    target_sources["media/root-data"] = roots / "root-data.img"
    target_sources["media/root-hash"] = roots / "root-hash.img"
    for name, source in target_sources.items():
        copy_regular(source, targets / name)
    (output / "public-input-names.txt").write_text("\n".join(sorted([*sources, "positive-release-tree"])) + "\n")
    (output / "mutation-target-names.txt").write_text("\n".join(sorted(target_sources)) + "\n")


if __name__ == "__main__":
    materialize(*[Path(os.environ[name]) for name in ("out", "releasePath", "allowlistPath", "trustPath", "bootPath", "mutationsPath", "rootPayloadsPath")])
