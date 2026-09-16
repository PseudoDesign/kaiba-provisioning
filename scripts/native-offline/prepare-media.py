#!/usr/bin/env python3
"""Materialize regular files and a review plan; never open a device node."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

MIB = 1024 * 1024
DATA_GUID = "b1a02b6c-8ec1-4ca9-9b8a-348211271de0"
HASH_GUID = "66d98f80-4260-4de0-98b5-232bcac98e29"
BOOT_GUID = "9254d478-36e9-4e03-bb62-6fbbd8e09f45"
DISK_GUID = "b268f110-7d11-47c7-9bcc-2c4b480e4404"


def digest(path):
    with path.open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def run(*args):
    return subprocess.check_output([str(a) for a in args], stderr=subprocess.STDOUT)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    signed, unsigned, manifest_file, review, hardware_file = map(pathlib.Path, sys.argv[1:6])
    capacity, output, probe_script = int(sys.argv[6]), pathlib.Path(sys.argv[7]), pathlib.Path(sys.argv[8])
    m = json.loads(manifest_file.read_bytes())
    hardware = json.loads(hardware_file.read_bytes())
    require(hardware["executionHost"]["hostname"] == "kaiba-rpi5-provisioner" and
            hardware["targetMedia"]["devicePath"] == "/dev/nvme0n1", "unexpected existing media selector")
    require(digest(unsigned / "manifest.json") == m["unsigned_artifacts_digest"], "unsigned manifest mismatch")
    require(digest(review / "review.json") == m["review_digest"], "review mismatch")
    for role, file in [("boot_image", signed / "boot.img"), ("root_data", unsigned / "nvme/root-data.img"), ("root_hash_tree", unsigned / "nvme/root-hash.img")]:
        require(digest(file) == m[role]["digest"] and file.stat().st_size == m[role]["size_bytes"], "artifact mismatch")
    root_size, hash_size = m["root_data"]["size_bytes"], m["root_hash_tree"]["size_bytes"]
    align = lambda size: ((size + MIB - 1) // MIB) * MIB
    data_start = 129 * MIB
    hash_start = data_start + align(root_size)
    minimum = hash_start + align(hash_size) + MIB
    require(capacity >= minimum and capacity % 512 == 0, "target capacity is too small or not sector aligned")
    run("veritysetup", "verify", unsigned / "nvme/root-data.img", unsigned / "nvme/root-hash.img", m["root_integrity_digest"].removeprefix("sha256:"))
    output.mkdir()
    shutil.copyfile(hardware_file, output / "hardware-configuration.json")
    shutil.copyfile(manifest_file, output / "signing-input.json")
    shutil.copytree(review, output / "review")
    shutil.copytree(signed, output / "verified-signing")
    shutil.copyfile(unsigned / "nvme/root-data.img", output / "root-data.img")
    shutil.copyfile(unsigned / "nvme/root-hash.img", output / "root-hash.img")
    boot = output / "boot-filesystem.img"
    with boot.open("xb") as f:
        f.truncate(128 * MIB)
    run("mkfs.vfat", "--invariant", "-F", "32", "-i", "4b414942", "-n", "KAIBA_BOOT", boot)
    with tempfile.TemporaryDirectory() as tmp:
        temp = pathlib.Path(tmp)
        (temp / "config.txt").write_text("boot_ramdisk=1\n")
        for name in ["boot.img", "boot.sig"]:
            shutil.copyfile(signed / name, temp / name)
        for name in ["config.txt", "boot.img", "boot.sig"]:
            run("touch", "--date=@315532800", temp / name)
            run("mcopy", "-p", "-m", "-i", boot, temp / name, "::/")
        run("fsck.fat", "-vn", boot)
        (temp / "readback").mkdir()
        run("mcopy", "-s", "-i", boot, "::*", str(temp / "readback") + "/")
        require(sorted(p.name for p in (temp / "readback").iterdir()) == ["boot.img", "boot.sig", "config.txt"], "outer FAT allowlist mismatch")
        for name in ["boot.img", "boot.sig", "config.txt"]:
            require(digest(temp / name) == digest(temp / "readback" / name), "outer FAT readback mismatch")
        disk = temp / "layout.img"
        with disk.open("xb") as f:
            f.truncate(capacity)
        specs = [(1, MIB, 128 * MIB, "ef00", BOOT_GUID, "KAIBA_BOOT"),
                 (2, data_start, align(root_size), "8300", DATA_GUID, "KAIBA_ROOT"),
                 (3, hash_start, align(hash_size), "8300", HASH_GUID, "KAIBA_VERITY")]
        args = ["sgdisk", "--clear", "--disk-guid=" + DISK_GUID]
        for number, start, size, kind, guid, label in specs:
            args += [f"--new={number}:{start // 512}:{(start + size) // 512 - 1}", f"--typecode={number}:{kind}", f"--partition-guid={number}:{guid}", f"--change-name={number}:{label}"]
        run(*args, disk)
        require(b"No problems found" in run("sgdisk", "--verify", disk), "GPT validation failed")
        with disk.open("rb") as f:
            (output / "gpt-primary.img").write_bytes(f.read(34 * 512))
            f.seek(capacity - 33 * 512)
            (output / "gpt-secondary.img").write_bytes(f.read(33 * 512))
    writes = []
    for name, offset in [("gpt-primary.img", 0), ("boot-filesystem.img", MIB), ("root-data.img", data_start), ("root-hash.img", hash_start), ("gpt-secondary.img", capacity - 33 * 512)]:
        f = output / name
        writes.append(dict(path=name, offset_bytes=offset, size_bytes=f.stat().st_size, digest=digest(f)))
    probe = json.loads(run(sys.executable, probe_script, unsigned / "nvme/root-data.img"))
    (output / "root-probe-plan.json").write_text(json.dumps(probe, indent=2) + "\n")
    plan = dict(schema_version="kaiba.provisioning.rpi5-native-offline-media-handoff/v1alpha1",
                source_revision=m["source_revision"], signing_input_digest=digest(manifest_file),
                target=hardware, required_logical_sector_size=512, required_capacity_bytes=capacity,
                partitions=[dict(number=n, offset_bytes=start, size_bytes=size, guid=guid, label=label) for n, start, size, kind, guid, label in specs],
                writes=writes, required_preimages=[dict(offset_bytes=w["offset_bytes"], size_bytes=w["size_bytes"]) for w in writes],
                readback="hash every complete written span from the physical device before boot",
                corruption_base_offset_bytes=data_start, corruption_plan="root-probe-plan.json",
                restoration="retain independent preimage copies and digests for every write span; restore and read back pristine candidate between cases; retain original GPT and media recovery route",
                execution_authorized=False, physical_staging_ready=False, hardware_observed=False, fleet_admission="unevaluated")
    (output / "media-plan.json").write_text(json.dumps(plan, indent=2) + "\n")


if __name__ == "__main__":
    main()
