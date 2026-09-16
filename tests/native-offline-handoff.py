"""Independent reconstruction/readback of the public fixture's write spans."""
import hashlib
import json
import pathlib
import subprocess
import sys

media = pathlib.Path(sys.argv[1])
plan = json.loads((media / "media-plan.json").read_bytes())
assert plan["execution_authorized"] is False
assert plan["hardware_observed"] is False
assert plan["physical_staging_ready"] is False
assert plan["fleet_admission"] == "unevaluated"
assert plan["target"]["executionHost"]["hostname"] == "kaiba-rpi5-provisioner"
assert plan["required_capacity_bytes"] == 512 * 1024 * 1024
assert [w["path"] for w in plan["writes"]] == ["gpt-primary.img", "boot-filesystem.img", "root-data.img", "root-hash.img", "gpt-secondary.img"]
with open("fixture-disk.img", "x+b") as disk:
    disk.truncate(plan["required_capacity_bytes"])
    end = 0
    for write in plan["writes"]:
        payload = (media / write["path"]).read_bytes()
        assert len(payload) == write["size_bytes"]
        assert "sha256:" + hashlib.sha256(payload).hexdigest() == write["digest"]
        assert write["offset_bytes"] >= end
        end = write["offset_bytes"] + len(payload)
        assert end <= plan["required_capacity_bytes"]
        disk.seek(write["offset_bytes"])
        disk.write(payload)
    for write in plan["writes"]:
        disk.seek(write["offset_bytes"])
        assert "sha256:" + hashlib.sha256(disk.read(write["size_bytes"])).hexdigest() == write["digest"]
assert b"No problems found" in subprocess.check_output(["sgdisk", "--verify", "fixture-disk.img"])
for partition in plan["partitions"]:
    info = subprocess.check_output(["sgdisk", f"--info={partition['number']}", "fixture-disk.img"]).decode().lower()
    assert partition["guid"] in info
    assert f"first sector: {partition['offset_bytes'] // 512} " in info
assert subprocess.check_output(["mtype", "-i", str(media / "boot-filesystem.img"), "::config.txt"]) == b"boot_ramdisk=1\n"
assert subprocess.check_output(["mtype", "-i", str(media / "boot-filesystem.img"), "::boot.img"]) == (media / "verified-signing/boot.img").read_bytes()
probes = json.loads((media / "root-probe-plan.json").read_bytes())
assert len(probes["cases"]) == 2
for case in probes["cases"]:
    with (media / "root-data.img").open("rb") as data:
        data.seek(case["data_block"] * 4096)
        block = bytearray(data.read(4096))
    assert "sha256:" + hashlib.sha256(block).hexdigest() == case["original_block_digest"]
    block[case["byte_offset"] % 4096] ^= case["xor_mask"]
    assert "sha256:" + hashlib.sha256(block).hexdigest() == case["altered_block_digest"]
