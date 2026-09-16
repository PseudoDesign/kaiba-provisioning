#!/usr/bin/env python3
"""Describe two fixed ext4 corruption experiments without modifying the image."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def describe(image, block, purpose):
    with image.open("rb") as stream:
        stream.seek(block * 4096)
        original = stream.read(4096)
    if len(original) != 4096:
        raise ValueError("probe block is outside the root image")
    changed = bytearray(original)
    changed[1024 if block == 0 else 0] ^= 1
    return {
        "purpose": purpose,
        "data_block": block,
        "byte_offset": block * 4096 + (1024 if block == 0 else 0),
        "xor_mask": 1,
        "original_block_digest": "sha256:" + hashlib.sha256(original).hexdigest(),
        "altered_block_digest": "sha256:" + hashlib.sha256(changed).hexdigest(),
    }


def plan(image):
    superblock = subprocess.check_output(["dumpe2fs", "-h", image], text=True, stderr=subprocess.DEVNULL)
    if not re.search(r"^Block size:\s+4096$", superblock, re.MULTILINE):
        raise ValueError("experiment requires 4096-byte ext4 blocks")
    output = subprocess.check_output(
        ["debugfs", "-R", "bmap /kaiba-offline-read-probe 0", image],
        text=True, stderr=subprocess.DEVNULL,
    ).strip()
    if not re.fullmatch(r"[1-9][0-9]*", output):
        raise ValueError("the late-read probe must have an allocated data block")
    return {
        "schema_version": "provisioning.kaiba.network/native-offline-root-probes/v1alpha1",
        "block_size": 4096,
        "probe_path": "/kaiba-offline-read-probe",
        "hardware_observed": False,
        "cases": [describe(image, 0, "startup-superblock"), describe(image, int(output), "first-read-after-mount")],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root_image", type=Path)
    arguments = parser.parse_args()
    print(json.dumps(plan(arguments.root_image), sort_keys=True, indent=2))
