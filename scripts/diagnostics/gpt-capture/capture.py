#!/usr/bin/env python3
"""Export bounded candidate GPT metadata regions from a read-only source."""

import argparse
import base64
import datetime
import fcntl
import hashlib
import json
import os
import stat
import struct
import sys


SECTOR = 512
SCHEMA = "kaiba-gpt-metadata-capture-v1"


def read_exact(fd, offset, size):
    data = os.pread(fd, size, offset)
    if len(data) != size:
        raise ValueError(f"short source read at {offset}: {len(data)} of {size} bytes")
    return data


def source_geometry(fd):
    info = os.fstat(fd)
    if stat.S_ISREG(info.st_mode):
        return info.st_size, "image-file"
    if stat.S_ISBLK(info.st_mode):
        capacity = struct.unpack("=Q", fcntl.ioctl(fd, 0x80081272, bytes(8)))[0]  # BLKGETSIZE64
        sector = struct.unpack("=I", fcntl.ioctl(fd, 0x1268, bytes(4)))[0]  # BLKSSZGET
        if sector != SECTOR:
            raise ValueError(f"logical sector size is {sector}; only 512 is supported")
        return capacity, "block-device-readback"
    raise ValueError("source must be a regular image file or a block device")


def capture(fd, description):
    capacity, kind = source_geometry(fd)
    if capacity % SECTOR or capacity < 68 * SECTOR:
        raise ValueError("source capacity must contain at least 68 whole 512-byte sectors")
    primary = read_exact(fd, SECTOR, SECTOR)
    if primary[:8] != b"EFI PART":
        raise ValueError("source has no primary GPT signature at LBA 1")
    alternate = struct.unpack_from("<Q", primary, 32)[0]
    if not 67 <= alternate < capacity // SECTOR:
        raise ValueError("primary GPT alternate LBA is outside the supported capture bounds")

    # Fixed 128-by-128 geometry: head plus declared and physical-end backup
    # candidates. Their bytes remain untrusted until parser replay and review.
    intervals = sorted([
        (0, 34 * SECTOR),
        ((alternate - 32) * SECTOR, (alternate + 1) * SECTOR),
        (capacity - 33 * SECTOR, capacity),
    ])
    merged = []
    for start, end in intervals:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    regions = [(start, read_exact(fd, start, end - start)) for start, end in merged]
    if regions[0][1][SECTOR:2 * SECTOR] != primary:
        raise ValueError("primary GPT changed while determining capture ranges")
    for offset, data in regions:
        if read_exact(fd, offset, len(data)) != data:
            raise ValueError("GPT metadata changed between read passes")
    if source_geometry(fd) != (capacity, kind):
        raise ValueError("source geometry changed during capture")

    with open(__file__, "rb") as tool:
        tool_digest = hashlib.sha256(tool.read()).hexdigest()
    return {
        "schema_version": SCHEMA,
        "source_kind": kind,
        "source_description": description,
        "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "capture_tool_sha256": tool_digest,
        "capacity_bytes": capacity,
        "logical_sector_size_bytes": SECTOR,
        "regions": [{
            "offset_bytes": offset,
            "data_base64": base64.b64encode(data).decode("ascii"),
            "sha256": hashlib.sha256(data).hexdigest(),
        } for offset, data in regions],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="image file or block device opened read-only")
    parser.add_argument("--description", required=True, help="operator-supplied origin and observation reference")
    args = parser.parse_args()
    if not args.description.strip():
        parser.error("--description must not be blank")
    # Nonblocking open prevents a FIFO supplied by mistake from hanging before
    # fstat rejects it. The descriptor never has write access.
    fd = os.open(args.source, os.O_RDONLY | os.O_NONBLOCK)
    try:
        result = capture(fd, args.description)
    finally:
        os.close(fd)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"GPT metadata capture: {error}", file=sys.stderr)
        sys.exit(1)
