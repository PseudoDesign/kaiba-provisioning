#!/usr/bin/env python3
"""Malak-side inventory, explicit disk writing, and independent evidence retention.

No SSH execution, service changes, or writes to a disk occur during `plan`.
`write` requires the same stable disk identity, fresh boot-bound inventory, and
the SHA256 of the exact reviewed plan. This is not an unattended provisioning API.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def digest(path, length=None):
    h = hashlib.sha256()
    with open(path, 'rb', buffering=0) as f:
        remaining = length
        while remaining is None or remaining > 0:
            b = f.read(4 * 1024 * 1024 if remaining is None else min(remaining, 4 * 1024 * 1024))
            if not b:
                if remaining:
                    raise ValueError('short-read')
                break
            h.update(b)
            if remaining is not None:
                remaining -= len(b)
    return h.hexdigest()


def save(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, sort_keys=True, indent=2)
        f.write('\n'); f.flush(); os.fsync(f.fileno())
    fd = os.open(Path(path).parent, os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def nodes(disk):
    yield disk
    for child in disk.get('children', []):
        yield from nodes(child)


def validate_disk(disk, minimum):
    if disk['type'] != 'disk' or disk['ro'] or not disk.get('serial') or disk['size'] < minimum:
        raise ValueError('need-writable-whole-disk-with-serial-and-capacity')
    for item in nodes(disk):
        if any(item.get('mountpoints') or []) or item['type'] not in ('disk', 'part'):
            raise ValueError('disk-in-use-or-mapped')
        if (item.get('partlabel') or '').startswith('disk-main-') or item.get('fstype') in ('crypto_LUKS', 'LVM2_member', 'linux_raid_member'):
            raise ValueError('protected-or-unreviewed-storage-layout')


def inventory(device, minimum):
    if not str(device).startswith('/dev/disk/by-id/') or '-part' in device.name:
        raise ValueError('stable-whole-disk-by-id-required')
    resolved = device.resolve(strict=True)
    if not stat.S_ISBLK(resolved.stat().st_mode):
        raise ValueError('not-block-device')
    data = json.loads(subprocess.check_output([
        'lsblk', '--json', '--bytes', '--paths', '--output',
        'NAME,TYPE,SIZE,RO,SERIAL,MODEL,WWN,MAJ:MIN,MOUNTPOINTS,FSTYPE,LABEL,PARTLABEL', str(resolved)]))
    if len(data['blockdevices']) != 1:
        raise ValueError('ambiguous-device')
    disk = data['blockdevices'][0]
    validate_disk(disk, minimum)
    swaps = subprocess.check_output(['swapon', '--show', '--noheadings', '--raw', '--output', 'NAME'], text=True).splitlines()
    for item in nodes(disk):
        if item['name'] in swaps:
            raise ValueError('active-swap')
        sysfs = Path('/sys/dev/block') / item['maj:min'] / 'holders'
        if any(sysfs.iterdir()):
            raise ValueError('device-has-holders')
    return {'by_id': str(device), 'resolved': str(resolved), 'disk': disk,
            'host': os.uname().nodename, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def read_manifest(bundle):
    m = json.loads((bundle / 'manifest.json').read_text())
    if m['schema'] != 'kaiba.nvme-qualification-image/v1' or m['image'] != 'qualification.img' or m['synthetic'] is not True:
        raise ValueError('wrong-image-manifest')
    image = bundle / m['image']
    if not image.is_file() or image.stat().st_size != m['bytes'] or digest(image) != m['sha256']:
        raise ValueError('image-integrity')
    return m, image


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='action', required=True)
    plan = sub.add_parser('plan')
    plan.add_argument('--bundle', type=Path, required=True)
    plan.add_argument('--device', type=Path, required=True)
    plan.add_argument('--out', type=Path, required=True)
    write = sub.add_parser('write')
    write.add_argument('--plan', type=Path, required=True)
    write.add_argument('--confirm-plan-sha256', required=True)
    write.add_argument('--confirm-erase-serial', required=True)
    write.add_argument('--receipt', type=Path, required=True)
    capture = sub.add_parser('capture', help='Retain JSONL from an independently invoked SSH command on stdin')
    capture.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    if a.action == 'capture':
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as f:
            for line in sys.stdin:
                event = json.loads(line)
                f.write(json.dumps(event, sort_keys=True) + '\n'); f.flush(); os.fsync(f.fileno())
                print(json.dumps(event, sort_keys=True), flush=True)
        return
    if a.action == 'plan':
        m, image = read_manifest(a.bundle.resolve())
        inv = inventory(a.device, m['bytes'])
        save(a.out, {'schema': 'kaiba.nvme-write-plan/v1', 'bundle': str(a.bundle.resolve()), 'manifest': m, 'inventory': inv})
        print(json.dumps({'plan': str(a.out), 'plan_sha256': digest(a.out), 'erase_serial': inv['disk']['serial'], 'bytes': inv['disk']['size']}))
        return
    if os.geteuid() != 0:
        raise ValueError('write-requires-root')
    if digest(a.plan) != a.confirm_plan_sha256:
        raise ValueError('plan-review-digest-mismatch')
    plan = json.loads(a.plan.read_text())
    if plan['schema'] != 'kaiba.nvme-write-plan/v1':
        raise ValueError('wrong-plan-schema')
    m, image = read_manifest(Path(plan['bundle']))
    inv = inventory(Path(plan['inventory']['by_id']), m['bytes'])
    if m != plan['manifest'] or inv != plan['inventory'] or inv['disk']['serial'] != a.confirm_erase_serial:
        raise ValueError('device-or-image-changed')
    # O_EXCL asks the block layer to reject a mounted/claimed device. The open
    # descriptor remains bound to this device if a by-id symlink later changes.
    flags = os.O_RDWR | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(inv['resolved'], flags)
    intent = Path(str(a.receipt) + '.intent.json')
    save(intent, {'plan_sha256': a.confirm_plan_sha256, 'inventory': inv, 'status': 'write-may-be-partial-do-not-boot'})
    try:
        st = os.fstat(fd)
        if f'{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}' != inv['disk']['maj:min']:
            raise ValueError('device-changed-at-open')
        # Clear obsolete backup GPT metadata at the end of the approved disk.
        os.lseek(fd, inv['disk']['size'] - 1024 * 1024, os.SEEK_SET)
        zero = b'\0' * (1024 * 1024)
        if os.write(fd, zero) != len(zero): raise ValueError('short-tail-write')
        os.lseek(fd, 0, os.SEEK_SET)
        with image.open('rb') as src:
            while block := src.read(4 * 1024 * 1024):
                view = memoryview(block)
                while view:
                    n = os.write(fd, view)
                    if n <= 0: raise ValueError('short-write')
                    view = view[n:]
        os.fsync(fd)
        # Linux BLKFLSBUF invalidates the clean block cache before readback;
        # verification must read the device rather than our just-written pages.
        fcntl.ioctl(fd, 0x1261)
        os.lseek(fd, 0, os.SEEK_SET)
        h = hashlib.sha256(); remaining = m['bytes']
        while remaining:
            b = os.read(fd, min(remaining, 4 * 1024 * 1024))
            if not b: raise ValueError('short-readback')
            h.update(b); remaining -= len(b)
        if h.hexdigest() != m['sha256']:
            raise ValueError('disk-readback-mismatch')
        save(a.receipt, {'status': 'written-and-readback-verified', 'image_sha256': m['sha256'], 'bytes': m['bytes'], 'inventory': inv})
    finally:
        os.close(fd)
    print(json.dumps({'receipt': str(a.receipt), 'sha256': digest(a.receipt)}))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(json.dumps({'status': 'stopped', 'error': str(error)}), file=sys.stderr)
        sys.exit(1)
