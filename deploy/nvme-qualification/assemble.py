"""Append a disposable data partition to the pinned MBR Pi image, without mounts."""
import json
import os
from pathlib import Path
import subprocess
import sys

image, data = map(Path, sys.argv[1:])
table = json.loads(subprocess.check_output(['sfdisk', '--json', image]))['partitiontable']
assert table['label'] == 'dos' and table.get('sectorsize', 512) == 512
parts = table['partitions']
assert len(parts) == 2 and parts[1]['type'] == '83'
start = ((max(p['start'] + p['size'] for p in parts) + 2047) // 2048) * 2048
sectors = data.stat().st_size // 512
assert data.stat().st_size % 512 == 0
with image.open('r+b') as f:
    f.truncate((start + sectors) * 512)
subprocess.run(['sfdisk', '--append', image], input=f'{start},{sectors},83\n'.encode(), check=True)
with image.open('r+b') as dest, data.open('rb') as src:
    dest.seek(start * 512)
    while block := src.read(4 * 1024 * 1024):
        dest.write(block)
    dest.flush()
    os.fsync(dest.fileno())
