"""Software-only kernel I/O test: a loop device, no USB/Pi/signing interface."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

source, bundle = Path(sys.argv[1]), Path(sys.argv[2])
spec = importlib.util.spec_from_file_location('executor', source/'executor.py')
e = importlib.util.module_from_spec(spec); spec.loader.exec_module(e)
p = e.packet.validate(e.load(bundle/'packet.json'))
state = Path(p['host']['state_directory']); state.mkdir(mode=0o700)
image = Path('/var/lib/disposable-loop.img')
with image.open('xb') as f:
    f.truncate(p['capacity_bytes'])
subprocess.run(['mkfs.ext4', '-q', '-F', str(image)], check=True)
path = subprocess.check_output(['losetup', '--find', '--show', str(image)], text=True).strip()
mount = Path('/mnt/original'); mount.mkdir(parents=True)
subprocess.run(['mount', path, str(mount)], check=True)
(mount/'test-record').write_text('original-fixture-data')
dev = os.stat(path).st_rdev
try:
    e.inactive({f'{os.major(dev)}:{os.minor(dev)}'})
    raise AssertionError('mounted target accepted')
except e.Rejected as error:
    assert str(error) == 'target-mounted'
subprocess.run(['umount', str(mount)], check=True)
subprocess.run(['blockdev', '--setro', path], check=True)

class LoopDisk(e.Disk):
    # The production data path, exclusive opens, RO windows and cache flushes
    # are exercised; USB/host/inactivity selection is NOT simulated as passed.
    def __init__(self):
        self.path = path
        self.fd = os.open(path, os.O_RDONLY)
    def check(self, fd=None, readonly=1):
        if fd is None: fd = self.fd
        assert e.number(fd, e.BLKROGET, '=I') == readonly
        assert e.number(fd, 0x80081272, '=Q') == p['capacity_bytes']
        assert e.number(fd, 0x1268, '=I') == 512

def setup():
    records = e.Records(state)
    disk = LoopDisk()
    return records, disk, e.Engine(bundle, records, disk)

r, d, engine = setup()
now=e.timestamp()
a=dict(schema_version='kaiba.device-secret-media-authorization/v1alpha1',
       packet_sha256=engine.hash, executor_sha256=e.code_digest(), reviewer_reference='reviewer:synthetic-vm',
       approved_at=(now-e.datetime.timedelta(seconds=10)).isoformat(),
       expires_at=(now+e.datetime.timedelta(hours=1)).isoformat(), actions=['backup','stage','restore'])
r.save('authorization.json', a)
engine.run('stage'); engine.run('verify')
assert e.number(d.fd, e.BLKROGET, '=I') == 1
r.close(); d.close()
# Re-open all state/FDs to exercise process restart boundaries.
r,d,engine=setup()
try:
    engine.run('stage')
    raise AssertionError('stage repeated')
except e.Rejected as error:
    assert str(error) == 'action-already-attempted'
engine.run('restore')
assert e.number(d.fd, e.BLKROGET, '=I') == 1
subprocess.run(['mount', '-o', 'ro,noload', path, str(mount)], check=True)
assert (mount/'test-record').read_text() == 'original-fixture-data'
subprocess.run(['umount', str(mount)], check=True)
try:
    engine.run('restore')
    raise AssertionError('restore repeated')
except e.Rejected as error:
    assert str(error) == 'action-already-attempted'
r.close(); d.close()
subprocess.run(['losetup', '--detach', path], check=True)
print('SOFTWARE_ONLY_LOOP_IO_PASSED hardware_qualified=false')
