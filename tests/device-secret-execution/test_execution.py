import copy
import base64
import contextlib
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid
import zlib

SOURCE = Path(os.environ['KAIBA_EXECUTION_SOURCE'])
spec = importlib.util.spec_from_file_location('executor', SOURCE/'executor.py')
e = importlib.util.module_from_spec(spec); spec.loader.exec_module(e)
p = e.packet


def config():
    return dict(schema_version='kaiba.device-secret-target/v1alpha1', scheme='kaiba-firmware-hmac-counter-v1',
                experiment_id='execution-fixture', target_reference='synthetic-board', source_revision='a'*40,
                volume_uuid='33333333-3333-4333-8333-333333333333', partition_uuid='44444444-4444-4444-8444-444444444444',
                board_serial_sha256='e'*64, disk_serial_sha256=hashlib.sha256(b'SYNTHETIC_DISK').hexdigest(),
                nonce_hex=bytes(range(32)).hex(), slot_id=1, expected_usage=0)


def host():
    return dict(hostname='synthetic', machine_id_sha256='f'*64, disk_by_id='/dev/disk/by-id/ata-SYNTHETIC',
                enclosure_by_id='/dev/disk/by-id/usb-SYNTHETIC', disk_serial='SYNTHETIC_DISK', enclosure_serial='SYNTHETIC_USB',
                usb_vendor='1234', usb_product='5678', state_directory='/var/lib/kaiba-device-secret-synthetic')


def settings():
    return dict(uart_by_id='/dev/serial/by-id/synthetic', uart_by_path='/dev/serial/by-path/synthetic',
                idle_timeout_seconds=60, observation_seconds=10, maximum_bytes=65536)


def authorization(packet_hash, actions=('backup', 'stage', 'restore')):
    now = e.timestamp()
    return dict(schema_version='kaiba.device-secret-media-authorization/v1alpha1', packet_sha256=packet_hash,
                executor_sha256=e.code_digest(), reviewer_reference='reviewer:synthetic',
                approved_at=(now-datetime.timedelta(seconds=10)).isoformat(),
                expires_at=(now+datetime.timedelta(hours=1)).isoformat(), actions=list(actions))


def synthetic_media(root):
    # Base bytes are from the existing real signing/finalizer/FAT/GPT fixture.
    # Adjusting its review here is explicitly synthetic composition, not new
    # signing evidence or an operator candidate. No fixture reaches hardware.
    media = root/'media'; shutil.copytree(os.environ['KAIBA_EXECUTION_MEDIA'], media)
    for f in media.rglob('*'):
        if f.is_file(): f.chmod(0o600)
        elif f.is_dir(): f.chmod(0o700)
    media.chmod(0o700)
    experiment = root/'experiment.json'; experiment.write_bytes(p.canonical(config()))
    review = p.load(media/'review/review.json'); review['device_secret_experiment_digest'] = 'sha256:'+p.sha(experiment)
    (media/'review/review.json').write_bytes(p.canonical(review))
    signing = p.load(media/'signing-input.json'); signing['review_digest'] = 'sha256:'+p.sha(media/'review/review.json')
    (media/'signing-input.json').write_bytes(p.canonical(signing))
    base = p.load(media/'media-plan.json'); base['signing_input_digest'] = 'sha256:'+p.sha(media/'signing-input.json')
    (media/'media-plan.json').write_bytes(p.canonical(base))
    return media, experiment


def create_packet(root):
    media, experiment = synthetic_media(root)
    hf, cf = root/'host.json', root/'capture.json'
    hf.write_bytes(p.canonical(host())); cf.write_bytes(p.canonical(settings()))
    reviews = {}
    for name in ('slot_suitability', 'authorized_images', 'recovery_route'):
        reviews[name] = root/(name+'.md'); reviews[name].write_text('Synthetic software fixture only; no approval.\n')
    out = root/'packet'
    value = p.compose(media, experiment, hf, cf, reviews, out)
    return out, value


class FileDisk:
    def __init__(self, path, size):
        self.path = path
        with path.open('wb') as f: f.truncate(size)
        self.fd = os.open(path, os.O_RDWR)
        self.fail_write = False; self.bad_readback = False; self.writes = 0
    def check(self, fd=None, readonly=1): pass
    def read_open(self): return os.open(self.path, os.O_RDONLY)
    def write(self, spans, paths):
        for s, path in zip(spans, paths):
            with path.open('rb') as f:
                for pos in range(0, s['size'], e.CHUNK):
                    data = f.read(min(e.CHUNK, s['size']-pos))
                    os.pwrite(self.fd, data, s['offset']+pos); self.writes += 1
                    if self.fail_write: raise e.Rejected('injected-uncertain-write')
        os.fsync(self.fd)
        if self.bad_readback: os.pwrite(self.fd, b'X', 0)
    def close(self): os.close(self.fd)


class ExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(); cls.root = Path(cls.temp.name)
        cls.bundle, cls.plan = create_packet(cls.root)
    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()
    def setUp(self):
        self.state_temp = tempfile.TemporaryDirectory(); self.root = Path(self.state_temp.name)
        self.state = self.root/'state'; self.state.mkdir(mode=0o700)
        self.trust = patch.object(e, 'trusted_path', lambda *args: None); self.trust.start()
        self.records = e.Records(self.state)
        self.disk = FileDisk(self.root/'disk.img', self.plan['capacity_bytes'])
        # Nonzero originals prove restoration, including the entire new extent.
        for s in self.plan['spans']:
            os.pwrite(self.disk.fd, b'original-'+s['name'].encode(), s['offset'])
        self.engine = e.Engine(self.bundle, self.records, self.disk)
        self.auth = authorization(self.engine.hash)
        self.set_auth(self.auth)
    def tearDown(self):
        self.disk.close(); self.records.close(); self.trust.stop(); self.state_temp.cleanup()
    def set_auth(self, a): (self.state/'authorization.json').write_bytes(p.canonical(a))
    def reject(self, fn, code):
        with self.assertRaisesRegex(e.Rejected, code): fn()
    def test_round_trip_stage_restore_and_no_repeat(self):
        os.pwrite(self.disk.fd, b"untouched-gap", 32768)
        self.engine.run('stage'); self.engine.run('verify')
        self.assertEqual(p.load(self.state/'stage.complete.json')['result'], 'passed')
        before = self.disk.writes
        self.reject(lambda: self.engine.run('stage'), 'action-already-attempted')
        self.assertEqual(self.disk.writes, before)
        # The target legitimately changes only its disposable encrypted extent.
        os.pwrite(self.disk.fd, b'ciphertext', self.plan['spans'][4]['offset'])
        self.engine.run('restore')
        for s in self.plan['spans']:
            expected = b'original-'+s['name'].encode()
            self.assertEqual(os.pread(self.disk.fd, len(expected), s['offset']), expected)
        self.assertEqual(os.pread(self.disk.fd, 13, 32768), b'untouched-gap')
        self.reject(lambda: self.engine.run('restore'), 'action-already-attempted')
    def test_uncertain_stage_consumed_and_explicit_restore(self):
        self.disk.fail_write = True
        self.reject(lambda: self.engine.run('stage'), 'injected-uncertain-write')
        self.assertTrue(self.records.has('stage.intent.json'))
        self.assertFalse(self.records.has('stage.complete.json'))
        self.disk.fail_write = False
        self.reject(lambda: self.engine.run('stage'), 'action-already-attempted')
        self.engine.run('restore')
    def test_corrupt_preimage_refuses_restore_without_writes(self):
        self.engine.run('stage'); before = self.disk.writes
        with (self.state/'gpt-primary.img.preimage').open('r+b') as f: f.write(b'bad')
        self.reject(lambda: self.engine.run('restore'), 'backup-corrupt')
        self.assertEqual(self.disk.writes, before)
    def test_changed_disk_after_backup_refuses_stage(self):
        self.engine.run('backup')
        os.pwrite(self.disk.fd, b'changed', self.plan['spans'][3]['offset'])
        self.reject(lambda: self.engine.run('stage'), 'readback-mismatch')
        self.assertEqual(self.disk.writes, 0)
    def test_incomplete_backup_never_repeated(self):
        self.engine.begin('backup')
        self.reject(lambda: self.engine.run('backup'), 'already-attempted')
        with self.assertRaises(OSError): self.engine.run('stage')
        self.assertEqual(self.disk.writes, 0)
    def test_failed_readback_is_not_completion(self):
        self.disk.bad_readback = True
        self.reject(lambda: self.engine.run('stage'), 'readback-mismatch')
        self.assertFalse(self.records.has('stage.complete.json'))
        self.reject(lambda: self.engine.run('stage'), 'already-attempted')
    def test_authority_separate_exact_expiring(self):
        cases = [dict(packet_sha256='1'*64), dict(executor_sha256='1'*64), dict(actions=['backup']),
                 dict(expires_at='2020-01-01T00:00:00+00:00'), dict(actions=['backup','stage','stage'])]
        for update in cases:
            with self.subTest(update=update):
                self.set_auth(dict(self.auth, **update))
                with self.assertRaises(e.Rejected): self.engine.run('stage')
                self.assertFalse(self.records.has('backup.intent.json'))
        self.assertEqual(self.disk.writes, 0)
    def test_approval_does_not_enable_repeat_after_process_restart(self):
        self.engine.run('stage')
        later = e.Engine(self.bundle, self.records, self.disk)
        self.set_auth(authorization(later.hash))
        self.reject(lambda: later.run('stage'), 'already-attempted')
    def test_writer_restores_readonly_after_short_write(self):
        ioctls = []
        def ioctl(fd, op, arg=None):
            ioctls.append((op, arg))
            return struct.pack('=I', 1)
        real = e.Disk.__new__(e.Disk)
        real.fd = self.disk.fd; real.path = str(self.disk.path)
        real.check = lambda *args, **kwargs: None
        paths = [self.bundle/s['name'] for s in self.plan['spans']]
        with patch.object(e.fcntl, 'ioctl', ioctl), patch.object(e.os, 'pwrite', return_value=1) as write:
            self.reject(lambda: real.write(self.plan['spans'], paths), 'short-write-no-retry')
        self.assertEqual(write.call_count, 1)
        self.assertEqual([(op, struct.unpack('=I', arg)[0]) for op, arg in ioctls if op == e.BLKROSET],
                         [(e.BLKROSET, 0), (e.BLKROSET, 1)])

    def test_packet_binding_and_bounds(self):
        cases = [lambda x: x['spans'][4].update(size=64*p.MIB),
                 lambda x: x['spans'][2].update(offset=p.MIB),
                 lambda x: x['spans'][0].update(name='../other'),
                 lambda x: x['spans'][1].update(size=True),
                 lambda x: x.update(execution_authority=True),
                 lambda x: x['experiment'].update(slot_id=True),
                 lambda x: x['capture_plan'].update(volume_uuid=str(uuid.uuid4())),
                 lambda x: x['reviews'].update(authorized_images=None),
                 lambda x: x['host'].update(disk_serial='CHANGED')]
        for mutate in cases:
            value = copy.deepcopy(self.plan); mutate(value)
            with self.assertRaises(e.Rejected): p.validate(value)
    def test_gpt_partition_and_checksums(self):
        data = (self.bundle/'gpt-primary.img').read_bytes()
        header = bytearray(data[512:604]); expected = struct.unpack_from('<I', header, 16)[0]
        struct.pack_into('<I', header, 16, 0)
        self.assertEqual(zlib.crc32(header), expected)
        entries = data[1024:17408]
        self.assertEqual(zlib.crc32(entries), struct.unpack_from('<I', data, 512+88)[0])
        part = entries[3*128:4*128]
        self.assertEqual(str(uuid.UUID(bytes_le=part[16:32])), config()['partition_uuid'])
        start, end = struct.unpack_from('<QQ', part, 32)
        self.assertEqual((start*512, (end-start+1)*512),
                         (self.plan['spans'][4]['offset'], 65*p.MIB))
        secondary = (self.bundle/'gpt-secondary.img').read_bytes()
        self.assertEqual(secondary[:128*128], entries)
    def test_immutable_entry_rejects_mutable_packet(self):
        proc = subprocess.run([sys.executable, '-I', str(SOURCE/'executor.py'), str(self.bundle), 'stage'], capture_output=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b'immutable-packet-required', proc.stderr)
    def test_private_projection_preserves_simulation_and_checks_raw(self):
        spec = importlib.util.spec_from_file_location('report', SOURCE/'report.py')
        report = importlib.util.module_from_spec(spec); spec.loader.exec_module(report)
        state = self.root/'capture'
        store = p.capture.Store(state)
        store.initialize(self.plan['capture_plan'], 'simulation')
        for phase in p.capture.PHASES:
            plan=self.plan['capture_plan']; boot=str(uuid.uuid4()); frames=[]
            for index, check in enumerate(p.capture.checks(phase), 1):
                frame=dict(schema_version=p.capture.EVENT_SCHEMA,
                           **{k: plan[k] for k in p.capture.BINDINGS},
                           phase=phase, boot_id=boot, sequence=index, check=check, passed=True)
                frames.append(p.capture.PREFIX+p.canonical(frame))
            tape=dict(schema_version=p.capture.TAPE_SCHEMA, phase=phase,
                      chunks=[dict(at_seconds=1, base64=base64.b64encode(b''.join(frames)).decode())])
            @contextlib.contextmanager
            def source(plan, current):
                yield p.capture.Simulation(tape, current)
            store.observe(source, lambda _: None)
        store.close()
        result=report.project(self.bundle, state)
        self.assertEqual(result['mode'], 'simulation')
        self.assertEqual(len(result['phases']), 2)
        self.assertIs(result['hardware_qualified'], False)
        self.assertIs(result['publication_authorized'], False)
        encoded=json.dumps(result)
        for forbidden in ('SYNTHETIC_DISK', 'SYNTHETIC_USB', 'uart_by_id', 'nonce_hex', 'board_serial', boot):
            self.assertNotIn(forbidden, encoded)
        with (state/'create.uart').open('ab') as f: f.write(b'changed')
        with self.assertRaises(report.p.capture.Rejected): report.project(self.bundle, state)

    def test_duplicate_json_and_unknown_fields(self):
        with self.assertRaises(e.Rejected): p.decode(b'{"a":1,"a":2}')
        value=copy.deepcopy(self.plan); value['command']='dd'
        with self.assertRaises(e.Rejected): p.validate(value)


if __name__ == '__main__': unittest.main()
