"""One fixed packet, six bounded spans, durable one-use stage and restore.

No signing, firmware, mounting, power, network, or arbitrary command interface.
Production entry is the immutable Nix wrapper with a baked-in packet path.
"""
import datetime
import errno
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import signal
import shutil
import stat
import struct
import subprocess
import sys

spec = importlib.util.spec_from_file_location('packet', Path(__file__).with_name('packet.py'))
packet = importlib.util.module_from_spec(spec); spec.loader.exec_module(packet)
require, canonical, load = packet.require, packet.canonical, packet.load
Rejected = packet.capture.Rejected
CHUNK = 1024 * 1024
BLKROSET, BLKROGET, BLKFLSBUF = 0x125d, 0x125e, 0x1261


def code_digest():
    sources = {name: packet.sha(Path(__file__).parent/name)
               for name in ('executor.py', 'packet.py', 'runner.py')}
    runtime = {name: os.path.realpath(shutil.which(name) or '/absent')
               for name in ('systemctl', 'udevadm', 'findmnt')}
    runtime['python'] = os.path.realpath(sys.executable)
    return hashlib.sha256(canonical(dict(sources=sources, runtime=runtime))).hexdigest()


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc)


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL, timeout=20)


def number(fd, op, fmt):
    return struct.unpack(fmt, fcntl.ioctl(fd, op, bytes(struct.calcsize(fmt))))[0]


def span_hash(fd, span):
    h = hashlib.sha256()
    for pos in range(0, span['size'], CHUNK):
        size = min(CHUNK, span['size']-pos)
        data = os.pread(fd, size, span['offset']+pos)
        require(len(data) == size, 'short-read')
        h.update(data)
    return h.hexdigest()


def trusted_path(path, directory=True):
    require(path.is_absolute(), 'absolute-path-required')
    for component in list(reversed(path.parents)) + [path]:
        st = component.lstat()
        require(not stat.S_ISLNK(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022, 'untrusted-path')
    st = path.lstat()
    require(stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode), 'path-type')
    if directory:
        require(stat.S_IMODE(st.st_mode) == 0o700, 'private-state-required')
    else:
        require(st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o600, 'private-file-required')


class Records:
    def __init__(self, root):
        self.root = root
        trusted_path(root)
        self.lock = os.open(root/'.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        trusted_path(root/'.lock', False)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.sync()
        # Persist the state directory's own name before any device mutation.
        parent = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try: os.fsync(parent)
        finally: os.close(parent)

    def sync(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try: os.fsync(fd)
        finally: os.close(fd)

    def has(self, name):
        return os.path.lexists(self.root/name)

    def read(self, name):
        trusted_path(self.root/name, False)
        return load(self.root/name)

    def save(self, name, data):
        fd = os.open(self.root/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            require(os.write(fd, canonical(data)) == len(canonical(data)), 'short-record-write')
            os.fsync(fd)
        finally: os.close(fd)
        self.sync()
        require(self.read(name) == data, 'record-readback')

    def close(self):
        os.close(self.lock)


def check_authority(records, p_hash, action):
    a = records.read('authorization.json')
    packet.capture.exact_fields(a, ('schema_version', 'packet_sha256', 'executor_sha256', 'reviewer_reference',
                                   'approved_at', 'expires_at', 'actions'))
    require(a['schema_version'] == 'kaiba.device-secret-media-authorization/v1alpha1' and
            a['packet_sha256'] == p_hash and a['executor_sha256'] == code_digest(), 'authorization-binding')
    require(isinstance(a['reviewer_reference'], str) and
            re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', a['reviewer_reference']), 'reviewer-reference')
    require(type(a['actions']) is list and len(set(a['actions'])) == len(a['actions']) and
            set(a['actions']) <= set(packet.ACTIONS) and action in a['actions'], 'action-not-authorized')
    try:
        begin, end = [datetime.datetime.fromisoformat(a[k]) for k in ('approved_at', 'expires_at')]
        now = timestamp()
        require(begin.tzinfo is not None and end.tzinfo is not None and
                begin <= now <= end and datetime.timedelta(0) < end-begin <= datetime.timedelta(hours=24), 'authorization-expired')
    except (TypeError, ValueError):
        raise Rejected('authorization-time') from None
    return hashlib.sha256(canonical(a)).hexdigest()


def inactive(numbers):
    namespaces = set()
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit(): continue
        try:
            st = (proc/'ns/mnt').stat(); ns = (st.st_dev, st.st_ino)
            if ns in namespaces: continue
            lines = (proc/'mountinfo').read_text().splitlines(); namespaces.add(ns)
        except OSError as error:
            if error.errno in (errno.ENOENT, errno.ESRCH): continue
            raise
        require(all(line.split()[2] not in numbers for line in lines), 'target-mounted')
        # Some filesystems expose a virtual device number in mountinfo. Check
        # the block source too, when it is visible in this namespace.
        for line in lines:
            source = line.split(' - ', 1)[1].split()[1]
            if not source.startswith('/'): continue
            source = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), source)
            try: mounted = os.stat(source)
            except FileNotFoundError: continue
            if stat.S_ISBLK(mounted.st_mode):
                require(f'{os.major(mounted.st_rdev)}:{os.minor(mounted.st_rdev)}' not in numbers, 'target-mounted')
    require(namespaces, 'no-mount-namespace')
    for line in Path('/proc/swaps').read_text().splitlines()[1:]:
        path = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), line.split()[0])
        st = os.stat(path); device = st.st_rdev if stat.S_ISBLK(st.st_mode) else st.st_dev
        require(f'{os.major(device)}:{os.minor(device)}' not in numbers, 'target-swap')


class Disk:
    def __init__(self, p):
        self.p, self.fd, self.sequence = p, None, None
        require(os.geteuid() == 0, 'root-required')
        h = p['host']
        require(os.uname().nodename == h['hostname'], 'wrong-host')
        machine = Path('/etc/machine-id').read_text().strip()
        require(re.fullmatch('[0-9a-f]{32}', machine) and
                hashlib.sha256(machine.encode()).hexdigest() == h['machine_id_sha256'], 'wrong-host-id')
        resolved = [os.path.realpath(h[k]) for k in ('disk_by_id', 'enclosure_by_id')]
        require(resolved[0] == resolved[1] and re.fullmatch('/dev/sd[a-z]+', resolved[0]), 'not-reviewed-usb-disk')
        self.path = resolved[0]
        self.base = Path('/sys/class/block')/Path(self.path).name
        require(not (self.base/'partition').exists(), 'whole-disk-required')
        self.check()
        self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.check(self.fd)
        except BaseException:
            self.close(); raise

    def check(self, fd=None, readonly=1):
        h = self.p['host']
        props = dict(line.split('=', 1) for line in command('udevadm', 'info', '--query=property', '--name='+self.path).splitlines() if '=' in line)
        expected = dict(ID_BUS='usb', ID_SERIAL_SHORT=h['disk_serial'], ID_USB_SERIAL_SHORT=h['enclosure_serial'],
                        ID_USB_VENDOR_ID=h['usb_vendor'], ID_USB_MODEL_ID=h['usb_product'])
        require(all(props.get(k) == v for k,v in expected.items()), 'disk-identity')
        entries = [os.stat(h[k]) for k in ('disk_by_id', 'enclosure_by_id')]
        st = os.stat(self.path, follow_symlinks=False)
        require(stat.S_ISBLK(st.st_mode) and st.st_uid == 0 and
                all(stat.S_ISBLK(e.st_mode) and e.st_rdev == st.st_rdev for e in entries), 'device-changed')
        guard = dict(line.split('=', 1) for line in command('systemctl', 'show', 'udisks2.service',
                    '--property=ActiveState,UnitFileState').splitlines() if '=' in line)
        require(guard == dict(ActiveState='inactive', UnitFileState='masked-runtime'), 'automount-guard')
        children = [self.base] + [x for x in self.base.iterdir() if (x/'partition').is_file()]
        require(all(not list((x/'holders').iterdir()) for x in children), 'target-holders')
        numbers = {(x/'dev').read_text().strip() for x in children}
        inactive(numbers)
        state_dev = os.stat(h['state_directory']).st_dev
        require(f'{os.major(state_dev)}:{os.minor(state_dev)}' not in numbers, 'backup-on-target')
        require(command('findmnt', '-n', '-o', 'FSTYPE', '--target', h['state_directory']).strip()
                in ('ext4', 'xfs', 'btrfs'), 'persistent-backup-required')
        require(int((self.base/'size').read_text())*512 == self.p['capacity_bytes'] and
                int((self.base/'queue/logical_block_size').read_text()) == 512 and
                int((self.base/'ro').read_text()) == readonly, 'device-geometry-or-guard')
        if fd is not None:
            opened = os.fstat(fd)
            require(stat.S_ISBLK(opened.st_mode) and opened.st_rdev == st.st_rdev, 'opened-device-changed')
            seq = number(fd, 0x80081280, '=Q')
            require(seq > 0 and (self.sequence is None or seq == self.sequence), 'attachment-changed')
            self.sequence = seq
            require(number(fd, 0x80081272, '=Q') == self.p['capacity_bytes'] and number(fd, 0x1268, '=I') == 512
                    and number(fd, BLKROGET, '=I') == readonly, 'opened-device-geometry-or-guard')

    def read_open(self):
        self.check(self.fd)
        fd = os.open(self.path, os.O_RDONLY | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self.check(fd); fcntl.ioctl(fd, BLKFLSBUF)
            return fd
        except BaseException:
            os.close(fd); raise

    def write(self, spans, paths):
        # Original read-only descriptor remains tied to this attachment even if
        # opening the writer fails. RO restoration is attempted on every exit.
        self.check(self.fd)
        writer = None
        try:
            fcntl.ioctl(self.fd, BLKROSET, struct.pack('=I', 0))
            writer = os.open(self.path, os.O_RDWR | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.check(writer, readonly=0)
            # Payload first; primary GPT last. This is not power-loss atomic.
            for index in (1, 2, 3, 4, 5, 0):
                span = spans[index]
                self.check(writer, readonly=0)
                with paths[index].open('rb') as f:
                    for pos in range(0, span['size'], CHUNK):
                        size = min(CHUNK, span['size']-pos); data = f.read(size)
                        require(len(data) == size, 'short-payload-read')
                        require(os.pwrite(writer, data, span['offset']+pos) == size, 'short-write-no-retry')
                    require(not f.read(1), 'long-payload')
                os.fsync(writer)
        finally:
            try:
                fcntl.ioctl(self.fd, BLKROSET, struct.pack('=I', 1))
                require(number(self.fd, BLKROGET, '=I') == 1, 'readonly-restore-failed')
            finally:
                if writer is not None: os.close(writer)
        self.check(self.fd)

    def close(self):
        if self.fd is not None: os.close(self.fd); self.fd = None


class Engine:
    def __init__(self, bundle, records, disk):
        self.bundle, self.r, self.disk = bundle, records, disk
        self.p = packet.validate(load(bundle/'packet.json'))
        self.hash = packet.sha(bundle/'packet.json')

    def previous(self, action):
        result = self.r.read(action+'.complete.json')
        require(result.get('packet_sha256') == self.hash and result.get('executor_sha256') == code_digest()
                and result.get('action') == action and result.get('result') == 'passed', 'prior-result-binding')
        return result

    def begin(self, action):
        require(not self.r.has(action+'.intent.json') and not self.r.has(action+'.complete.json'), 'action-already-attempted')
        authority = check_authority(self.r, self.hash, action)
        self.r.save(action+'.intent.json', dict(action=action, packet_sha256=self.hash, executor_sha256=code_digest(),
                    authorization_sha256=authority, started_at=timestamp().isoformat(),
                    host_boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()))

    def finish(self, action, spans):
        self.r.save(action+'.complete.json', dict(action=action, packet_sha256=self.hash, executor_sha256=code_digest(),
                    result='passed', spans=spans, finished_at=timestamp().isoformat(), hardware_qualified=False))

    def readback(self, spans):
        fd = self.disk.read_open()
        try:
            for s in spans:
                self.disk.check(fd)
                require(span_hash(fd, s) == s['sha256'], 'full-span-readback-mismatch')
            self.disk.check(fd)
        finally: os.close(fd)

    def backup(self):
        require(not self.r.has('stage.intent.json') and not self.r.has('restore.intent.json'), 'backup-order')
        self.begin('backup')
        saved = []
        fd = self.disk.read_open()
        try:
            for s in self.p['spans']:
                self.disk.check(fd)
                path = self.r.root/(s['name']+'.preimage')
                target = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                h = hashlib.sha256()
                try:
                    for pos in range(0, s['size'], CHUNK):
                        size = min(CHUNK, s['size']-pos); data = os.pread(fd, size, s['offset']+pos)
                        require(len(data) == size and os.write(target, data) == size, 'backup-short-io')
                        h.update(data)
                    os.fsync(target)
                finally: os.close(target)
                self.r.sync()
                require(packet.sha(path) == h.hexdigest(), 'backup-readback')
                saved.append(dict(s, sha256=h.hexdigest()))
            self.disk.check(fd)
        finally: os.close(fd)
        # Fresh descriptor/cache invalidation; backup hashes must match source.
        self.readback(saved)
        self.finish('backup', saved)

    def preimages(self):
        saved = self.previous('backup')['spans']
        require(type(saved) is list and len(saved) == 6, 'backup-spans')
        paths = []
        for original, s in zip(self.p['spans'], saved):
            packet.capture.exact_fields(s, ('name', 'offset', 'size', 'sha256'))
            require(all(original[k] == s[k] for k in ('name', 'offset', 'size')) and packet.hexdigest(s['sha256']), 'backup-extent')
            path = self.r.root/(s['name']+'.preimage'); trusted_path(path, False)
            require(path.stat().st_size == s['size'] and packet.sha(path) == s['sha256'], 'backup-corrupt')
            paths.append(path)
        return saved, paths

    def run(self, action):
        if action == 'backup': self.backup(); return
        if action == 'verify':
            self.previous('stage')
            require(not self.r.has('restore.intent.json'), 'already-restoring')
            self.readback(self.p['spans']); return
        require(action in ('stage', 'restore'), 'unsupported-action')
        # Verify authority before doing even the automatically included backup.
        check_authority(self.r, self.hash, action)
        require(not self.r.has(action+'.intent.json') and not self.r.has(action+'.complete.json'), 'action-already-attempted')
        if action == 'stage':
            require(not self.r.has('restore.intent.json'), 'already-restoring')
            if not self.r.has('backup.intent.json'): self.backup()
            original, _ = self.preimages()
            self.readback(original)
            spans = self.p['spans']; paths = [self.bundle/s['name'] for s in spans]
            for s, path in zip(spans, paths):
                require(path.is_file() and not path.is_symlink() and path.stat().st_size == s['size']
                        and packet.sha(path) == s['sha256'], 'artifact-corrupt')
        else:
            require(self.r.has('stage.intent.json'), 'nothing-staged')
            intent = self.r.read('stage.intent.json')
            require(intent.get('packet_sha256') == self.hash and intent.get('executor_sha256') == code_digest(), 'stage-intent-binding')
            spans, paths = self.preimages()
        self.begin(action)
        self.disk.write(spans, paths)
        self.readback(spans)
        self.finish(action, spans)


def main():
    require(len(sys.argv) == 3 and sys.argv[2] in ('describe', 'status', 'backup', 'stage', 'verify', 'restore'), 'command')
    bundle, action = Path(sys.argv[1]), sys.argv[2]
    require(str(bundle).startswith('/nix/store/') and bundle.is_dir(), 'immutable-packet-required')
    p = packet.validate(load(bundle/'packet.json'))
    if action == 'describe':
        print(canonical(dict(packet_sha256=packet.sha(bundle/'packet.json'), executor_sha256=code_digest(),
                             execution_authority=False, hardware_qualified=False)).decode(), end=''); return
    require(os.geteuid() == 0, 'root-required')
    os.umask(0o077)
    records = Records(Path(p['host']['state_directory']))
    disk = None
    try:
        if action == 'status':
            print(canonical({k: dict(attempted=records.has(k+'.intent.json'), complete_record_present=records.has(k+'.complete.json'))
                             for k in packet.ACTIONS}).decode(), end=''); return
        if action in packet.ACTIONS: check_authority(records, packet.sha(bundle/'packet.json'), action)
        disk = Disk(p)
        Engine(bundle, records, disk).run(action)
        print('RESULT passed '+action+' hardware_qualified=false', flush=True)
    finally:
        if disk: disk.close()
        records.close()


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise Rejected('interrupted-no-retry')
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP): signal.signal(sig, interrupted)
    try: main()
    except BaseException as error:
        # Error codes only, never raw device contents or exception interpolation.
        code = str(error) if isinstance(error, Rejected) else 'io-or-validation-failure'
        print('STOP: '+code+'; preserve state and do not repeat the action', file=sys.stderr)
        sys.exit(1)
