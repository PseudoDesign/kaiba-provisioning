"""Bounded operator-launched enrollment orchestration; Linux only.

The reviewed adapter is privileged execution code, not untrusted data. It owns
host/device operations and authoritative reconciliation. This runner owns order,
one-use intents, deadlines, secret lifetime, and the completion boundary.
"""
import argparse
import ctypes
import datetime as dt
import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import resource
import select
import signal
import stat
import subprocess
import sys
import termios
import time

SCHEMA = 'kaiba.pilot-enrollment-run/v1alpha1'
STEPS = ('prepare-authority', 'prepare-device', 'initialize-device',
         'start-enrollment', 'submit-bootstrap', 'install-credential',
         'prove-installed', 'activate', 'verify-access', 'test-isolation',
         'test-restart', 'backup', 'resume-serving', 'remove-temporary-access')
HEX = re.compile(r'[0-9a-f]{64}\Z')
LABEL = re.compile(r'[a-z0-9][a-z0-9-]{0,63}\Z')
MAX_JSON = 65536


class Stop(Exception):
    """Only fixed codes: no subprocess output or secret values in exceptions."""


def require(ok, code):
    if not ok:
        raise Stop(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate-field')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Stop('nonfinite-json')))
    except (ValueError, UnicodeError, RecursionError):
        raise Stop('invalid-json') from None


def fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names), 'unexpected-fields')


def timestamp(value):
    require(isinstance(value, str) and value.endswith('Z'), 'invalid-time')
    try:
        return dt.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except ValueError:
        raise Stop('invalid-time') from None


def read_file(path, maximum=MAX_JSON, owner=None, mode=None):
    # Reject special files before opening, then check the opened inode again.
    before = Path(path).lstat()
    require(stat.S_ISREG(before.st_mode), 'not-regular')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        s = os.fstat(stream.fileno())
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and
                (s.st_dev, s.st_ino) == (before.st_dev, before.st_ino), 'file-changed')
        require(owner is None or s.st_uid == owner, 'wrong-owner')
        require(owner is None or not s.st_mode & 0o022, 'writable-by-others')
        require(mode is None or stat.S_IMODE(s.st_mode) == mode, 'wrong-mode')
        require(s.st_size <= maximum, 'file-too-large')
        data = stream.read(maximum + 1)
        require(len(data) <= maximum, 'file-too-large')
        return data


def trusted_parent(path, owner):
    current = Path(path)
    while True:
        s = current.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == owner and
                not s.st_mode & 0o022, 'untrusted-parent')
        if current.parent == current:
            break
        current = current.parent


def validate(packet):
    fields(packet, ('schema_version', 'run_id', 'asset', 'target_digest',
                    'issued_at', 'expires_at', 'host_boot_id', 'state_directory',
                    'progress_file', 'observer_uid', 'adapter', 'context',
                    'step_timeout_seconds'))
    require(packet['schema_version'] == SCHEMA, 'wrong-schema')
    for key in ('run_id', 'asset'):
        require(isinstance(packet[key], str) and LABEL.fullmatch(packet[key]), 'invalid-label')
    require(isinstance(packet['target_digest'], str) and HEX.fullmatch(packet['target_digest']), 'invalid-target')
    start, end = timestamp(packet['issued_at']), timestamp(packet['expires_at'])
    require(0 < end - start <= 12 * 3600, 'invalid-window')
    require(isinstance(packet['host_boot_id'], str) and
            re.fullmatch(r'[0-9a-f-]{36}', packet['host_boot_id']), 'invalid-boot')
    for key in ('state_directory', 'progress_file'):
        path = packet[key]
        require(isinstance(path, str) and path.startswith('/') and
                '..' not in Path(path).parts and str(Path(path)) == path, 'invalid-path')
    require(Path(packet['state_directory']) != Path(packet['progress_file']) and
            Path(packet['state_directory']) not in Path(packet['progress_file']).parents,
            'progress-inside-journal')
    require(type(packet['observer_uid']) is int and packet['observer_uid'] >= 0, 'invalid-observer')
    require(type(packet['step_timeout_seconds']) is int and
            1 <= packet['step_timeout_seconds'] <= 1800, 'invalid-timeout')
    for key in ('adapter', 'context'):
        fields(packet[key], ('path', 'sha256'))
        item = packet[key]
        require(isinstance(item['path'], str) and len(item['path']) <= 1024 and item['path'].startswith('/') and
                '..' not in Path(item['path']).parts, 'invalid-input-path')
        require(isinstance(item['sha256'], str) and HEX.fullmatch(item['sha256']), 'invalid-hash')
    require(packet['adapter']['path'].startswith('/nix/store/'), 'adapter-must-be-immutable')


class Secret:
    """No Python string copy: terminal -> locked anonymous page -> backup pipe."""
    def __init__(self):
        self.page = mmap.mmap(-1, mmap.PAGESIZE)
        self.address = ctypes.addressof(ctypes.c_char.from_buffer(self.page))
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        self.libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        self.libc.read.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
        self.libc.read.restype = ctypes.c_ssize_t
        self.size = 0
        if self.libc.mlock(ctypes.c_void_p(self.address), mmap.PAGESIZE) != 0:
            self.page.close()
            raise Stop('cannot-lock-secret-memory')
        try:
            self.page.madvise(mmap.MADV_DONTDUMP)
        except BaseException:
            self.close()
            raise

    def prompt(self, tty, timeout=300):
        old = termios.tcgetattr(tty)
        new = list(old)
        new[3] &= ~(termios.ECHO | termios.ICANON)
        new[6] = list(old[6]); new[6][termios.VMIN] = 1; new[6][termios.VTIME] = 0
        deadline = time.monotonic() + timeout
        termios.tcsetattr(tty, termios.TCSAFLUSH, new)
        scratch = mmap.PAGESIZE - 1
        try:
            os.write(tty, b'Saved backup recovery passphrase (held in RAM until backup finishes): ')
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0 and select.select([tty], [], [], remaining)[0], 'credential-prompt-timeout')
                count = self.libc.read(tty, ctypes.c_void_p(self.address + scratch), 1)
                require(count == 1, 'credential-input-failed')
                byte = self.page[scratch]; self.page[scratch] = 0
                if byte in (10, 13):
                    require(self.size > 0, 'empty-credential')
                    break
                if byte in (8, 127):
                    if self.size:
                        self.size -= 1; self.page[self.size] = 0
                    continue
                require(byte >= 32 and self.size < 1024, 'invalid-credential-input')
                self.page[self.size] = byte; self.size += 1
        finally:
            termios.tcsetattr(tty, termios.TCSAFLUSH, old)
            os.write(tty, b'\n')

    def pipe(self):
        read, write = os.pipe2(os.O_CLOEXEC)
        try:
            # <=1024 bytes fits in an empty pipe; no secret in argv/env/files.
            sent = os.write(write, memoryview(self.page)[:self.size])
            require(sent == self.size, 'credential-pipe-failed')
        except BaseException:
            os.close(read)
            raise
        finally:
            os.close(write)
        return read

    def close(self):
        if not self.page.closed:
            ctypes.memset(ctypes.c_void_p(self.address), 0, mmap.PAGESIZE)
            self.libc.munlock(ctypes.c_void_p(self.address), mmap.PAGESIZE)
            self.page.close()
            self.size = 0


class Journal:
    def __init__(self, directory, binding, create):
        self.path = Path(directory)
        self.owner = os.geteuid()
        if create:
            self.path.mkdir(mode=0o700)
        s = self.path.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == self.owner and
                stat.S_IMODE(s.st_mode) == 0o700, 'unsafe-journal')
        self.lock = os.open(self.path / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        lock_stat = os.fstat(self.lock)
        require(stat.S_ISREG(lock_stat.st_mode) and lock_stat.st_nlink == 1 and
                lock_stat.st_uid == self.owner and stat.S_IMODE(lock_stat.st_mode) == 0o600, 'unsafe-lock')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.lock)
            raise Stop('job-already-running') from None
        if create:
            self.write('binding.json', binding)
            parent = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        require(self.read('binding.json') == binding, 'journal-binding-changed')

    def read(self, name):
        path = self.path / name
        if not path.exists():
            require(not path.is_symlink(), 'journal-symlink')
            return None
        return decode(read_file(path, owner=self.owner, mode=0o600))

    def write(self, name, value):
        fd = os.open(self.path / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
        self.sync()

    def sync(self):
        fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def close(self):
        os.close(self.lock)


class Adapter:
    def __init__(self, packet, packet_hash, guard, secret):
        self.packet, self.packet_hash, self.guard, self.secret = packet, packet_hash, guard, secret

    def validate_completion(self, result, step):
        fields(result, ('schema_version', 'run_id', 'target_digest', 'operation_id', 'action', 'step', 'outcome'))
        require(result['action'] in ('execute', 'reconcile') and result == {
            'schema_version': SCHEMA, 'run_id': self.packet['run_id'],
            'target_digest': self.packet['target_digest'],
            'operation_id': sha(canonical([self.packet_hash, step])),
            'action': result['action'], 'step': step, 'outcome': 'complete'}, 'journal-completion-binding')

    def call(self, action, step):
        self.guard(cleanup=action == 'safe-stop')
        timeout = min(self.packet['step_timeout_seconds'], 60 if action == 'safe-stop' else timestamp(self.packet['expires_at']) - time.time())
        require(timeout > 0, 'execution-window-expired')
        request = dict(schema_version=SCHEMA, packet_sha256=self.packet_hash,
                       run_id=self.packet['run_id'], target_digest=self.packet['target_digest'],
                       context=self.packet['context'], action=action, step=step,
                       operation_id=sha(canonical([self.packet_hash, step])))
        argv = [self.packet['adapter']['path']]
        keyfd = None
        if (action == 'execute' and step == 'backup') or action == 'check-credential':
            require(self.secret is not None and self.secret.size > 0, 'backup-credential-missing')
            keyfd = self.secret.pipe()
            argv += ['--recovery-key-fd', str(keyfd)]
        process = None
        try:
            # No controlling terminal and no inherited environment/other descriptors.
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, close_fds=True,
                                       pass_fds=() if keyfd is None else (keyfd,),
                                       start_new_session=True,
                                       env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
            if keyfd is not None:
                os.close(keyfd); keyfd = None
            request_raw = canonical(request)
            require(len(request_raw) <= 4096, 'adapter-request-too-large')
            process.stdin.write(request_raw); process.stdin.close()
            raw = bytearray(); end = time.monotonic() + timeout
            while True:
                remaining = end - time.monotonic()
                require(remaining > 0, 'adapter-timeout')
                require(select.select([process.stdout], [], [], remaining)[0], 'adapter-timeout')
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                raw.extend(chunk)
                require(len(raw) <= MAX_JSON, 'adapter-response-too-large')
            require(process.wait(timeout=max(0.01, end-time.monotonic())) == 0, 'adapter-failed')
            result = decode(raw)
            fields(result, ('schema_version', 'run_id', 'target_digest', 'operation_id', 'action', 'step', 'outcome'))
            require(result == {key: request[key] for key in result if key != 'outcome'} |
                    {'outcome': result['outcome']}, 'adapter-response-binding')
            require(result['outcome'] in ('complete', 'unknown', 'blocked'), 'adapter-outcome')
            # Only this closed response enters the journal. Raw stdout/stderr never does.
            return result
        finally:
            if keyfd is not None:
                os.close(keyfd)
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                for stream in (process.stdin, process.stdout):
                    stream.close()


class Run:
    def __init__(self, journal, adapter, guard, publish=lambda value: None):
        self.journal, self.adapter, self.guard, self.publish = journal, adapter, guard, publish

    def request(self, action, step):
        try:
            return self.adapter.call(action, step)
        except (Stop, OSError, subprocess.SubprocessError) as error:
            if isinstance(error, Stop) and str(error) == 'interrupted':
                raise
            return None

    def step(self, step):
        self.guard()
        done = self.journal.read(step + '.complete.json')
        if done:
            self.adapter.validate_completion(done, step)
            return
        self.publish({'status': 'running', 'step': step})
        intent = self.journal.read(step + '.intent.json')
        if intent is None:
            self.journal.write(step + '.intent.json', {'step': step})
            result = self.request('execute', step)
        else:
            result = None
        if not result or result['outcome'] != 'complete':
            # Read-only reconciliation can recognize a committed operation after a
            # lost reply. It cannot authorize re-execution of an uncertain mutation.
            result = self.request('reconcile', step)
        require(result is not None and result['outcome'] == 'complete', 'reconciliation-required:' + step)
        self.adapter.validate_completion(result, step)
        self.journal.write(step + '.complete.json', result)

    def run(self):
        require(self.journal.read('result.json') is None, 'job-already-complete')
        try:
            preflight = self.adapter.call('preflight', 'preflight')
            require(preflight['outcome'] == 'complete', 'preflight-blocked')
            for step in STEPS:
                self.step(step)
                if step == 'backup' and self.adapter.secret is not None:
                    self.adapter.secret.close(); self.adapter.secret = None
            result = {'status': 'passed', 'completed_steps': list(STEPS),
                      'full_qualification': False, 'authority': 'reviewed-pilot-only'}
            self.journal.write('result.json', result); self.publish(result)
            return result
        except BaseException:
            # This is a separately reviewed, idempotent safe-stop, never rollback
            # of enrollment/issuance. It must not resume old serving after new writes.
            started = any(self.journal.read(step + '.intent.json') is not None for step in STEPS)
            cleanup = self.request('safe-stop', 'safe-stop') if started else None
            self.publish({'status': 'stopped', 'cleanup_verified':
                          cleanup is not None and cleanup['outcome'] == 'complete'})
            raise


def live_guard(packet, cleanup=False):
    now = time.time()
    if not cleanup:
        require(timestamp(packet['issued_at']) <= now < timestamp(packet['expires_at']), 'execution-window-expired')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == packet['host_boot_id'], 'host-rebooted')
    require(len(Path('/proc/swaps').read_text().splitlines()) == 1, 'swap-must-be-disabled')
    for name in ('adapter', 'context'):
        item = packet[name]
        raw = read_file(item['path'], 16*1024*1024 if name == 'adapter' else MAX_JSON,
                        owner=0, mode=None if name == 'adapter' else 0o600)
        require(sha(raw) == item['sha256'], 'reviewed-input-changed')
        if name == 'context':
            trusted_parent(Path(item['path']).parent, 0)


def progress_writer(packet, create):
    path = Path(packet['progress_file'])
    trusted_parent(path.parent, 0)
    if create:
        require(not path.exists() and not path.is_symlink(), 'progress-path-exists')
    elif path.exists() or path.is_symlink():
        read_file(path, owner=packet['observer_uid'], mode=0o600)
    def publish(result):
        data = dict(schema_version=SCHEMA, run_id=packet['run_id'], asset=packet['asset'],
                    updated_at=dt.datetime.now(dt.timezone.utc).isoformat(), runner_pid=os.getpid(), **result)
        # This is observation output only, never read back as execution authority.
        temporary = path.with_name(path.name + '.new')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchown(fd, packet['observer_uid'], -1)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(canonical(data)); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path)
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        except BaseException:
            if temporary.exists():
                temporary.unlink()
            raise
    return publish


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('validate', 'run', 'resume'))
    parser.add_argument('--packet', required=True)
    parser.add_argument('--sha256', required=True, help='independently reviewed packet digest')
    parser.add_argument('--retain-recovery-passphrase', action='store_true',
                        help='consent to one local prompt and RAM retention through backup')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'root-launch-required')
    os.umask(0o077); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None)
    require(libc.prctl(4, 0, 0, 0, 0) == 0, 'cannot-disable-dumpability')
    trusted_parent(Path(args.packet).parent, 0)
    raw = read_file(args.packet, owner=0, mode=0o600)
    require(sha(raw) == args.sha256, 'packet-digest-mismatch')
    packet = decode(raw); validate(packet); live_guard(packet)
    if args.command == 'validate':
        print('Packet structure and local guards passed; adapter preflight and execution not run.')
        return
    trusted_parent(Path(packet['state_directory']).parent, 0)
    require(args.packet != packet['progress_file'] and packet['context']['path'] != packet['progress_file'],
            'progress-overlaps-input')
    publish = progress_writer(packet, args.command == 'run')
    secret = None; journal = None; executing = False; ready = False
    try:
        journal = Journal(packet['state_directory'], {'packet_sha256': args.sha256}, args.command == 'run')
        require(journal.read('result.json') is None, 'job-already-complete')
        ready = True
        publish({'status': 'preflight'})
        need_secret = journal.read('backup.complete.json') is None
        adapter = Adapter(packet, args.sha256, lambda cleanup=False: live_guard(packet, cleanup), None)
        # Read-only preflight before any prompt. Run checks it again after the prompt.
        require(adapter.call('preflight', 'preflight')['outcome'] == 'complete', 'preflight-blocked')
        if need_secret:
            require(args.retain_recovery_passphrase, 'explicit-retention-consent-required')
            secret = Secret()
            tty = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
            try:
                secret.prompt(tty)
            finally:
                os.close(tty)
            adapter.secret = secret
            require(adapter.call('check-credential', 'check-credential')['outcome'] == 'complete',
                    'recovery-credential-not-verified')
        executing = True
        Run(journal, adapter, lambda: live_guard(packet), publish).run()
        print('RESULT passed: reviewed pilot enrollment sequence and backup completed.')
    except BaseException:
        if ready and not executing:
            publish({'status': 'stopped-before-execution'})
        raise
    finally:
        if secret is not None:
            secret.close()
        if journal is not None:
            journal.close()


if __name__ == '__main__':
    def interrupted(_signal, _frame):
        raise Stop('interrupted')
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(sig, interrupted)
    try:
        main()
    except (Stop, OSError, ValueError, subprocess.SubprocessError) as error:
        print('STOP: ' + (str(error) if isinstance(error, Stop) else type(error).__name__) +
              '; preserve state and reconcile. No automatic mutation retry.', file=sys.stderr)
        sys.exit(1)
