"""Passive, resumable capture for a planned two-boot device-secret experiment.

This program cannot sign, stage media, change power, transmit on UART, or call
firmware crypto. Target-reported checks are observations, never admission or
operation authority. Simulation runs cannot be resumed as hardware captures.
"""
import argparse
import base64
import datetime
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import stat
import sys
import termios
import time
import uuid

PLAN_SCHEMA = 'kaiba.device-secret-experiment-plan/v1alpha1'
EVENT_SCHEMA = 'kaiba.device-secret-experiment-event/v1alpha1'
STATE_SCHEMA = 'kaiba.device-secret-experiment-run/v1alpha1'
TAPE_SCHEMA = 'kaiba.device-secret-experiment-simulation/v1alpha1'
PREFIX = b'KAIBA_DEVICE_SECRET_EVENT='
PHASES = ('create', 'reopen')
BINDINGS = ('experiment_id', 'target_reference', 'source_revision', 'boot_image_sha256',
            'verity_root_hash', 'volume_uuid', 'nonce_sha256', 'slot_id')
COMMON_CHECKS = ('started', 'raw_read_blocked', 'legacy_read_blocked', 'key_write_locked',
                 'same_input', 'domain_separation', 'nonce_separation')
FINAL_CHECKS = ('hmac_closed', 'signing_closed', 'locks_cannot_clear', 'complete')
MAX_LINE = 4096
MAX_JSON = 1024 * 1024


class Rejected(Exception):
    """A bounded failure code; never includes untrusted input or secret bytes."""


def require(condition, code):
    if not condition:
        raise Rejected(code)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def decode(data):
    def finite_float(value):
        number = float(value)
        require(math.isfinite(number), 'nonfinite-json')
        return number

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_float=finite_float,
                          parse_constant=lambda _: (_ for _ in ()).throw(Rejected('nonfinite-json')))
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected('invalid-json') from None


def regular_bytes(path, maximum=MAX_JSON):
    # Reject special files before opening; recheck the opened inode as well.
    before = os.lstat(path)
    require(stat.S_ISREG(before.st_mode), 'input-not-regular')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        after = os.fstat(fd)
        require(stat.S_ISREG(after.st_mode) and (before.st_dev, before.st_ino) ==
                (after.st_dev, after.st_ino), 'input-changed')
        require(after.st_size <= maximum, 'input-too-large')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            data = stream.read(maximum + 1)
        require(len(data) <= maximum, 'input-too-large')
        return data
    finally:
        os.close(fd)


def exact_fields(value, fields):
    require(type(value) is dict and set(value) == set(fields), 'unexpected-fields')


def valid_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value and int(uuid.UUID(value)) != 0
    except (ValueError, TypeError, AttributeError):
        return False


def validate_plan(plan):
    exact_fields(plan, ('schema_version', *BINDINGS, 'uart_by_id', 'uart_by_path',
                        'idle_timeout_seconds', 'observation_seconds', 'maximum_bytes'))
    require(plan['schema_version'] == PLAN_SCHEMA, 'unsupported-plan')
    for key in ('experiment_id', 'target_reference'):
        require(isinstance(plan[key], str) and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', plan[key]), 'invalid-identifier')
    for key in ('boot_image_sha256', 'verity_root_hash', 'nonce_sha256', 'source_revision'):
        size = 40 if key == 'source_revision' else 64
        require(isinstance(plan[key], str) and re.fullmatch('[0-9a-f]{' + str(size) + '}', plan[key])
                and set(plan[key]) != {'0'}, 'invalid-binding')
    require(valid_uuid(plan['volume_uuid']), 'invalid-volume-uuid')
    require(type(plan['slot_id']) is int and 1 <= plan['slot_id'] <= 32, 'invalid-slot')
    for key, directory in [('uart_by_id', '/dev/serial/by-id/'), ('uart_by_path', '/dev/serial/by-path/')]:
        value = plan[key]
        require(isinstance(value, str) and value.startswith(directory)
                and re.fullmatch(r'[A-Za-z0-9_.:-]+', value[len(directory):])
                and value[len(directory):] not in ('.', '..'), 'invalid-uart-selector')
    for key, low, high in [('idle_timeout_seconds', 10, 3600), ('observation_seconds', 10, 600),
                           ('maximum_bytes', 4096, 16 * 1024 * 1024)]:
        require(type(plan[key]) is int and low <= plan[key] <= high, 'invalid-capture-bound')
    return plan


def checks(phase):
    require(phase in PHASES, 'invalid-phase')
    return COMMON_CHECKS + ('volume_created' if phase == 'create' else 'volume_reopened',) + FINAL_CHECKS


class Events:
    def __init__(self, plan, phase, previous_boots):
        self.plan, self.phase = plan, phase
        self.previous_boots = previous_boots
        self.buffer = b''
        self.records = []
        self.boot_id = None

    def feed(self, data):
        self.buffer += data
        while b'\n' in self.buffer:
            line, self.buffer = self.buffer.split(b'\n', 1)
            require(len(line) <= MAX_LINE, 'line-too-large')
            if PREFIX not in line:
                continue
            require(line.count(PREFIX) == 1, 'interleaved-or-duplicate-frame')
            payload = line.split(PREFIX, 1)[1].removesuffix(b'\r')
            record = decode(payload)
            exact_fields(record, ('schema_version', *BINDINGS, 'phase', 'boot_id', 'sequence', 'check', 'passed'))
            require(record['schema_version'] == EVENT_SCHEMA, 'unsupported-event')
            require(canonical(record).rstrip(b'\n') == payload, 'noncanonical-or-interleaved-frame')
            require(all(record[key] == self.plan[key] and type(record[key]) is type(self.plan[key])
                        for key in BINDINGS), 'event-binding-mismatch')
            require(record['phase'] == self.phase, 'unexpected-phase')
            require(valid_uuid(record['boot_id']), 'invalid-boot-id')
            require(record['boot_id'] not in self.previous_boots, 'replayed-boot-id')
            require(self.boot_id is None or record['boot_id'] == self.boot_id, 'extra-boot')
            index = len(self.records)
            require(index < len(checks(self.phase)), 'extra-event')
            require(type(record['sequence']) is int and record['sequence'] == index + 1
                    and record['check'] == checks(self.phase)[index], 'event-order')
            require(type(record['passed']) is bool, 'invalid-outcome')
            require(record['passed'], 'target-check-failed:' + checks(self.phase)[index])
            self.boot_id = record['boot_id']
            self.records.append(record)
        require(len(self.buffer) <= MAX_LINE, 'line-too-large')

    def finish(self):
        require(PREFIX not in self.buffer, 'truncated-frame')
        require(not self.buffer or self.buffer.isspace(), 'truncated-line')
        require(len(self.records) == len(checks(self.phase)), 'missing-events')


class Serial:
    """Fixed read-only UART, exclusive open, continuous attachment checks."""
    def __init__(self, plan):
        self.paths = (plan['uart_by_id'], plan['uart_by_path'])
        self.fd = None
        self.original = None
        self.exclusive = False

    def identity(self):
        values = [os.stat(path) for path in self.paths]
        require(all(stat.S_ISCHR(v.st_mode) for v in values), 'uart-not-character-device')
        values = [(v.st_dev, v.st_ino, v.st_rdev) for v in values]
        require(values[0] == values[1], 'uart-selectors-disagree')
        return values[0]

    def verify(self):
        current = os.fstat(self.fd)
        require(self.identity() == self.expected == (current.st_dev, current.st_ino, current.st_rdev), 'uart-reattached')

    def __enter__(self):
        self.expected = self.identity()
        try:
            self.fd = os.open(self.paths[0], os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC)
            self.verify()
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.ioctl(self.fd, termios.TIOCEXCL)
            self.exclusive = True
            self.original = termios.tcgetattr(self.fd)
            settings = termios.tcgetattr(self.fd)
            settings[0] = settings[1] = settings[3] = 0
            settings[2] &= ~(termios.CSIZE | termios.PARENB | termios.CSTOPB | termios.CRTSCTS | termios.HUPCL)
            settings[2] |= termios.CS8 | termios.CREAD | termios.CLOCAL
            settings[4] = settings[5] = termios.B115200
            settings[6][termios.VMIN] = settings[6][termios.VTIME] = 0
            termios.tcsetattr(self.fd, termios.TCSANOW, settings)
            termios.tcflush(self.fd, termios.TCIFLUSH)
            self.verify()
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def __exit__(self, *unused):
        error = None
        if self.fd is not None:
            try:
                if self.original is not None:
                    termios.tcsetattr(self.fd, termios.TCSANOW, self.original)
            except (OSError, termios.error) as failure:
                error = failure
            try:
                if self.exclusive:
                    fcntl.ioctl(self.fd, termios.TIOCNXCL)
            except (OSError, termios.error) as failure:
                error = failure
            finally:
                os.close(self.fd)
                self.fd = None
        if error:
            raise Rejected('uart-cleanup-failed') from None

    def now(self):
        return time.monotonic()

    def read(self, wait):
        self.verify()
        if not select.select([self.fd], [], [], wait)[0]:
            return b''
        try:
            data = os.read(self.fd, 4096)
        except BlockingIOError:
            return b''
        require(bool(data), 'uart-disconnected')
        self.verify()
        return data


class Simulation:
    def __init__(self, tape, phase):
        exact_fields(tape, ('schema_version', 'phase', 'chunks'))
        require(tape['schema_version'] == TAPE_SCHEMA and tape['phase'] == phase, 'invalid-simulation')
        require(type(tape['chunks']) is list and len(tape['chunks']) <= 10000, 'invalid-simulation')
        self.chunks = []
        prior, total = 0, 0
        for chunk in tape['chunks']:
            exact_fields(chunk, ('at_seconds', 'base64'))
            at = chunk['at_seconds']
            require(type(at) in (int, float) and prior <= at <= 7200, 'invalid-simulation-time')
            try:
                data = base64.b64decode(chunk['base64'], validate=True)
            except (ValueError, TypeError):
                raise Rejected('invalid-simulation-bytes') from None
            total += len(data)
            require(total <= MAX_JSON, 'simulation-too-large')
            self.chunks.append((at, data))
            prior = at
        self.clock = 0.0

    def now(self):
        return self.clock

    def read(self, wait):
        if self.chunks and self.chunks[0][0] <= self.clock + wait:
            self.clock, data = self.chunks.pop(0)
            return data
        self.clock += wait
        return b''


def capture(plan, phase, previous_boots, source, raw):
    events = Events(plan, phase, previous_boots)
    started = source.now()
    deadline = started + plan['idle_timeout_seconds']
    boot_at = None
    count = 0
    while True:
        remaining_time = deadline - source.now()
        if remaining_time <= 0:
            break
        data = source.read(min(0.25, remaining_time))
        received_at = source.now()
        if not data:
            # select() can return just after its timeout through ordinary
            # scheduling latency. An empty final wait completes the window.
            continue
        remaining = plan['maximum_bytes'] - count
        retained = data[:remaining]
        raw.write(retained)
        raw.flush()
        os.fsync(raw.fileno())
        count += len(retained)
        require(len(data) <= remaining, 'capture-byte-limit')
        require(received_at <= deadline, 'capture-deadline-overrun')
        events.feed(data)
        if boot_at is None and events.boot_id is not None:
            boot_at = received_at
            deadline = boot_at + plan['observation_seconds']
    require(boot_at is not None, 'boot-not-observed')
    events.finish()
    return {'outcome': 'matched-target-report', 'boot_id': events.boot_id,
            'checks': [r['check'] for r in events.records], 'wait_for_boot_seconds': boot_at - started,
            'observation_seconds': source.now() - boot_at, 'capture_complete': True}


class Store:
    """Owner-only state with one writer, atomic checkpoints and durable intents."""
    def __init__(self, path):
        self.path = Path(path)
        require(self.path.is_absolute() and str(self.path) == str(self.path.resolve()), 'state-path-not-canonical')
        self.path.mkdir(mode=0o700, parents=False, exist_ok=True)
        parent = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.lock = None
        try:
            info = os.fstat(self.fd)
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'state-directory-not-private')
            self.lock = os.open('.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
            self.check_file(self.lock)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def check_file(fd):
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600, 'state-file-not-private')

    def close(self):
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def write(self, name, value, replace=False):
        target = '.checkpoint' if replace else name
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
        if replace:
            os.rename(target, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)

    def read(self, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.fd)
        with os.fdopen(fd, 'rb') as stream:
            self.check_file(stream.fileno())
            data = stream.read(MAX_JSON + 1)
        require(len(data) <= MAX_JSON, 'state-too-large')
        return decode(data)

    def initialize(self, plan, mode):
        require(mode in ('uart', 'simulation'), 'invalid-mode')
        require(not os.listdir(self.path) or os.listdir(self.path) == ['.lock'], 'state-already-initialized')
        validate_plan(plan)
        self.write('plan.json', plan)
        state = {'schema_version': STATE_SCHEMA, 'plan_sha256': digest(canonical(plan)), 'mode': mode,
                 'completed': [], 'active_phase': None, 'blocked': None,
                 'hardware_qualified': False, 'execution_authority': False}
        self.write('state.json', state)
        return state

    def load(self):
        require('.checkpoint' not in os.listdir(self.fd), 'interrupted-checkpoint-needs-review')
        plan = validate_plan(self.read('plan.json'))
        state = self.read('state.json')
        exact_fields(state, ('schema_version', 'plan_sha256', 'mode', 'completed', 'active_phase',
                             'blocked', 'hardware_qualified', 'execution_authority'))
        require(state['schema_version'] == STATE_SCHEMA and state['plan_sha256'] == digest(canonical(plan)), 'state-plan-mismatch')
        require(state['mode'] in ('uart', 'simulation') and state['hardware_qualified'] is False
                and state['execution_authority'] is False, 'invalid-state-scope')
        require(type(state['completed']) is list and len(state['completed']) <= 2, 'invalid-state-progress')
        expected_phase = PHASES[len(state['completed'])] if len(state['completed']) < 2 else None
        require(state['active_phase'] is None or state['active_phase'] == expected_phase, 'invalid-active-phase')
        require(state['blocked'] is None or (isinstance(state['blocked'], str) and
                re.fullmatch(r'[a-z0-9:-]{1,96}', state['blocked'])), 'invalid-blocked-state')
        boot_ids = []
        for index, saved in enumerate(state['completed']):
            exact_fields(saved, ('phase', 'result_sha256'))
            phase = PHASES[index]
            require(saved['phase'] == phase, 'invalid-state-order')
            result = self.read(phase + '.result.json')
            exact_fields(result, ('outcome', 'boot_id', 'checks', 'wait_for_boot_seconds',
                'observation_seconds', 'capture_complete', 'finished_at', 'phase', 'mode',
                'raw_sha256', 'raw_bytes', 'hardware_qualified', 'execution_authority'))
            require(type(result['observation_seconds']) in (float, int)
                    and type(result['wait_for_boot_seconds']) in (float, int)
                    and 0 <= result['wait_for_boot_seconds'] <= plan['idle_timeout_seconds']
                    and type(result['raw_bytes']) is int and 0 <= result['raw_bytes'] <= plan['maximum_bytes'],
                    'invalid-result-bounds')
            require(digest(canonical(result)) == saved['result_sha256'] and result['outcome'] == 'matched-target-report'
                    and result['mode'] == state['mode'] and result['capture_complete'] is True
                    and result['hardware_qualified'] is False and result['execution_authority'] is False
                    and result['phase'] == phase and result['checks'] == list(checks(phase))
                    and result['observation_seconds'] >= plan['observation_seconds'], 'result-mismatch')
            raw = regular_bytes(self.path / (phase + '.uart'), 16 * 1024 * 1024)
            require(digest(raw) == result['raw_sha256'] and len(raw) == result['raw_bytes'], 'raw-capture-mismatch')
            require(valid_uuid(result['boot_id']) and result['boot_id'] not in boot_ids, 'replayed-boot-id')
            boot_ids.append(result['boot_id'])
        return plan, state, boot_ids

    def observe(self, source_factory, ready):
        plan, state, boot_ids = self.load()
        require(state['blocked'] is None and state['active_phase'] is None, 'run-needs-review-no-automatic-retry')
        require(len(state['completed']) < len(PHASES), 'run-already-complete')
        phase = PHASES[len(state['completed'])]
        ready(phase)
        # Persist before opening UART. An interruption cannot replay this phase.
        state['active_phase'] = phase
        self.write('state.json', state, replace=True)
        self.write(phase + '.intent.json', {'created_at': utc(), 'phase': phase, 'mode': state['mode'],
                    'plan_sha256': state['plan_sha256'],
                    'operator_isolation': 'operator-confirmed-off-and-isolated' if state['mode'] == 'uart' else 'synthetic'})
        fd = os.open(phase + '.uart', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        os.fsync(self.fd)
        result = {'outcome': 'incomplete', 'capture_complete': False}
        failure = None
        try:
            with os.fdopen(fd, 'wb') as raw:
                with source_factory(plan, phase) as source:
                    result = capture(plan, phase, boot_ids, source, raw)
        except (Rejected, OSError, termios.error, KeyboardInterrupt) as error:
            failure = str(error) if isinstance(error, Rejected) else 'capture-io-error-or-interrupted'
            result = {'outcome': 'needs-review', 'capture_complete': False, 'failure': failure}
        raw = regular_bytes(self.path / (phase + '.uart'), 16 * 1024 * 1024)
        result.update(finished_at=utc(), phase=phase, mode=state['mode'], raw_sha256=digest(raw), raw_bytes=len(raw),
                      hardware_qualified=False, execution_authority=False)
        self.write(phase + '.result.json', result)
        if failure:
            state['blocked'] = failure
        else:
            state['completed'].append({'phase': phase, 'result_sha256': digest(canonical(result))})
            state['active_phase'] = None
        self.write('state.json', state, replace=True)
        return state


def show(state):
    next_phase = PHASES[len(state['completed'])] if len(state['completed']) < 2 else None
    print(json.dumps({'mode': state['mode'], 'completed_phases': [c['phase'] for c in state['completed']],
        'next_phase': next_phase, 'needs_review': bool(state['blocked'] or state['active_phase']),
        'stop_reason': state['blocked'] or ('interrupted-capture' if state['active_phase'] else None),
        'hardware_qualified': False, 'execution_authority': False}, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('init', 'status', 'run', 'rehearse'):
        cmd = sub.add_parser(command)
        cmd.add_argument('--state', required=True)
        if command == 'init':
            cmd.add_argument('--plan', required=True)
            cmd.add_argument('--mode', required=True, choices=['uart', 'simulation'])
        if command == 'rehearse':
            cmd.add_argument('--tape', required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    store = None
    try:
        store = Store(args.state)
        if args.command == 'init':
            show(store.initialize(decode(regular_bytes(args.plan)), args.mode))
        elif args.command == 'status':
            show(store.load()[1])
        elif args.command == 'rehearse':
            from contextlib import contextmanager
            require(store.load()[1]['mode'] == 'simulation', 'simulation-cannot-enter-uart-run')
            tape = decode(regular_bytes(args.tape))
            @contextmanager
            def simulated(plan, phase):
                yield Simulation(tape, phase)
            state = store.observe(simulated, lambda phase: None)
            show(state)
            return 3 if state['blocked'] else 0
        else:
            from contextlib import contextmanager
            require(store.load()[1]['mode'] == 'uart', 'uart-cannot-enter-simulation-run')
            require(sys.stdin.isatty(), 'manual-readiness-requires-terminal')
            def ready(phase):
                print('Phase ' + phase + ': confirm the reviewed procedure, Pi fully off for 10 seconds,')
                print('network/data disconnected, intended media fitted, UART unchanged. Type READY.')
                require(input().strip() == 'READY', 'operator-readiness-not-confirmed')
            @contextmanager
            def serial(plan, phase):
                with Serial(plan) as source:
                    print('CAPTURE_ARMED: apply isolated power now. No powered acknowledgement is needed.', flush=True)
                    yield source
            while len(store.load()[1]['completed']) < 2:
                state = store.observe(serial, ready)
                show(state)
                if state['blocked']:
                    return 3
            print('Both target-report captures matched. Retain readback and physical records for review; no qualification is granted.')
        return 0
    except (Rejected, OSError, KeyboardInterrupt, EOFError) as error:
        code = str(error) if isinstance(error, Rejected) else 'local-io-error-or-interrupted'
        print('STOP: ' + code + '; preserve state; do not retry an uncertain phase', file=sys.stderr)
        return 3
    finally:
        if store:
            store.close()


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
