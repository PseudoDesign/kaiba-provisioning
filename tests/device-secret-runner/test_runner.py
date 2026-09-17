import base64
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import termios
import unittest
from unittest import mock

SCRIPT = Path(os.environ.get('KAIBA_DEVICE_SECRET_RUNNER_SOURCE',
    Path(__file__).resolve().parents[2] / 'scripts/device-secret/runner.py'))
spec = importlib.util.spec_from_file_location('runner', SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
BOOT1 = '11111111-1111-4111-8111-111111111111'
BOOT2 = '22222222-2222-4222-8222-222222222222'


def plan():
    return dict(schema_version=runner.PLAN_SCHEMA, experiment_id='synthetic-test-only',
        target_reference='synthetic-board', source_revision='a' * 40,
        boot_image_sha256='b' * 64, verity_root_hash='c' * 64,
        volume_uuid='33333333-3333-4333-8333-333333333333', nonce_sha256='d' * 64,
        slot_id=1, uart_by_id='/dev/serial/by-id/synthetic-never-opened',
        uart_by_path='/dev/serial/by-path/synthetic-never-opened',
        idle_timeout_seconds=600, observation_seconds=10, maximum_bytes=65536)


def event(phase, index, boot=BOOT1):
    value = {key: plan()[key] for key in runner.BINDINGS}
    return value | dict(schema_version=runner.EVENT_SCHEMA, phase=phase, boot_id=boot,
                        sequence=index + 1, check=runner.checks(phase)[index], passed=True)


def line(record):
    return runner.PREFIX + runner.canonical(record)


def tape(phase='create', boot=BOOT1, start=300):
    chunks = [dict(at_seconds=0, base64=base64.b64encode(b'ordinary boot noise\r\n').decode())]
    for index in range(len(runner.checks(phase))):
        chunks.append(dict(at_seconds=start + index / 10,
                           base64=base64.b64encode(line(event(phase, index, boot))).decode()))
    return dict(schema_version=runner.TAPE_SCHEMA, phase=phase, chunks=chunks)


@contextmanager
def simulation(value):
    yield runner.Simulation(value, value['phase'])


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = runner.Store(self.root / 'state')
        self.store.initialize(plan(), 'simulation')

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def observe(self, value=None):
        value = tape() if value is None else value
        return self.store.observe(lambda p, phase: simulation(value), lambda phase: None)

    def test_two_boots_resume_with_distinct_identities_and_retained_digests(self):
        first = self.observe()
        self.assertIsNone(first['blocked'])
        result = self.store.read('create.result.json')
        self.assertEqual(result['wait_for_boot_seconds'], 300)
        self.assertEqual(result['observation_seconds'], 10)
        self.store.close()
        self.store = runner.Store(self.root / 'state')
        second = self.observe(tape('reopen', BOOT2))
        self.assertEqual([r['phase'] for r in second['completed']], ['create', 'reopen'])
        self.assertFalse(second['hardware_qualified'])
        self.assertFalse(second['execution_authority'])
        self.store.load()
        with self.assertRaisesRegex(runner.Rejected, 'already-complete'):
            self.observe()

    def test_full_window_observes_contradiction_after_complete_marker(self):
        value = tape(start=1)
        contradictory = event('create', 3)
        contradictory['passed'] = False
        value['chunks'].append(dict(at_seconds=9, base64=base64.b64encode(line(contradictory)).decode()))
        state = self.observe(value)
        self.assertEqual(state['blocked'], 'extra-event')
        self.assertEqual(state['completed'], [])

    def test_waiting_does_not_spend_observation_window(self):
        state = self.observe(tape(start=599))
        self.assertIsNone(state['blocked'])
        self.assertEqual(self.store.read('create.result.json')['observation_seconds'], 10)

    def test_final_empty_poll_tolerates_scheduler_latency(self):
        class Delayed(runner.Simulation):
            def read(self, wait):
                data = super().read(wait)
                if self.clock >= 310:
                    self.clock += 0.002
                return data
        @contextmanager
        def source(p, phase):
            yield Delayed(tape(), phase)
        state = self.store.observe(source, lambda phase: None)
        self.assertIsNone(state['blocked'])
        self.assertGreater(self.store.read('create.result.json')['observation_seconds'], 10)

    def test_late_bytes_are_retained_but_cannot_satisfy_capture(self):
        class Delayed(runner.Simulation):
            def read(self, wait):
                data = super().read(wait)
                if self.clock >= 310:
                    self.clock += 0.002
                    return b'late bytes\n'
                return data
        @contextmanager
        def source(p, phase):
            yield Delayed(tape(), phase)
        state = self.store.observe(source, lambda phase: None)
        self.assertEqual(state['blocked'], 'capture-deadline-overrun')
        self.assertTrue((self.root / 'state/create.uart').read_bytes().endswith(b'late bytes\n'))

    def test_absent_boot_is_inconclusive_and_not_retried(self):
        value = tape(); value['chunks'] = value['chunks'][:1]
        state = self.observe(value)
        self.assertEqual(state['blocked'], 'boot-not-observed')
        self.assertFalse(self.store.read('create.result.json')['capture_complete'])
        with self.assertRaisesRegex(runner.Rejected, 'no-automatic-retry'):
            self.observe()

    def test_missing_complete_event_never_passes(self):
        value = tape(); value['chunks'].pop()
        self.assertEqual(self.observe(value)['blocked'], 'missing-events')

    def test_repeated_boot_id_is_rejected_across_phases(self):
        self.observe()
        self.assertEqual(self.observe(tape('reopen', BOOT1))['blocked'], 'replayed-boot-id')

    def test_durable_intent_before_source_open_and_interrupted_resume(self):
        class SimulatedCrash(BaseException):
            pass
        def crash(p, phase):
            self.assertEqual(self.store.read('state.json')['active_phase'], 'create')
            self.assertTrue((self.root / 'state/create.intent.json').exists())
            raise SimulatedCrash
        with self.assertRaises(SimulatedCrash):
            self.store.observe(crash, lambda phase: None)
        self.store.close()
        self.store = runner.Store(self.root / 'state')
        with self.assertRaisesRegex(runner.Rejected, 'no-automatic-retry'):
            self.observe()

    def test_completed_capture_corruption_is_detected_after_restart(self):
        self.observe()
        with (self.root / 'state/create.uart').open('ab') as stream:
            stream.write(b'changed')
        with self.assertRaisesRegex(runner.Rejected, 'raw-capture-mismatch'):
            self.store.load()

    def test_invalid_result_shape_and_bounds_fail_closed(self):
        self.observe()
        original = self.store.read('create.result.json')
        for altered in [[], original | {'observation_seconds': True}, original | {'raw_bytes': 'unknown'}]:
            with self.subTest(altered=altered):
                (self.root / 'state/create.result.json').write_bytes(runner.canonical(altered))
                with self.assertRaises(runner.Rejected):
                    self.store.load()

    def test_changed_plan_is_rejected(self):
        changed = plan(); changed['boot_image_sha256'] = 'e' * 64
        (self.root / 'state/plan.json').write_bytes(runner.canonical(changed))
        with self.assertRaisesRegex(runner.Rejected, 'state-plan-mismatch'):
            self.store.load()

    def test_concurrent_writer_cannot_open_state(self):
        with self.assertRaises(OSError):
            runner.Store(self.root / 'state')

    def test_partly_written_checkpoint_prevents_another_capture(self):
        (self.root / 'state/.checkpoint').write_text('interrupted')
        with self.assertRaisesRegex(runner.Rejected, 'interrupted-checkpoint'):
            self.observe()
        with self.assertRaisesRegex(runner.Rejected, 'interrupted-checkpoint'):
            self.store.load()

    def test_source_cleanup_failure_cannot_produce_success(self):
        @contextmanager
        def source(p, phase):
            yield runner.Simulation(tape(), phase)
            raise runner.Rejected('uart-cleanup-failed')
        state = self.store.observe(source, lambda phase: None)
        self.assertEqual(state['blocked'], 'uart-cleanup-failed')
        self.assertFalse(self.store.read('create.result.json')['capture_complete'])

    def test_observation_keeps_partial_bytes_after_source_failure(self):
        class Broken(runner.Simulation):
            def read(self, wait):
                if self.clock > 300:
                    raise OSError('sensitive untrusted error text')
                return super().read(wait)
        @contextmanager
        def source(p, phase):
            yield Broken(tape(), phase)
        self.store.observe(source, lambda phase: None)
        result = self.store.read('create.result.json')
        self.assertEqual(result['failure'], 'capture-io-error-or-interrupted')
        self.assertGreater(result['raw_bytes'], 0)
        self.assertNotIn('sensitive', json.dumps(result))

    def test_limit_retains_only_bounded_raw_prefix(self):
        value = tape(); value['chunks'] = [dict(at_seconds=1, base64=base64.b64encode(b'x' * 70000).decode())]
        state = self.observe(value)
        self.assertEqual(state['blocked'], 'capture-byte-limit')
        self.assertEqual((self.root / 'state/create.uart').stat().st_size, plan()['maximum_bytes'])

    def test_synthetic_files_are_owner_only(self):
        self.observe()
        for p in (self.root / 'state').iterdir():
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)


class ProtocolTests(unittest.TestCase):
    def test_binding_order_failure_and_extra_fields(self):
        mutations = [
            ('wrong-image', {'boot_image_sha256': 'e' * 64}),
            ('wrong-target', {'target_reference': 'another-board'}),
            ('wrong-phase', {'phase': 'reopen'}),
            ('wrong-slot', {'slot_id': 2}),
            ('boolean-slot', {'slot_id': True}),
            ('wrong-nonce', {'nonce_sha256': 'f' * 64}),
            ('bad-uuid', {'boot_id': 'unknown'}),
            ('out-of-order', {'sequence': 2}),
            ('boolean-sequence', {'sequence': True}),
            ('failed-check', {'passed': False}),
            ('numeric-outcome', {'passed': 1}),
            ('secret-field', {'key_material': 'must-not-be-retained-in-results'}),
        ]
        for name, change in mutations:
            with self.subTest(name=name):
                parser = runner.Events(plan(), 'create', [])
                with self.assertRaises(runner.Rejected):
                    parser.feed(line(event('create', 0) | change))

    def test_canonical_events_accept_console_prefix_crlf_and_fragmentation(self):
        parser = runner.Events(plan(), 'create', [])
        raw = b''.join(b'[ 1.0] harness: ' + line(event('create', i)).replace(b'\n', b'\r\n')
                       for i in range(len(runner.checks('create'))))
        for offset in range(0, len(raw), 7):
            parser.feed(raw[offset:offset + 7])
        parser.finish()

    def test_interleaving_and_duplicate_fields_are_not_repaired(self):
        original = line(event('create', 0))
        broken = original[:80] + b'[kernel interjection]\n' + original[80:]
        duplicate = original.replace(b'"passed":true', b'"passed":true,"passed":true')
        for data in [broken, duplicate, original + original, original.rstrip() + b' trailing\n']:
            with self.subTest(data=data[:32]):
                parser = runner.Events(plan(), 'create', [])
                with self.assertRaises(runner.Rejected):
                    parser.feed(data)

    def test_oversized_and_truncated_frames_fail(self):
        parser = runner.Events(plan(), 'create', [])
        with self.assertRaisesRegex(runner.Rejected, 'line-too-large'):
            parser.feed(b'x' * (runner.MAX_LINE + 1))
        parser = runner.Events(plan(), 'create', [])
        parser.feed(line(event('create', 0)).rstrip(b'\n'))
        with self.assertRaisesRegex(runner.Rejected, 'truncated-frame'):
            parser.finish()
        parser = runner.Events(plan(), 'create', [])
        for i in range(len(runner.checks('create'))):
            parser.feed(line(event('create', i)))
        parser.feed(runner.PREFIX[:10])
        with self.assertRaisesRegex(runner.Rejected, 'truncated-line'):
            parser.finish()

    def test_invalid_plan_bounds_paths_and_unknown_authority_are_rejected(self):
        for change in [{'slot_id': 0}, {'slot_id': True}, {'execution_authorized': True},
                       {'maximum_bytes': 0}, {'observation_seconds': 601},
                       {'uart_by_id': '/dev/sda'}, {'uart_by_path': '/dev/serial/by-path/../sda'},
                       {'boot_image_sha256': '0' * 64}]:
            with self.subTest(change=change), self.assertRaises(runner.Rejected):
                runner.validate_plan(plan() | change)

    def test_simulation_rejects_nonfinite_or_reordered_time(self):
        for value in [float('nan'), -1, True, '1']:
            bad = tape(); bad['chunks'][0]['at_seconds'] = value
            with self.subTest(value=value), self.assertRaises(runner.Rejected):
                runner.Simulation(bad, 'create')

    def test_json_rejects_nonfinite_numbers_including_overflow(self):
        for value in [b'NaN', b'Infinity', b'-Infinity', b'1e999']:
            with self.subTest(value=value), self.assertRaises(runner.Rejected):
                runner.decode(value)


class CLITests(unittest.TestCase):
    def test_uart_command_sequences_readiness_and_arming_without_powered_replies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = runner.Store(root / 'state')
            store.initialize(plan(), 'uart')
            store.close()
            entered = []
            @contextmanager
            def serial(p):
                phase = runner.PHASES[len(entered)]
                entered.append(phase)
                yield runner.Simulation(tape(phase, BOOT1 if phase == 'create' else BOOT2), phase)
            with mock.patch.object(runner, 'Serial', side_effect=serial), \
                 mock.patch.object(runner.sys.stdin, 'isatty', return_value=True), \
                 mock.patch('builtins.input', side_effect=['READY', 'READY']) as readiness, \
                 mock.patch('builtins.print') as output:
                self.assertEqual(runner.main(['run', '--state', str(root / 'state')]), 0)
                self.assertEqual(readiness.call_count, 2)
                self.assertEqual(entered, ['create', 'reopen'])
                self.assertEqual(sum(str(c.args[0]).startswith('CAPTURE_ARMED:') for c in output.call_args_list), 2)

    def test_operator_abort_leaves_phase_unstarted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = runner.Store(root / 'state')
            store.initialize(plan(), 'uart')
            store.close()
            with mock.patch.object(runner, 'Serial') as serial, \
                 mock.patch.object(runner.sys.stdin, 'isatty', return_value=True), \
                 mock.patch('builtins.input', return_value='cancel'), mock.patch('builtins.print'):
                self.assertEqual(runner.main(['run', '--state', str(root / 'state')]), 3)
                serial.assert_not_called()
            self.assertFalse((root / 'state/create.intent.json').exists())
            store = runner.Store(root / 'state')
            try:
                self.assertIsNone(store.load()[1]['active_phase'])
            finally:
                store.close()

    def test_packaged_style_commands_resume_without_hardware(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'plan.json').write_bytes(runner.canonical(plan()))
            state = root / 'state'
            def cli(*args):
                command = ([os.environ['KAIBA_DEVICE_SECRET_RUNNER_COMMAND']]
                           if 'KAIBA_DEVICE_SECRET_RUNNER_COMMAND' in os.environ
                           else [sys.executable, '-I', str(SCRIPT)])
                return subprocess.run([*command, *args], capture_output=True, text=True)
            result = cli('init', '--state', str(state), '--plan', str(root / 'plan.json'), '--mode', 'simulation')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(cli('run', '--state', str(state)).returncode, 3)
            for phase, boot in [('create', BOOT1), ('reopen', BOOT2)]:
                (root / 'tape.json').write_bytes(runner.canonical(tape(phase, boot)))
                result = cli('rehearse', '--state', str(state), '--tape', str(root / 'tape.json'))
                self.assertEqual(result.returncode, 0, result.stderr)
            status = json.loads(cli('status', '--state', str(state)).stdout)
            self.assertEqual(status['completed_phases'], ['create', 'reopen'])
            self.assertEqual(status['mode'], 'simulation')
            self.assertFalse(status['hardware_qualified'])
            self.assertEqual(cli('init', '--state', str(state), '--plan', str(root / 'plan.json'), '--mode', 'uart').returncode, 3)

    def test_rehearsal_cannot_write_into_a_uart_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'plan.json').write_bytes(runner.canonical(plan()))
            (root / 'tape.json').write_bytes(runner.canonical(tape()))
            with mock.patch('builtins.print'):
                self.assertEqual(runner.main(['init', '--state', str(root / 'state'), '--plan', str(root / 'plan.json'), '--mode', 'uart']), 0)
                self.assertEqual(runner.main(['rehearse', '--state', str(root / 'state'), '--tape', str(root / 'tape.json')]), 3)
            self.assertFalse((root / 'state/create.intent.json').exists())

    def test_special_file_and_symlink_inputs_rejected(self):
        with self.assertRaisesRegex(runner.Rejected, 'input-not-regular'):
            runner.regular_bytes('/dev/null')
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'link'; p.symlink_to('/etc/hostname')
            with self.assertRaisesRegex(runner.Rejected, 'input-not-regular'):
                runner.regular_bytes(p)


class SerialTests(unittest.TestCase):
    def test_passive_pty_capture_flushes_stale_input_and_restores_settings(self):
        master, slave = os.openpty()
        try:
            path = os.ttyname(slave)
            original = termios.tcgetattr(slave)
            os.write(master, b'stale boot bytes\n')
            fixture = plan() | {'uart_by_id': path, 'uart_by_path': path}
            with mock.patch.object(runner.os, 'open', wraps=os.open) as opener:
                with runner.Serial(fixture) as serial:
                    self.assertEqual(opener.call_args.args[1] & os.O_ACCMODE, os.O_RDONLY)
                    self.assertEqual(serial.read(0.01), b'')
                    os.write(master, b'fresh boot bytes\n')
                    self.assertEqual(serial.read(0.1), b'fresh boot bytes\n')
            self.assertEqual(termios.tcgetattr(slave), original)
        finally:
            os.close(master); os.close(slave)

    def test_selector_disagreement_prevents_open(self):
        master1, slave1 = os.openpty(); master2, slave2 = os.openpty()
        try:
            fixture = plan() | {'uart_by_id': os.ttyname(slave1), 'uart_by_path': os.ttyname(slave2)}
            with mock.patch.object(runner.os, 'open', wraps=os.open) as opener:
                with self.assertRaisesRegex(runner.Rejected, 'selectors-disagree'):
                    with runner.Serial(fixture):
                        self.fail('opened mismatched UART')
                opener.assert_not_called()
        finally:
            for fd in (master1, slave1, master2, slave2): os.close(fd)

    def test_uart_attachment_change_is_rejected(self):
        master, slave = os.openpty()
        try:
            path = os.ttyname(slave)
            with runner.Serial(plan() | {'uart_by_id': path, 'uart_by_path': path}) as serial:
                with mock.patch.object(serial, 'identity', return_value=(0, 0, 0)):
                    with self.assertRaisesRegex(runner.Rejected, 'uart-reattached'):
                        serial.read(0)
        finally:
            os.close(master); os.close(slave)


if __name__ == '__main__':
    unittest.main()
