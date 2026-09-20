import base64
import datetime
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.environ.get('KAIBA_DEVELOPMENT_SCRIPTS', str(Path(__file__).resolve().parents[2] / 'scripts/device-secret')))
s = importlib.import_module('storage_development')
d = s.d
BOOT = '11111111-1111-4111-8111-111111111111'
NEXT = '22222222-2222-4222-8222-222222222222'
BINARY = b'\x7fELF\x02\x01' + bytes(12) + b'\xb7\x00' + bytes(50)


def storage_config():
    return dict(schema_version=s.CONFIG_SCHEMA, scheme='kaiba-firmware-hmac-counter-v1',
                experiment_id='synthetic-experiment', target_reference='synthetic-board', source_revision='a'*40,
                volume_uuid='33333333-3333-4333-8333-333333333333', partition_uuid='44444444-4444-4444-8444-444444444444',
                board_serial_sha256='e'*64, disk_serial_sha256='f'*64, nonce_hex=bytes(range(32)).hex(),
                slot_id=1, expected_usage=8)


def response(phase='create', boot=BOOT, passed=True):
    return dict(schema_version='kaiba.device-secret-storage-result/v1alpha1', mode='development', phase=phase,
                boot_id=boot, boot_image_sha256='b'*64, verity_root_hash='c'*64,
                volume_uuid=storage_config()['volume_uuid'], nonce_sha256=hashlib.sha256(bytes(range(32))).hexdigest(),
                passed=passed, stop='complete' if passed else 'luks-derivation', volume_verified=passed,
                runtime_locks_closed=True, storage_closed=True, journal_completed=passed,
                hardware_qualified=False, lock_rejection_qualified=False,
                last_firmware_outcome=0 if passed else 2, last_mailbox_tag=0x30092, last_mailbox_errno=0 if passed else 22)


class StorageSession(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.state = self.root/'state'; self.source = self.root/'config.json'
        self.pin = self.root/'known_hosts'
        key = b'\0\0\0\x0bssh-ed25519\0\0\0 ' + bytes(32)
        self.pin.write_bytes(b'10.0.0.2 ssh-ed25519 ' + base64.b64encode(key) + b'\n')
        self.config = dict(schema_version=s.SCHEMA, address='10.0.0.2', user='codex', identity_file='/private/key',
                known_hosts=str(self.pin), board_serial_sha256='e'*64, boot_image_sha256='b'*64,
                firmware_version='c'*40, kernel_release='6.18.34', helper_sha256=hashlib.sha256(BINARY).hexdigest(),
                slot_id=1, expected_usage=8, checks=['create', 'reopen'], max_runs=2, max_reboots=1,
                expires_at=(d.now()+datetime.timedelta(hours=1)).isoformat().replace('+00:00', 'Z'),
                uart_by_id='/dev/serial/by-id/synthetic', uart_by_path='/dev/serial/by-path/synthetic', storage=storage_config())
        self.helper = self.root/'helper'; self.helper.write_bytes(BINARY)

    def init(self):
        self.source.write_text(json.dumps(self.config))
        d.initialize(self.state, self.source, config_validator=s.validate)
        session = s.Session(self.state); self.addCleanup(session.close); return session

    def run_fixture(self, session, phase='create', boot=BOOT, passed=True):
        def execute(*args, **kwargs):
            self.assertTrue(list(self.state.glob('*.intent.json')))
            self.assertEqual(kwargs['timeout'], 210)
            return subprocess.CompletedProcess([], 0 if passed else 3, json.dumps(response(phase, boot, passed)).encode(), b'')
        with patch.object(d, 'inspect', return_value={'boot_id': boot}), patch.object(d, 'remote', side_effect=execute):
            return session.run(self.helper, phase)

    def recorded_reboot(self, session):
        session.allowed('reboot')
        attempt = session.intent('reboot', {'boot_id': BOOT})
        d.write(self.state/f'{attempt}.result.json', d.canonical(dict(status='passed', after={'boot_id': NEXT})))

    def test_exact_create_reboot_reopen_order_and_budget(self):
        session = self.init()
        with patch.object(d, 'inspect', side_effect=AssertionError('no SSH')):
            with self.assertRaisesRegex(d.Rejected, 'phase-order'): session.run(self.helper, 'reopen')
            with self.assertRaisesRegex(d.Rejected, 'phase-order'): session.reboot()
        self.assertEqual(self.run_fixture(session)['status'], 'passed')
        with self.assertRaisesRegex(d.Rejected, 'phase-order'): session.allowed('create')
        with self.assertRaisesRegex(d.Rejected, 'phase-order'): session.allowed('reopen')
        self.recorded_reboot(session)
        self.assertEqual(self.run_fixture(session, 'reopen', NEXT)['status'], 'passed')
        with self.assertRaises(d.Rejected): session.allowed('reopen')
        with self.assertRaises(d.Rejected): session.allowed('reboot')

    def test_failure_stops_every_later_action(self):
        session = self.init()
        result = self.run_fixture(session, passed=False)
        self.assertEqual(result['observation']['last_mailbox_errno'], 22)
        self.assertFalse(result['hardware_qualified'])
        for action in ('create', 'reboot', 'reopen'):
            with self.subTest(action=action), self.assertRaisesRegex(d.Rejected, 'failed-attempt'): session.allowed(action)

    def test_timeout_consumes_intent_without_retry(self):
        session = self.init()
        with patch.object(d, 'inspect', return_value={'boot_id': BOOT}), patch.object(
                d, 'remote', side_effect=subprocess.TimeoutExpired('ssh', 210)), self.assertRaises(subprocess.TimeoutExpired):
            session.run(self.helper, 'create')
        with self.assertRaisesRegex(d.Rejected, 'unfinished'): session.allowed('create')

    def test_reopen_requires_the_authenticated_changed_boot(self):
        session = self.init(); self.run_fixture(session); self.recorded_reboot(session)
        with patch.object(d, 'inspect', return_value={'boot_id': BOOT}), patch.object(
                d, 'remote', side_effect=AssertionError('no execution')), self.assertRaisesRegex(d.Rejected, 'boot-binding'):
            session.run(self.helper, 'reopen')
        self.assertEqual(len(list(self.state.glob('*.intent.json'))), 2)

    def test_closed_configuration_rejects_broader_authority_and_mismatches(self):
        changes = [{'max_runs': 3}, {'max_reboots': 2}, {'checks': ['create']}, {'schema_version': d.SCHEMA},
                   {'slot_id': 2}, {'storage': storage_config() | {'device': '/dev/nvme0n1'}},
                   {'storage': storage_config() | {'board_serial_sha256': 'f'*64}},
                   {'storage': storage_config() | {'schema_version': 'kaiba.device-secret-target/v1alpha1'}},
                   {'storage': storage_config() | {'slot_id': True}},
                   {'storage': storage_config() | {'nonce_hex': '0'*64}},
                   {'storage': storage_config() | {'experiment_id': '$(touch /tmp/no)'}}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(d.Rejected): s.validate(self.config | change)
        session = self.init()
        session.close()
        with self.assertRaises(d.Rejected): d.Session(self.state)

    def test_bad_helper_and_expiry_fail_before_target_contact(self):
        session = self.init(); self.helper.write_bytes(b'bad')
        with patch.object(d, 'inspect', side_effect=AssertionError('no SSH')), self.assertRaisesRegex(d.Rejected, 'digest'):
            session.run(self.helper, 'create')
        self.assertFalse(list(self.state.glob('*.intent.json')))
        session.config['expires_at'] = '2000-01-01T00:00:00Z'
        with self.assertRaisesRegex(d.Rejected, 'expired'): session.allowed('create')

    def test_result_cannot_promote_missing_cleanup_or_qualification(self):
        changes = [{'hardware_qualified': True}, {'lock_rejection_qualified': True}, {'mode': 'synthetic-development'}, {'storage_closed': False},
                   {'runtime_locks_closed': False}, {'journal_completed': False}, {'volume_verified': False},
                   {'passed': 1}, {'boot_id': NEXT}, {'nonce_sha256': 'a'*64}, {'extra': 'x'}, {'phase': 'reopen'},
                   {'last_firmware_outcome': 2}, {'last_mailbox_errno': 22}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(d.Rejected):
                s.validate_result(json.dumps(response() | change).encode(), self.config, 'create', BOOT, 0)

    def test_runtime_upload_is_quoted_and_has_no_format_or_shell_key_commands(self):
        script = s.run_script(self.config, 'create', BINARY, BOOT, '0001')
        self.assertEqual(subprocess.run(['bash', '-n'], input=script.encode(), capture_output=True).returncode, 0)
        self.assertIn('StrictHostKeyChecking=yes', d.ssh(self.config, self.pin))
        self.assertIn(base64.b64encode(d.canonical(self.config['storage'])).decode(), script)
        for forbidden in ('cryptsetup ', 'mkfs', 'blockdev --setrw', 'rpi-fw-crypto ', 'reboot\n'):
            self.assertNotIn(forbidden, script)

    @unittest.skipUnless(os.environ.get('KAIBA_STORAGE_HELPER'), 'native helper checked by Nix')
    def test_native_config_contract_and_qualification_separation(self):
        helper = os.environ['KAIBA_STORAGE_HELPER']
        for change, expected in [({}, 0), ({'schema_version': 'kaiba.device-secret-target/v1alpha1'}, 3),
                                 ({'slot_id': 2}, 3), ({'nonce_hex': '0'*64}, 3), ({'path': '/dev/vdb'}, 3)]:
            with self.subTest(change=change):
                self.source.write_text(json.dumps(storage_config() | change))
                r = subprocess.run([helper, '--check-config', str(self.source)], capture_output=True)
                self.assertEqual(r.returncode, expected, r.stderr)
        for command in ('reset', 'format', 'sign', 'generate', 'read-lock'):
            self.assertEqual(subprocess.run([helper, command], capture_output=True).returncode, 2)
