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
d = importlib.import_module('development')
BOOT = '11111111-1111-4111-8111-111111111111'
NEXT_BOOT = '22222222-2222-4222-8222-222222222222'
BINARY = b'\x7fELF\x02\x01' + bytes(12) + b'\xb7\x00' + bytes(50)
KEY = b'\0\0\0\x0bssh-ed25519\0\0\0 ' + bytes(32)


def response(check='inspect', success=True):
    names = ['count', 'status', 'usage']
    if check != 'inspect':
        names += ['apply-runtime-locks', 'runtime-locks']
        names += ['raw-read-blocked'] if check == 'read-lock' else ['hmac-control', 'hmac-repeat', 'hmac-separation']
        names += ['close-runtime-locks', 'closed-status']
        if check == 'hmac': names += ['hmac-closed']
    return dict(schema_version='kaiba.device-secret-development/v1alpha1', mode='development', check=check,
                boot_id=BOOT, slot_id=1, expected_usage=8, passed=success,
                stop='complete' if success else 'raw-read-blocked', cleanup_locks_closed=None if check == 'inspect' else True,
                hardware_qualified=False, steps=[dict(name=n, passed=success, outcome=0,
                mailbox_tag=0x3008f, mailbox_errno=0, value=None) for n in names])


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pin = self.root / 'known_hosts'
        self.pin.write_bytes(b'10.0.0.2 ssh-ed25519 ' + base64.b64encode(KEY) + b'\n')
        self.config = dict(schema_version=d.SCHEMA, address='10.0.0.2', user='codex', identity_file='/private/key',
             known_hosts=str(self.pin), board_serial_sha256='a'*64, boot_image_sha256='b'*64,
             firmware_version='c'*40, kernel_release='6.18.34', helper_sha256=hashlib.sha256(BINARY).hexdigest(),
             slot_id=1, expected_usage=8, checks=['inspect', 'read-lock', 'hmac'], max_runs=4, max_reboots=2,
             expires_at=(d.now()+datetime.timedelta(hours=1)).isoformat().replace('+00:00', 'Z'),
             uart_by_id='/dev/serial/by-id/synthetic', uart_by_path='/dev/serial/by-path/synthetic')
        self.source = self.root/'config.json'; self.state = self.root/'state'
        self.helper = self.root/'helper'; self.helper.write_bytes(BINARY)

    def init(self):
        self.source.write_text(json.dumps(self.config))
        d.initialize(self.state, self.source)
        s = d.Session(self.state); self.addCleanup(s.close); return s

    def test_closed_session_limits_and_injection(self):
        for change in [{'arbitrary_command': 'sudo anything'}, {'user': 'root; touch /tmp/no'},
                       {'address': '-oProxyCommand=anything'}, {'slot_id': True}, {'expected_usage': 1},
                       {'checks': ['genkey']}, {'checks': ['inspect', 'inspect']}, {'max_reboots': 99},
                       {'firmware_version': '$(anything)'}, {'kernel_release': '6.18\nanything'}]:
            with self.subTest(change=change), self.assertRaises((d.Rejected, ValueError)):
                d.validate(self.config | change)

    def test_initialization_is_file_only_and_private(self):
        with patch.object(d, 'remote', side_effect=AssertionError('no target contact')):
            s = self.init()
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.state/'session.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.state/'known_hosts').read_bytes(), self.pin.read_bytes())
        self.assertFalse(s.auth.get('execution_authority', False))

    def test_changed_session_and_overlong_window_rejected(self):
        self.config['expires_at'] = (d.now()+datetime.timedelta(days=2)).isoformat().replace('+00:00', 'Z')
        self.source.write_text(json.dumps(self.config))
        with self.assertRaises(d.Rejected): d.initialize(self.state, self.source)
        self.config['expires_at'] = (d.now()+datetime.timedelta(hours=1)).isoformat().replace('+00:00', 'Z')
        s = self.init(); s.close()
        self.config['max_runs'] = 8
        (self.state/'session.json').write_text(json.dumps(self.config))
        with self.assertRaises(d.Rejected): d.Session(self.state)

    def test_strict_SSH_and_shell_payload(self):
        cmd = d.ssh(self.config, self.pin)
        self.assertIn('StrictHostKeyChecking=yes', cmd); self.assertIn('IdentityAgent=none', cmd)
        script = d.run_script(self.config, 'inspect', BINARY, BOOT, '0001')
        self.assertEqual(subprocess.run(['bash', '-n'], input=script.encode(), capture_output=True).returncode, 0)
        self.assertIn(base64.b64encode(BINARY).decode(), script)
        self.assertNotIn('/dev/nvme', script)

    def test_wrong_binary_fails_before_SSH_or_intent(self):
        s = self.init(); self.helper.write_bytes(b'wrong')
        with patch.object(d, 'remote', side_effect=AssertionError('no SSH')), self.assertRaises(d.Rejected):
            s.run(self.helper, 'inspect')
        self.assertFalse(list(self.state.glob('*.intent.json')))

    def test_run_records_intent_before_execution_and_retains_result(self):
        s = self.init()
        def execute(*args):
            self.assertTrue((self.state/'0001.intent.json').exists())
            return subprocess.CompletedProcess([], 0, json.dumps(response()).encode(), b'')
        with patch.object(d, 'inspect', return_value={'boot_id': BOOT, 'power_status': 'throttled=0x50000'}), patch.object(d, 'remote', side_effect=execute):
            result = s.run(self.helper, 'inspect')
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(json.loads((self.state/'0001.intent.json').read_text())['before']['power_status'], 'throttled=0x50000')
        self.assertTrue((self.state/'0001.stdout').exists())
        self.assertFalse(result['hardware_qualified'])

    def test_interrupted_remote_attempt_cannot_be_repeated(self):
        s = self.init()
        with patch.object(d, 'inspect', return_value={'boot_id': BOOT}), patch.object(d, 'remote', side_effect=subprocess.TimeoutExpired('ssh', 50)), self.assertRaises(subprocess.TimeoutExpired):
            s.run(self.helper, 'read-lock')
        s.close(); s = d.Session(self.state); self.addCleanup(s.close)
        with self.assertRaisesRegex(d.Rejected, 'unfinished'): s.allowed('read-lock')

    def test_failed_check_and_malformed_response_cannot_be_promoted(self):
        s = self.init()
        with patch.object(d, 'inspect', return_value={'boot_id': BOOT}), patch.object(d, 'remote', return_value=subprocess.CompletedProcess([], 3, json.dumps(response('read-lock', False)).encode(), b'')):
            result = s.run(self.helper, 'read-lock')
        self.assertEqual(result['status'], 'failed')
        s.close(); s = d.Session(self.state); self.addCleanup(s.close)
        with self.assertRaisesRegex(d.Rejected, 'failed-attempt'): s.allowed('hmac')
        for change in [{'boot_id': NEXT_BOOT}, {'hardware_qualified': True}, {'steps': []}, {'passed': 1}, {'cleanup_locks_closed': True}]:
            with self.assertRaises(d.Rejected):
                d.validate_result(json.dumps(response() | change).encode(), self.config, 'inspect', BOOT, 0)

    def test_expiry_and_budget_enforced(self):
        s = self.init(); s.config['expires_at'] = '2000-01-01T00:00:00Z'
        with self.assertRaisesRegex(d.Rejected, 'expired'): s.allowed('inspect')
        s.config['expires_at'] = self.config['expires_at']; s.config['max_reboots'] = 0
        with self.assertRaisesRegex(d.Rejected, 'budget'): s.allowed('reboot')

    def test_expiry_during_preflight_prevents_execution(self):
        s = self.init()
        def preflight(*unused):
            s.config['expires_at'] = '2000-01-01T00:00:00Z'
            return {'boot_id': BOOT}
        with patch.object(d, 'inspect', side_effect=preflight), \
             patch.object(d, 'remote', side_effect=AssertionError('must not execute')), \
             self.assertRaisesRegex(d.Rejected, 'expired-before-execution'):
            s.run(self.helper, 'hmac')
        self.assertFalse(list(self.state.glob('*.intent.json')))

    def test_concurrent_runner_cannot_acquire_same_session(self):
        s = self.init()
        with self.assertRaises(BlockingIOError): d.Session(self.state)

    def test_mismatched_UART_key_never_replaces_pin(self):
        s = self.init()
        original = (self.state/'known_hosts').read_bytes()
        transcript = ('KAIBA_SECURE_BOOT_EVIDENCE=pass signed=80000009 boot_img_sha256=sha256:' + 'b'*64 + '\n' +
                      'KAIBA_DEVELOPMENT_SSH=ready user=codex address=10.0.0.2 host_key=SHA256:WRONG\n').encode()
        class FakeSerial:
            def __init__(self, unused): pass
            def __enter__(self): return self
            def __exit__(self, *unused): pass
            def read(self, unused): return transcript
        with patch.object(d, 'Serial', FakeSerial), patch.object(d.time, 'monotonic', side_effect=[0, 0, 0, 121]), \
             patch.object(d, 'inspect', return_value={'boot_id': BOOT}), \
             patch.object(d, 'remote', return_value=subprocess.CompletedProcess([], 0, b'', b'')), \
             patch.object(d.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, original, b'')), \
             self.assertRaisesRegex(d.Rejected, 'SSH-UART-key-mismatch'):
            s.reboot()
        self.assertEqual((self.state/'known_hosts').read_bytes(), original)
        self.assertTrue((self.state/'0001.intent.json').exists())
        self.assertFalse((self.state/'0001.result.json').exists())

    def test_reboot_reauthenticates_from_UART_and_keeps_old_pin(self):
        s = self.init()
        _, fp = d.key_line(self.pin.read_bytes(), '10.0.0.2')
        transcript = ('KAIBA_SECURE_BOOT_EVIDENCE=pass signed=80000009 boot_img_sha256=sha256:' + 'b'*64 + '\n' +
                      'KAIBA_DEVELOPMENT_SSH=ready user=codex address=10.0.0.2 host_key=' + fp + '\n').encode()
        class FakeSerial:
            def __init__(self, unused): pass
            def __enter__(self): return self
            def __exit__(self, *unused): pass
            def read(self, unused): return transcript
        scan = subprocess.CompletedProcess([], 0, self.pin.read_bytes(), b'')
        with patch.object(d, 'Serial', FakeSerial), patch.object(d.time, 'monotonic', side_effect=[0, 0, 0, 121]), \
             patch.object(d, 'inspect', side_effect=[{'boot_id': BOOT}, {'boot_id': NEXT_BOOT}]), \
             patch.object(d, 'remote', return_value=subprocess.CompletedProcess([], 0, b'', b'')), \
             patch.object(d.subprocess, 'run', return_value=scan):
            r = s.reboot()
        self.assertEqual(r['status'], 'passed'); self.assertFalse(r['cold_power_verified'])
        self.assertEqual((self.state/'0001.prior_known_hosts').read_bytes(), self.pin.read_bytes())
        self.assertEqual((self.state/'0001.uart').read_bytes(), transcript)

if __name__ == '__main__': unittest.main()
