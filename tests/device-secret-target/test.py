import hashlib
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CHECK, TARGET = sys.argv[1:3]
sys.argv = sys.argv[:1]

def config():
    return dict(schema_version='kaiba.device-secret-target/v1alpha1', scheme='kaiba-firmware-hmac-counter-v1',
        experiment_id='synthetic-experiment', target_reference='synthetic-board', source_revision='a'*40,
        volume_uuid='33333333-3333-4333-8333-333333333333', partition_uuid='44444444-4444-4444-8444-444444444444',
        board_serial_sha256='e'*64, disk_serial_sha256='f'*64, nonce_hex=bytes(range(32)).hex(), slot_id=1, expected_usage=8)

class TargetTests(unittest.TestCase):
    def invoke(self, operation, fault=None, diagnostics=False):
        env = os.environ.copy()
        if fault: env['KAIBA_TEST_FAULT'] = fault
        args = [CHECK, operation] + (['--diagnostics'] if diagnostics else [])
        result = subprocess.run(args, env=env, capture_output=True, text=True, check=True)
        self.assertEqual(result.stderr, '')
        return result.stdout.strip()

    def test_counter_encoding_matches_pinned_upstream_construction(self):
        context = hashlib.sha256(b'kaiba:protected-state:luks2:v1\0' + bytes(range(32))).digest()
        expected = b'\0\0\0\1rpi-otp-derived-key:firmware-hmac-v1:raw\0' + context + b'\0\0\1\0'
        self.assertEqual(self.invoke('message'), expected.hex())

    def test_one_slot_metadata_accepts_slot_one(self):
        self.assertEqual(self.invoke('count'), '0 1')
        self.assertEqual(self.invoke('status'), '0 4865')
        self.assertEqual(self.invoke('usage'), '0 8')

    def test_typed_lock_responses_and_positive_controls(self):
        for operation, code in [('raw', 1), ('legacy', 1), ('hmac', 0), ('sign', 0), ('close', 1)]:
            with self.subTest(operation=operation): self.assertEqual(self.invoke(operation), f'{code} 0')

    def test_transport_failure_is_not_a_lock(self):
        for operation in ['raw', 'legacy', 'hmac', 'sign', 'count']:
            with self.subTest(operation=operation): self.assertEqual(self.invoke(operation, 'ioctl-denied'), '2 0')

    def test_failure_diagnostics_preserve_errno_and_tag_without_response_bytes(self):
        for fault, code in [('ioctl-denied', errno.EPERM), ('raw-ioctl-invalid', errno.EINVAL),
                            ('ioctl-timeout', errno.ETIMEDOUT)]:
            with self.subTest(fault=fault):
                lines = self.invoke('raw', fault, diagnostics=True).splitlines()
                self.assertCountEqual(lines, ['2 0', 'KAIBA_DEVICE_SECRET_DIAGNOSTIC=check:synthetic-check '
                    f'last_firmware_outcome:transport-failure last_mailbox_tag:0x00030094 last_mailbox_errno:{code}'])
        lines = self.invoke('raw', 'locked-with-secret', diagnostics=True).splitlines()
        self.assertCountEqual(lines, ['3 0', 'KAIBA_DEVICE_SECRET_DIAGNOSTIC=check:synthetic-check '
            'last_firmware_outcome:malformed-reply last_mailbox_tag:0x00030094 last_mailbox_errno:0'])

    def test_successful_exchange_does_not_reuse_previous_errno(self):
        lines = self.invoke('legacy-then-hmac', diagnostics=True).splitlines()
        self.assertCountEqual(lines, ['0 0', 'KAIBA_DEVICE_SECRET_DIAGNOSTIC=check:synthetic-check '
            'last_firmware_outcome:success last_mailbox_tag:0x00030092 last_mailbox_errno:0'])

    def test_malformed_headers_and_short_hmac_fail_closed(self):
        self.assertEqual(self.invoke('hmac', 'bad-header'), '3 0')
        self.assertEqual(self.invoke('hmac', 'hmac-short'), '3 0')

    def test_unsupported_and_unexpected_secret_return_do_not_pass(self):
        self.assertEqual(self.invoke('raw', 'wrong-lock-error'), '4 0')
        self.assertEqual(self.invoke('raw', 'private-returned'), '0 0')
        self.assertEqual(self.invoke('raw', 'locked-with-secret'), '3 0')
        self.assertEqual(self.invoke('legacy', 'legacy-zeros'), '4 0')
        self.assertEqual(self.invoke('legacy', 'legacy-io'), '4 0')

    def test_closed_configuration_rejects_ambiguous_or_unreviewed_bindings(self):
        bad = [{'slot_id': 0}, {'slot_id': 2}, {'slot_id': True}, {'expected_usage': 1},
               {'nonce_hex': '00'}, {'nonce_hex': '00'*32}, {'scheme': 'legacy-hkdf-v1'}, {'source_revision': '0'*40},
               {'source_revision': 'a'*40 + '\0ignored'}, {'command': 'anything'}, {'volume_uuid': config()['partition_uuid']}]
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'config.json'
            for change in [{}] + bad:
                with self.subTest(change=change):
                    p.write_text(json.dumps(config() | change))
                    result = subprocess.run([TARGET, '--check-config', str(p)], capture_output=True)
                    self.assertEqual(result.returncode, 3 if change else 0)
                    self.assertNotIn(b'KEY', result.stdout)
            p.write_text(json.dumps(config() | {'expected_usage': 0}))
            self.assertEqual(subprocess.run([TARGET, '--check-config', str(p)], capture_output=True).returncode, 0)
            p.write_text(json.dumps(config())[:-1] + ',"slot_id":1}')
            self.assertEqual(subprocess.run([TARGET, '--check-config', str(p)], capture_output=True).returncode, 3)

    def test_production_cli_has_no_secret_export_or_programming_commands(self):
        for command in ['hmac', 'genkey', 'privkey', 'set-key-usage', '--simulate', '--force']:
            with self.subTest(command=command):
                self.assertEqual(subprocess.run([TARGET, command], capture_output=True).returncode, 2)

if __name__ == '__main__': unittest.main()
