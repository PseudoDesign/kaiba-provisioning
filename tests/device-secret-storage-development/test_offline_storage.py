import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_storage_session import response, storage_config, s
import offline_storage as o


class OfflineCapture(unittest.TestCase):
    def setUp(self):
        self.plan = dict(schema_version='kaiba.offline-storage-capture-plan/v1alpha1',
                         boot_image_sha256='b'*64, verity_root_hash='c'*64,
                         volume_uuid=storage_config()['volume_uuid'], nonce_hex=storage_config()['nonce_hex'])

    def raw(self, phase='create', **changes):
        v = response(phase, '11111111-1111-4111-8111-111111111111' if phase == 'create'
                     else '22222222-2222-4222-8222-222222222222')
        v.update(mode='offline-development', schema_version='kaiba.device-secret-storage-offline-result/v1alpha1')
        v.update(changes)
        return o.PREFIX + json.dumps(v).encode() + b'\r\n'

    def test_pair_never_claims_cold_power_or_qualification(self):
        result = o.assess_pair(b'boot log\n' + self.raw(), self.raw('reopen'), self.plan)
        self.assertEqual(result['status'], 'matched-target-reports')
        for field in ('cold_power_verified', 'physical_isolation_verified', 'hardware_qualified',
                      'lock_rejection_qualified', 'execution_authority'):
            self.assertIs(result[field], False)

    def test_failed_or_mismatched_reports_rejected(self):
        for changes in [dict(passed=False), dict(journal_completed=False), dict(storage_closed=False),
                        dict(runtime_locks_closed=False), dict(mode='synthetic-offline-development'),
                        dict(mode='development'), dict(schema_version='kaiba.device-secret-storage-result/v1alpha1'),
                        dict(verity_root_hash='d'*64), dict(boot_image_sha256='d'*64),
                        dict(volume_uuid='99999999-9999-4999-8999-999999999999'),
                        dict(nonce_sha256='d'*64), dict(hardware_qualified=True)]:
            with self.subTest(changes=changes), self.assertRaises(Exception):
                o.assess_pair(self.raw(**changes), self.raw('reopen'), self.plan)

    def test_missing_duplicate_interleaved_and_truncated(self):
        for raw in [b'', self.raw()+self.raw(), b'interleaved '+self.raw(), self.raw()[:-15],
                    self.raw()+o.PREFIX+b'{bad}', b'x'*(4*1024**2)+self.raw()]:
            with self.assertRaises(Exception):o.assess_pair(raw, self.raw('reopen'), self.plan)

    def test_order_and_repeated_boot_rejected(self):
        with self.assertRaises(Exception):o.assess_pair(self.raw('reopen'), self.raw(), self.plan)
        with self.assertRaises(Exception):o.assess_pair(self.raw(), self.raw('reopen', boot_id=response()['boot_id']), self.plan)

    @unittest.skipUnless(os.environ.get('KAIBA_OFFLINE_STORAGE_HELPER'), 'packaged helper required')
    def test_closed_config_and_cli(self):
        helper = os.environ['KAIBA_OFFLINE_STORAGE_HELPER']
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'config.json'; c = storage_config()
            p.write_text(json.dumps(c))
            self.assertNotEqual(subprocess.run([helper, '--check-config', str(p)], capture_output=True).returncode, 0)
            c['schema_version'] = 'kaiba.device-secret-storage-offline-development/v1alpha1'
            p.write_text(json.dumps(c))
            self.assertEqual(subprocess.run([helper, '--check-config', str(p)], capture_output=True).returncode, 0)
            self.assertEqual(subprocess.run([helper, 'reopen', str(p), '--expected-boot-id', response()['boot_id']], capture_output=True).returncode, 2)
            c['retry'] = True; p.write_text(json.dumps(c))
            self.assertNotEqual(subprocess.run([helper, '--check-config', str(p)], capture_output=True).returncode, 0)
