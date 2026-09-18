import json
import os
import subprocess
import sys
import unittest

HELPER, PRODUCTION = sys.argv[1:3]
sys.argv = sys.argv[:1]
BOOT = '11111111-1111-4111-8111-111111111111'

class Helper(unittest.TestCase):
    def run_check(self, check, fault=None, boot=BOOT):
        env = os.environ.copy()
        if fault: env['KAIBA_TEST_FAULT'] = fault
        r = subprocess.run([HELPER, check, '--slot-id', '1', '--expected-usage', '8', '--expected-boot-id', boot],
                           capture_output=True, text=True, env=env)
        result = json.loads(r.stdout)
        self.assertFalse(result['hardware_qualified'])
        self.assertEqual(r.returncode, 0 if result['passed'] else 3)
        self.assertNotIn('PRIVATE_MATERIAL', r.stdout)
        return result, [int(line.split()[1], 16) for line in r.stderr.splitlines()]

    def test_inspection_has_only_three_metadata_calls(self):
        r, tags = self.run_check('inspect')
        self.assertTrue(r['passed']); self.assertIsNone(r['cleanup_locks_closed'])
        self.assertEqual(tags, [0x3008f, 0x30090, 0x3009c])

    def test_read_probe_locks_first_and_always_closes(self):
        r, tags = self.run_check('read-lock')
        self.assertTrue(r['passed']); self.assertTrue(r['cleanup_locks_closed'])
        self.assertEqual(tags, [0x3008f, 0x30090, 0x3009c, 0x38090, 0x30090, 0x30094, 0x3008e, 0x38090, 0x30090])

    def test_einval_and_last_error_stay_separate_and_failed(self):
        r, tags = self.run_check('read-lock', 'raw-einval')
        self.assertFalse(r['passed']); self.assertTrue(r['cleanup_locks_closed'])
        raw, error = r['steps'][5:7]
        self.assertEqual((raw['outcome'], raw['mailbox_tag'], raw['mailbox_errno']), (2, 0x30094, 22))
        self.assertEqual(error['value'], 4)
        self.assertEqual(tags.count(0x30094), 1)
        self.assertNotIn(0x30092, tags)

    def test_unexpected_private_response_is_never_exported(self):
        r, tags = self.run_check('read-lock', 'private-returned')
        self.assertFalse(r['passed']); self.assertTrue(r['cleanup_locks_closed'])
        self.assertEqual(tags.count(0x30094), 1)

    def test_hmac_has_four_bounded_calls_and_only_boolean_results(self):
        r, tags = self.run_check('hmac')
        self.assertTrue(r['passed']); self.assertTrue(r['cleanup_locks_closed'])
        self.assertEqual(tags.count(0x30092), 4)
        self.assertNotIn(0x30094, tags)
        for step in r['steps']:
            if step['name'].startswith('hmac-'): self.assertIsNone(step['value'])

    def test_unknown_and_failed_preconditions_prevent_mutation(self):
        for fault in ['preclosed', 'usage-mismatch', 'no-slots', 'malformed', 'transport']:
            r, tags = self.run_check('hmac', fault)
            self.assertFalse(r['passed']); self.assertNotIn(0x38090, tags)
            self.assertNotIn(0x30092, tags)
        r, tags = self.run_check('hmac', boot='22222222-2222-4222-8222-222222222222')
        self.assertFalse(r['passed']); self.assertEqual(tags, [])

    def test_hmac_failures_and_cleanup_failure_do_not_pass(self):
        for fault in ['short-hmac', 'no-separation', 'cleanup']:
            r, tags = self.run_check('hmac', fault)
            self.assertFalse(r['passed']); self.assertLessEqual(tags.count(0x30092), 3)
            self.assertEqual(r['cleanup_locks_closed'], fault != 'cleanup')
            self.assertEqual(tags.count(0x38090), 2)

    def test_cli_has_no_general_firmware_or_media_interface(self):
        for command in ['genkey', 'privkey', 'sign', 'format', '--simulate', '--force', '--tag', 'set-usage']:
            r = subprocess.run([PRODUCTION, command], capture_output=True)
            self.assertEqual(r.returncode, 2)
        r = subprocess.run([PRODUCTION, '--version'], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0); self.assertIn('development', r.stdout)

if __name__ == '__main__': unittest.main()
