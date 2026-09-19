import errno
import json
import os
import subprocess
import sys
import unittest

HELPER, PRODUCTION = sys.argv[1:3]
sys.argv = sys.argv[:1]
BOOT = '11111111-1111-4111-8111-111111111111'

class Helper(unittest.TestCase):
    def run_check(self, check, fault=None, boot=BOOT, hmac_fail_at=None, hmac_errno=errno.EINVAL):
        env = os.environ.copy()
        for key in ['KAIBA_TEST_FAULT', 'KAIBA_TEST_HMAC_FAIL_CALL', 'KAIBA_TEST_HMAC_ERRNO']:
            env.pop(key, None)
        if fault: env['KAIBA_TEST_FAULT'] = fault
        if hmac_fail_at is not None:
            env['KAIBA_TEST_HMAC_FAIL_CALL'] = str(hmac_fail_at)
            env['KAIBA_TEST_HMAC_ERRNO'] = str(hmac_errno)
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

    def test_hmac_transport_failure_is_followed_by_one_separate_diagnostic(self):
        names = ['hmac-control', 'hmac-repeat', 'hmac-separation', 'hmac-closed']
        for attempt, name in enumerate(names, 1):
            for code in [errno.EINVAL, errno.EIO, errno.ETIMEDOUT]:
                with self.subTest(attempt=attempt, errno=code):
                    r, tags = self.run_check('hmac', hmac_fail_at=attempt, hmac_errno=code)
                    self.assertFalse(r['passed']); self.assertTrue(r['cleanup_locks_closed'])
                    self.assertEqual(r['stop'], name)
                    index = next(i for i, s in enumerate(r['steps']) if s['name'] == name)
                    original, diagnostic = r['steps'][index:index+2]
                    self.assertEqual((original['passed'], original['outcome'], original['mailbox_tag'], original['mailbox_errno'], original['value']),
                                     (False, 2, 0x30092, code, None))
                    self.assertEqual(diagnostic, dict(name='last-error-after-transport-failure', passed=True,
                                     outcome=0, mailbox_tag=0x3008e, mailbox_errno=0, value=4))
                    # Before cleanup can overwrite last-error; no repeated HMAC.
                    last_hmac = max(i for i, tag in enumerate(tags) if tag == 0x30092)
                    self.assertEqual(tags[last_hmac+1], 0x3008e)
                    self.assertEqual(tags.count(0x3008e), 1)
                    self.assertEqual(tags.count(0x30092), attempt)
                    self.assertEqual(tags.count(0x38090), 2)
                    self.assertNotIn(0x30094, tags)
                    if attempt < 4:
                        self.assertEqual(tags[last_hmac+2:], [0x38090, 0x30090])
                    else:
                        self.assertEqual(tags[-4:], [0x38090, 0x30090, 0x30092, 0x3008e])

    def test_failed_last_error_query_preserves_original_failure_and_cleanup(self):
        for attempt, name in [(1, 'hmac-control'), (4, 'hmac-closed')]:
            for fault, outcome, code in [('last-error-io', 2, errno.EIO), ('last-error-malformed', 3, 0)]:
                with self.subTest(attempt=attempt, fault=fault):
                    r, tags = self.run_check('hmac', fault, hmac_fail_at=attempt)
                    self.assertFalse(r['passed']); self.assertTrue(r['cleanup_locks_closed'])
                    self.assertEqual(r['stop'], name)
                    original = next(s for s in r['steps'] if s['name'] == name)
                    self.assertEqual((original['outcome'], original['mailbox_errno']), (2, errno.EINVAL))
                    diagnostic = next(s for s in r['steps'] if s['name'] == 'last-error-after-transport-failure')
                    self.assertEqual((diagnostic['passed'], diagnostic['outcome'], diagnostic['mailbox_tag'], diagnostic['mailbox_errno'], diagnostic['value']),
                                     (False, outcome, 0x3008e, code, None))
                    self.assertEqual(tags.count(0x3008e), 1)
                    self.assertEqual(tags.count(0x38090), 2)

    def test_other_firmware_error_is_retained_without_promotion(self):
        r, tags = self.run_check('hmac', 'last-error-other', hmac_fail_at=4)
        self.assertFalse(r['passed']); self.assertEqual(r['stop'], 'hmac-closed')
        self.assertEqual(r['steps'][-1]['value'], 8)
        self.assertEqual(tags.count(0x30092), 4)

    def test_cleanup_failure_retains_hmac_diagnostic(self):
        r, tags = self.run_check('hmac', 'cleanup', hmac_fail_at=1)
        self.assertFalse(r['passed']); self.assertFalse(r['cleanup_locks_closed'])
        self.assertEqual(r['stop'], 'cleanup-locks')
        self.assertEqual([s['name'] for s in r['steps'][-4:]],
                         ['hmac-control', 'last-error-after-transport-failure', 'close-runtime-locks', 'closed-status'])
        self.assertEqual(tags.count(0x30092), 1)
        self.assertEqual(tags.count(0x38090), 2)

    def test_interruption_skips_diagnostic_but_still_closes_locks(self):
        r, tags = self.run_check('hmac', 'hmac-interrupted', hmac_fail_at=1)
        self.assertFalse(r['passed']); self.assertTrue(r['cleanup_locks_closed'])
        self.assertEqual(r['stop'], 'interrupted')
        self.assertNotIn(0x3008e, tags)
        self.assertEqual(tags.count(0x38090), 2)

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
