import base64
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(os.environ.get('KAIBA_PILOT_RUNNER_SOURCE', Path(__file__).resolve().parents[2]/'scripts/pilot-enrollment'))
spec = importlib.util.spec_from_file_location('protocol', SOURCE/'protocol.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.path = Path(self.tmp.name)
        ref = {'record_id': 'fixture', 'revision': 1, 'digest': 'sha256:'+'a'*64}
        self.plan = {'run_id': 'fixture', 'target': {'asset_ref': 'b'},
                     'records': {role: {'handle': role, 'ref': ref} for role in ('adoption', 'policy', 'decision')},
                     'binding': {'target': {'asset_ref': 'b'}, 'adoption_ref': ref, 'policy_ref': ref, 'admission_ref': ref}}
        self.store = p.Store(self.path, self.plan)
        self.status = {'schema_version': 'kaiba.pilot-device-client/v1alpha1', 'phase': 'initialized',
                       'spki': base64.b64encode(b'synthetic-spki').decode(),
                       'spki_digest': p.digest(b'synthetic-spki'), 'full_qualification': False}
        self.calls = []; self.rows = {}; self.lose = None; self.changed = None
        self.hook = p.Protocol(self.plan, self.store, self.authority, self.device)

    def tearDown(self):
        self.store.close(); self.tmp.cleanup()

    def device(self, action, data):
        self.calls.append(('device', action))
        if action == 'status':
            return copy.deepcopy(self.status)
        if action == 'init':
            return self.status
        if action == 'bootstrap':
            self.status.update(phase='bootstrap_proved', enrollment_id='enrollment-b', logical_device_id='logical-b')
            return {'signature': 'synthetic'}
        raise AssertionError(action)

    def authority(self, path, role='operator', body=None, key=None):
        self.calls.append(('authority', 'GET' if body is None else 'POST'))
        if path.endswith('/enrollments'):
            value = {'id': 'enrollment-b', 'logical_device_id': 'logical-b', 'state': 'awaiting_proof',
                     'request': body, 'intent': self.plan['binding'],
                     'challenge': {'binding': self.plan['binding'], 'enrollment_id': 'enrollment-b', 'logical_device_id': 'logical-b'}}
            self.rows['b'] = copy.deepcopy(value)
        elif path.endswith('/proof'):
            self.rows['b']['state'] = 'staged'; value = self.rows['b']
        elif path.endswith('/activate'):
            self.rows['b']['state'] = 'active'; value = self.rows['b']
        else:
            value = copy.deepcopy(self.rows['b'])
        if body is not None and self.lose:
            raise p.r.Stop('lost')
        if self.changed:
            value = self.changed(copy.deepcopy(value))
        return value

    def test_lost_start_is_not_rediscovered_by_mutation(self):
        self.lose = True
        with self.assertRaises(p.r.Stop): self.hook.execute('start-enrollment')
        self.assertFalse(self.hook.probe('start-enrollment'))
        with self.assertRaisesRegex(p.r.Stop, 'already-attempted'): self.hook.execute('start-enrollment')
        self.assertEqual(self.calls.count(('authority', 'POST')), 1)

    def test_lost_proof_reply_reconciles_without_signing_twice(self):
        self.assertTrue(self.hook.execute('start-enrollment'))
        self.lose = True
        with self.assertRaises(p.r.Stop): self.hook.execute('submit-bootstrap')
        self.assertTrue(self.hook.probe('submit-bootstrap'))
        self.assertEqual(self.calls.count(('device', 'bootstrap')), 1)
        with self.assertRaisesRegex(p.r.Stop, 'already-attempted'): self.hook.execute('submit-bootstrap')

    def test_changed_authority_identity_stops_before_key_use(self):
        self.hook.execute('start-enrollment')
        for key in ('id', 'logical_device_id'):
            self.changed = lambda value: value | {key: 'different'}
            with self.assertRaisesRegex(p.r.Stop, 'identity-changed'): self.hook.probe('start-enrollment')
        self.assertNotIn(('device', 'bootstrap'), self.calls)

    def test_changed_client_key_stops_before_proof(self):
        self.hook.execute('start-enrollment')
        self.status.update(spki=base64.b64encode(b'other').decode(), spki_digest=p.digest(b'other'))
        with self.assertRaisesRegex(p.r.Stop, 'key-changed'): self.hook.execute('submit-bootstrap')
        self.assertNotIn(('device', 'bootstrap'), self.calls)

    def test_changed_records_and_target_rejected(self):
        self.hook.execute('start-enrollment')
        self.rows['b']['request']['records']['decision']['handle'] = 'another'
        with self.assertRaisesRegex(p.r.Stop, 'request-mismatch'): self.hook.probe('start-enrollment')

    def test_plan_and_existing_journal_are_bound(self):
        changed = copy.deepcopy(self.plan); changed['run_id'] = 'other'
        with self.assertRaisesRegex(p.r.Stop, 'plan-changed'):
            p.Protocol(changed, self.store, self.authority, self.device)
        self.store.close(); self.store = p.Store(self.path, self.plan)
        with self.assertRaises(BlockingIOError): p.Store(self.path, self.plan)

    def test_corrupt_or_symlinked_journal_is_not_missing(self):
        (self.path/'start-enrollment.response.json').symlink_to(self.path/'binding.json')
        with self.assertRaisesRegex(p.r.Stop, 'not-regular'): self.hook.probe('start-enrollment')

    def test_authority_url_restrictions_before_loading_keys(self):
        for url in ('http://example.com', 'https://user@example.com', 'https://example.com/x', 'https://example.com/?redirect=x'):
            with self.assertRaisesRegex(p.r.Stop, 'authority-url'):
                p.Authority(url, 'unused', {})

    def test_http_rejects_redirect_and_oversize_without_retry(self):
        authority = object.__new__(p.Authority)
        authority.host = 'fixture'; authority.port = 443; authority.contexts = {'operator': None}
        with patch.object(p.http.client, 'HTTPSConnection') as factory:
            conn = factory.return_value; response = conn.getresponse.return_value
            response.status = 302
            with self.assertRaises(p.r.Stop): authority('/api/v1/pilot/enrollments/id')
            self.assertEqual(conn.request.call_count, 1); conn.close.assert_called_once()
            factory.reset_mock(); response.status = 200
            response.getheader.return_value = 'application/json'
            response.read.return_value = b'x'*(p.LIMIT+1)
            with self.assertRaisesRegex(p.r.Stop, 'response-size'): authority('/api/v1/pilot/enrollments/id')
            self.assertEqual(conn.request.call_count, 1); conn.close.assert_called_once()


if __name__ == '__main__': unittest.main()
