import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import test_transport
from test_transport import plan as host_plan

SOURCE=Path(os.environ.get('KAIBA_PILOT_RUNNER_SOURCE',Path(__file__).resolve().parents[2]/'scripts/pilot-enrollment'))
spec=importlib.util.spec_from_file_location('peer',SOURCE/'peer.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


def plan():
    return {'schema_version':'kaiba.pilot-existing-device/v1alpha1','host':host_plan(),
            'client':'/nix/store/'+'a'*32+'-client/bin/kaiba-pilot-device','uid':1001,'gid':1001,
            'expected_status':{'schema_version':'kaiba.pilot-device-client/v1alpha1','phase':'verified',
                               'spki':'public','spki_digest':'sha256:'+'d'*64,'enrollment_id':'peer',
                               'logical_device_id':'logical-peer','full_qualification':False}}


class Peer(unittest.TestCase):
    def test_read_only_route_and_unchanged_state_on_success_or_failure(self):
        q=plan();p.validate(q)
        with patch.object(p,'guard'),patch.object(p,'state_digest',return_value='same'),patch.object(p.d,'command') as command:
            for action,value in (('init',None),('prepare',None),('install','cert'),('check-isolation','peer'),('check-isolation','../other')):
                with self.assertRaises(p.r.Stop):p.dispatch(q,{'action':action,'input':value})
            command.assert_not_called()
            status=p.r.canonical(q['expected_status'])
            command.side_effect=[status,b'{"fixture":"self"}',status]
            self.assertEqual(p.dispatch(q,{'action':'self','input':None}),{'fixture':'self'})
            self.assertEqual([c.args[0][-1] for c in command.call_args_list],['status','self','status'])
            for call in command.call_args_list:self.assertIn(q['client'],call.args[0])
            command.reset_mock();command.side_effect=[status,p.r.Stop('connection failed')]
            with self.assertRaises(p.r.Stop):p.dispatch(q,{'action':'self','input':None})
            self.assertEqual(command.call_count,2)
    def test_state_or_public_status_drift_refuses_success(self):
        q=plan()
        with patch.object(p,'guard'),patch.object(p,'state_digest',side_effect=['before','after']),patch.object(p.d,'command',return_value=p.r.canonical(q['expected_status'])):
            with self.assertRaisesRegex(p.r.Stop,'state-changed'):p.dispatch(q,{'action':'status','input':None})
        with patch.object(p,'guard'),patch.object(p,'state_digest',return_value='same'),patch.object(p.d,'command',return_value=b'{}'):
            with self.assertRaisesRegex(p.r.Stop,'status-changed'):p.dispatch(q,{'action':'self','input':None})
    def test_client_path_and_account_scope(self):
        for update in ({'client':'/tmp/client'},{'uid':0},{'expected_status':plan()['expected_status']|{'private_key':'not allowed'}}):
            with self.assertRaises(p.r.Stop):p.validate(plan()|update)


class PeerTransport(unittest.TestCase):
    setUp=test_transport.Transport.setUp
    tearDown=test_transport.Transport.tearDown
    def test_existing_dispatch_cannot_reach_initial_setup(self):
        import transport
        device=transport.ExistingDevice(self.config,plan())
        with patch.object(device,'exchange') as exchange:
            for action in ('prepare','init','install','bootstrap','observe','prove-installed'):
                with self.assertRaises(p.r.Stop):device(action)
            exchange.assert_not_called()
            device('check-isolation','target');exchange.assert_called_once_with('check-isolation','target')
        self.assertEqual(set(device.modules),{'runner','device','peer'})
        self.assertEqual(device.window,device.plan['host'])
