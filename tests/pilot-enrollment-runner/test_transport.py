import base64
import copy
import datetime as dt
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(os.environ.get('KAIBA_PILOT_RUNNER_SOURCE', Path(__file__).resolve().parents[2]/'scripts/pilot-enrollment'))
spec = importlib.util.spec_from_file_location('transport', SOURCE/'transport.py')
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)


def plan():
    now = dt.datetime.now(dt.timezone.utc)
    return {'schema_version':'kaiba.pilot-device-hook/v1alpha1','run_id':'fixture',
            'issued_at':(now-dt.timedelta(seconds=30)).isoformat().replace('+00:00','Z'),
            'expires_at':(now+dt.timedelta(minutes=5)).isoformat().replace('+00:00','Z'),
            'boot_id':'1'*36,'system':'/nix/store/fixture-system','booted_system':'/nix/store/fixture-system',
            'board_sha256':'a'*64,'nvme_sha256':'b'*64,'volume_uuid':'11111111-1111-4111-8111-111111111111',
            'partition':'/dev/nvme0n1p2','client_sha256':'c'*64,'client_size':1,
            'config':{'schema_version':'kaiba.pilot-device-client/v1alpha1',
                      'protected_volume_uuid':'11111111-1111-4111-8111-111111111111'}}


class Transport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.key = self.root/'identity'; self.key.write_text('synthetic-not-an-ssh-key'); self.key.chmod(0o600)
        self.config = {'ssh':'/nix/store/'+'a'*32+'-openssh/bin/ssh', 'host':'fixture.example',
                       'port':22,'user':'operator','identity':str(self.key),'identity_uid':os.getuid(),
                       'known_hosts':'/nix/store/'+'b'*32+'-known-hosts','known_hosts_sha256':t.r.sha(b'fixture'),
                       'python':'/nix/store/'+'c'*32+'-python3/bin/python3','timeout_seconds':10}
        self.device = t.Device(self.config, plan())
    def tearDown(self): self.tmp.cleanup()
    def test_explicit_pins_no_agent_config_or_password_prompt(self):
        with patch.object(t.r, 'read_file', return_value=b'fixture') as read:
            argv = self.device.argv()
        read.assert_called_once_with(self.config['known_hosts'], owner=0)
        self.assertEqual(argv[1:4], ['-F','/dev/null','-T'])
        for option in ('StrictHostKeyChecking=yes','IdentityAgent=none','BatchMode=yes','ForwardAgent=no',
                       'ControlPath=none','ProxyCommand=none','ConnectionAttempts=1','ClearAllForwardings=yes',
                       'PasswordAuthentication=no','KbdInteractiveAuthentication=no'):
            self.assertIn(option, argv)
        self.assertEqual(argv[-2],'operator@fixture.example')
        self.assertNotIn('synthetic-not-an-ssh-key',str(argv))
    def test_mutated_known_hosts_or_open_identity_rejected_before_ssh(self):
        with patch.object(t.r, 'read_file', return_value=b'changed'):
            with self.assertRaisesRegex(t.r.Stop,'known-hosts-changed'): self.device.argv()
        self.key.chmod(0o644)
        with self.assertRaisesRegex(t.r.Stop,'identity-metadata'): self.device.argv()
    def test_no_shell_injection_or_arbitrary_command(self):
        for key,value in (('host','-oProxyCommand=evil'),('user','a;id'),('python','/tmp/interpreter'),('host','host$(id)')):
            with self.assertRaises(t.r.Stop): t.Device(self.config|{key:value}, plan())
        with patch.object(t, 'exchange') as call:
            with self.assertRaises(t.r.Stop): self.device('shell', 'id')
            call.assert_not_called()
    def test_response_bound_to_exact_request_and_nonce(self):
        sent = []
        def exchange(argv, raw, timeout):
            sent.append(raw)
            return t.r.canonical({'schema':'kaiba.pilot-ssh/v1alpha1','request_sha256':t.r.sha(raw),'value':{'status':'observed'}})
        with patch.object(self.device,'argv',return_value=['fixture']),patch.object(t,'exchange',side_effect=exchange):
            self.assertEqual(self.device('observe'),{'status':'observed'})
            self.device('observe')
        self.assertNotEqual(sent[0],sent[1])
        with patch.object(self.device,'argv',return_value=['fixture']),patch.object(t,'exchange',return_value=t.r.canonical({'schema':'kaiba.pilot-ssh/v1alpha1','request_sha256':'0'*64,'value':{}})):
            with self.assertRaisesRegex(t.r.Stop,'response-binding'): self.device('status')
    def test_expired_plan_stops_without_connecting(self):
        self.device.plan['expires_at']='2000-01-01T00:00:00Z'
        with patch.object(t,'exchange') as call:
            with self.assertRaisesRegex(t.r.Stop,'plan-window'): self.device('status')
            call.assert_not_called()


class Processes(unittest.TestCase):
    def test_concurrent_input_output_and_exact_bytes(self):
        code="import sys; sys.stdout.buffer.write(b'ready');sys.stdout.flush();raw=sys.stdin.buffer.read();sys.stdout.buffer.write(str(len(raw)).encode())"
        result=t.exchange([sys.executable,'-c',code],b'x'*(2*1024*1024),10)
        self.assertEqual(result,b'ready2097152')
    def test_unbounded_output_stops_instead_of_deadlocking_on_input(self):
        with self.assertRaisesRegex(t.r.Stop,'output-too-large'):
            t.exchange([sys.executable,'-c',"import sys;sys.stdout.buffer.write(b'x'*2000000);sys.stdout.flush();sys.stdin.read()"],b'x'*(2*1024*1024),5)
    def test_no_implicit_retry_after_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker=Path(tmp)/'attempts'
            code="import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.write_text(p.read_text()+'x' if p.exists() else 'x');sys.stdin.read();sys.exit(1)"
            with self.assertRaisesRegex(t.r.Stop,'command-failed'):
                t.exchange([sys.executable,'-c',code,str(marker)],b'input',5)
            self.assertEqual(marker.read_text(),'x')
    def test_timeout(self):
        with self.assertRaisesRegex(t.r.Stop,'timeout'):
            t.exchange([sys.executable,'-c','import time;time.sleep(10)'],b'input',.1)
    def test_bootstrap_observation_cannot_call_dispatch(self):
        runner=base64.b64encode(b"def require(value, message):\n if not value: raise RuntimeError(message)\n").decode()
        device=base64.b64encode(b"def host_guard(plan):\n assert plan == {'fixture': True}\ndef dispatch(*args):\n raise RuntimeError('mutation invoked')\n").decode()
        payload=t.r.canonical({'schema':'kaiba.pilot-ssh/v1alpha1','nonce':'fixture','modules':{'runner':runner,'device':device},'plan':{'fixture':True},'action':'observe','input':None})
        raw=t.exchange([sys.executable,'-I','-B','-c',t.BOOTSTRAP],payload,5)
        result=t.r.decode(raw)
        self.assertEqual(result['request_sha256'],t.r.sha(payload))
        self.assertEqual(result['value'],{'status':'observed','device_mutated':False})


if __name__ == '__main__': unittest.main()
