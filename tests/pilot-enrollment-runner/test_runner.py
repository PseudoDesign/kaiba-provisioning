import ctypes
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(os.environ.get('KAIBA_PILOT_RUNNER_SOURCE',
    Path(__file__).resolve().parents[2] / 'scripts/pilot-enrollment'))
spec = importlib.util.spec_from_file_location('runner', SOURCE / 'runner.py')
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
spec = importlib.util.spec_from_file_location('adapter', SOURCE / 'adapter.py')
a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)


def packet():
    now = dt.datetime.now(dt.timezone.utc)
    return dict(schema_version=r.SCHEMA, run_id='fixture-run', asset='mako',
                target_digest='a'*64, issued_at=(now-dt.timedelta(minutes=1)).isoformat().replace('+00:00','Z'),
                expires_at=(now+dt.timedelta(hours=1)).isoformat().replace('+00:00','Z'),
                host_boot_id='11111111-1111-1111-1111-111111111111',
                state_directory='/var/lib/kaiba-run/example', progress_file='/var/lib/kaiba-status/job.json',
                observer_uid=1000, adapter={'path':'/nix/store/example/bin/adapter','sha256':'b'*64},
                context={'path':'/var/lib/kaiba-run/context.json','sha256':'c'*64}, step_timeout_seconds=20)


class Engine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/'journal'
        self.j = r.Journal(self.path, {'packet_sha256':'a'*64}, True)
        self.calls=[];self.applied=[];self.secret=Mock();self.adapter=Mock(secret=self.secret)
        self.adapter.call.side_effect=self.call
    def tearDown(self):
        self.j.close();self.tmp.cleanup()
    def call(self, action, step):
        self.calls.append((action,step))
        if action=='execute':self.applied.append(step)
        return {'step':step,'action':action,'outcome':'complete'}
    def run_job(self):
        return r.Run(self.j,self.adapter,lambda:None).run()
    def test_complete_sequence_releases_secret_before_serving(self):
        self.assertEqual(self.run_job()['status'],'passed')
        self.assertEqual(self.applied,list(r.STEPS));self.secret.close.assert_called_once()
        self.assertIsNone(self.adapter.secret)
        self.assertFalse(self.j.read('result.json')['full_qualification'])
    def test_lost_reply_recognizes_commit_without_reissue(self):
        def call(action,step):
            result=self.call(action,step)
            if action=='execute' and step=='start-enrollment':raise r.Stop('lost-reply')
            return result
        self.adapter.call.side_effect=call;self.run_job()
        self.assertEqual(self.applied.count('start-enrollment'),1)
        self.assertIn(('reconcile','start-enrollment'),self.calls)
    def test_unknown_result_stops_before_install_or_activation(self):
        def call(action,step):
            result=self.call(action,step)
            if step=='submit-bootstrap':result['outcome']='unknown'
            return result
        self.adapter.call.side_effect=call
        with self.assertRaisesRegex(r.Stop,'reconciliation-required'):self.run_job()
        self.assertNotIn('install-credential',self.applied);self.assertNotIn('activate',self.applied)
        self.assertIn(('safe-stop','safe-stop'),self.calls);self.assertIsNone(self.j.read('result.json'))
    def test_existing_intent_only_reconciles_after_process_restart(self):
        self.j.write('prepare-authority.intent.json',{'step':'prepare-authority'})
        self.j.close();self.j=r.Journal(self.path,{'packet_sha256':'a'*64},False)
        self.run_job();self.assertNotIn('prepare-authority',self.applied)
        self.assertIn(('reconcile','prepare-authority'),self.calls)
    def test_complete_job_does_not_contact_adapter(self):
        self.run_job();self.calls.clear()
        with self.assertRaisesRegex(r.Stop,'already-complete'):self.run_job()
        self.assertEqual(self.calls,[])
    def test_failed_preflight_does_not_stop_existing_services(self):
        self.adapter.call.return_value={'outcome':'blocked'};self.adapter.call.side_effect=None
        with self.assertRaisesRegex(r.Stop,'preflight-blocked'):self.run_job()
        self.adapter.call.assert_called_once_with('preflight','preflight')
    def test_backup_failure_never_resumes_serving(self):
        def call(action,step):
            result=self.call(action,step)
            if step=='backup':result['outcome']='blocked'
            return result
        self.adapter.call.side_effect=call
        with self.assertRaises(r.Stop):self.run_job()
        self.assertNotIn('resume-serving',self.applied)
    def test_interrupt_does_not_reconcile_then_continue(self):
        def call(action,step):
            result=self.call(action,step)
            if action=='execute' and step=='start-enrollment':raise r.Stop('interrupted')
            return result
        self.adapter.call.side_effect=call
        with self.assertRaisesRegex(r.Stop,'interrupted'):self.run_job()
        self.assertNotIn(('reconcile','start-enrollment'),self.calls)
        self.assertNotIn('submit-bootstrap',self.applied)
        self.assertIn(('safe-stop','safe-stop'),self.calls)
    def test_second_process_cannot_acquire_job(self):
        with self.assertRaisesRegex(r.Stop,'already-running'):
            r.Journal(self.path,{'packet_sha256':'a'*64},False)
    def test_journal_never_overwrites_evidence(self):
        self.j.write('intent.json',{'keep':True})
        with self.assertRaises(FileExistsError):self.j.write('intent.json',{'keep':False})
        self.assertEqual(self.j.read('intent.json'),{'keep':True})


class Validation(unittest.TestCase):
    def test_valid_packet(self):r.validate(packet())
    def test_packet_rejects_expanded_scope_and_bad_paths(self):
        for key,value in [('unreviewed',True),('expires_at','2030-01-01T00:00:00Z'),
                          ('target_digest','wrong'),('observer_uid',True),('state_directory','/a/../b'),
                          ('step_timeout_seconds',999999)]:
            data=packet();data[key]=value
            with self.subTest(key=key),self.assertRaises(r.Stop):r.validate(data)
    def test_duplicate_json_rejected(self):
        with self.assertRaises(r.Stop):r.decode(b'{"run_id":"one","run_id":"two"}')
    def test_secret_field_is_not_allowed_in_packet(self):
        data=packet();data['passphrase']='DO-NOT-PERSIST'
        with self.assertRaises(r.Stop):r.validate(data)
    def test_symlink_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'link';p.symlink_to('/proc/self/environ')
            with self.assertRaises(r.Stop):r.read_file(p)
    def test_expired_cleanup_is_scoped_and_still_checks_inputs(self):
        data=packet();data['expires_at']='2000-01-01T00:00:00Z'
        with self.assertRaisesRegex(r.Stop,'execution-window-expired'):r.live_guard(data)
        with self.assertRaisesRegex(r.Stop,'host-rebooted'):r.live_guard(data,cleanup=True)


class SecretTests(unittest.TestCase):
    def test_terminal_echo_disabled_and_secret_pipe_only(self):
        master,slave=pty.openpty();secret=r.Secret();errors=[]
        def prompt():
            try:secret.prompt(slave,timeout=3)
            except BaseException as e:errors.append(e)
        thread=threading.Thread(target=prompt);thread.start()
        try:
            self.assertTrue(select.select([master],[],[],2)[0]);os.read(master,4096)
            # Wait until terminal echo has actually been disabled.
            import termios
            end=time.monotonic()+2
            while termios.tcgetattr(slave)[3]&termios.ECHO:
                self.assertLess(time.monotonic(),end);time.sleep(.01)
            os.write(master,b'synthetic-recovery\n');thread.join(3)
            self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
            fd=secret.pipe()
            try:self.assertEqual(os.read(fd,4096),b'synthetic-recovery')
            finally:os.close(fd)
            output=os.read(master,4096);self.assertNotIn(b'synthetic-recovery',output)
        finally:
            secret.close();thread.join(4);os.close(master);os.close(slave)
        self.assertEqual(secret.size,0)
    def test_prompt_timeout_restores_terminal(self):
        import termios
        master,slave=pty.openpty();secret=r.Secret();before=termios.tcgetattr(slave)
        try:
            with self.assertRaisesRegex(r.Stop,'prompt-timeout'):secret.prompt(slave,.01)
            self.assertEqual(termios.tcgetattr(slave),before)
        finally:secret.close();os.close(master);os.close(slave)


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.context={'operations':{k:{'execute':{'argv':['execute']},'probe':{'argv':['probe']}}
                                    for k in (*r.STEPS,'preflight','check-credential','safe-stop')}}
    def test_reconcile_only_probes(self):
        with patch.object(a,'invoke',return_value='complete') as invoke:
            a.dispatch(self.context,{'action':'reconcile','step':'activate'})
            self.assertEqual(invoke.call_count,1);self.assertEqual(invoke.call_args.args[0]['argv'],['probe'])
    def test_successful_execute_requires_probe(self):
        with patch.object(a,'invoke',side_effect=['complete','unknown']) as invoke:
            self.assertEqual(a.dispatch(self.context,{'action':'execute','step':'activate'}),'unknown')
            self.assertEqual(invoke.call_count,2)
    def test_secret_fd_only_reaches_backup_executor(self):
        with patch.object(a,'invoke',return_value='complete') as invoke:
            a.dispatch(self.context,{'action':'execute','step':'backup'},42)
            self.assertEqual(invoke.call_args_list[0].args[2],42)
            self.assertEqual(len(invoke.call_args_list[1].args),2)
        with self.assertRaises(a.r.Stop):a.dispatch(self.context,{'action':'execute','step':'activate'},42)
    def test_bad_credential_stops_before_any_enrollment(self):
        with patch.object(a,'invoke',return_value='blocked') as invoke:
            self.assertEqual(a.dispatch(self.context,{'action':'check-credential','step':'check-credential'},42),'blocked')
            self.assertEqual(invoke.call_count,1)


if __name__=='__main__':unittest.main()
