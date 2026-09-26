import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

SOURCE=Path(os.environ.get('KAIBA_PILOT_RUNNER_SOURCE',Path(__file__).resolve().parents[2]/'scripts/pilot-enrollment'))
s=importlib.util.spec_from_file_location('runner',SOURCE/'runner.py');r=importlib.util.module_from_spec(s);s.loader.exec_module(r)

class ProcessRehearsal(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.config={'database':str(self.root/'authority.sqlite'),'key_hash':hashlib.sha256(b'fixture-secret').hexdigest()}
        self.context=self.root/'context.json';self.context.write_text(json.dumps(self.config))
        self.exe=self.root/'fixture'
        self.exe.write_text('#!'+sys.executable+'\n'+Path(__file__).with_name('fixture.py').read_text());self.exe.chmod(0o700)
        self.secret=r.Secret();ctypes.memmove(self.secret.address,b'fixture-secret',14);self.secret.size=14
        self.packet={'run_id':'fixture','target_digest':'a'*64,'expires_at':'2099-01-01T00:00:00Z',
                     'adapter':{'path':str(self.exe)},'context':{'path':str(self.context),'sha256':r.sha(self.context.read_bytes())},'step_timeout_seconds':2}
        self.adapter=r.Adapter(self.packet,'b'*64,lambda **kw:None,self.secret)
        self.journal=r.Journal(self.root/'journal',{'packet_sha256':'b'*64},True)
    def tearDown(self):self.secret.close();self.journal.close();self.temp.cleanup()
    def scenario(self,**changes):
        self.config.update(changes);self.context.write_text(json.dumps(self.config));self.packet['context']['sha256']=r.sha(self.context.read_bytes())
    def test_complete_job_across_processes_and_lost_reply(self):
        self.scenario(lose_reply='start-enrollment')
        self.assertEqual(self.adapter.call('check-credential','check-credential')['outcome'],'complete')
        result=r.Run(self.journal,self.adapter,lambda:None).run();self.assertEqual(result['status'],'passed')
        db=sqlite3.connect(self.config['database']);steps=[row[0] for row in db.execute('SELECT step FROM operations ORDER BY rowid')];db.close()
        self.assertEqual(steps,list(r.STEPS))
        saved=sqlite3.connect(self.config['database']+'.backup')
        self.assertEqual(saved.execute("SELECT COUNT(*) FROM operations WHERE step='activate'").fetchone()[0],1);saved.close()
        self.assertTrue(self.secret.page.closed)
        for f in (self.root/'journal').iterdir():
            self.assertNotIn(b'fixture-secret',f.read_bytes());self.assertNotIn(b'SYNTHETIC-SENSITIVE',f.read_bytes())
    def test_copied_completion_from_other_target_rejected(self):
        self.scenario()
        result=self.adapter.call('execute','prepare-authority')
        result['target_digest']='d'*64
        self.journal.write('prepare-authority.complete.json',result)
        with self.assertRaisesRegex(r.Stop,'journal-completion-binding'):
            r.Run(self.journal,self.adapter,lambda:None).run()
    def test_wrong_target_result_not_accepted(self):
        self.scenario(wrong_target='preflight')
        with self.assertRaisesRegex(r.Stop,'binding'):self.adapter.call('preflight','preflight')
    def test_bounded_output(self):
        self.scenario(oversize='preflight')
        with self.assertRaisesRegex(r.Stop,'too-large'):self.adapter.call('preflight','preflight')
    def test_timeout(self):
        self.scenario(hang='preflight');self.packet['step_timeout_seconds']=1
        with self.assertRaisesRegex(r.Stop,'timeout'):self.adapter.call('preflight','preflight')
    def test_wrong_recovery_credential_fails_before_mutations(self):
        self.config['key_hash']='0'*64;self.scenario()
        with self.assertRaisesRegex(r.Stop,'adapter-failed'):self.adapter.call('check-credential','check-credential')
        self.assertFalse(Path(self.config['database']).exists())


class CommandAdapterProcess(unittest.TestCase):
    def test_backup_descriptor_is_not_forwarded_to_probe(self):
        spec=importlib.util.spec_from_file_location('adapter',SOURCE/'adapter.py');a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);hook=root/'hook.py'
            hook.write_text('''import argparse,json,os,sys
p=argparse.ArgumentParser();p.add_argument('--recovery-key-fd',type=int);a=p.parse_args()
q=json.load(sys.stdin)
if q['action']=='execute':
    assert os.read(a.recovery_key_fd,100)==b'synthetic-key'
else:
    assert a.recovery_key_fd is None
assert 'synthetic-key' not in ' '.join(sys.argv)
assert 'synthetic-key' not in str(dict(os.environ))
print(json.dumps({'outcome':'complete'}))
''')
            cmd={'argv':[sys.executable,str(hook)]};context={'operations':{'backup':{'execute':cmd,'probe':cmd}}}
            rd,wr=os.pipe();os.write(wr,b'synthetic-key');os.close(wr)
            try:self.assertEqual(a.dispatch(context,{'action':'execute','step':'backup'},rd),'complete')
            finally:os.close(rd)

if __name__=='__main__':unittest.main()
