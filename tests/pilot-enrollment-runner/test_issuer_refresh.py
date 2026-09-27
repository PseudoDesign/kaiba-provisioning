import copy
import datetime as dt
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE=Path(os.environ.get('KAIBA_PILOT_RUNNER_SOURCE',Path(__file__).resolve().parents[2]/'scripts/pilot-enrollment'))
spec=importlib.util.spec_from_file_location('issuer_refresh',SOURCE/'issuer_refresh.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def config():
    return {'reader':{'client_cert':'issuer.crt','client_key':'issuer.key'},
            'renewal':{'unchanged':True},'grants':[
                {'binding':{'target':{'asset':'a'},'adoption_ref':'a','policy_ref':'p','admission_ref':'d','expiry':'unchanged'},'records':{'adoption':'a'}},
                {'binding':{'target':{'asset':'b'},'adoption_ref':'b','policy_ref':'p','admission_ref':'d','expiry':'unchanged'},'records':{'adoption':'b'}}]}


def plan():
    now=dt.datetime.now(dt.timezone.utc)
    return {'schema_version':'kaiba.pilot-issuer-refresh/v1alpha1','run_id':'fixture',
            'boot_id':'fixture','issued_at':(now-dt.timedelta(seconds=5)).isoformat().replace('+00:00','Z'),'expires_at':(now+dt.timedelta(minutes=5)).isoformat().replace('+00:00','Z'),
            'approval_digest':'a'*64,'issuer':'/nix/store/fixture/bin/kaiba-pilot-issuer',
            'storage_guard':'/nix/store/fixture-storage-guard.py','storage_guard_sha256':'f'*64,
            'unit_sha256':'b'*64,'old_config_sha256':'c'*64,'replacement':'/nix/store/replacement',
            'replacement_sha256':'d'*64,'old_scope_digest':'sha256:'+'1'*64,
            'fleet_certificate_sha256':'e'*64,'target':{'asset':'b'}}


class Scope(unittest.TestCase):
    def test_only_selected_references_change(self):
        old=config();new=copy.deepcopy(old)
        new['grants'][1]['binding']['admission_ref']='fresh';new['grants'][1]['records']['decision']='fresh'
        m.difference(old,new,{'asset':'b'})
        for mutate in (lambda x:x['renewal'].update(unchanged=False),
                       lambda x:x['grants'][0]['binding'].update(admission_ref='changed'),
                       lambda x:x['grants'][1]['binding'].update(expiry='extended'),
                       lambda x:x['grants'][1]['binding'].update(target={'asset':'other'})):
            bad=copy.deepcopy(new);mutate(bad)
            with self.assertRaises(m.r.Stop):m.difference(old,bad,{'asset':'b'})
        with self.assertRaises(m.r.Stop):m.difference(old,old,{'asset':'b'})
    def test_plan_rejects_mutable_tools_and_long_window(self):
        for changes in ({'issuer':'/tmp/issuer'}, {'replacement':'/nix/store/../etc/config'},
                        {'approval_digest':'bad'}, {'expires_at':'2099-01-01T00:00:00Z'}):
            with self.assertRaises(m.r.Stop):m.validate(plan()|changes)


class Guards(unittest.TestCase):
    def test_stopped_writer_and_loaded_unit_are_independent_guards(self):
        p=plan();unit=('ExecStart='+p['issuer']+' --config fixed').encode();storage=b'synthetic storage guard'
        p.update(unit_sha256=m.r.sha(unit),storage_guard_sha256=m.r.sha(storage))
        account=types.SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())
        states={name:'inactive' for name in m.STOPPED}|{name:'active' for name in m.ACTIVE}
        loaded='{ path='+p['issuer']+' ; argv[]=fixed ; }'
        def call(argv):
            if argv[0]=='/usr/bin/python3':return b'passed'
            field=argv[3];name=argv[2].removeprefix('kaiba-pilot-').removesuffix('.service')
            if field=='--property=ExecStart':return loaded.encode()
            if field=='--property=MainPID':return b'0'
            return states[name].encode()
        def text(path,*args,**kwargs):
            return 'fixture' if str(path).endswith('boot_id') else 'Filename Type Size Used Priority\n'
        with patch.object(m.pwd,'getpwnam',return_value=account),patch.object(m.os,'geteuid',return_value=0),patch.object(m.Path,'read_text',text),patch.object(m.r,'read_file',side_effect=lambda path,**kw:unit if path==m.UNIT else storage):
            fixture=m.Refresh(p);fixture.call=call;fixture.guard()
            states['issuer']='active'
            with self.assertRaisesRegex(m.r.Stop,'service-state'):fixture.guard()
            states['issuer']='inactive';loaded='{ path=/nix/store/old/bin/kaiba-pilot-issuer ; }'
            with self.assertRaisesRegex(m.r.Stop,'loaded-writer'):fixture.guard()


class Transition(unittest.TestCase):
    def scenario(self,fault=None):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);issuer=root/'issuer';issuer.mkdir(mode=0o700)
            old=m.r.canonical(config());new=copy.deepcopy(config())
            new['grants'][1]['binding']['admission_ref']='fresh';new['grants'][1]['records']['decision']='fresh'
            new=m.r.canonical(new);candidate=root/'candidate';candidate.write_bytes(new)
            live=issuer/'config.json';live.write_bytes(old);live.chmod(0o600)
            p=plan()|{'old_config_sha256':m.r.sha(old),'replacement_sha256':m.r.sha(new)}
            prepared={'status':'prepared','operation_id':'','old_scope_digest':p['old_scope_digest'],
                      'new_scope_digest':'sha256:'+'2'*64,'old_config_digest':'sha256:'+'3'*64,'new_config_digest':'sha256:'+'4'*64}
            account=types.SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())
            read=m.r.read_file
            def fixture_read(path,*args,**kwargs):
                if str(path)==p['replacement']:path=candidate
                kwargs.pop('owner',None)
                return read(path,*args,**kwargs)
            class Fixture(m.Refresh):
                def guard(self, **kwargs):pass
                def parents(self):pass
                def public_identity(self):return b'synthetic certificate'
                def admin(self,mode,request):
                    self.calls.append(mode)
                    if mode=='plan':return prepared
                    if mode=='apply':
                        self.committed=True
                        if fault=='lost':raise m.r.Stop('synthetic-lost-apply-response')
                    if mode=='inspect' and fault=='audit':return self.expected(prepared,'committed')|{'new_scope_digest':'sha256:'+'9'*64}
                    self.assert_committed()
                    return self.expected(prepared,'committed')
                def assert_committed(self):
                    if not self.committed:raise AssertionError('inspection before commit')
            with patch.object(m,'ROOT',root),patch.object(m,'CONFIG',live),patch.object(m.pwd,'getpwnam',return_value=account),patch.object(m.os,'fchown'),patch.object(m.os,'chown'),patch.object(m.r,'read_file',side_effect=fixture_read):
                fixture=Fixture(p);fixture.calls=[];fixture.committed=False
                if fault:
                    with self.assertRaises(m.r.Stop):fixture.execute()
                    self.assertEqual(live.read_bytes(),old)
                    self.assertFalse((fixture.state/'result.json').exists())
                    with self.assertRaises(m.r.Stop):fixture.execute()
                    self.assertEqual(fixture.calls.count('apply'),1)
                    with self.assertRaises(m.r.Stop):fixture.probe()
                else:
                    previous=os.umask(0o077)
                    try:fixture.execute()
                    finally:os.umask(previous)
                    self.assertEqual(live.read_bytes(),new)
                    self.assertEqual((fixture.state/'before.json').read_bytes(),old)
                    self.assertEqual((fixture.inputs/'request.json').stat().st_mode&0o777,0o440)
                    self.assertTrue(fixture.probe())
                    # A completion marker cannot hide a changed live config.
                    live.write_bytes(old)
                    with self.assertRaises(m.r.Stop):fixture.probe()
                    self.assertEqual(fixture.calls.count('apply'),1)
    def test_commit_precedes_install_and_probe_checks_current_state(self):self.scenario()
    def test_lost_reply_cannot_repeat_apply_or_install(self):self.scenario('lost')
    def test_audit_mismatch_cannot_install(self):self.scenario('audit')


class IdentityPipe(unittest.TestCase):
    def test_root_feeder_is_ephemeral_and_only_apply_receives_pipe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cert=root/'reader.crt';key=root/'reader.key'
            cert.write_bytes(b'synthetic public certificate');cert.chmod(0o644);key.write_bytes(b'synthetic private test key');key.chmod(0o600)
            child=root/'child.py';child.write_text("""import base64,json,os,sys
args=sys.argv;mode=args[args.index('--grant-refresh')+1]
if mode=='apply':
 fd=int(args[args.index('--fleet-reader-identity-fd')+1])
 with os.fdopen(fd,'rb') as pipe: bundle=json.load(pipe)
 assert base64.b64decode(bundle['private_key_pem'])==b'synthetic private test key'
 assert base64.b64decode(bundle['certificate_pem'])==b'synthetic public certificate'
else:
 assert '--fleet-reader-identity-fd' not in args
print(json.dumps({'mode':mode,'pipe_checked':mode=='apply'}))
""")
            account=types.SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())
            real_popen=subprocess.Popen;real_read=m.r.read_file;parent_pid=os.getpid();calls=[]
            def popen(argv,**kwargs):
                self.assertEqual(kwargs.pop('user'),os.getuid());self.assertEqual(kwargs.pop('group'),os.getgid())
                self.assertEqual(kwargs.pop('extra_groups'),[])
                self.assertNotIn('synthetic private test key',str(argv)+str(kwargs['env']))
                calls.append(argv)
                return real_popen([sys.executable,str(child),*argv[1:]],**kwargs)
            def read(path,*args,**kwargs):
                if Path(path)==key:
                    if os.getpid()==parent_pid:raise AssertionError('parent read key')
                return real_read(path,*args,**kwargs)
            class Fixture(m.Refresh):
                def guard(self, **kwargs):pass
            with patch.object(m.pwd,'getpwnam',return_value=account),patch.object(m,'FLEET_CERT',cert),patch.object(m,'FLEET_KEY',key),patch.object(m.subprocess,'Popen',side_effect=popen),patch.object(m.r,'read_file',side_effect=read):
                fixture=Fixture(plan()|{'fleet_certificate_sha256':m.r.sha(cert.read_bytes())})
                for mode in ('plan','apply','inspect'):
                    self.assertEqual(fixture.admin(mode,root/'public-request.json'),{'mode':mode,'pipe_checked':mode=='apply'})
            self.assertEqual(len(calls),3)
            self.assertEqual(set(p.name for p in root.iterdir()),{'reader.crt','reader.key','child.py'})
            self.assertEqual(key.stat().st_mode&0o777,0o600)


class ProcessBounds(unittest.TestCase):
    def test_output_bound_and_no_stderr_forwarding(self):
        proc=subprocess.Popen([sys.executable,'-c',"import sys;sys.stderr.write('synthetic secret');print('{}')"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.assertEqual(m.collect(proc,5),b'{}\n')
        proc=subprocess.Popen([sys.executable,'-c',"import sys;sys.stderr.write('x'*2000000)"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        with self.assertRaisesRegex(m.r.Stop,'output'):m.collect(proc,5)
    def test_deadline_kills_stalled_child(self):
        proc=subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        with self.assertRaisesRegex(m.r.Stop,'timeout'):m.collect(proc,.1)
        self.assertIsNotNone(proc.poll())


if __name__=='__main__':unittest.main()
