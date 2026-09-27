import copy
import datetime as dt
import importlib.util
import os
import sys
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE=Path(os.environ.get('KAIBA_PILOT_RUNNER_SOURCE',Path(__file__).resolve().parents[2]/'scripts/pilot-enrollment'))
spec=importlib.util.spec_from_file_location('deployment',SOURCE/'deployment.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)


def plan():
    now=dt.datetime.now(dt.timezone.utc)
    start=(now-dt.timedelta(seconds=2)).isoformat().replace('+00:00','Z')
    end=(now+dt.timedelta(minutes=5)).isoformat().replace('+00:00','Z')
    q={'schema_version':'kaiba.pilot-issuer-refresh/v1alpha1','run_id':'fixture','boot_id':'fixture',
       'issued_at':start,'expires_at':end,'approval_digest':'a'*64,'issuer':'/nix/store/new/bin/kaiba-pilot-issuer',
       'storage_guard':'/nix/store/storage.py','storage_guard_sha256':'b'*64,'unit_sha256':'c'*64,
       'old_config_sha256':d.r.sha(b'old issuer'),'replacement':'/nix/store/issuer.json','replacement_sha256':d.r.sha(b'new issuer'),
       'old_scope_digest':'sha256:'+'d'*64,'fleet_certificate_sha256':'e'*64,'target':{'asset':'b'}}
    return {'schema_version':'kaiba.pilot-host-deployment/v1alpha1','run_id':'fixture','boot_id':'fixture',
            'issued_at':start,'expires_at':end,'storage_guard':q['storage_guard'],'storage_guard_sha256':q['storage_guard_sha256'],
            'controller':'/nix/store/control','controller_sha256':'f'*64,
            'issuer_before':'/nix/store/old/bin/kaiba-pilot-issuer','issuer_after':q['issuer'],
            'issuer_unit_sha256':'a'*64,'units':{u:'a'*64 for u in (d.SUPERVISOR,*d.SERVICES)},'peer_id':'peer-a','refresh_plan':q,
            'files':[{'target':role+'/config.json','source':'/nix/store/'+role+'.json','before_sha256':d.r.sha(b'old reader'),'after_sha256':d.r.sha(b'new reader')} for role in ('observation','admission')]}


class Scope(unittest.TestCase):
    def test_host_command_can_find_system_helper_without_inheriting_path(self):
        # Model UFW resolving sysctl from /usr/sbin, without calling real UFW,
        # requiring root, or depending on the test host's system directories.
        with tempfile.TemporaryDirectory() as tmp:
            helper=Path(tmp)/'sysctl'
            helper.write_text('#!'+sys.executable+'\nprint("fixture-sysctl-read-only")\n')
            helper.chmod(0o755)
            host=object.__new__(d.Deployment);host.plan=plan();host.cleaning=False
            real_popen=d.subprocess.Popen
            def launch(argv,**kwargs):
                env=kwargs['env']
                self.assertEqual(set(env),{'PATH','LC_ALL'})
                self.assertNotIn('/untrusted',env['PATH'].split(':'))
                env['PATH']=':'.join(tmp if p=='/usr/sbin' else p for p in env['PATH'].split(':'))
                return real_popen(argv,**kwargs)
            child='import subprocess; print(subprocess.check_output(["sysctl", "net.ipv4.ip_forward"], text=True).strip())'
            with patch.dict(os.environ,{'PATH':'/untrusted','SECRET_TEST_INPUT':'must-not-inherit'}),patch.object(d.subprocess,'Popen',side_effect=launch):
                self.assertEqual(host.call([sys.executable,'-c',child]),b'fixture-sysctl-read-only\n')

    def test_target_scope_and_refresh_binding(self):
        d.validate(plan())
        for target in ('issuer/config.json','fleet/reader.key','admission/../issuer/config.json','/etc/passwd'):
            p=plan();p['files'][0]['target']=target
            with self.assertRaises(d.r.Stop):d.validate(p)
        for field,value in (('run_id','other'),('issuer','/nix/store/other/bin/kaiba-pilot-issuer'),('boot_id','other')):
            p=plan();p['refresh_plan'][field]=value
            with self.assertRaises(d.r.Stop):d.validate(p)
        p=plan();del p['units'][d.SUPERVISOR]
        with self.assertRaises(d.r.Stop):d.validate(p)
        p=plan();p['files'].append(p['files'][0])
        with self.assertRaises(d.r.Stop):d.validate(p)


class Listener(unittest.TestCase):
    def check(self,sockets,executables,states=None):
        host=object.__new__(d.Deployment);host.plan=plan();host.cleaning=False
        initial={'ActiveState':'active','MainPID':'42','InvocationID':'first'}
        host.state_of=lambda unit: next(states) if states is not None else initial.copy()
        def socket_read(argv):
            self.assertEqual(argv,['/usr/bin/ss','-H','-lntp','sport = :18443'])
            return next(sockets)
        host.call=socket_read
        reads=[];clock=[0]
        def resolve(path,strict=False):
            self.assertTrue(strict)
            if str(path).startswith('/proc/'):
                reads.append(str(path));value=next(executables)
                if isinstance(value,Exception):raise value
                return Path(value)
            return path
        def sleep(seconds):clock[0]+=10
        with patch.object(d.Path,'resolve',resolve),patch.object(d.time,'monotonic',side_effect=lambda:clock[0]),patch.object(d.time,'sleep',side_effect=sleep):
            host.issuer_ready('/nix/store/expected/bin/kaiba-pilot-issuer')
        return reads

    @staticmethod
    def socket(pid=42,address='127.0.0.1'):
        return ('LISTEN 0 128 '+address+':18443 0.0.0.0:* users:(("issuer",pid='+str(pid)+',fd=3))\n').encode()

    def test_pre_exec_without_listener_waits_before_reading_executable(self):
        reads=self.check(iter([b'',self.socket()]),iter(['/nix/store/expected/bin/kaiba-pilot-issuer']))
        self.assertEqual(reads,['/proc/42/exe'])

    def test_wrong_executable_owning_listener_is_rejected(self):
        with self.assertRaisesRegex(d.r.Stop,'deployment-issuer-executable'):
            self.check(iter([self.socket()]),iter(['/nix/store/wrong/bin/issuer']))

    def test_process_exit_during_observation_waits_for_fresh_read(self):
        self.check(iter([self.socket(),self.socket()]),iter([FileNotFoundError(),'/nix/store/expected/bin/kaiba-pilot-issuer']))

    def test_changed_pid_or_invocation_cannot_satisfy_readiness(self):
        first={'ActiveState':'active','MainPID':'42','InvocationID':'first'}
        for changed in (first|{'MainPID':'43'},first|{'InvocationID':'second'}):
            with self.subTest(changed=changed):
                self.check(iter([self.socket(),self.socket()]),iter(['/nix/store/wrong/bin/issuer','/nix/store/expected/bin/kaiba-pilot-issuer']),iter([first,changed,first,first]))

    def test_wrong_listener_owner_or_address_times_out_without_executable_read(self):
        for socket in (self.socket(pid=43),self.socket(address='0.0.0.0'),b''):
            with self.subTest(socket=socket),self.assertRaisesRegex(d.r.Stop,'deployment-listener-not-ready'):
                self.check(iter([socket]*4),iter([]))

    def test_failed_service_is_not_ready(self):
        with self.assertRaisesRegex(d.r.Stop,'deployment-listener-start-failed'):
            self.check(iter([]),iter([]),iter([{'ActiveState':'failed','MainPID':'0'}]))


class Sequence(unittest.TestCase):
    def scenario(self,fault=None):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'authority';root.mkdir(mode=0o700);units=Path(tmp)/'units';units.mkdir()
            for role in ('issuer','observation','admission'):(root/role).mkdir(mode=0o700)
            issuer_config=root/'issuer/config.json';issuer_config.write_bytes(b'old issuer')
            for role in ('observation','admission'):
                (root/role/'config.json').write_bytes(b'old reader');(root/role/'config.json').chmod(0o600)
            p=plan();unit=('ExecStart='+p['issuer_before']+' --config fixed\nRestart=no\n').encode()
            (units/'kaiba-pilot-issuer.service').write_bytes(unit)
            p['issuer_unit_sha256']=p['units']['kaiba-pilot-issuer.service']=d.r.sha(unit)
            p['refresh_plan']['unit_sha256']=d.r.sha(unit.replace(p['issuer_before'].encode(),p['issuer_after'].encode()))
            peer={'id':'peer-a','state':'active','binding':{'full_qualification':False,'key':'unchanged'}}
            account=types.SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())
            read=d.r.read_file
            def fixture_read(path,*args,**kwargs):
                if str(path) in ('/nix/store/observation.json','/nix/store/admission.json'):return b'new reader'
                kwargs.pop('owner',None);return read(path,*args,**kwargs)
            class Refresh:
                def __init__(self,q):self.q=q;self.calls=0
                def configuration(self,expected):
                    d.r.require(d.r.sha(issuer_config.read_bytes())==expected,'fixture-issuer-changed')
                def execute(self):
                    self.calls+=1
                    case.assertTrue(host.initialized)
                    case.assertEqual(host.active, set(d.SERVICES[:3]))
                    case.assertTrue(all((root/item['target']).read_bytes()==b'new reader' for item in p['files']))
                    issuer_config.write_bytes(b'new issuer')
                    if fault=='refresh-lost':raise d.r.Stop('fixture-lost-after-commit')
                def probe(self):return issuer_config.read_bytes()==b'new issuer'
            class Host(d.Deployment):
                def guard(self,cleanup=False):pass
                def protected_root(self):pass
                def state_of(self,u):return {'ActiveState':'active' if u in self.active else 'inactive'}
                def issuer_ready(self,binary):
                    case.assertIn(d.SERVICES[3],self.active)
                    case.assertEqual(binary,p['issuer_after'])
                    case.assertIn(binary.encode(),self.upgrade.read_bytes())
                    if issuer_config.read_bytes()==b'old issuer':self.initialized=True
                def readers_ready(self):case.assertTrue(set(d.READERS)<=self.active)
                def call(self,argv,timeout=120):
                    self.commands.append(list(argv))
                    if argv==[p['controller'],'stop']:self.active.clear()
                    elif argv[:2]==['/usr/bin/systemctl','start']:self.active.update(argv[2:])
                    elif argv[:2]==['/usr/bin/systemctl','stop']:self.active.difference_update(argv[2:])
                    if fault=='start' and argv[:2]==['/usr/bin/systemctl','start']:
                        raise d.r.Stop('fixture-start-failed')
                    return b''
            case=self
            def authority(path):
                self.assertEqual(path,'/api/v1/pilot/enrollments/peer-a')
                value=copy.deepcopy(peer)
                if fault=='peer' and host.refresher.calls:value['binding']['key']='changed'
                return value
            with patch.object(d,'ROOT',root),patch.object(d,'UNITS',units),patch.object(d.refresh,'Refresh',Refresh),patch.object(d.pwd,'getpwnam',return_value=account),patch.object(d.os,'fchown'),patch.object(d.r,'read_file',side_effect=fixture_read):
                host=Host(p,authority);host.active={d.SUPERVISOR,*d.SERVICES};host.commands=[];host.initialized=False
                if fault:
                    with self.assertRaises(d.r.Stop):host.execute()
                    self.assertFalse((host.state/'result.json').exists())
                    before=issuer_config.read_bytes();host.safe_stop()
                    self.assertEqual(host.active,set());self.assertEqual(issuer_config.read_bytes(),before)
                    with self.assertRaises(d.r.Stop):host.execute()
                    self.assertLessEqual(host.refresher.calls,1)
                else:
                    host.execute();self.assertTrue(host.probe())
                    self.assertEqual(host.active,set(d.SERVICES));self.assertEqual(host.refresher.calls,1)
                    self.assertEqual((host.state/'issuer-unit.before').read_bytes(),unit)
                    self.assertEqual((host.state/'file-0.before').read_bytes(),b'old reader')
                    self.assertFalse(d.r.decode((host.state/'result.json').read_bytes())['device_contacted'])
                    (root/'observation/config.json').write_bytes(b'changed')
                    with self.assertRaises(d.r.Stop):host.probe()
    def test_full_order_and_fresh_probe(self):self.scenario()
    def test_partial_start_stops_without_replay(self):self.scenario('start')
    def test_committed_refresh_is_never_rolled_back(self):self.scenario('refresh-lost')
    def test_peer_change_blocks_completion(self):self.scenario('peer')


if __name__=='__main__':unittest.main()
