import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_backup import plan as backup_plan
from test_deployment import plan as deployment_plan

SOURCE=Path(os.environ.get('KAIBA_PILOT_RUNNER_SOURCE',Path(__file__).resolve().parents[2]/'scripts/pilot-enrollment'))
spec=importlib.util.spec_from_file_location('serving',SOURCE/'serving.py');s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)


def policy():
    p=deployment_plan()
    files={str(s.ROOT/x):{'sha256':'a'*64,'owner':'root','mode':0o600} for x in
           ('pki/transport.crt','pki/management.crt','issuer/ca.crt','management/operator.crt','management/station.crt')}
    keys={}
    for role,owner in (('observation','kaiba-pilot-observe'),('admission','kaiba-pilot-admit'),('fleet','kaiba-pilot-fleet'),('issuer','kaiba-pilot-issuer'),('management','root')):
        if role!='management':
            for name in ('config.json','tls.crt',*(('reader.crt',) if role in ('fleet','issuer') else ())):files[str(s.ROOT/role/name)]={'sha256':'a'*64,'owner':owner,'mode':0o600}
        for name in (('operator','station') if role=='management' else ('tls','reader') if role in ('fleet','issuer') else ('tls',)):
            keys[str(s.ROOT/role/(name+'.key'))]=owner
    keys[str(s.ROOT/'issuer/ca.key')]='kaiba-pilot-issuer'
    q={'schema_version':'kaiba.pilot-serving-handoff/v1alpha1','run_id':p['run_id'],'boot_id':p['boot_id'],
       'issued_at':p['issued_at'],'not_after':p['expires_at'],'storage_guard':p['storage_guard'],
       'storage_guard_sha256':p['storage_guard_sha256'],'predecessor_config_sha256':'f'*64,
       'units':p['units'],'files':files,'private_metadata':keys,
       'firewall_before':'Status: active\nExisting Ace rule\n',
       'target_rule':{'interface':'enp4s0','source':'192.0.2.2','destination':'192.0.2.1','comment':'kaiba-fixture'},
       'backup_template':backup_plan()}
    return q


class Policy(unittest.TestCase):
    def test_scope_and_firewall_preserve_existing_rules(self):
        p=policy();s.validate(p)
        s.firewall(p,p['firewall_before'],False)
        s.firewall(p,p['firewall_before']+s.rule_line(p)+'\n',True)
        for raw in (s.rule_line(p),'Status: active\n'+s.rule_line(p),p['firewall_before']+s.rule_line(p)+'\nExtra rule',p['firewall_before']+s.rule_line(p)+'\n'+s.rule_line(p)):
            with self.assertRaises(s.r.Stop):s.firewall(p,raw,True)
        del p['files'][str(s.ROOT/'fleet/config.json')]
        with self.assertRaises(s.r.Stop):s.validate(p)
    def test_extended_window_or_unscoped_network_rejected(self):
        p=policy();p['not_after']='2099-01-01T00:00:00Z'
        with self.assertRaises(s.r.Stop):s.validate(p)
        p=policy();p['target_rule']['source']='0.0.0.0'
        with self.assertRaises(s.r.Stop):s.validate(p)


class Handoff(unittest.TestCase):
    def scenario(self,failure=None,short=False):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);authority=root/'authority';authority.mkdir(mode=0o700)
            config=root/'serving.json';journals=root/'journal';journals.mkdir()
            with patch.object(s,'ROOT',authority),patch.object(s,'CONFIG',config),patch.object(s,'JOURNALS',journals):
                p=policy();old=s.r.canonical({'not_after':p['not_after'],'fixture':'old'})
                config.write_bytes(old);config.chmod(0o600);p['predecessor_config_sha256']=s.r.sha(old)
                c={'schema':'kaiba.pilot-serving/v1alpha1','issued_at':p['issued_at'],'not_after':p['not_after'],
                   'guard':'/nix/store/'+'b'*32+'-guard/bin/kaiba-pilot-serving-guard',
                   'guard_sha256':s.r.sha(b'wrapper'),'units':{u:p['units'][u] for u in s.d.SERVICES}}
                case=self
                class Host(s.d.Deployment):
                    def __init__(self):self.plan=deployment_plan();self.active=set(s.d.SERVICES);self.cleaning=False;self.commands=[];self.network=p['firewall_before']
                    def guard(self,cleanup=False):pass
                    def state_of(self,u):return {'ActiveState':'active' if u in self.active else 'inactive'}
                    def call(self,argv,timeout=120):
                        self.commands.append(argv)
                        if argv==['/usr/sbin/ufw','status','verbose']:return self.network.encode()
                        if argv==['/usr/sbin/ufw',*s.rule_args(p)]:self.network+=s.rule_line(p)+'\n'
                        elif argv==['/usr/sbin/ufw','--force','delete',*s.rule_args(p)]:self.network=p['firewall_before']
                        elif argv==[self.plan['controller'],'stop']:self.active.clear()
                        elif argv==[self.plan['controller'],'start']:
                            if failure=='start':raise s.r.Stop('fixture-start-failed')
                            self.active={s.d.SUPERVISOR,*s.d.SERVICES}
                        return b''
                    def safe_stop(self):self.active.clear()
                    def readers_ready(self):pass
                    def issuer_ready(self,*args):pass
                    def listener_ready(self,*args,**kw):pass
                class Access:
                    plan={'run_id':p['run_id'],'enrollments':{role:{'id':role,'state':'active','binding':{'full_qualification':False,'credential':{'not_after':p['not_after'],'not_before':p['issued_at']}}} for role in ('peer','target')}}
                    def probe(self,step):case.assertEqual(step,'test-restart');return True
                    def records(self):
                        if failure=='drift':raise s.r.Stop('fixture-record-drift')
                    def self_reads(self):pass
                if short:
                    Access.plan['enrollments']['target']['binding']['credential']['not_after']=(s.dt.datetime.now(s.dt.timezone.utc)+s.dt.timedelta(seconds=60)).isoformat().replace('+00:00','Z')
                class Backup:
                    def __init__(self,plan):self.plan=plan
                    def probe(self):
                        if failure=='backup':raise s.r.Stop('fixture-backup-failed')
                        return {'status':'passed','plan_sha256':s.r.sha(s.r.canonical(self.plan)),'services_started':False,'recovery_passphrase_test':'passed'}
                read=s.r.read_file
                def fixture_read(path,*args,**kwargs):
                    if str(path)==c['guard']:return b'wrapper'
                    kwargs.pop('owner',None);return read(path,*args,**kwargs)
                with patch.object(s.r,'trusted_parent'),patch.object(s.r,'read_file',side_effect=fixture_read),patch.object(s.d.os,'fchown'),patch.object(s.Guard,'base'),patch.object(s.b,'Backup',Backup),patch.object(s.Handoff,'observe'):
                    host=Host();handoff=s.Handoff(p,host,Access(),c,p['predecessor_config_sha256'])
                    handoff.open_access()
                    with self.assertRaises(s.r.Stop):handoff.open_access()
                    backup=handoff.prepare_backup()
                    self.assertEqual(host.active,set())
                    self.assertEqual(config.read_bytes(),s.r.canonical(c))
                    self.assertTrue(set('serving-fixture/'+x for x in s.PRESERVED)<=set(backup.plan['preserved_files']))
                    # Model the retained result produced by the actual separately
                    # tested backup hook. No mount or credential claim here.
                    path=journals/'kaiba-backup-fixture';path.mkdir(mode=0o700)
                    if failure!='backup':host.write(path/'result.json',s.r.canonical(backup.probe()))
                    if failure:
                        with self.assertRaises(s.r.Stop):handoff.resume()
                        handoff.cleanup();self.assertEqual(host.active,set());self.assertEqual(host.network,p['firewall_before'])
                        self.assertFalse((handoff.journal/'result.json').exists())
                    else:
                        handoff.resume();self.assertTrue(handoff.probe())
                        if short:
                            # The supervisor remains available for the peer; Fleet
                            # enforces individual certificate expiry on requests.
                            with patch.object(s.time,'time',return_value=s.time.time()+120):self.assertTrue(handoff.guard.check())
                        self.assertEqual(host.active,{s.d.SUPERVISOR,*s.d.SERVICES})
                        with self.assertRaises(FileExistsError):handoff.resume()
                        config.write_bytes(b'changed')
                        with self.assertRaises(s.r.Stop):handoff.verify_live()
    def test_preserved_controls_backup_then_supervised_start(self):self.scenario()
    def test_shorter_target_credential_does_not_extend_or_shorten_cohort(self):self.scenario(short=True)
    def test_failed_backup_never_starts(self):self.scenario('backup')
    def test_failed_start_leaves_reviewable_state_and_removes_only_own_rule(self):self.scenario('start')
    def test_live_record_drift_stops_completion(self):self.scenario('drift')
