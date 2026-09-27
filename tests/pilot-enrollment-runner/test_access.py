import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

SOURCE=Path(os.environ.get('KAIBA_PILOT_RUNNER_SOURCE',Path(__file__).resolve().parents[2]/'scripts/pilot-enrollment'))
spec=importlib.util.spec_from_file_location('access',SOURCE/'access.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)


class Access(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();root=Path(self.tmp.name);root.chmod(0o700)
        self.plan={'schema_version':'kaiba.pilot-access-checks/v1alpha1','run_id':'test',
                   'fleet_address':'192.0.2.1','enrollments':{role:{'id':role,'state':'active','binding':{'full_qualification':False,'revision':3 if role=='peer' else 1}} for role in ('peer','target')}}
        self.current=copy.deepcopy(self.plan['enrollments']);self.calls=[];self.denial=403;self.fail_after_stop=False
        self.self_drift=False;self.lost=False
        case=self
        class Host:
            plan={'run_id':'test','peer_id':'peer','issuer_after':'/nix/store/issuer'}
            active=set(a.d.SERVICES)
            generation=1
            def guard(self):pass
            def states(self,units,wanted):
                for u in units:a.r.require((u in self.active)==(wanted=='active'),'fixture-service-state')
            def state_of(self,u):return {'ActiveState':'active' if u in self.active else 'inactive','InvocationID':str(self.generation)*32}
            def stop_children(self):self.active.clear();case.calls.append('stop')
            def call(self,argv):
                case.calls.append('start')
                if case.fail_after_stop:raise a.r.Stop('fixture-start-failed')
                case.assertEqual(argv,['/usr/bin/systemctl','start',*a.d.SERVICES]);self.active.update(a.d.SERVICES);self.generation+=1
            def readers_ready(self):pass
            def issuer_ready(self,binary):case.assertEqual(binary,self.plan['issuer_after'])
            def listener_ready(self,unit,port,address):case.assertEqual((unit,port,address),('kaiba-pilot-fleet.service',18444,'192.0.2.1'))
        self.host=Host()
        self.store=a.p.Store(root,self.plan)
        def authority(path):
            role=path.rsplit('/',1)[1];return copy.deepcopy(self.current[role])
        def device(role):
            def run(action,value=None):
                self.calls.append((role,action,value))
                own={'authorized':'pilot','instance_id':role,'binding':copy.deepcopy(self.current[role]['binding']),'full_qualification':False}
                if self.self_drift:own['binding']['revision']+=1
                if action=='self':return own
                self.assertEqual(action,'check-isolation')
                if self.lost:raise a.r.Stop('fixture-lost-response')
                return {'schema_version':'kaiba.pilot-isolation/v1alpha1','self':own,'other_instance_id':value,'http_status':self.denial}
            return run
        self.check=a.Checks(self.plan,self.store,self.host,authority,{role:device(role) for role in ('peer','target')})
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def test_two_way_isolation_restart_and_fresh_probes(self):
        self.check.isolation();self.assertTrue(self.check.probe('test-isolation'))
        self.check.restart();self.assertTrue(self.check.probe('test-restart'))
        self.assertEqual([c for c in self.calls if isinstance(c,tuple) and c[1]=='check-isolation'], [('peer','check-isolation','target'),('target','check-isolation','peer')])
        self.assertEqual([c for c in self.calls if isinstance(c,str)],['stop','start'])
        self.current['peer']['binding']['revision']=4
        with self.assertRaises(a.r.Stop):self.check.probe('test-restart')
    def test_non_denial_never_passes(self):
        self.denial=200
        with self.assertRaises(a.r.Stop):self.check.isolation()
        self.assertIsNone(self.store.read('isolation-result'))
    def test_lost_isolation_cannot_be_replayed_or_probed_as_success(self):
        self.lost=True
        with self.assertRaises(a.r.Stop):self.check.isolation()
        before=len(self.calls)
        with self.assertRaises(FileExistsError):self.check.isolation()
        with self.assertRaises(a.r.Stop):self.check.probe('test-isolation')
        self.assertEqual(before,len(self.calls))
    def test_failure_after_stop_requires_cleanup_not_replay(self):
        self.check.isolation();self.fail_after_stop=True
        with self.assertRaises(a.r.Stop):self.check.restart()
        self.assertIsNotNone(self.store.read('restart-intent'))
        self.assertIsNone(self.store.read('restart-result'))
        self.assertEqual(self.host.active,set())
        with self.assertRaises(a.r.Stop):self.check.restart()
        self.assertEqual(self.calls.count('stop'),1)
    def test_success_marker_does_not_hide_process_or_self_drift(self):
        self.check.isolation();self.check.restart()
        self.host.generation+=1
        with self.assertRaises(a.r.Stop):self.check.probe('test-restart')
        self.host.generation-=1;self.self_drift=True
        with self.assertRaises(a.r.Stop):self.check.probe('test-restart')
    def test_peer_target_alias_rejected(self):
        p=copy.deepcopy(self.plan);p['enrollments']['target']=p['enrollments']['peer']
        with self.assertRaises(a.r.Stop):a.validate(p)
