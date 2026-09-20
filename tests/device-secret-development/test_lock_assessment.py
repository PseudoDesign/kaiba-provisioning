import copy,json,os,subprocess,sys,unittest
sys.path.insert(0,os.environ['KAIBA_DEVELOPMENT_SCRIPTS'])
import lock_checks
BOOT='11111111-1111-4111-8111-111111111111'
PLAN=dict(schema_version='kaiba.device-secret-lock-checks-plan/v1alpha1',boot_id=BOOT,slot_id=1,expected_usage=8)
class Assessment(unittest.TestCase):
 def fixture(self,fault=None):
  env=dict(os.environ);env.pop('KAIBA_TEST_FAULT',None)
  if fault:env['KAIBA_TEST_FAULT']=fault
  r=subprocess.run([os.environ['KAIBA_LOCK_FIXTURE'],'locks','--slot-id','1','--expected-usage','8','--expected-boot-id',BOOT],env=env,capture_output=True,check=True)
  helper=json.loads(r.stdout)
  results=[0,0,-22 if fault=='raw-einval' else 0,-22 if fault=='sign-einval' else 0]
  observer=dict(schema_version='kaiba.firmware-rejection-observation/v1alpha1',complete=True,helper_exit=0,rejected=0,hardware_qualified=False,
    events=[dict(sequence=i,complete=True,copy_failed=False,tag=tag,result=results[i],request_valid=True,reply_valid=True,response_marked=True,operation_error=i>=2,payload_unchanged_or_zero=i>=2) for i,tag in enumerate([0x30092,0x30091,0x30094,0x30091])])
  return helper,observer
 def assess(self,h,o,plan=PLAN):return lock_checks.assess(json.dumps(h).encode()+b'\nKAIBA_FIRMWARE_OBSERVER='+json.dumps(o).encode()+b'\n',plan)
 def test_complete_observation_keeps_qualification_false(self):
  h,o=self.fixture();a=self.assess(h,o)
  self.assertEqual(a['status'],'matched-target-and-kernel-observations');self.assertFalse(a['hardware_qualified']);self.assertFalse(a['execution_authority'])
 def test_linux_error_steps_remain_failed(self):
  for fault,name in [('raw-einval','raw-read-blocked'),('sign-einval','sign-closed')]:
   h,o=self.fixture(fault);a=self.assess(h,o)
   self.assertEqual(a['original_failed_operations'],[name])
   self.assertFalse(next(s for s in h['steps'] if s['name']==name)['passed'])
 def test_bad_observer_data_rejects(self):
  h,base=self.fixture('raw-einval')
  for index in range(4):
   for key,value in [('complete',False),('copy_failed',True),('request_valid',False),('reply_valid',False),('response_marked',False),('tag',0),('result',-5),('sequence',99),('result',False)]:
    with self.subTest(index=index,key=key):
     o=copy.deepcopy(base);o['events'][index][key]=value
     with self.assertRaises(Exception):self.assess(h,o)
  for index in (2,3):
   o=copy.deepcopy(base);o['events'][index]['payload_unchanged_or_zero']=False
   with self.assertRaises(Exception):self.assess(h,o)
  for key,value in [('rejected',1),('complete',False),('events',base['events'][:-1]),('events',base['events']*2)]:
   o=copy.deepcopy(base);o[key]=value
   with self.assertRaises(Exception):self.assess(h,o)
 def test_controls_order_cleanup_and_stale_error_reject(self):
  base,o=self.fixture('raw-einval')
  for name in [s['name'] for s in base['steps']]:
   with self.subTest(name=name):
    h=copy.deepcopy(base);h['steps']=[s for s in h['steps'] if s['name']!=name]
    with self.assertRaises(Exception):self.assess(h,o)
  h=copy.deepcopy(base);next(s for s in h['steps'] if s['name']=='last-error-raw-read')['value']=8
  with self.assertRaises(Exception):self.assess(h,o)
  h=copy.deepcopy(base);h['cleanup_locks_closed']=False
  with self.assertRaises(Exception):self.assess(h,o)
  h=copy.deepcopy(base);h['steps'][-1]['value']=1
  with self.assertRaises(Exception):self.assess(h,o)
 def test_changed_boot_slot_usage_or_framing_rejects(self):
  h,o=self.fixture()
  for key,value in [('boot_id','22222222-2222-4222-8222-222222222222'),('slot_id',2),('expected_usage',0),('slot_id',True)]:
   p=dict(PLAN);p[key]=value
   with self.assertRaises(Exception):self.assess(h,o,p)
  with self.assertRaises(Exception):lock_checks.assess(b'{}\n{}\n{}',PLAN)
if __name__=='__main__':unittest.main()
