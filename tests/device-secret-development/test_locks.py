import json,os,subprocess,sys,unittest
HELPER,PRODUCTION=sys.argv[1:3];sys.argv=sys.argv[:1]
BOOT='11111111-1111-4111-8111-111111111111'
class Locks(unittest.TestCase):
 def run_case(self,fault=None):
  env=dict(os.environ);env.pop('KAIBA_TEST_FAULT',None)
  if fault:env['KAIBA_TEST_FAULT']=fault
  r=subprocess.run([HELPER,'locks','--slot-id','1','--expected-usage','8','--expected-boot-id',BOOT],env=env,capture_output=True,text=True)
  v=json.loads(r.stdout);tags=[int(x.split()[1],16) for x in r.stderr.splitlines() if x.startswith("TAG ")]
  self.assertEqual(r.returncode,0 if v['completed'] else 3)
  self.assertFalse(v['hardware_qualified']);self.assertNotIn('PRIVATE_MATERIAL',r.stdout)
  self.assertLessEqual(tags.count(0x38090),4);self.assertLessEqual(tags.count(0x30092),1);self.assertLessEqual(tags.count(0x30091),2)
  return v,tags
 def test_validation_reason_survives_cleanup_without_extra_calls(self):
  for fault,reason in [('sign-status','operation-status'),('sign-length','output-too-short'),('sign-response-length','output-outside-response')]:
   env=dict(os.environ,KAIBA_TEST_FAULT=fault)
   r=subprocess.run([HELPER,'locks','--slot-id','1','--expected-usage','8','--expected-boot-id',BOOT],env=env,capture_output=True,text=True)
   v=json.loads(r.stdout)
   self.assertEqual(r.returncode,3);self.assertEqual(v['stop'],'sign-control');self.assertTrue(v['cleanup_locks_closed'])
   self.assertEqual([x for x in r.stderr.splitlines() if not x.startswith('TAG ')],[f'KAIBA_RESPONSE_VALIDATION step=sign-control reason={reason}'])
   self.assertEqual([int(x.split()[1],16) for x in r.stderr.splitlines() if x.startswith('TAG ')],[0x3008f,0x30090,0x3009c,0x38090,0x30090,0x30092,0x30091,0x38090,0x30090])
 def test_exact_bounded_sequence(self):
  v,tags=self.run_case();self.assertTrue(v['completed']);self.assertTrue(v['cleanup_locks_closed'])
  self.assertEqual(tags,[0x3008f,0x30090,0x3009c,0x38090,0x30090,0x30092,0x30091,0x30094,0x3008e,0x30024,0x30081,0x38090,0x30090,0x30091,0x3008e,0x38090,0x30090,0x38090,0x30090])
 def test_linux_denial_is_preserved_as_failed_step_not_promoted(self):
  for fault,name in [('raw-einval','raw-read-blocked'),('sign-einval','sign-closed')]:
   with self.subTest(fault=fault):
    v,tags=self.run_case(fault);self.assertTrue(v['completed'])
    step=next(s for s in v['steps'] if s['name']==name)
    self.assertFalse(step['passed']);self.assertEqual((step['outcome'],step['mailbox_errno']),(2,22))
 def test_negative_cases_stop_and_cleanup(self):
  for fault in ['private-returned','legacy-unlocked','legacy-io','sign-control','sign-timeout','sign-unlocked','clearable-locks','cleanup','last-error-other','interrupt-sign-control','clear-io-after-effect']:
   with self.subTest(fault=fault):
    v,tags=self.run_case(fault);self.assertFalse(v['completed'])
    self.assertEqual(tags[-2:],[0x38090,0x30090])
    if fault!='cleanup':self.assertTrue(v['cleanup_locks_closed'])
    if fault in ['private-returned','legacy-unlocked','legacy-io','sign-control']:self.assertEqual(tags.count(0x30091),1)
 def test_preclosed_never_runs_secret_operations(self):
  v,tags=self.run_case('preclosed');self.assertFalse(v['completed']);self.assertEqual(tags,[0x3008f,0x30090,0x3009c])
 def test_production_rejects_unrelated_modes_before_device_access(self):
  for mode in ['hmac','read-lock','inspect']:
   r=subprocess.run([PRODUCTION,mode,'--slot-id','1','--expected-usage','8','--expected-boot-id',BOOT],capture_output=True)
   self.assertEqual(r.returncode,2)
if __name__=='__main__':unittest.main()
