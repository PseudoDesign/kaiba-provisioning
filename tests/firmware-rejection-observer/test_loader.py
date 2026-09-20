import json,os,pathlib,subprocess,sys,tempfile,unittest
BINARY=sys.argv.pop(1)
class Loader(unittest.TestCase):
 def run_case(self,fault=None):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td);trace=p/'trace';helper=p/'helper'
   helper.write_text('#!/bin/sh\necho helper >> "$TRACE"\nexit 3\n');helper.chmod(0o700)
   env=dict(os.environ,TRACE=str(trace));env.pop('FAULT',None)
   if fault:env['FAULT']=fault
   run=subprocess.run([BINARY,'object',str(helper),'1','0','11111111-1111-4111-8111-111111111111'],env=env,capture_output=True,text=True,timeout=10)
   lines=trace.read_text().splitlines();payload=None
   if 'KAIBA_FIRMWARE_OBSERVER=' in run.stdout:payload=json.loads(run.stdout.split('KAIBA_FIRMWARE_OBSERVER=')[1])
   return run,lines,payload
 def test_helper_failure_is_preserved_and_probes_detach_before_reap(self):
  r,lines,v=self.run_case();self.assertEqual(r.returncode,0,r.stderr)
  self.assertEqual(v['helper_exit'],3);self.assertTrue(v['complete']);self.assertFalse(v['hardware_qualified'])
  self.assertEqual(lines,['load','target','attach','attach','helper','detach','detach','close'])
 def test_verify_only_never_forks_or_selects_target(self):
  with tempfile.TemporaryDirectory() as td:
   trace=pathlib.Path(td)/'trace'
   r=subprocess.run([BINARY,'--verify-only','object'],env=dict(os.environ,TRACE=str(trace)),capture_output=True,text=True,timeout=10)
   self.assertEqual(r.returncode,0,r.stderr)
   self.assertEqual(trace.read_text().splitlines(),['load','attach','attach','detach','detach','close'])
 def test_setup_failures_never_release_helper(self):
  for fault in ['load','target','attach']:
   with self.subTest(fault=fault):
    r,lines,v=self.run_case(fault);self.assertNotEqual(r.returncode,0);self.assertNotIn('helper',lines)
    self.assertEqual(lines[-1],'close')
 def test_map_read_failures_not_complete(self):
  for fault in ['stats','event']:
   with self.subTest(fault=fault):
    r,lines,v=self.run_case(fault);self.assertNotEqual(r.returncode,0);self.assertFalse(v['complete'])
if __name__=='__main__':unittest.main()
