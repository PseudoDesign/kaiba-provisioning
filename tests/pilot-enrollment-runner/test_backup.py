import errno
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(os.environ.get('KAIBA_PILOT_RUNNER_SOURCE', Path(__file__).resolve().parents[2]/'scripts/pilot-enrollment'))
spec=importlib.util.spec_from_file_location('backup',SOURCE/'backup.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)


def plan():
    return {'schema_version':'kaiba.pilot-backup-hook/v1alpha1','run_id':'fixture','boot_id':'fixture',
            'expires_at':'2099-01-01T00:00:00Z','luks_uuid':'11111111-1111-4111-8111-111111111111',
            'usb':{'path':'/dev/disk/by-id/usb-fixture-part1','serial':'fixture','uuid':'ABCD-1234',
                   'disk_size':4000000000,'partition_size':3000000000},
            'cryptsetup':'/nix/store/fixture/bin/cryptsetup','postgres':'/nix/store/fixture/bin',
            'preserved_files':{'control.json':b.r.sha(b'synthetic control')}}


class Files(unittest.TestCase):
    def test_exclusive_copy_and_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/'source';dst=Path(tmp)/'dest';src.write_bytes(b'x'*8192)
            self.assertEqual(b.copy_exclusive(src,dst,8192),b.file_hash(src))
            self.assertEqual(dst.read_bytes(),src.read_bytes())
            with self.assertRaises(FileExistsError):b.copy_exclusive(src,dst,8192)
            with self.assertRaises(b.r.Stop):b.copy_exclusive(src,Path(tmp)/'wrong',8193)
    def test_snapshot_metadata_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(b.os,'listxattr',return_value=[]):
            root=Path(tmp);path=root/'fixture';path.write_text('not a secret')
            first=b.snapshot(root);path.chmod(0o400)
            self.assertNotEqual(b.snapshot(root),first)
            (root/'link').symlink_to(path)
            with self.assertRaises(b.r.Stop):b.snapshot(root)
    def test_snapshot_preserves_xattr_values_and_detects_changes(self):
        # CI's build filesystem may reject xattrs. Supply synthetic syscall
        # results while exercising the actual snapshot comparison.
        with tempfile.TemporaryDirectory() as tmp, patch.object(b.os,'listxattr',return_value=['user.fixture']) as names:
            root=Path(tmp)
            with patch.object(b.os,'getxattr',return_value=b'original') as values:
                first=b.snapshot(root)
                values.assert_called_once_with(root,'user.fixture',follow_symlinks=False)
            names.assert_called_once_with(root,follow_symlinks=False)
            self.assertEqual(first['.']['xattrs'],{'user.fixture':b'original'.hex()})
            with patch.object(b.os,'getxattr',return_value=b'changed'):
                self.assertNotEqual(b.snapshot(root),first)
    def test_snapshot_refuses_unreadable_xattrs(self):
        with tempfile.TemporaryDirectory() as tmp:
            for code in (errno.EOPNOTSUPP,errno.EACCES):
                with self.subTest(code=code), patch.object(b.os,'listxattr',side_effect=OSError(code,'synthetic xattr failure')):
                    with self.assertRaises(OSError):b.snapshot(Path(tmp))
                with self.subTest(value_code=code), patch.object(b.os,'listxattr',return_value=['user.fixture']), patch.object(b.os,'getxattr',side_effect=OSError(code,'synthetic xattr failure')):
                    with self.assertRaises(OSError):b.snapshot(Path(tmp))
    def test_reject_path_escape_and_oversized_mapping_name(self):
        for change in ({'run_id':'x'*57},{'preserved_files':{'../elsewhere':'a'*64}},
                       {'postgres':'/usr/bin'},{'usb':plan()['usb']|{'path':'/dev/sda'}}):
            with self.assertRaises(b.r.Stop):b.validate(plan()|change)


class Sequence(unittest.TestCase):
    """Root/mount/xattr calls substituted; real file copy and comparisons."""
    def scenario(self, failure=None):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);src=root/'source';src.mkdir(mode=0o700)
            (src/'control.json').write_bytes(b'synthetic control')
            image=root/'image';image.write_bytes(b'synthetic ciphertext'*128)
            size=image.stat().st_size
            class Fixture(b.Backup):
                def __init__(self):
                    super().__init__(plan());self.state=root/'journal';self.usb=root/'usb';self.restore=root/'restore'
                    self.restore_mapper=root/'mapper';self.destination=self.usb/'backup/authority.luks'
                    self.active={'source'};self.operations=[]
                def guard(self):pass
                def image_identity(self):
                    s=image.stat();return s.st_dev,s.st_ino,s.st_size
                def stopped(self):self.operations.append('writers-stopped')
                def mapping(self,mapper,image,readonly):return 'restore' if readonly else 'source'
                def usb_identity(self):return 'usb'
                def mounted(self,*args):pass
                def database(self,*args):pass
                def mounts(self):return [{'maj:min':x,'target':str(root/x)} for x in self.active]
                def call(self,argv):return self.plan['luks_uuid'].encode()
                def stage(self,name,argv):
                    self.record(name+'.intent',{'stage':name});self.operations.append(name)
                    if name=='usb-mount':self.active.add('usb')
                    elif name=='source-unmount':self.active.remove('source')
                    elif name=='restore-mount':
                        shutil.copytree(src,self.restore,dirs_exist_ok=True)
                        if failure=='tree':(self.restore/'control.json').write_bytes(b'wrong restored data')
                    elif name=='restore-unmount':
                        for child in self.restore.iterdir():child.unlink()
                    elif name=='usb-unmount':
                        self.active.remove('usb');shutil.rmtree(self.destination.parent)
                    elif name=='source-remount':self.active.add('source')
                    self.record(name+'.complete',{'status':'completed'})
            fixture=Fixture();rd,wr=os.pipe();os.write(wr,b'synthetic credential');os.close(wr)
            def consume(crypt,path,fd,**kw):
                self.assertEqual(os.read(fd,100),b'synthetic credential');os.close(fd)
                self.assertEqual(kw['mapper'],fixture.restore_name)
                if failure=='credential':raise b.r.Stop('synthetic-credential-rejection')
            with patch.object(b,'IMAGE',image),patch.object(b,'SOURCE',src),patch.object(b,'SIZE',size),patch.object(b.r,'trusted_parent'),patch.object(b.recovery,'consume',side_effect=consume), patch.object(b.os,'listxattr',return_value=[]):
                if failure:
                    with self.assertRaises(b.r.Stop):fixture.run(rd)
                    self.assertFalse((fixture.state/'result.json').exists())
                    self.assertNotIn('source-remount',fixture.operations)
                else:
                    result=fixture.run(rd)
                    self.assertEqual(result['status'],'passed');self.assertFalse(result['services_started'])
                    self.assertLess(fixture.operations.index('database-checksums'),fixture.operations.index('source-remount'))
                    self.assertEqual(fixture.active,{'source'})
                    retry,write=os.pipe();os.close(write)
                    with self.assertRaisesRegex(b.r.Stop,'attempt-or-scratch'):fixture.run(retry)
            with self.assertRaises(OSError):os.fstat(rd)
    def test_complete_sequence(self):self.scenario()
    def test_wrong_credential_leaves_attempt_for_review(self):self.scenario('credential')
    def test_restore_mismatch_cannot_complete(self):self.scenario('tree')


if __name__=='__main__':unittest.main()
