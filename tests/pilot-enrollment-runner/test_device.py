import base64
import datetime as dt
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(os.environ.get('KAIBA_PILOT_RUNNER_SOURCE', Path(__file__).resolve().parents[2]/'scripts/pilot-enrollment'))
spec = importlib.util.spec_from_file_location('device', SOURCE/'device.py')
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
UUID = '11111111-1111-4111-8111-111111111111'


class Ancestry(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()
    def node(self, name, child=None, marker=None):
        node = self.root/name; (node/'slaves').mkdir(parents=True)
        if marker:
            (node/'dm').mkdir(); (node/'dm/uuid').write_text(marker)
        if child:
            (node/'slaves/child').mkdir(); (node/'slaves/child/dev').write_text(child)
        return node
    def chain(self):
        self.node('253:1', '253:0', 'LVM-fixture')
        self.node('253:0', '259:2', 'CRYPT-LUKS2-'+UUID.replace('-', '')+'-crypted')
        self.node('259:2')
    def test_selected_encrypted_ancestry(self):
        self.chain(); (self.root/'259:2/slaves').rmdir(); d.encrypted_ancestry('253:1', '259:2', UUID, self.root)
    def test_plaintext_or_other_partition_rejected(self):
        self.node('259:2')
        with self.assertRaisesRegex(d.r.Stop, 'backing-mismatch'):
            d.encrypted_ancestry('259:2', '259:2', UUID, self.root)
        self.node('253:0', '259:2', 'CRYPT-LUKS2-'+UUID.replace('-', '')+'-crypted')
        with self.assertRaisesRegex(d.r.Stop, 'backing-mismatch'):
            d.encrypted_ancestry('253:0', '259:3', UUID, self.root)
    def test_other_keyslot_volume_or_ambiguous_chain_rejected(self):
        self.chain()
        with self.assertRaisesRegex(d.r.Stop, 'encryption-mismatch'):
            d.encrypted_ancestry('253:1', '259:2', UUID.replace('11111111', '22222222', 1), self.root)
        (self.root/'253:1/slaves/other').mkdir()
        with self.assertRaisesRegex(d.r.Stop, 'ambiguous'):
            d.encrypted_ancestry('253:1', '259:2', UUID, self.root)
    def test_cycle_rejected(self):
        self.node('253:1', '253:0'); self.node('253:0', '253:1')
        with self.assertRaisesRegex(d.r.Stop, 'cycle'):
            d.encrypted_ancestry('253:1', '259:2', UUID, self.root)


class DeviceDispatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.patches = []
        for name in ('ROOT', 'TOOLS', 'INPUTS', 'SESSION'):
            path = self.root/name; path.mkdir(mode=0o700)
            p = patch.object(d, name, path); p.start(); self.patches.append(p)
        self.user = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        self.calls = []
        self.plan = {'run_id': 'fixture', 'config': {}}
        self.guard = patch.object(d, 'host_guard'); self.guard.start()
        self.prepared = patch.object(d, 'prepared', return_value=self.user); self.prepared.start()
        original = d.write
        self.writer = patch.object(d, 'write', side_effect=lambda path, raw, **kw:
            original(path, raw, uid=os.getuid(), gid=os.getgid(), mode=kw.get('mode',0o600)))
        self.writer.start()
        self.command = patch.object(d, 'command', side_effect=self.call); self.command_mock = self.command.start()
    def tearDown(self):
        for p in (*self.patches, self.guard, self.prepared, self.writer, self.command): p.stop()
        self.tmp.cleanup()
    def call(self, argv):
        self.calls.append(list(map(str, argv))); return b'{"phase":"fixture"}'
    def test_one_attempt_even_after_lost_result(self):
        self.command_mock.side_effect = d.r.Stop('lost-client-output')
        with self.assertRaises(d.r.Stop): d.dispatch(self.plan, {'action':'init','input':None})
        self.assertTrue((d.SESSION/'init.intent.json').is_file())
        self.assertFalse((d.SESSION/'init.complete.json').exists())
        self.command_mock.side_effect = self.call
        with self.assertRaises(FileExistsError): d.dispatch(self.plan, {'action':'init','input':None})
        self.assertEqual(self.calls, [])
    def test_public_input_outside_state_and_group_readable(self):
        def run(argv):
            path = d.INPUTS/'install.input'
            self.assertEqual(path.read_text(), 'synthetic certificate')
            self.assertEqual(path.stat().st_mode&0o777,0o440)
            self.assertEqual(list(d.ROOT.iterdir()), [])
            return self.call(argv)
        self.command_mock.side_effect = run
        d.dispatch(self.plan, {'action':'install','input':'synthetic certificate'})
        self.assertFalse((d.INPUTS/'install.input').exists())
        self.assertTrue((d.SESSION/'install.complete.json').exists())
        self.assertEqual(self.calls[0][-1], 'install')
        self.assertEqual(self.calls[0][1:4], ['-u', d.USER, '--'])
    def test_status_does_not_create_mutation_intent(self):
        d.dispatch(self.plan, {'action':'status','input':None})
        self.assertEqual(list(d.SESSION.iterdir()), [])
        self.assertEqual(self.calls[0][-1], 'status')
    def test_unknown_or_expanded_action_has_no_side_effects(self):
        for action in ('reboot','renew','shell','luksFormat'):
            with self.assertRaises(d.r.Stop): d.dispatch(self.plan, {'action':action,'input':None})
        with self.assertRaises(d.r.Stop): d.dispatch(self.plan, {'action':'status','input':None,'command':'other'})
        self.assertEqual(self.calls, [])
    def test_extra_input_rejected_before_intent(self):
        with self.assertRaises(d.r.Stop): d.dispatch(self.plan, {'action':'init','input':'extra'})
        self.assertEqual(list(d.SESSION.iterdir()), [])
    def test_host_guard_precedes_any_action(self):
        with patch.object(d, 'host_guard', side_effect=d.r.Stop('wrong-device')):
            with self.assertRaises(d.r.Stop): d.dispatch(self.plan, {'action':'prepare','input':''})
        self.assertEqual(self.calls, [])


class FilesystemGuards(unittest.TestCase):
    def test_symlink_and_permissions_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d.directory(root, os.getuid(), os.getgid(), 0o700)
            root.chmod(0o755)
            with self.assertRaises(d.r.Stop): d.directory(root, os.getuid(), os.getgid(), 0o700)
            alias = root/'alias'; alias.symlink_to(root)
            with self.assertRaises(d.r.Stop): d.directory(alias, os.getuid(), os.getgid(), 0o755)
    def test_prepare_rejects_binary_before_account_or_files(self):
        with patch.object(d, 'command') as command:
            with self.assertRaisesRegex(d.r.Stop, 'binary-mismatch'):
                d.prepare({'client_size':1,'client_sha256':'0'*64}, b'x')
            command.assert_not_called()


if __name__ == '__main__': unittest.main()
