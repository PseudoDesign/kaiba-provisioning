"""Boundary tests for operations which will eventually write physical media."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('writer', Path(__file__).with_name('host.py'))
writer = importlib.util.module_from_spec(spec); spec.loader.exec_module(writer)


class Guards(unittest.TestCase):
    def disk(self):
        return {'type': 'disk', 'size': 240_000_000_000, 'serial': 'TEST-ONLY', 'ro': False,
                'mountpoints': [None], 'partlabel': None, 'fstype': None,
                'children': [{'type': 'part', 'mountpoints': [None], 'partlabel': None, 'fstype': 'ext4'}]}

    def test_unmounted_plain_spare(self):
        writer.validate_disk(self.disk(), 8_000_000_000)

    def test_mounted_child_and_nested_mapper_denied(self):
        for change in ({'mountpoints': ['/']}, {'type': 'crypt'}, {'type': 'lvm'}, {'type': 'raid1'}):
            disk = self.disk(); disk['children'][0].update(change)
            with self.assertRaises(ValueError): writer.validate_disk(disk, 1)

    def test_protected_pilot_and_encrypted_storage_denied(self):
        for change in ({'partlabel': 'disk-main-boot'}, {'fstype': 'crypto_LUKS'},
                       {'fstype': 'LVM2_member'}, {'fstype': 'linux_raid_member'},
                       {'fstype': 'crypto_LUKS', 'label': 'KAIBA_Q_ROOT'}):
            disk = self.disk(); disk['children'][0].update(change)
            with self.assertRaises(ValueError): writer.validate_disk(disk, 1)

    def test_capacity_serial_readonly_and_partition_denied(self):
        for change in ({'size': 10}, {'serial': None}, {'ro': True}, {'type': 'part'}):
            disk = self.disk(); disk.update(change)
            with self.assertRaises(ValueError): writer.validate_disk(disk, 100)

    def test_short_readback_denied(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d)/'image'; f.write_bytes(b'test')
            with self.assertRaises(ValueError): writer.digest(f, 5)

    def test_intent_is_exclusive_and_not_symlink_following(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'intent'; writer.save(path, {'status': 'intent'})
            with self.assertRaises(FileExistsError): writer.save(path, {'status': 'overwrite'})
            link = Path(d)/'link'; link.symlink_to(path)
            with self.assertRaises(FileExistsError): writer.save(link, {})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__': unittest.main(verbosity=2)
