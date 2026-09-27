import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(os.environ.get('KAIBA_PILOT_RUNNER_SOURCE', Path(__file__).resolve().parents[2]/'scripts/pilot-enrollment'))
spec = importlib.util.spec_from_file_location('recovery', SOURCE/'recovery.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)


def pipe():
    read, write = os.pipe(); os.write(write, b'synthetic-test-credential'); os.close(write)
    return read


class Recovery(unittest.TestCase):
    def test_one_descriptor_only_and_no_fallback(self):
        fd = pipe()
        with patch.object(p.subprocess, 'run') as run:
            run.return_value.returncode = 0
            p.consume('/nix/store/fixture/cryptsetup', '/tmp/fixture.luks', fd)
            args, kw = run.call_args
            self.assertEqual(kw['pass_fds'], (fd,))
            self.assertIn('--test-passphrase', args[0]); self.assertIn('--disable-external-tokens', args[0])
            self.assertIn('--batch-mode', args[0]); self.assertEqual(args[0][args[0].index('--key-slot')+1], '0')
            self.assertNotIn('synthetic-test-credential', str(args)+str(kw))
            self.assertEqual(run.call_count, 1)
        with self.assertRaises(OSError): os.fstat(fd)

    def test_failure_does_not_retry_or_keep_pipe(self):
        fd = pipe()
        with patch.object(p.subprocess, 'run') as run:
            run.return_value.returncode = 2
            with self.assertRaises(p.r.Stop): p.consume('/fixture', '/tmp/fixture.luks', fd)
            self.assertEqual(run.call_count, 1)
        with self.assertRaises(OSError): os.fstat(fd)

    def test_open_requires_readonly_and_unique_mapper(self):
        fd = pipe()
        with patch.object(p.subprocess, 'run') as run:
            run.return_value.returncode = 0
            p.consume('/fixture', '/tmp/fixture.luks', fd, mapper='kaiba-synthetic-recovery')
            self.assertIn('--readonly', run.call_args[0][0])
            self.assertNotIn('--test-passphrase', run.call_args[0][0])

    @unittest.skipUnless(os.environ.get('KAIBA_TEST_CRYPTSETUP'), 'native Nix check provides cryptsetup')
    def test_real_disposable_luks_slot_check_without_token_or_mount(self):
        crypt = os.environ['KAIBA_TEST_CRYPTSETUP']
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp)/'synthetic.luks'
            with image.open('wb') as f: f.truncate(32*1024*1024)
            fd = pipe()
            try:
                subprocess.run([crypt, 'luksFormat', '--batch-mode', '--type', 'luks2',
                                '--pbkdf', 'pbkdf2', '--pbkdf-force-iterations', '1000',
                                '--key-file', '/proc/self/fd/'+str(fd), str(image)],
                               pass_fds=(fd,), stdin=subprocess.DEVNULL, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
            finally: os.close(fd)
            header = image.read_bytes()[:16*1024*1024]
            p.consume(crypt, image, pipe())
            rd, wr = os.pipe(); os.write(wr, b'different-synthetic-credential'); os.close(wr)
            with self.assertRaises(p.r.Stop): p.consume(crypt, image, rd)
            self.assertEqual(image.read_bytes()[:16*1024*1024], header)


if __name__ == '__main__': unittest.main()
