"""Noninteractive recovery-slot consumers for the reviewed backup hooks.

The caller pins the executable/image/mapper and verifies host/storage guards.
These operations cannot format storage, enroll tokens or modify key slots.
Secret bytes are never read into this Python process or passed in arguments.
"""
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runner as r


def consume(cryptsetup, image, keyfd, *, mapper=None, timeout=60, env=None):
    r.require(isinstance(keyfd, int) and keyfd > 2 and
              stat.S_ISFIFO(os.fstat(keyfd).st_mode), 'recovery-credential-not-pipe')
    try:
        return _consume(cryptsetup, image, keyfd, mapper, timeout, env)
    finally:
        os.close(keyfd)


def _consume(cryptsetup, image, keyfd, mapper, timeout, env):
    r.require(isinstance(timeout, int) and 1 <= timeout <= 120, 'recovery-timeout')
    r.require(Path(cryptsetup).is_absolute() and Path(image).is_absolute(), 'recovery-path')
    argv = [str(cryptsetup), 'open', '--batch-mode', '--disable-external-tokens',
            '--key-slot', '0', '--tries', '1', '--key-file', '/proc/self/fd/'+str(keyfd)]
    if mapper is None:
        argv += ['--test-passphrase', str(image)]
    else:
        r.require(isinstance(mapper, str) and re.fullmatch(r'kaiba-[a-z0-9-]{1,64}', mapper), 'recovery-mapper')
        r.require(not os.path.lexists('/dev/mapper/'+mapper), 'recovery-mapper-exists')
        argv += ['--readonly', str(image), mapper]
    # Only fixed packet-reviewed library settings may augment this environment.
    environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
    if env is not None:
        r.fields(env, ('LD_LIBRARY_PATH',))
        r.require(isinstance(env['LD_LIBRARY_PATH'], str) and
                  all(part.startswith('/nix/store/') for part in env['LD_LIBRARY_PATH'].split(':')), 'recovery-library-path')
        environment.update(env)
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env=environment, close_fds=True,
                            pass_fds=(keyfd,), timeout=timeout)
    r.require(result.returncode == 0, 'recovery-credential-or-open-failed')
