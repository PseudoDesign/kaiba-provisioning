"""Reviewed one-device host hook for initial pilot enrollment on NixOS.

No firmware, OTP, disk formatting, reboot, OS switch or credential export.
The plan and authenticated transport are supplied by the reviewed owner packet.
"""
import argparse
import base64
import grp
import json
import os
from pathlib import Path
import pwd
import resource
import re
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runner as r

ROOT = Path('/var/lib/kaiba-pilot-device')
TOOLS = Path('/var/lib/kaiba-pilot-device-tools')
INPUTS = Path('/var/lib/kaiba-pilot-device-inputs')
SESSION = Path('/var/lib/kaiba-pilot-device-install')
USER = 'kaiba-pilot-device'
SW = '/run/current-system/sw/bin/'
ENV = {'PATH': SW, 'LC_ALL': 'C', 'HOME': '/var/empty'}
MUTATIONS = ('init', 'bootstrap', 'install', 'prove-installed')


def absent(path):
    r.require(not os.path.lexists(path), 'device-path-already-exists')


def directory(path, uid, gid, mode):
    s = Path(path).lstat()
    r.require(stat.S_ISDIR(s.st_mode) and s.st_uid == uid and s.st_gid == gid and
              stat.S_IMODE(s.st_mode) == mode, 'device-directory-metadata')


def write(path, raw, uid=0, gid=0, mode=0o600):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as out:
        os.fchown(out.fileno(), uid, gid); os.fchmod(out.fileno(), mode)
        out.write(raw); out.flush(); os.fsync(out.fileno())
    fd = os.open(Path(path).parent, os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def command(argv):
    result = subprocess.run(list(map(str, argv)), stdin=subprocess.DEVNULL, capture_output=True,
                            env=ENV, timeout=60, close_fds=True)
    r.require(result.returncode == 0 and len(result.stdout) <= 1024*1024, 'device-command-failed')
    return result.stdout


def validate(plan):
    r.fields(plan, ('schema_version', 'run_id', 'issued_at', 'expires_at', 'boot_id',
                    'system', 'booted_system', 'board_sha256', 'nvme_sha256',
                    'volume_uuid', 'partition', 'client_sha256', 'client_size', 'config'))
    r.require(plan['schema_version'] == 'kaiba.pilot-device-hook/v1alpha1', 'device-plan-schema')
    r.require(isinstance(plan['run_id'], str) and r.LABEL.fullmatch(plan['run_id']), 'device-run-id')
    r.require(0 < r.timestamp(plan['expires_at'])-r.timestamp(plan['issued_at']) <= 43200, 'device-window')
    for field in ('board_sha256', 'nvme_sha256', 'client_sha256'):
        r.require(isinstance(plan[field], str) and r.HEX.fullmatch(plan[field]), 'device-plan-digest')
    for field in ('system', 'booted_system'):
        r.require(isinstance(plan[field], str) and plan[field].startswith('/nix/store/') and
                  '/' not in plan[field][len('/nix/store/'):], 'device-system-path')
    r.require(plan['partition'] in ('/dev/nvme0n1p2', '/dev/nvme0n1p3'), 'device-partition')
    r.require(isinstance(plan['client_size'], int) and 0 < plan['client_size'] <= 16*1024*1024, 'device-client-size')
    r.require(isinstance(plan['volume_uuid'], str) and
              re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', plan['volume_uuid']), 'device-volume-uuid')
    r.require(plan['config']['schema_version'] == 'kaiba.pilot-device-client/v1alpha1' and
              plan['config']['protected_volume_uuid'] == plan['volume_uuid'], 'device-client-config')


def encrypted_ancestry(device, partition, uuid, sysfs=Path('/sys/dev/block')):
    """Require a single block ancestry chain through the selected LUKS mapping."""
    seen = set(); encrypted = False
    for _ in range(16):
        r.require(device not in seen, 'device-block-cycle'); seen.add(device)
        node = sysfs/device
        marker = node/'dm/uuid'
        if marker.exists():
            value = marker.read_text().strip()
            if value.startswith('CRYPT-'):
                r.require(not encrypted and value.startswith('CRYPT-LUKS2-'+uuid.replace('-', '')+'-'), 'device-encryption-mismatch')
                encrypted = True
        # Kernel partition nodes need not expose a slaves directory. Stop at
        # the exact pinned partition, never at an arbitrary missing sysfs path.
        if device == partition:
            r.require(encrypted and node.is_dir(), 'device-encrypted-backing-mismatch')
            return
        slaves = list((node/'slaves').iterdir())
        if not slaves:
            r.require(encrypted and device == partition, 'device-encrypted-backing-mismatch')
            return
        r.require(len(slaves) == 1, 'device-block-ancestry-ambiguous')
        device = (slaves[0]/'dev').read_text().strip()
    raise r.Stop('device-block-depth')


def host_guard(plan):
    validate(plan)
    r.require(os.geteuid() == 0, 'device-root-required')
    r.require(r.timestamp(plan['issued_at']) <= time.time() < r.timestamp(plan['expires_at']), 'device-plan-expired')
    r.require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == plan['boot_id'], 'device-rebooted')
    for path, field in (('/run/current-system', 'system'), ('/run/booted-system', 'booted_system')):
        r.require(str(Path(path).resolve()) == plan[field], 'device-system-changed')
    r.require(r.sha(Path('/proc/device-tree/serial-number').read_bytes().replace(b'\0', b'')) == plan['board_sha256'], 'device-board-mismatch')
    serial = Path('/sys/class/block/nvme0n1/device/serial').read_bytes().replace(b' ', b'').replace(b'\n', b'')
    r.require(r.sha(serial) == plan['nvme_sha256'], 'device-nvme-mismatch')
    r.require(len(Path('/proc/swaps').read_text().splitlines()) == 1, 'device-swap-active')
    for tool in ('runuser', 'findmnt', 'groupadd', 'useradd', 'mount', 'nologin'):
        r.require(os.access(SW+tool, os.X_OK), 'device-required-tool-unavailable')
    r.trusted_parent(ROOT.parent, 0)
    parent = ROOT.parent.stat(); part = Path(plan['partition']).stat()
    r.require(stat.S_ISBLK(part.st_mode), 'device-partition-not-block')
    dev = lambda value: f'{os.major(value)}:{os.minor(value)}'
    encrypted_ancestry(dev(parent.st_dev), dev(part.st_rdev), plan['volume_uuid'])


def prepared(plan):
    directory(SESSION, 0, 0, 0o700)
    r.require(r.read_file(SESSION/'plan.json', owner=0, mode=0o600) == r.canonical(plan), 'device-installed-plan-changed')
    user = pwd.getpwnam(USER); group = grp.getgrnam(USER)
    r.require(user.pw_uid != 0 and user.pw_gid == group.gr_gid and
              user.pw_dir == '/var/empty' and user.pw_shell == SW+'nologin', 'device-account-changed')
    directory(ROOT, user.pw_uid, user.pw_gid, 0o700)
    directory(TOOLS, 0, 0, 0o755); directory(INPUTS, 0, user.pw_gid, 0o750)
    r.require(r.sha(r.read_file(TOOLS/USER, maximum=16*1024*1024, owner=0, mode=0o555)) == plan['client_sha256'], 'device-client-changed')
    config = INPUTS/'config.json'
    r.require(config.lstat().st_gid == user.pw_gid and
              r.read_file(config, owner=0, mode=0o440) == r.canonical(plan['config']), 'device-config-changed')
    rows = r.decode(command([SW+'findmnt', '--json', '--mountpoint', ROOT, '-o', 'TARGET,SOURCE,FSTYPE,OPTIONS']))['filesystems']
    r.require(len(rows) == 1 and rows[0]['target'] == str(ROOT) and rows[0]['fstype'] == 'ext4' and
              {'rw', 'nosuid', 'nodev', 'noexec'} <= set(rows[0]['options'].split(',')), 'device-protected-mount')
    r.require(ROOT.stat().st_dev == ROOT.parent.stat().st_dev, 'device-state-filesystem-changed')
    r.require(set(p.name for p in ROOT.iterdir()) <= {'.lock', 'state.json'}, 'device-unexpected-state-files')
    return user


def prepare(plan, binary):
    r.require(len(binary) == plan['client_size'] and r.sha(binary) == plan['client_sha256'], 'device-binary-mismatch')
    for path in (ROOT, TOOLS, INPUTS, SESSION):
        absent(path)
    try:
        pwd.getpwnam(USER)
    except KeyError:
        pass
    else:
        raise r.Stop('device-account-exists')
    try:
        grp.getgrnam(USER)
    except KeyError:
        pass
    else:
        raise r.Stop('device-group-exists')
    SESSION.mkdir(mode=0o700)
    write(SESSION/'plan.json', r.canonical(plan))
    write(SESSION/'prepare.intent.json', r.canonical({'operation': 'prepare', 'run_id': plan['run_id']}))
    command([SW+'groupadd', '--system', USER])
    command([SW+'useradd', '--system', '--gid', USER, '--no-create-home', '--home-dir', '/var/empty', '--shell', SW+'nologin', USER])
    user = pwd.getpwnam(USER)
    ROOT.mkdir(mode=0o700); os.chown(ROOT, user.pw_uid, user.pw_gid)
    TOOLS.mkdir(mode=0o755); os.chmod(TOOLS, 0o755)
    INPUTS.mkdir(mode=0o750); os.chown(INPUTS, 0, user.pw_gid); os.chmod(INPUTS, 0o750)
    write(TOOLS/USER, binary, mode=0o555)
    write(INPUTS/'config.json', r.canonical(plan['config']), gid=user.pw_gid, mode=0o440)
    command([SW+'mount', '--bind', ROOT, ROOT])
    command([SW+'mount', '-o', 'remount,bind,rw,nosuid,nodev,noexec', ROOT])
    prepared(plan)
    write(SESSION/'prepare.complete.json', r.canonical({'status': 'prepared', 'key_created': False}))
    return {'status': 'prepared', 'key_created': False}


def dispatch(plan, request):
    host_guard(plan)
    action = request.get('action')
    r.require(action in ('prepare', 'probe-prepare', 'status', 'self', *MUTATIONS), 'device-action')
    r.fields(request, ('action', 'input'))
    if action == 'prepare':
        r.require(isinstance(request['input'], str), 'device-binary-input')
        return prepare(plan, base64.b64decode(request['input'], validate=True))
    user = prepared(plan)
    if action == 'probe-prepare':
        r.require(request['input'] is None, 'device-unexpected-input')
        return {'status': 'prepared', 'key_created': (ROOT/'state.json').exists()}
    supplied = request['input']
    r.require((action in ('bootstrap', 'install')) == (supplied is not None), 'device-input-scope')
    if action in MUTATIONS:
        # Never replay an uncertain client operation, including after lost SSH output.
        write(SESSION/(action+'.intent.json'), r.canonical({'action': action, 'run_id': plan['run_id']}))
    argv = [SW+'runuser', '-u', USER, '--', TOOLS/USER, '--state', ROOT]
    input_path = None
    if action == 'init':
        r.require(not (ROOT/'state.json').exists(), 'device-already-initialized')
        argv += ['--config', INPUTS/'config.json']
    elif action in ('bootstrap', 'install'):
        if action == 'install':
            r.require(isinstance(supplied, str) and 0 < len(supplied) <= 65536, 'device-certificate-input')
            raw = supplied.encode()
        else:
            r.require(isinstance(supplied, dict), 'device-challenge-input'); raw = r.canonical(supplied)
        r.require(len(raw) <= 65536, 'device-input-size')
        input_path = INPUTS/(action+'.input')
        write(input_path, raw, gid=user.pw_gid, mode=0o440)
        argv += ['--input', input_path]
    try:
        value = r.decode(command([*argv, action]))
    finally:
        if input_path is not None:
            input_path.unlink()  # Public input only; durable intent remains outside state.
    if action in MUTATIONS:
        write(SESSION/(action+'.complete.json'), r.canonical({'status': 'completed', 'action': action}))
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True); parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    os.umask(0o077); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    r.trusted_parent(Path(args.plan).parent, 0)
    raw = r.read_file(args.plan, owner=0)
    r.require(r.sha(raw) == args.sha256, 'device-plan-digest')
    request = sys.stdin.buffer.read(24*1024*1024+1)
    r.require(len(request) <= 24*1024*1024, 'device-request-size')
    print(json.dumps(dispatch(r.decode(raw), r.decode(request))))


if __name__ == '__main__':
    try:
        main()
    except (r.Stop, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('device hook stopped: '+(str(error) if isinstance(error, r.Stop) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
