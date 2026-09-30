"""Explicit test-image operations. Never an installer for the live pilot."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time

BASE = Path('/srv/qualification')
MARKER = 'kaiba.nvme-qualification/v1\n'
IDENTITY_UNITS = ['kaiba-identity-pilot-probe.timer', 'kaiba-identity-pilot-probe.service',
                  'spire-agent.service', 'kaiba-identity-pilot-bundle.service', 'spire-server.service']


def command(*args, **kw):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw).stdout.strip()


def image_guard():
    if os.geteuid() != 0 or Path('/etc/kaiba-qualification-image').read_text() != MARKER:
        raise ValueError('requires-root-on-disposable-image')
    if command('findmnt', '-n', '-o', 'FSTYPE', '/') != 'overlay':
        raise ValueError('recovery-root-is-not-volatile-overlay')
    if 'ro' not in command('findmnt', '-n', '-o', 'OPTIONS', '/run/qualification-lower').split(','):
        raise ValueError('lower-system-filesystem-is-not-readonly')
    layout = command('lsblk', '--json', '-o', 'NAME,TYPE,FSTYPE,PARTLABEL')
    if 'crypto_LUKS' in layout or 'disk-main-' in layout:
        raise ValueError('pilot-or-unreviewed-disk-present')


def guard():
    image_guard()
    if not os.path.ismount(BASE) or (BASE/'image-marker').read_text() != MARKER:
        raise ValueError('test-data-not-mounted')
    if command('findmnt', '-n', '-o', 'UUID', str(BASE)) != 'fa0aabf4-5a16-4e9d-a7db-903064ca1a03':
        raise ValueError('wrong-data-volume')
    if not os.path.ismount('/var/lib/kaiba'):
        raise ValueError('identity-bind-not-mounted')
    if command('findmnt', '-n', '-o', 'UUID', '/var/lib/kaiba') != 'fa0aabf4-5a16-4e9d-a7db-903064ca1a03':
        raise ValueError('identity-bind-is-not-on-test-data')


def synchronized():
    return command('timedatectl', 'show', '-p', 'NTPSynchronized', '--value') == 'yes'


def require_clock():
    if not synchronized():
        raise ValueError('synchronized-time-required')


def emit(value):
    print(json.dumps({'synthetic': True, 'hardware_qualified': False,
                      'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                      'observed_at_unix': time.time(), **value}, sort_keys=True), flush=True)


def exclusive(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(content); f.flush(); os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--settings', type=Path, required=True)
    p.add_argument('action', choices=['status', 'identity-init', 'identity-check', 'identity-backup', 'identity-restore',
                                     'offline-arm', 'offline-disarm', 'offline-check', 'case', 'shutdown', 'data-check'])
    p.add_argument('rest', nargs=argparse.REMAINDER)
    a = p.parse_args()
    image_guard()
    if a.action == 'data-check':
        device = Path('/dev/disk/by-uuid/fa0aabf4-5a16-4e9d-a7db-903064ca1a03').resolve(strict=True)
        mounted = subprocess.run(['findmnt', '-rn', '-S', str(device)], capture_output=True, text=True)
        if mounted.returncode == 0:
            raise ValueError('unmount-data-and-identity-bind-before-readonly-fsck')
        result = subprocess.run(['e2fsck', '-fn', str(device)], capture_output=True, text=True)
        emit({'status': 'read-only-filesystem-diagnosis', 'exit_code': result.returncode,
              'stdout': result.stdout, 'stderr': result.stderr})
        return
    guard()
    lock = open('/run/kaiba-qualification.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if a.action == 'status':
        states = {u: subprocess.run(['systemctl', 'is-active', u], capture_output=True, text=True).stdout.strip() for u in IDENTITY_UNITS}
        manifest = Path('/var/lib/kaiba/identity/pilot-bootstrap/manifest.json')
        emit({'status': 'observed', 'clock_synchronized': synchronized(), 'offline_selected': (BASE/'offline').exists(),
              'services': states, 'identity_manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest() if manifest.exists() else None,
              'ssh_host_key': command('ssh-keygen', '-lf', str(BASE/'ssh/ssh_host_ed25519_key.pub'))})
    elif a.action == 'identity-init':
        require_clock()
        command('systemctl', 'start', 'kaiba-identity-pilot-initialize.service')
        emit({'status': 'identity-initialized'})
    elif a.action == 'identity-check':
        require_clock()
        command('systemctl', 'start', 'spire-server.service', 'spire-agent.service')
        command('systemctl', 'start', 'kaiba-identity-pilot-probe.service')
        values = [json.loads(line) for line in Path('/var/lib/kaiba-identity-pilot-probe/identity.jsonl').read_text().splitlines()]
        expected = 'spiffe://nvme-qualification.kaiba.test/device/ace-test/instance/disposable-nvme/workload/identity-probe'
        if not values or any(v['spiffe_id'] != expected for v in values):
            raise ValueError('unexpected-workload-identity')
        emit({'status': 'identity-fetch-passed', 'certificates': values})
    elif a.action == 'identity-backup':
        # Synthetic state only. Remain stopped until an explicit identity-check.
        command('systemctl', 'stop', *IDENTITY_UNITS)
        archive = BASE/'backups'/('identity-'+str(time.time_ns())+'.tar')
        command('tar', '--numeric-owner', '-cpf', str(archive), '-C', str(BASE), 'identity')
        command('sync', '-f', str(archive))
        with archive.open('rb') as f: digest = hashlib.file_digest(f, 'sha256').hexdigest()
        emit({'status': 'synthetic-identity-backup-created-services-stopped', 'path': str(archive), 'sha256': digest})
    elif a.action == 'identity-restore':
        if len(a.rest) != 2:
            raise ValueError('usage: identity-restore /srv/qualification/backups/ARCHIVE.tar SHA256')
        archive = Path(a.rest[0]).resolve(strict=True)
        if archive.parent != BASE/'backups' or archive.suffix != '.tar':
            raise ValueError('only-local-synthetic-identity-backup-accepted')
        with archive.open('rb') as f: sha = hashlib.file_digest(f, 'sha256').hexdigest()
        if sha != a.rest[1]: raise ValueError('backup-digest-mismatch')
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                parts = Path(member.name).parts
                if not parts or parts[0] != 'identity' or '..' in parts or not (member.isfile() or member.isdir()):
                    raise ValueError('unsafe-identity-archive')
            command('systemctl', 'stop', *IDENTITY_UNITS)
            command('systemctl', 'stop', 'var-lib-kaiba.mount')
            if os.path.ismount('/var/lib/kaiba'): raise ValueError('identity-still-mounted')
            preserved = BASE/('identity.preserved-'+str(time.time_ns()))
            (BASE/'identity').rename(preserved)
            tar.extractall(BASE, filter='tar')
        command('sync', '-f', str(BASE))
        command('systemctl', 'start', 'var-lib-kaiba.mount')
        emit({'status': 'synthetic-identity-restored-services-stopped', 'preserved': str(preserved),
              'next': 'identity-check with synchronized time; obsolete state is not automatically authorized'})
    elif a.action == 'offline-arm':
        exclusive(BASE/'offline', MARKER)
        emit({'status': 'offline-selected-for-next-boot', 'next': 'clean shutdown, then power cycle; use local console'})
    elif a.action == 'offline-disarm':
        (BASE/'offline').unlink()
        command('sync', '-f', str(BASE))
        emit({'status': 'online-selected-for-next-boot', 'next': 'clean reboot; current isolation remains in force'})
    elif a.action == 'offline-check':
        if not (BASE/'offline').exists() or synchronized():
            raise ValueError('offline-preconditions-not-met')
        if not Path('/var/lib/kaiba/identity/pilot-bootstrap/manifest.json').is_file():
            raise ValueError('offline-check-needs-previously-initialized-identity')
        rules = command('nft', 'list', 'table', 'inet', 'qualification_offline')
        if rules.count('policy drop') != 2:
            raise ValueError('isolation-firewall-not-present')
        deadline = time.monotonic() + 90
        while True:
            states = {u: subprocess.run(['systemctl', 'is-active', u], capture_output=True, text=True).stdout.strip() for u in ('spire-server.service', 'spire-agent.service')}
            if any(v == 'active' for v in states.values()):
                raise ValueError('protected-service-active-without-time')
            logs = command('journalctl', '-b', '-u', 'spire-server.service', '-u', 'spire-agent.service', '--no-pager', '-n', '120')
            if all(v in ('failed', 'inactive') for v in states.values()) and 'online synchronized clock required for this pilot' in logs:
                break
            if time.monotonic() >= deadline:
                raise ValueError('offline-time-refusal-not-proven-within-90-seconds')
            time.sleep(2)
        emit({'status': 'offline-start-denied-as-required', 'isolation': 'software-enforced; not a physical air gap',
              'services': states, 'clock_guard_refusal_observed': True})
    elif a.action == 'shutdown':
        emit({'status': 'shutdown-requested', 'instruction': 'wait for console halt before removing power or swapping NVMe'})
        subprocess.run(['systemctl', 'poweroff'], check=True)
    else:
        require_clock()
        cases = BASE/'cases'
        command('chown', 'qualification:qualification', str(cases))
        command('chmod', '0700', str(cases))
        subprocess.run(['runuser', '-u', 'qualification', '--', sys.executable, '-I', '-B', str(Path(__file__).with_name('campaign.py')),
                        '--settings', str(a.settings), '--cases', str(cases), *a.rest], check=True)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        emit({'status': 'stopped-preserve-state', 'error_kind': type(error).__name__, 'error': str(error)})
        sys.exit(1)
