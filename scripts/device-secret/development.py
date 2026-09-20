"""Trusted-operator development session; no signing, media writer or power relay.

The exact session is an execution bound, not a source of user authorization.
A recorded intent precedes remote execution. Unknown/failed actions stop further
runs; no reset, force, automatic retry, or unchecked SSH host-key replacement.
"""
import argparse
import base64
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

# Installed alongside this file; no caller-controlled module path.
from runner import Serial, Rejected, require, regular_bytes, decode, canonical

SCHEMA = 'kaiba.device-secret-development-session/v1alpha1'
CHECKS = {'inspect', 'read-lock', 'hmac'}
HEX = re.compile(r'[0-9a-f]{64}')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
FIELDS = {'schema_version', 'address', 'user', 'identity_file', 'known_hosts',
          'board_serial_sha256', 'boot_image_sha256', 'firmware_version', 'kernel_release',
          'helper_sha256', 'slot_id', 'expected_usage', 'checks', 'max_runs', 'max_reboots',
          'expires_at', 'uart_by_id', 'uart_by_path'}


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def expiry(value):
    require(isinstance(value, str) and value.endswith('Z'), 'expiry-must-be-UTC')
    try:
        return datetime.datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError:
        raise Rejected('invalid-expiry') from None


def validate(c):
    require(type(c) is dict and set(c) == FIELDS and c['schema_version'] == SCHEMA, 'session-fields')
    require(type(c['address']) is str and str(ipaddress.IPv4Address(c['address'])) == c['address'], 'IPv4-required')
    require(type(c['user']) is str and re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', c['user']), 'invalid-user')
    for k in ['identity_file', 'known_hosts', 'uart_by_id', 'uart_by_path']:
        require(type(c[k]) is str and c[k].startswith('/') and '\x00' not in c[k] and '\n' not in c[k], 'absolute-path-required')
    require(c['uart_by_id'].startswith('/dev/serial/by-id/') and c['uart_by_path'].startswith('/dev/serial/by-path/'), 'fixed-UART-selectors-required')
    for k in ['board_serial_sha256', 'boot_image_sha256', 'helper_sha256']:
        require(type(c[k]) is str and HEX.fullmatch(c[k]), 'invalid-digest')
    require(type(c['firmware_version']) is str and re.fullmatch(r'[0-9a-f]{40}', c['firmware_version']), 'invalid-firmware')
    require(type(c['kernel_release']) is str and re.fullmatch(r'[a-zA-Z0-9._+-]{1,100}', c['kernel_release']), 'invalid-kernel')
    for k, low, high in [('slot_id', 1, 32), ('expected_usage', 0, 14), ('max_runs', 1, 32), ('max_reboots', 0, 16)]:
        require(type(c[k]) is int and low <= c[k] <= high, 'invalid-bound')
    require(c['expected_usage'] == 0 or c['expected_usage'] >= 8, 'reserved-usage')
    require(type(c['checks']) is list and c['checks'] and all(type(x) is str and x in CHECKS for x in c['checks'])
            and len(c['checks']) == len(set(c['checks'])), 'invalid-checks')
    expiry(c['expires_at'])
    return c


def write(path, data):
    with path.open('xb') as f:
        os.chmod(path, 0o600)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def key_line(raw, address):
    lines = [l for l in raw.decode('ascii').splitlines() if l and not l.startswith('#')]
    require(len(lines) == 1, 'one-pinned-host-key-required')
    parts = lines[0].split()
    require(len(parts) == 3 and parts[:2] == [address, 'ssh-ed25519'], 'exact-host-ed25519-key-required')
    blob = base64.b64decode(parts[2], validate=True)
    require(len(blob) == 51 and blob[:19] == b'\0\0\0\x0bssh-ed25519\0\0\0 ', 'invalid-ed25519-key')
    fp = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
    return lines[0].encode() + b'\n', fp


def ssh(c, known):
    return ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + str(known), '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
            '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes', '-o', 'ConnectTimeout=8',
            '-o', 'ConnectionAttempts=1', '-i', c['identity_file'], c['user'] + '@' + c['address']]


def remote(c, known, script, timeout=50):
    return subprocess.run(ssh(c, known) + ['sudo -n bash -seu -o pipefail'],
                          input=script.encode(), capture_output=True, timeout=timeout)


def preflight(c):
    # Inputs below are restricted to hex/numeric/version alphabets in validate.
    return f'''export LC_ALL=C
trap 'printf "PREFLIGHT_FAILED line=%s\\n" "$LINENO" >&2' ERR
umask 077
ulimit -c 0
test "$(uname -m)" = aarch64
test "$(uname -r)" = {shlex.quote(c['kernel_release'])}
test "$(tr -d '\\000' < /proc/device-tree/serial-number | sha256sum | cut -d ' ' -f1)" = {c['board_serial_sha256']}
test "$(od -An -tx1 /proc/device-tree/chosen/bootloader/signed | tr -d ' \\n')" = 80000009
test "$(od -An -tx1 -v /proc/device-tree/chosen/bootloader/boot_img_sha256 | tr -d ' \\n')" = {c['boot_image_sha256']}{'0'*64}
test "$(vcgencmd bootloader_version | sed -n 's/^version //p')" = '{c['firmware_version']} (release)'
test "$(findmnt -n -o FSTYPE /run)" = tmpfs
test "$(findmnt -n -o SOURCE,FSTYPE,OPTIONS /)" = '/dev/mapper/root ext4 ro,nodev,noatime'
dmsetup status root | grep -Ex '0 [0-9]+ verity V' >/dev/null
test -z "$(swapon --noheadings --show=NAME)"
# Historical flags remain evidence; active power/thermal flags block execution.
throttled="$(vcgencmd get_throttled)"
[[ "$throttled" =~ ^throttled=0x[0-9a-f]+$ ]]
flags="${{throttled#throttled=}}"
test "$((flags & 15))" -eq 0
trap - ERR
'''


def inspect(c, known):
    r = remote(c, known, preflight(c) + "cat /proc/sys/kernel/random/boot_id\nprintf '%s\\n' \"$throttled\"\n")
    require(r.returncode == 0 and not r.stderr,
            'remote-preflight-failed exit=' + str(r.returncode) + ' stderr=' + r.stderr[:4096].decode(errors='replace'))
    lines = r.stdout.decode().splitlines()
    require(len(lines) == 2 and UUID.fullmatch(lines[0]) and re.fullmatch(r'throttled=0x[0-9a-f]+', lines[1]), 'invalid-preflight-response')
    return {'boot_id': lines[0], 'power_status': lines[1]}


def run_script(c, check, binary, boot, attempt):
    # Static bytes enter a fixed, root-owned tmpfs directory, never a shell
    # expression. The durable host intent prevents replay; target files are
    # disposable and do not claim to provide a second execution authority.
    require(UUID.fullmatch(boot) and re.fullmatch(r'[0-9]{4}', attempt), 'invalid-attempt')
    encoded = base64.b64encode(binary).decode()
    return preflight(c) + f'''test "$(cat /proc/sys/kernel/random/boot_id)" = {boot}
test ! -L /run/kaiba-device-secret-development
install -d -m 0700 /run/kaiba-device-secret-development
d="$(mktemp -d /run/kaiba-device-secret-development/attempt-{attempt}.XXXXXXXX)"
trap 'rm -f -- "$d/helper"' EXIT
base64 -d > "$d/helper" <<'KAIBA_HELPER_BYTES'
{encoded}
KAIBA_HELPER_BYTES
test "$(sha256sum "$d/helper" | cut -d ' ' -f1)" = {c['helper_sha256']}
chmod 0500 "$d/helper"
"$d/helper" {check} --slot-id {c['slot_id']} --expected-usage {c['expected_usage']} --expected-boot-id {boot}
'''


def validate_result(raw, c, check, boot, rc):
    require(len(raw) <= 32768, 'oversize-result')
    value = decode(raw)
    require(type(value) is dict and set(value) == {'schema_version', 'mode', 'check', 'boot_id', 'slot_id',
            'expected_usage', 'passed', 'stop', 'cleanup_locks_closed', 'hardware_qualified', 'steps'}, 'result-fields')
    require(value['schema_version'] == 'kaiba.device-secret-development/v1alpha1' and value['mode'] == 'development'
            and value['check'] == check and value['boot_id'] == boot and type(value['slot_id']) is int
            and value['slot_id'] == c['slot_id'] and type(value['expected_usage']) is int
            and value['expected_usage'] == c['expected_usage'] and value['hardware_qualified'] is False, 'result-binding')
    require(type(value['passed']) is bool and rc == (0 if value['passed'] else 3), 'result-exit-disagreement')
    require(type(value['steps']) is list and len(value['steps']) <= 20, 'result-step-bound')
    for step in value['steps']:
        require(type(step) is dict and set(step) == {'name', 'passed', 'outcome', 'mailbox_tag', 'mailbox_errno', 'value'}, 'step-fields')
        require(type(step['name']) is str and re.fullmatch(r'[a-z-]{1,60}', step['name']) and type(step['passed']) is bool, 'invalid-step')
        for field, low, high in [('outcome', 0, 4), ('mailbox_tag', 0, 0xffffffff), ('mailbox_errno', 0, 4095)]:
            require(type(step[field]) is int and low <= step[field] <= high, 'invalid-diagnostic')
        require(step['value'] is None or type(step['value']) is int and 0 <= step['value'] <= 0xffffffff, 'invalid-metadata')
    require(type(value['stop']) is str and re.fullmatch(r'[a-z-]{1,60}', value['stop']), 'invalid-stop')
    require(value['cleanup_locks_closed'] is None or type(value['cleanup_locks_closed']) is bool, 'invalid-cleanup')
    if value['passed']:
        expected = ['count', 'status', 'usage']
        if check != 'inspect':
            expected += ['apply-runtime-locks', 'runtime-locks']
            expected += ['raw-read-blocked'] if check == 'read-lock' else ['hmac-control', 'hmac-repeat', 'hmac-separation']
            expected += ['close-runtime-locks', 'closed-status']
            if check == 'hmac': expected += ['hmac-closed']
        require([s['name'] for s in value['steps']] == expected and all(s['passed'] for s in value['steps'])
                and value['stop'] == 'complete' and value['cleanup_locks_closed'] is (None if check == 'inspect' else True), 'incomplete-success')
    return value


def assess_hmac_observation(value):
    """Describe the recorded boundary; never change an operation's outcome."""
    steps = value['steps']
    names = [s['name'] for s in steps]
    require(len(names) == len(set(names)), 'ambiguous-assessment-steps')

    def step(name, tag, value=None, outcome=0, passed=True, error=0):
        return dict(name=name, passed=passed, outcome=outcome,
                    mailbox_tag=tag, mailbox_errno=error, value=value)

    # Validate the positive controls and their metadata, not just passed=true.
    controls = False
    if len(steps) >= 8:
        count, status = steps[0]['value'], steps[1]['value']
        controls = (type(count) is int and value['slot_id'] <= count <= 32
                    and type(status) is int and status & 1 == 1
                    and not status & ~0x1f01 and not status & 0x0c00
                    and steps[:8] == [
                        step('count', 0x3008f, count), step('status', 0x30090, status),
                        step('usage', 0x3009c, value['expected_usage']),
                        step('apply-runtime-locks', 0x38090), step('runtime-locks', 0x30090, 0x1301),
                        step('hmac-control', 0x30092), step('hmac-repeat', 0x30092),
                        step('hmac-separation', 0x30092)])
    closed = False
    if 'close-runtime-locks' in names:
        index = names.index('close-runtime-locks')
        closed = value['cleanup_locks_closed'] is True and steps[index:index+2] == [
            step('close-runtime-locks', 0x38090), step('closed-status', 0x30090, 0x1f01)]
    boundary = 'not-established'
    payload = 'not-established'
    if controls and closed and names[8:10] == ['close-runtime-locks', 'closed-status']:
        if (not value['passed'] and value['stop'] == 'hmac-closed' and steps[10:] == [
                step('hmac-closed', 0x30092, outcome=2, passed=False, error=22),
                step('last-error-after-transport-failure', 0x3008e, 4)]):
            boundary = 'linux-error-with-immediate-key-locked'
            payload = 'unavailable'
        elif (value['passed'] and value['stop'] == 'complete' and steps[10:] == [
                step('hmac-closed', 0x3008e, outcome=1)]):
            boundary = 'helper-validated-locked-response'
            payload = 'validated-by-helper'
    return dict(
        hmac_controls='observed' if controls else 'not-established',
        runtime_lock_closure='observed' if closed else 'not-established',
        post_closure_rejection=boundary, firmware_error_payload=payload,
        # Last-error is separate global metadata, not a correlated response.
        lock_cause='consistent-with-lock-rejection' if boundary == 'linux-error-with-immediate-key-locked'
                  else 'not-assessed',
    )


class Session:
    def __init__(self, path, read_only=False, config_validator=validate):
        self.path = Path(path)
        require(self.path.is_absolute() and not self.path.is_symlink(), 'absolute-private-state-required')
        st = self.path.stat()
        require(st.st_uid == os.geteuid() and st.st_mode & 0o077 == 0, 'state-not-private')
        self.lock = (self.path / 'lock').open('rb' if read_only else 'ab')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.config = config_validator(decode(regular_bytes(self.path / 'session.json')))
            self.auth = decode(regular_bytes(self.path / 'initial.json'))
            require(self.auth['session_sha256'] == hashlib.sha256(canonical(self.config)).hexdigest(), 'changed-session')
            self.known = self.path / 'known_hosts'
            self.intents = sorted(self.path.glob('*.intent.json'))
        except BaseException:
            self.lock.close()
            raise

    def close(self):
        self.lock.close()

    def assess_hmac(self, attempt):
        # Assessment works on failed/expired sessions, but never calls allowed,
        # creates an action intent, contacts the target, or changes a result.
        require(type(attempt) is str and re.fullmatch(r'[0-9]{4}', attempt)
                and 1 <= int(attempt) <= 48, 'invalid-assessment-attempt')
        intent = decode(regular_bytes(self.path / f'{attempt}.intent.json'))
        require(type(intent) is dict and set(intent) == {'action', 'before', 'session_sha256', 'started_at'}
                and type(intent['before']) is dict and type(intent['before'].get('boot_id')) is str
                and UUID.fullmatch(intent['before']['boot_id']) and intent['action'] == 'hmac'
                and intent['session_sha256'] == self.auth['session_sha256'], 'assessment-intent-binding')
        raw = regular_bytes(self.path / f'{attempt}.stdout', 32768)
        result_bytes = regular_bytes(self.path / f'{attempt}.result.json')
        result = decode(result_bytes)
        require(type(result) is dict and set(result) == {'status', 'observed_at', 'observation',
                'stdout_sha256', 'hardware_qualified'}
                and result['status'] in ('passed', 'failed') and result['hardware_qualified'] is False
                and result['stdout_sha256'] == hashlib.sha256(raw).hexdigest(), 'assessment-result-binding')
        require(regular_bytes(self.path / f'{attempt}.stderr') == b'', 'assessment-unexpected-stderr')
        value = validate_result(raw, self.config, 'hmac', intent['before']['boot_id'],
                                0 if result['status'] == 'passed' else 3)
        require(value == result['observation'], 'assessment-observation-mismatch')
        return dict(schema_version='kaiba.device-secret-hmac-assessment/v1alpha1', mode='development',
                    source=dict(attempt=attempt, session_sha256=self.auth['session_sha256'],
                                helper_sha256=self.config['helper_sha256'],
                                result_sha256=hashlib.sha256(result_bytes).hexdigest(),
                                stdout_sha256=result['stdout_sha256']),
                    recorded_result=result['status'], claims=assess_hmac_observation(value),
                    hardware_qualified=False, execution_authority=False,
                    session_continuation_authorized=False)

    def allowed(self, action):
        require(now() < expiry(self.config['expires_at']), 'session-expired')
        for p in self.intents:
            result = p.with_name(p.name.replace('.intent.', '.result.'))
            require(result.exists(), 'unfinished-attempt-no-retry')
            require(decode(regular_bytes(result))['status'] == 'passed', 'failed-attempt-needs-review')
        budget = self.config['max_reboots' if action == 'reboot' else 'max_runs']
        used = sum((decode(regular_bytes(p))['action'] == 'reboot') == (action == 'reboot') for p in self.intents)
        require(used < budget, 'session-budget-exhausted')

    def intent(self, action, before):
        require(now() < expiry(self.config['expires_at']), 'session-expired-before-execution')
        attempt = f'{len(self.intents)+1:04d}'
        path = self.path / f'{attempt}.intent.json'
        write(path, canonical(dict(action=action, before=before,
              started_at=now().isoformat(), session_sha256=self.auth['session_sha256'])))
        self.intents.append(path)
        return attempt

    def run(self, helper, check):
        c = self.config
        require(check in c['checks'], 'check-not-authorized')
        self.allowed(check)
        binary = regular_bytes(Path(helper), 16 * 1024 * 1024)
        require(hashlib.sha256(binary).hexdigest() == c['helper_sha256'], 'helper-digest-mismatch')
        require(binary[:6] == b'\x7fELF\x02\x01' and binary[18:20] == b'\xb7\x00', 'native-ARM64-helper-required')
        before = inspect(c, self.known)
        attempt = self.intent(check, before)
        # No exception handler retries remote commands. Timeout/interruption
        # retains this intent without a completion and blocks further actions.
        r = remote(c, self.known, run_script(c, check, binary, before['boot_id'], attempt))
        write(self.path / f'{attempt}.stdout', r.stdout)
        write(self.path / f'{attempt}.stderr', r.stderr)
        result = validate_result(r.stdout, c, check, before['boot_id'], r.returncode)
        require(not r.stderr, 'unexpected-stderr-needs-review')
        record = dict(status='passed' if result['passed'] else 'failed', observed_at=now().isoformat(),
                      observation=result, stdout_sha256=hashlib.sha256(r.stdout).hexdigest(), hardware_qualified=False)
        write(self.path / f'{attempt}.result.json', canonical(record))
        return record

    def reboot(self):
        c = self.config
        self.allowed('reboot')
        before = inspect(c, self.known)
        with Serial(c) as serial:
            attempt = self.intent('reboot', before)
            capture = self.path / f'{attempt}.uart'
            # Capture is already armed before the only reboot command.
            r = remote(c, self.known, preflight(c) + f"test \"$(cat /proc/sys/kernel/random/boot_id)\" = {before['boot_id']}\nreboot\n", timeout=15)
            write(self.path / f'{attempt}.reboot-command.json', canonical(dict(exit_code=r.returncode,
                  stdout=r.stdout.decode(errors='replace'), stderr=r.stderr.decode(errors='replace'))))
            require(r.returncode in (0, 255), 'reboot-command-failed')
            deadline = time.monotonic() + 120
            raw = bytearray()
            with capture.open('xb') as f:
                while time.monotonic() < deadline:
                    chunk = serial.read(min(1, max(0, deadline-time.monotonic())))
                    require(len(raw) + len(chunk) <= 4 * 1024**2, 'UART-byte-bound')
                    raw.extend(chunk); f.write(chunk); f.flush(); os.fsync(f.fileno())
        text = bytes(raw).decode(errors='replace').replace('\r', '')
        pattern = r'KAIBA_DEVELOPMENT_SSH=ready user=' + re.escape(c['user']) + r' address=' + re.escape(c['address']) + r' host_key=(SHA256:[A-Za-z0-9+/]+)'
        fps = re.findall(pattern, text)
        marker = 'KAIBA_SECURE_BOOT_EVIDENCE=pass signed=80000009 boot_img_sha256=sha256:' + c['boot_image_sha256']
        require(len(fps) == 1 and text.count(marker) == 1, 'missing-or-ambiguous-UART-identity')
        scan = subprocess.run(['ssh-keyscan', '-T', '8', '-t', 'ed25519', c['address']], capture_output=True, timeout=12)
        require(scan.returncode == 0, 'keyscan-failed')
        line, fp = key_line(scan.stdout, c['address'])
        require(fp == fps[0], 'SSH-UART-key-mismatch')
        known = self.path / f'{attempt}.known_hosts'
        write(known, line)
        after = inspect(c, known)
        require(after['boot_id'] != before['boot_id'], 'boot-id-not-changed')
        record = dict(status='passed', action='soft-reboot', before=before, after=after,
                      uart_sha256=hashlib.sha256(raw).hexdigest(), ssh_fingerprint=fp,
                      cold_power_verified=False, hardware_qualified=False)
        # Preserve old pins; changing the active pin happens only after UART
        # authentication and complete read-only preflight on the new boot.
        write(self.path / f'{attempt}.prior_known_hosts', regular_bytes(self.known))
        temp = self.path / f'{attempt}.next_known_hosts'; write(temp, line)
        os.replace(temp, self.known)
        write(self.path / f'{attempt}.result.json', canonical(record))
        return record


def initialize(path, config, config_validator=validate):
    c = config_validator(decode(regular_bytes(Path(config))))
    require(now() < expiry(c['expires_at']) <= now() + datetime.timedelta(hours=24), 'session-window-exceeds-24-hours')
    known, fp = key_line(regular_bytes(Path(c['known_hosts'])), c['address'])
    p = Path(path)
    require(p.is_absolute(), 'absolute-private-state-required')
    p.mkdir(mode=0o700)
    write(p / 'session.json', canonical(c))
    write(p / 'initial.json', canonical(dict(session_sha256=hashlib.sha256(canonical(c)).hexdigest(),
          ssh_fingerprint=fp, created_at=now().isoformat(), execution_authority=False)))
    write(p / 'known_hosts', known)
    return dict(status='prepared', execution_authority=False)


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description='Remote development checks; no image signing or media staging.')
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ['init', 'status', 'run', 'reboot', 'assess-hmac']:
        p = sub.add_parser(command); p.add_argument('--state', required=True)
        if command == 'init': p.add_argument('--config', required=True)
        if command == 'run':
            p.add_argument('--helper', required=True); p.add_argument('--check', choices=sorted(CHECKS), required=True)
        if command == 'assess-hmac': p.add_argument('--attempt', required=True)
    a = parser.parse_args(argv)
    try:
        if a.command == 'init': result = initialize(a.state, a.config)
        else:
            session = Session(a.state, read_only=a.command == 'assess-hmac')
            try:
                if a.command == 'run': result = session.run(a.helper, a.check)
                elif a.command == 'reboot': result = session.reboot()
                elif a.command == 'assess-hmac': result = session.assess_hmac(a.attempt)
                else: result = dict(attempts=[decode(regular_bytes(p)) for p in session.intents], execution_authority=False)
            finally: session.close()
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get('status') != 'failed' else 3
    except (Rejected, OSError, ValueError, subprocess.SubprocessError) as e:
        print('STOP: ' + str(e) + '; preserve state; no automatic retry', file=sys.stderr)
        return 3


if __name__ == '__main__':
    sys.exit(main())
