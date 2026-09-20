"""Bounded online LUKS development; no signing, media preparation or qualification.

Reuse the authenticated development session, but give storage its own schema,
helper digest and exact create/reboot/reopen sequence. Host intent and the shared
on-media journal both stop retries. No existing HMAC session authorizes storage.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import development as d
from runner import Rejected, canonical, decode, regular_bytes, require

SCHEMA = 'kaiba.device-secret-storage-session/v1alpha1'
CONFIG_SCHEMA = 'kaiba.device-secret-storage-development/v1alpha1'
CONFIG_FIELDS = {'schema_version', 'scheme', 'experiment_id', 'target_reference', 'source_revision',
                 'volume_uuid', 'partition_uuid', 'board_serial_sha256', 'disk_serial_sha256',
                 'nonce_hex', 'slot_id', 'expected_usage'}
RESULT_FIELDS = {'schema_version', 'mode', 'phase', 'boot_id', 'boot_image_sha256', 'verity_root_hash',
                 'volume_uuid', 'nonce_sha256', 'passed', 'stop', 'volume_verified', 'runtime_locks_closed',
                 'storage_closed', 'journal_completed', 'hardware_qualified', 'lock_rejection_qualified',
                 'last_firmware_outcome', 'last_mailbox_tag', 'last_mailbox_errno'}


def validate(c):
    require(type(c) is dict and set(c) == d.FIELDS | {'storage'} and c['schema_version'] == SCHEMA,
            'storage-session-fields')
    base = {k: c[k] for k in d.FIELDS}
    d.validate(base | {'schema_version': d.SCHEMA, 'checks': ['hmac']})
    require(c['checks'] == ['create', 'reopen'] and c['max_runs'] == 2 and c['max_reboots'] == 1
            and c['slot_id'] == 1, 'storage-session-bounds')
    s = c['storage']
    require(type(s) is dict and set(s) == CONFIG_FIELDS and s['schema_version'] == CONFIG_SCHEMA
            and s['scheme'] == 'kaiba-firmware-hmac-counter-v1', 'storage-config-fields')
    for field in ('experiment_id', 'target_reference'):
        require(type(s[field]) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', s[field]), 'storage-identifier')
    for field, length in [('source_revision', 40), ('nonce_hex', 64), ('board_serial_sha256', 64),
                          ('disk_serial_sha256', 64)]:
        require(type(s[field]) is str and re.fullmatch(r'[a-f0-9]{' + str(length) + '}', s[field])
                and int(s[field], 16) != 0, 'storage-digest')
    for field in ('volume_uuid', 'partition_uuid'):
        require(type(s[field]) is str and d.UUID.fullmatch(s[field]) and int(s[field].replace('-', ''), 16) != 0,
                'storage-uuid')
    require(s['volume_uuid'] != s['partition_uuid'] and s['board_serial_sha256'] == c['board_serial_sha256']
            and type(s['slot_id']) is int and s['slot_id'] == c['slot_id']
            and type(s['expected_usage']) is int and s['expected_usage'] == c['expected_usage'], 'storage-binding')
    return c


def validate_result(raw, c, phase, boot, rc):
    require(len(raw) <= 8192, 'storage-result-bound')
    v = decode(raw)
    require(type(v) is dict and set(v) == RESULT_FIELDS, 'storage-result-fields')
    require(v['schema_version'] == 'kaiba.device-secret-storage-result/v1alpha1' and v['mode'] == 'development'
            and v['phase'] == phase and v['boot_id'] == boot and v['boot_image_sha256'] == c['boot_image_sha256']
            and v['volume_uuid'] == c['storage']['volume_uuid']
            and v['nonce_sha256'] == hashlib.sha256(bytes.fromhex(c['storage']['nonce_hex'])).hexdigest()
            and type(v['verity_root_hash']) is str and d.HEX.fullmatch(v['verity_root_hash'])
            and int(v['verity_root_hash'], 16) != 0, 'storage-result-binding')
    for field in ('passed', 'volume_verified', 'runtime_locks_closed', 'storage_closed', 'journal_completed',
                  'hardware_qualified', 'lock_rejection_qualified'):
        require(type(v[field]) is bool, 'storage-result-boolean')
    require(not v['hardware_qualified'] and not v['lock_rejection_qualified'], 'storage-result-qualification')
    require(rc == (0 if v['passed'] else 3), 'storage-result-exit')
    require(type(v['stop']) is str and re.fullmatch(r'[a-z-]{1,60}', v['stop']), 'storage-result-stop')
    for field, high in [('last_firmware_outcome', 4), ('last_mailbox_tag', 0xffffffff), ('last_mailbox_errno', 4095)]:
        require(type(v[field]) is int and 0 <= v[field] <= high, 'storage-result-diagnostic')
    if v['passed']:
        require(v['stop'] == 'complete' and all(v[k] for k in
                ('volume_verified', 'runtime_locks_closed', 'storage_closed', 'journal_completed')),
                'storage-incomplete-success')
        require((v['last_firmware_outcome'], v['last_mailbox_tag'], v['last_mailbox_errno']) == (0, 0x30092, 0),
                'storage-success-firmware-diagnostic')
    return v


def run_script(c, phase, binary, boot, attempt):
    require(phase in ('create', 'reopen') and d.UUID.fullmatch(boot)
            and re.fullmatch(r'[0-9]{4}', attempt), 'storage-run-binding')
    encoded = base64.b64encode(binary).decode()
    config = base64.b64encode(canonical(c['storage'])).decode()
    return d.preflight(c) + f'''test "$(cat /proc/sys/kernel/random/boot_id)" = {boot}
test ! -L /run/kaiba-device-secret-storage-development
install -d -m 0700 /run/kaiba-device-secret-storage-development
storage_dir="$(mktemp -d /run/kaiba-device-secret-storage-development/attempt-{attempt}.XXXXXXXX)"
trap 'rm -f -- "$storage_dir/helper" "$storage_dir/config.json"' EXIT
base64 -d > "$storage_dir/helper" <<'KAIBA_STORAGE_HELPER'
{encoded}
KAIBA_STORAGE_HELPER
base64 -d > "$storage_dir/config.json" <<'KAIBA_STORAGE_CONFIG'
{config}
KAIBA_STORAGE_CONFIG
test "$(sha256sum "$storage_dir/helper" | cut -d ' ' -f1)" = {c['helper_sha256']}
chmod 0500 "$storage_dir/helper"
"$storage_dir/helper" {phase} "$storage_dir/config.json" --expected-boot-id {boot}
'''


class Session(d.Session):
    def __init__(self, path):
        super().__init__(path, config_validator=validate)

    def allowed(self, action):
        super().allowed(action)
        previous = [decode(regular_bytes(p))['action'] for p in self.intents]
        order = ['create', 'reboot', 'reopen']
        require(len(previous) < len(order) and previous == order[:len(previous)]
                and action == order[len(previous)], 'storage-phase-order')

    def run(self, helper, phase):
        c = self.config
        require(phase in c['checks'], 'storage-phase-not-authorized')
        self.allowed(phase)
        binary = regular_bytes(Path(helper), 16 * 1024 * 1024)
        require(hashlib.sha256(binary).hexdigest() == c['helper_sha256'], 'helper-digest-mismatch')
        require(binary[:6] == b'\x7fELF\x02\x01' and binary[18:20] == b'\xb7\x00', 'native-ARM64-helper-required')
        before = d.inspect(c, self.known)
        if phase == 'reopen':
            created = decode(regular_bytes(self.path / '0001.result.json'))['observation']
            rebooted = decode(regular_bytes(self.path / '0002.result.json'))['after']
            require(before['boot_id'] != created['boot_id'] and before['boot_id'] == rebooted['boot_id'],
                    'storage-reopen-boot-binding')
        attempt = self.intent(phase, before)
        r = d.remote(c, self.known, run_script(c, phase, binary, before['boot_id'], attempt), timeout=210)
        d.write(self.path / f'{attempt}.stdout', r.stdout)
        d.write(self.path / f'{attempt}.stderr', r.stderr)
        value = validate_result(r.stdout, c, phase, before['boot_id'], r.returncode)
        require(not r.stderr, 'storage-unexpected-stderr')
        record = dict(status='passed' if value['passed'] else 'failed', observed_at=d.now().isoformat(),
                      observation=value, stdout_sha256=hashlib.sha256(r.stdout).hexdigest(), hardware_qualified=False)
        d.write(self.path / f'{attempt}.result.json', canonical(record))
        return record


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description='Bounded remote LUKS development on a pre-approved disposable partition.')
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('init', 'status', 'create', 'reboot', 'reopen'):
        p = sub.add_parser(command); p.add_argument('--state', required=True)
        if command == 'init': p.add_argument('--config', required=True)
        if command in ('create', 'reopen'): p.add_argument('--helper', required=True)
    a = parser.parse_args(argv)
    try:
        if a.command == 'init':
            result = d.initialize(a.state, a.config, config_validator=validate)
        else:
            session = Session(a.state)
            try:
                if a.command in ('create', 'reopen'): result = session.run(a.helper, a.command)
                elif a.command == 'reboot': result = session.reboot()
                else: result = dict(attempts=[decode(regular_bytes(p)) for p in session.intents], execution_authority=False)
            finally: session.close()
        print(json.dumps(result, sort_keys=True))
        return 3 if result.get('status') == 'failed' else 0
    except (Rejected, OSError, ValueError, subprocess.SubprocessError) as e:
        print('STOP: ' + str(e) + '; preserve state; no automatic retry', file=sys.stderr)
        return 3


if __name__ == '__main__':
    sys.exit(main())
