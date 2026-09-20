"""Assess two saved offline storage captures. No hardware or execution authority."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

import storage_development as s
from runner import Rejected, decode, regular_bytes, require

PREFIX = b'KAIBA_DEVICE_SECRET_STORAGE_RESULT='
FIELDS = {'schema_version', 'boot_image_sha256', 'verity_root_hash', 'volume_uuid', 'nonce_hex'}


def validate_plan(p):
    require(type(p) is dict and set(p) == FIELDS
            and p['schema_version'] == 'kaiba.offline-storage-capture-plan/v1alpha1', 'capture-plan-fields')
    for name in ('boot_image_sha256', 'verity_root_hash', 'nonce_hex'):
        require(type(p[name]) is str and re.fullmatch('[0-9a-f]{64}', p[name])
                and int(p[name], 16) != 0, 'capture-plan-digest')
    require(type(p['volume_uuid']) is str and s.d.UUID.fullmatch(p['volume_uuid'])
            and int(p['volume_uuid'].replace('-', ''), 16) != 0, 'capture-plan-volume')
    return p


def assess_capture(raw, p, phase):
    validate_plan(p)
    require(phase in ('create', 'reopen'), 'capture-phase')
    require(len(raw) <= 4 * 1024**2 and raw.count(PREFIX) == 1, 'missing-or-duplicate-result')
    lines = raw.splitlines()
    line = next(line for line in lines if PREFIX in line)
    require(line.startswith(PREFIX) and len(line) <= 8192, 'interleaved-or-oversize-result')
    record = line[len(PREFIX):]
    v = decode(record)
    require(type(v) is dict and type(v.get('boot_id')) is str
            and s.d.UUID.fullmatch(v['boot_id']) and int(v['boot_id'].replace('-', ''), 16) != 0,
            'capture-boot-id')
    c = {'boot_image_sha256': p['boot_image_sha256'],
         'storage': {'volume_uuid': p['volume_uuid'], 'nonce_hex': p['nonce_hex']}}
    # No normalization of result claims or failed statuses. A successful parser
    # establishes only that these exact target reports matched the selected plan.
    v = s.validate_result(record, c, phase, v['boot_id'], 0, mode='offline-development',
                          schema='kaiba.device-secret-storage-offline-result/v1alpha1')
    require(v['verity_root_hash'] == p['verity_root_hash'], 'capture-root-binding')
    return v


def assess_pair(create, reopen, plan):
    a, b = assess_capture(create, plan, 'create'), assess_capture(reopen, plan, 'reopen')
    require(a['boot_id'] != b['boot_id'], 'capture-repeated-boot')
    return dict(status='matched-target-reports', create=a, reopen=b,
                capture_sha256=[hashlib.sha256(x).hexdigest() for x in (create, reopen)],
                cold_power_verified=False, physical_isolation_verified=False,
                hardware_qualified=False, lock_rejection_qualified=False, execution_authority=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--create-capture', required=True)
    parser.add_argument('--reopen-capture', required=True)
    a = parser.parse_args()
    try:
        result = assess_pair(regular_bytes(Path(a.create_capture), 4 * 1024**2),
                             regular_bytes(Path(a.reopen_capture), 4 * 1024**2),
                             decode(regular_bytes(Path(a.plan))))
        print(json.dumps(result, sort_keys=True))
    except (Rejected, OSError, ValueError) as e:
        print('STOP: ' + str(e) + '; preserve captures', file=sys.stderr)
        return 3
    return 0


if __name__ == '__main__':
    sys.exit(main())
