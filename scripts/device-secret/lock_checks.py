"""Read-only assessment of bounded lock-check helper and observer records."""
import argparse
import hashlib
import json
import re
from pathlib import Path
from runner import decode, require


def assess(raw, plan):
    require(type(plan) is dict and set(plan) == {'schema_version', 'boot_id', 'slot_id', 'expected_usage'}, 'plan-fields')
    require(plan['schema_version'] == 'kaiba.device-secret-lock-checks-plan/v1alpha1'
            and type(plan['boot_id']) is str and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', plan['boot_id'])
            and type(plan['slot_id']) is int and 1 <= plan['slot_id'] <= 32
            and type(plan['expected_usage']) is int and plan['expected_usage'] in (0, 8, 9, 10, 11, 12, 13, 14), 'plan-binding')
    require(len(raw) <= 32768, 'capture-bound')
    lines = raw.splitlines()
    require(len(lines) == 2 and lines[1].startswith(b'KAIBA_FIRMWARE_OBSERVER='), 'capture-framing')
    helper, observer = decode(lines[0]), decode(lines[1].split(b'=', 1)[1])
    require(type(helper) is dict and set(helper) == {'schema_version', 'mode', 'check', 'boot_id', 'slot_id',
            'expected_usage', 'completed', 'stop', 'cleanup_locks_closed', 'hardware_qualified', 'steps'}, 'helper-fields')
    require(helper['schema_version'] == 'kaiba.device-secret-lock-checks/v1alpha1'
            and helper['mode'] == 'development' and helper['check'] == 'locks'
            and helper['completed'] is True and helper['stop'] == 'complete'
            and helper['cleanup_locks_closed'] is True and helper['hardware_qualified'] is False, 'incomplete-helper')
    for key in ('boot_id', 'slot_id', 'expected_usage'):
        require(type(helper[key]) is type(plan[key]) and helper[key] == plan[key], 'helper-binding')
    require(type(helper['steps']) is list and len(helper['steps']) <= 20, 'step-bound')
    steps = list(helper['steps'])
    for s in steps:
        require(type(s) is dict and set(s) == {'name', 'passed', 'outcome', 'mailbox_tag', 'mailbox_errno', 'value'}
                and type(s['name']) is str and type(s['passed']) is bool, 'step-fields')
        for key in ('outcome', 'mailbox_tag', 'mailbox_errno'):
            require(type(s[key]) is int, 'step-type')
        require(s['value'] is None or type(s['value']) is int, 'step-value')
    def take(name, tag, value=None, outcome=0, passed=True, error=0):
        expected = dict(name=name, passed=passed, outcome=outcome, mailbox_tag=tag, mailbox_errno=error, value=value)
        require(steps and steps.pop(0) == expected, 'step-sequence:' + name)
    require(len(steps) >= 3, 'missing-metadata')
    count, status = steps[0]['value'], steps[1]['value']
    require(type(count) is int and plan['slot_id'] <= count <= 32 and type(status) is int
            and status & 1 and not status & ~0x1f01 and not status & 0x0c00, 'preclosed-or-invalid-key')
    take('count', 0x3008f, count); take('status', 0x30090, status)
    take('usage', 0x3009c, plan['expected_usage'])
    take('apply-runtime-locks', 0x38090); take('runtime-locks', 0x30090, 0x1301)
    take('hmac-control', 0x30092); take('sign-control', 0x30091)
    failed_operations = []
    def denial(name, error_name, tag):
        require(steps, 'missing-denial')
        if steps[0]['outcome'] == 1:
            take(name, 0x3008e, outcome=1)
            return 0
        take(name, tag, outcome=2, passed=False, error=22)
        take(error_name, 0x3008e, 4)
        failed_operations.append(name)
        return -22
    raw_result = denial('raw-read-blocked', 'last-error-raw-read', 0x30094)
    take('legacy-read-blocked', 0x30081, outcome=1, error=22)
    take('close-before-probes', 0x38090); take('closed-before-probes', 0x30090, 0x1f01)
    sign_result = denial('sign-closed', 'last-error-sign-closed', 0x30091)
    require(steps, 'missing-clear-result')
    if steps[0]['outcome'] == 2:
        take('attempt-clear-locks', 0x38090, outcome=2, passed=False, error=22)
        failed_operations.append('attempt-clear-locks')
    else:
        take('attempt-clear-locks', 0x38090)
    # Must precede cleanup: final closed-status could conceal a clearing effect.
    take('locks-remain-closed', 0x30090, 0x1f01)
    take('close-runtime-locks', 0x38090); take('closed-status', 0x30090, 0x1f01)
    require(not steps, 'extra-steps')
    require(type(observer) is dict and set(observer) == {'schema_version', 'complete', 'helper_exit', 'rejected',
            'hardware_qualified', 'events'} and observer['schema_version'] == 'kaiba.firmware-rejection-observation/v1alpha1'
            and observer['complete'] is True and observer['hardware_qualified'] is False
            and type(observer['helper_exit']) is int and observer['helper_exit'] == 0
            and type(observer['rejected']) is int and observer['rejected'] == 0, 'incomplete-observer')
    require(type(observer['events']) is list and len(observer['events']) == 4, 'observer-count')
    keys = {'sequence', 'complete', 'copy_failed', 'tag', 'result', 'request_valid', 'reply_valid',
            'response_marked', 'operation_error', 'payload_unchanged_or_zero'}
    for i, (event, tag, result) in enumerate(zip(observer['events'], [0x30092, 0x30091, 0x30094, 0x30091], [0, 0, raw_result, sign_result])):
        require(type(event) is dict and set(event) == keys, 'observer-event-fields')
        require(all(type(event[k]) is bool for k in keys - {'sequence', 'tag', 'result'})
                and all(type(event[k]) is int for k in ('sequence', 'tag', 'result')), 'observer-event-types')
        require(event['sequence'] == i and event['tag'] == tag and event['result'] == result
                and event['complete'] and not event['copy_failed'] and event['request_valid']
                and event['reply_valid'] and event['response_marked'], 'observer-event-binding')
        require(event['operation_error'] is (i >= 2), 'observer-operation-result')
        if i >= 2:
            require(event['payload_unchanged_or_zero'], 'unexpected-error-payload')
    return dict(schema_version='kaiba.device-secret-lock-checks-assessment/v1alpha1',
                status='matched-target-and-kernel-observations', capture_sha256=hashlib.sha256(raw).hexdigest(),
                claims=dict(crypto_read_denial='tagged-error-no-new-payload', signing_closure='positive-control-then-tagged-error-no-new-payload',
                            legacy_read_denial='helper-validated-pinned-exception', lock_clearing='status-retained-after-clearing-request',
                            generation_and_usage='lock-bits-observed-not-write-tested'),
                original_failed_operations=failed_operations, last_error_transaction_correlation=False,
                hardware_qualified=False, execution_authority=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--capture', type=Path, required=True)
    args = parser.parse_args()
    require(args.plan.stat().st_size <= 4096 and args.capture.stat().st_size <= 32768, 'input-bound')
    print(json.dumps(assess(args.capture.read_bytes(), decode(args.plan.read_bytes())), indent=2))


if __name__ == '__main__':
    main()
