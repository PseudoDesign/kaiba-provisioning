"""Native service rehearsal: retained keys, rollback, and crash reconciliation."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

settings, runner = sys.argv[1:]
reports = []
with tempfile.TemporaryDirectory(prefix='nvme-cases-') as directory:
    cases = Path(directory)
    def run(*args, success=True):
        p = subprocess.run([sys.executable, '-I', '-B', runner, '--settings', settings,
                            '--cases', cases, *args], capture_output=True, text=True, timeout=240)
        if (p.returncode == 0) != success:
            print(p.stdout); print(p.stderr)
            for log in cases.glob('*/*.log'):
                print(log.name, log.read_text(errors='replace')[-2500:])
            raise AssertionError((args, p.returncode))
        events = [json.loads(line) for line in p.stdout.splitlines() if line.startswith('{')]
        reports.extend(events)
        return events
    run('prepare', 'ack')
    run('prepare', 'ack', success=False)
    backup = run('backup', 'ack')[-1]
    run('after-ack', 'ack', '--simulate-interruption')
    run('check', 'ack', '--expected', 'revoked')
    run('after-ack', 'ack', success=False)
    run('restore', 'ack', '--backup-sha256', '0'*64, success=False)
    run('restore', 'ack', '--backup-sha256', backup['sha256'])
    # This profile has no monotonic anchor. An old backup MUST fail the retained
    # acknowledgement expectation, even though it can boot and its SQL is valid.
    run('check', 'ack', '--expected', 'revoked', success=False)
    run('check', 'ack', '--expected', 'active')
    run('prepare', 'before')
    run('before-commit', 'before', '--simulate-interruption')
    run('check', 'before', '--expected', 'active')
    run('rehearsal', 'suite')
Path('report.json').write_text(json.dumps({'synthetic': True, 'physical_power_cut': False,
    'hardware_qualified': False, 'obsolete_backup_detected_by_external_expectation': True,
    'events': reports}, indent=2)+'\n')
print('Native Fleet/PostgreSQL crash, retained key, and obsolete-backup checks passed')
