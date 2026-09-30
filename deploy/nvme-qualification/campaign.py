"""Resumable synthetic Fleet cases using the pinned real service executables.

The software fixture bypasses ONLY the device's encrypted-storage observation.
Physical results are kept separate from the existing full lifecycle rehearsals.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import types
import uuid


def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, sort_keys=True, default=str); f.write('\n')
        f.flush(); os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def event(case, phase, **kw):
    print(json.dumps({'schema': 'kaiba.nvme-case-event/v1', 'case_id': case,
                      'phase': phase, 'synthetic': True, 'hardware_qualified': False,
                      'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                      'observed_at_unix': time.time(), **kw}, sort_keys=True), flush=True)


def sql(run, statement):
    return subprocess.check_output([run.args.postgres/'psql', '-X', '-w', '-h', run.sock,
                                    '-p', str(run.pgport), '-d', 'postgres', '-v', 'ON_ERROR_STOP=1',
                                    '-Atc', statement], text=True).strip()


def start(run):
    subprocess.run([run.args.postgres/'pg_ctl', '-D', run.pg, '-l', run.root/'postgres.log',
                    '-o', f"-k {run.sock} -h '' -p {run.pgport}", '-w', 'start'], check=True, stdout=subprocess.DEVNULL)
    for n in ('observation', 'admission', 'issuer', 'fleet'):
        run.start(n)


def stop(run):
    for n in list(run.processes):
        run.stop(n)
    # A clean backup boundary, not the lifecycle fixture's immediate shutdown.
    subprocess.run([run.args.postgres/'pg_ctl', '-D', run.pg, '-m', 'fast', '-w', 'stop'],
                   check=True, stdout=subprocess.DEVNULL)


def load_run(cls, args, root, saved):
    # Never call __init__ on retained state: it generates keys and initdb.
    run = object.__new__(cls)
    run.args = args; run.root = root
    run.processes = {}; run.logs = {}; run.checks = []
    for k in ('ports', 'pgport', 'config', 'enrollments'):
        setattr(run, k, saved[k])
    run.pg = root/'postgres'; run.sock = root/'socket'
    run.client_roots = root/'fleet-client-roots.crt'
    run.reader_config = json.loads((root/'reader-config.json').read_text())
    run.env = dict(os.environ, KAIBA_DATABASE_URL=f'host={run.sock} port={run.pgport} dbname=postgres',
                   KAIBA_ISSUER_DATABASE_URL=f'host={run.sock} port={run.pgport} dbname=postgres')
    return run


def key_digests(root):
    state = json.loads((root/'client-a/state.json').read_text())
    # Hash only; never emit fixture private keys or full credential state.
    return {k: hashlib.sha256(state[k].encode()).hexdigest() for k in ('private_key_pkcs8', 'certificate')}


def check_retained(run, saved, expected):
    count = sql(run, 'SELECT count(*) FROM pilot_issued')
    if count != '2':
        raise ValueError('unexpected-issuance-count')
    if key_digests(run.root) != saved['key_digests']:
        raise ValueError('retained-key-or-certificate-changed')
    en = run.http('/api/v1/pilot/enrollments/' + run.enrollments['a']['id'])
    state = en['state']
    if state != expected:
        raise ValueError(f'unexpected-enrollment-state:{state};expected:{expected}')
    # A still-valid control member distinguishes revocation from total outage or
    # expiry. Never report revocation enforcement solely because TLS failed.
    run.http('/api/v1/pilot/self', 'b')
    run.http('/api/v1/pilot/self', 'a', status=403 if expected == 'revoked' else 200)
    return {'state': state, 'issued_certificates': 2, 'retained_key': True, 'control_member_authorized': True}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--settings', type=Path, required=True)
    p.add_argument('--cases', type=Path, required=True)
    p.add_argument('action', choices=['prepare', 'before-commit', 'after-ack', 'check', 'backup', 'restore', 'rehearsal'])
    p.add_argument('name')
    p.add_argument('--expected', choices=['active', 'revoked'])
    p.add_argument('--backup-sha256')
    p.add_argument('--simulate-interruption', action='store_true', help='Software rehearsal only: SIGKILL service processes, no power action')
    a = p.parse_args()
    if not re.fullmatch('[a-z][a-z0-9-]{0,31}', a.name):
        raise ValueError('invalid-case-name')
    if os.geteuid() == 0:
        raise ValueError('fixture-must-run-as-unprivileged-user')
    cfg = json.loads(a.settings.read_text())
    sys.path.insert(0, str(Path(cfg['fleet_source'])/'tests'))
    from pilot_lifecycle import Lifecycle
    args = types.SimpleNamespace(**{k: Path(v) for k, v in cfg.items() if k != 'fleet_source'})
    root = a.cases/a.name
    a.cases.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    if a.action == 'rehearsal':
        root.mkdir(mode=0o700)
        for script in ('pilot_lifecycle.py', 'pilot_recovery_cutover.py'):
            output = root/(script + '.report.json')
            command = [sys.executable, '-B', str(Path(cfg['fleet_source'])/'tests'/script)]
            for k in ('provisioning', 'fleet', 'postgres', 'fixture_client', 'device_client'):
                command += ['--'+k.replace('_', '-'), str(getattr(args, k))]
            command += ['--report', str(output)]
            with (root/(script+'.log')).open('x') as log:
                subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT,
                               env=dict(os.environ, TMPDIR=str(root)))
            report = json.loads(output.read_text())
            event(a.name, 'software-rehearsal-passed', test=script, checks=len(report['checks']))
        return
    if a.action == 'prepare':
        root.mkdir(mode=0o700)
        run = Lifecycle(args, root)
        try:
            for n in ('observation', 'admission', 'issuer', 'fleet'): run.start(n)
            run.enroll('a'); run.enroll('b')
            saved = {k: getattr(run, k) for k in ('ports', 'pgport', 'config', 'enrollments')}
            saved['case_id'] = str(uuid.uuid4())
            saved['key_digests'] = key_digests(root)
            save(root/'case.json', saved)
            checked = check_retained(run, saved, 'active')
        finally:
            stop(run)
        event(saved['case_id'], 'prepared', **checked)
        return
    saved = json.loads((root/'case.json').read_text())
    run = load_run(Lifecycle, args, root, saved)
    archive = a.cases/(a.name+'.tar')
    if a.action == 'backup':
        if (run.pg/'postmaster.pid').exists():
            raise ValueError('database-not-cleanly-stopped')
        with archive.open('xb') as dest:
            with tarfile.open(fileobj=dest, mode='w') as tar:
                tar.add(root, arcname=a.name)
            dest.flush(); os.fsync(dest.fileno())
        with archive.open('rb') as f: sha = hashlib.file_digest(f, 'sha256').hexdigest()
        event(saved['case_id'], 'synthetic-backup-created', path=str(archive), sha256=sha)
        return
    if a.action == 'restore':
        if (run.pg/'postmaster.pid').exists():
            raise ValueError('database-not-cleanly-stopped')
        with archive.open('rb') as f: sha = hashlib.file_digest(f, 'sha256').hexdigest()
        if not a.backup_sha256 or sha != a.backup_sha256:
            raise ValueError('separately-retained-backup-digest-required')
        with tarfile.open(archive) as tar:
            for item in tar.getmembers():
                parts = Path(item.name).parts
                if not parts or parts[0] != a.name or '..' in parts or not (item.isfile() or item.isdir()):
                    raise ValueError('unsafe-backup-member')
            # Preserve the old case; use original paths because TLS config files
            # bind them. Never start an obsolete backup automatically.
            preserved = a.cases/(a.name+'.preserved-'+str(time.time_ns()))
            root.rename(preserved)
            tar.extractall(a.cases, filter='data')
        event(saved['case_id'], 'synthetic-backup-restored-not-started', preserved=str(preserved))
        return
    start(run)
    abrupt = False
    try:
        if a.action == 'check':
            if not a.expected: raise ValueError('expected-state-from-independent-receipt-required')
            result = check_retained(run, saved, a.expected)
            event(saved['case_id'], 'retained-state-passed', **result)
            return
        if (root/'boundary.json').exists():
            raise ValueError('case-already-armed-do-not-rerun')
        check_retained(run, saved, 'active')
        endpoint = '/api/v1/pilot/enrollments/'+run.enrollments['a']['id']+'/revoked'
        save(root/'boundary.json', {'case_id': saved['case_id'], 'boundary': a.action})
        if a.action == 'before-commit':
            sql(run, "CREATE FUNCTION qualification_hold() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(3600); RETURN NEW; END $$; CREATE TRIGGER qualification_hold BEFORE UPDATE ON pilot_enrollments FOR EACH ROW EXECUTE FUNCTION qualification_hold();")
            outcome = []
            def request():
                try: run.http(endpoint, 'operator', {}); outcome.append('returned')
                except Exception: outcome.append('failed')
            thread = threading.Thread(target=request, daemon=True); thread.start()
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if sql(run, "SELECT count(*) FROM pg_stat_activity WHERE wait_event='PgSleep'") == '1': break
                if outcome: raise ValueError('request-ended-before-hold')
                time.sleep(.1)
            else: raise ValueError('commit-hold-not-observed')
            event(saved['case_id'], 'ready-before-commit', expected_after_restart='active',
                  cut_window_seconds=20, instruction='retain this event independently, then cut PoE within 20 seconds')
            # The client's 40-second deadline cancels the request; never continue
            # advertising a cut point after it no longer exists.
            if not a.simulate_interruption:
                time.sleep(20)
                event(saved['case_id'], 'cut-window-expired', result='inconclusive-without-timely-cut')
                return
        else:
            run.http(endpoint, 'operator', {})
            check_retained(run, saved, 'revoked')
            event(saved['case_id'], 'ready-after-ack', expected_after_restart='revoked',
                  instruction='retain this acknowledgement independently, then cut PoE')
        if a.simulate_interruption:
            for child in run.processes.values(): child.kill(); child.wait()
            run.processes.clear()
            subprocess.run([args.postgres/'pg_ctl', '-D', run.pg, '-m', 'immediate', '-w', 'stop'],
                           check=True, stdout=subprocess.DEVNULL)
            abrupt = True
            event(saved['case_id'], 'software-interruption-only', physical_power_cut=False)
        else:
            while True: time.sleep(1)
    finally:
        if not abrupt: stop(run)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(json.dumps({'phase': 'stopped-preserve-state', 'error_kind': type(error).__name__, 'error': str(error)}), flush=True)
        sys.exit(1)
