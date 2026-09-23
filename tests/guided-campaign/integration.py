"""Real packaged controller + kiosk + mTLS + device client, disposable software."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

parser = argparse.ArgumentParser()
parser.add_argument('--campaign', required=True)
parser.add_argument('--station', required=True)
parser.add_argument('--plan', required=True)
parser.add_argument('--negative-plans', required=True, type=Path)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
os.umask(0o077)
root = Path.cwd()/'campaign-bench'
root.mkdir(mode=0o700)
for name in ('journal', 'device-state'):
    (root/name).mkdir(mode=0o700)
now = dt.datetime.now(dt.timezone.utc)
ca_key = ec.generate_private_key(ec.SECP256R1())
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Disposable station campaign CA')])
ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
      .serial_number(1).not_valid_before(now-dt.timedelta(hours=1)).not_valid_after(now+dt.timedelta(hours=1))
      .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
      .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
      .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
      .sign(ca_key, hashes.SHA256()))
ca_pem = ca.public_bytes(serialization.Encoding.PEM)
(root/'ca.crt').write_bytes(ca_pem)

def certificate(name, principal=None):
    import ipaddress
    key = ec.generate_private_key(ec.SECP256R1())
    san = [x509.UniformResourceIdentifier(principal)] if principal else [x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]
    cert = (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=1)).not_valid_after(now+dt.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if principal else ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .add_extension(x509.SubjectAlternativeName(san), True).sign(ca_key, hashes.SHA256()))
    (root/(name+'.crt')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (root/(name+'.key')).write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

certificate('server')
certificate('station', 'spiffe://kaiba.network/station/software-station/lane/lane-1')
certificate('wrong', 'spiffe://kaiba.network/station/other-station/lane/lane-1')
config = dict(schema_version='kaiba.device-enrollment-client/v1alpha1', mode='development',
              fleet_url='https://127.0.0.1:9', server_ca_pem=ca_pem.decode(), issuer_ca_pem=ca_pem.decode(),
              issuer_id='disposable-issuer', authority_id='synthetic', transaction_id='synthetic-transaction',
              target='synthetic-target', restart_requirement='process',
              provisioning_ref=dict(record_id='synthetic-record', revision=1, digest='sha256:'+'a'*64))
(root/'client-config.json').write_text(json.dumps(config))

def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

authority_port, kiosk_port = port(), port()
descriptor = json.loads(subprocess.check_output([args.campaign, '--plan', args.plan, '--describe-plan']))
authority_command = [args.campaign, '--plan', args.plan, '--state', str(root/'journal'), '--listen', f'127.0.0.1:{authority_port}', '--tls-cert', str(root/'server.crt'), '--tls-key', str(root/'server.key'), '--client-ca', str(root/'ca.crt')]
kiosk_command = [args.station, '--listen', f'127.0.0.1:{kiosk_port}', '--station-id', 'software-station', '--lane-id', 'lane-1', '--campaign-url', f'https://127.0.0.1:{authority_port}', '--campaign-id', descriptor['campaign_id'], '--campaign-plan-digest', descriptor['plan_digest'], '--campaign-server-ca', str(root/'ca.crt'), '--tls-cert', str(root/'station.crt'), '--tls-key', str(root/'station.key')]
processes = {}
origin = f'http://127.0.0.1:{kiosk_port}'
checks = []

def start(name, command):
    output = (root/(name+'.log')).open('ab')
    processes[name] = subprocess.Popen(command, cwd=root, stdout=output, stderr=subprocess.STDOUT)
    output.close()

def stop(name):
    process = processes.pop(name)
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()

def request(path, body=None, token=None, expected=200):
    headers = {'Origin': origin}
    if token:
        headers['X-Kaiba-Campaign-Token'] = token
    if body is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(origin+path, data=None if body is None else json.dumps(body).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            assert response.status == expected
            return json.load(response)
    except urllib.error.HTTPError as error:
        assert error.code == expected, (path, error.code, error.read())
        return json.load(error)

def wait(status=None):
    deadline = time.monotonic()+30
    while time.monotonic() < deadline:
        try:
            result = request('/api/v1/state')
            if status is None or result['status'] == status:
                return result
        except (OSError, AssertionError):
            pass
        time.sleep(.05)
    raise AssertionError('station did not reach '+str(status))

try:
    start('authority', authority_command)
    start('kiosk', kiosk_command)
    state = wait('ready')
    token = request('/runtime-config.json')['session_token']
    assert state['mode'] == 'software_rehearsal'
    request('/api/v1/actions', dict(request_id='bad', expected_revision=1, action='begin', input=''), 'wrong-token', 403)
    assert not (root/'called-inspect').exists()
    start_action = dict(request_id='begin', expected_revision=state['revision'], action='begin', input='')
    request('/api/v1/actions', start_action, token)
    state = wait('awaiting_input')
    request('/api/v1/actions', start_action, token)
    assert state['step_id'] == 'restart_client'
    checks.append('automatic steps execute once and double taps reconcile the same request')
    stop('kiosk')
    start('kiosk', kiosk_command)
    resumed = wait('awaiting_input')
    assert resumed == state
    request('/api/v1/actions', dict(request_id='old-session', expected_revision=state['revision'], action='submit', input='ready'), token, 403)
    token = request('/runtime-config.json')['session_token']
    checks.append('kiosk restart restores authoritative progress and replaces session capability')
    stop('authority')
    request('/api/v1/state', expected=503)
    start('authority', authority_command)
    assert wait('awaiting_input') == state
    checks.append('authority outage and durable restart do not repeat an executor')
    action = dict(request_id='physical-response', expected_revision=state['revision'], action='submit', input='ready')
    request('/api/v1/actions', action, token)
    wait('completed')
    request('/api/v1/actions', action, token)
    report = request('/api/v1/report', token=token)
    assert report['campaign_complete'] and len(report['attempts']) == 4
    assert not report['state']['production_enrollment'] and not report['state']['hardware_qualified']
    assert len(report['remaining_admission_conditions']) == 8
    assert all(x['status'] == 'not_evaluated' for x in report['remaining_admission_conditions'])
    private = json.loads((root/'device-state/state.json').read_text())
    # The actual client has a key, but neither it nor PEM credentials enter the export.
    assert 'private_key_pkcs8' in private
    encoded = json.dumps(report)
    assert 'private_key_pkcs8' not in encoded and 'BEGIN ' not in encoded and private['private_key_pkcs8'] not in encoded
    assert len(list(root.glob('called-*'))) == 4
    checks.append('packaged client key persists across processes; typed report excludes private state')
    context = ssl.create_default_context(cafile=str(root/'ca.crt'))
    context.load_cert_chain(str(root/'wrong.crt'), str(root/'wrong.key'))
    try:
        urllib.request.urlopen(f'https://127.0.0.1:{authority_port}/api/v1/campaign/state', context=context)
        raise AssertionError('wrong station accepted')
    except urllib.error.HTTPError as error:
        assert error.code == 403
    checks.append('real mTLS rejects a different authenticated station')
    # Exercise the actual fixed-process boundary, including a timeout, using
    # immutable Nix-store programs. These never invoke the device client.
    for plan_path in sorted(args.negative_plans.glob('*.json')):
        stop('kiosk')
        stop('authority')
        kind = plan_path.stem
        state_path = root/('negative-journal-'+kind)
        state_path.mkdir(mode=0o700)
        descriptor = json.loads(subprocess.check_output([args.campaign, '--plan', str(plan_path), '--describe-plan']))
        authority_negative = list(authority_command)
        authority_negative[authority_negative.index('--plan')+1] = str(plan_path)
        authority_negative[authority_negative.index('--state')+1] = str(state_path)
        kiosk_negative = list(kiosk_command)
        kiosk_negative[kiosk_negative.index('--campaign-id')+1] = descriptor['campaign_id']
        kiosk_negative[kiosk_negative.index('--campaign-plan-digest')+1] = descriptor['plan_digest']
        start('authority', authority_negative)
        start('kiosk', kiosk_negative)
        state = wait('ready')
        token = request('/runtime-config.json')['session_token']
        request('/api/v1/actions', dict(request_id='fault', expected_revision=state['revision'], action='begin', input=''), token)
        wait('reconciliation_required')
        failed = request('/api/v1/report', token=token)
        assert len(failed['attempts']) == 1 and not failed['campaign_complete']
        assert failed['attempts'][0]['outcome'] == 'uncertain'
        assert failed['attempts'][0]['failure_category'] in ('executor_preflight', 'executor_failed', 'invalid_result', 'interrupted')
        assert 'synthetic-must-not-escape' not in json.dumps(failed)
        assert 'synthetic-must-not-escape' not in (state_path/'state.json').read_text()
        marker = root/('called-negative-'+kind)
        assert marker.exists() == (kind != 'digest')
        if kind == 'digest':
            assert failed['attempts'][0]['failure_category'] == 'executor_preflight'
        if kind == 'timeout':
            assert failed['attempts'][0]['failure_category'] == 'interrupted'
        stop('authority')
        start('authority', authority_negative)
        assert wait('reconciliation_required')['actions'] == []
    checks.append('digest, stderr, overflow, malformed output, timeout and exit failures stop without replay or raw diagnostics')
    args.output.mkdir(parents=True)
    (args.output/'report.json').write_text(json.dumps(dict(status='passed', mode='software_rehearsal', hardware_qualified=False, production_enrollment=False, checks=checks, campaign=report), indent=2)+'\n')
    print('PASS guided campaign native integration:', len(checks), 'scenario groups')
finally:
    for name in list(processes):
        stop(name)
