"""Bounded initial-enrollment operations for a reviewed host adapter.

Only public client status, proofs and authority responses enter this journal.
Host deployment, SSH, encrypted backup and serving remain separate hooks.
A failed or lost mutation response is observed, never automatically repeated.
"""
import base64
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runner as r

STEPS = ('initialize-device', 'start-enrollment', 'submit-bootstrap',
         'install-credential', 'prove-installed', 'activate', 'verify-access')
ID = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}\Z')
LIMIT = 1024 * 1024


def digest(value):
    return 'sha256:' + hashlib.sha256(value).hexdigest()


class Authority:
    """HTTPS/mTLS without proxies, redirects, implicit retries or unbounded bodies."""
    def __init__(self, url, ca, clients):
        parsed = urlsplit(url)
        r.require(parsed.scheme == 'https' and parsed.hostname and
                  not parsed.username and not parsed.password and not parsed.query and
                  not parsed.fragment and parsed.path in ('', '/'), 'authority-url')
        self.host, self.port = parsed.hostname, parsed.port or 443
        r.require(set(clients) == {'station', 'operator'}, 'authority-principals')
        self.contexts = {}
        for role, (cert, key) in clients.items():
            ctx = ssl.create_default_context(cafile=ca)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(cert, key)
            self.contexts[role] = ctx

    def __call__(self, path, role='operator', body=None, key=None):
        r.require(role in self.contexts and isinstance(path, str) and
                  re.fullmatch(r'/api/v1/pilot/enrollments(?:/[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}(?:/(?:proof|activate))?)?', path), 'authority-request')
        raw = None if body is None else r.canonical(body)
        r.require(raw is None or len(raw) <= LIMIT, 'authority-request-size')
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.contexts[role], timeout=15)
        headers = {'Accept': 'application/json'}
        if raw is not None:
            headers['Content-Type'] = 'application/json'
        if key is not None:
            r.require(isinstance(key, str) and ID.fullmatch(key), 'idempotency-key')
            headers['Idempotency-Key'] = key
        try:
            conn.request('GET' if raw is None else 'POST', path, raw, headers)
            response = conn.getresponse()
            r.require(response.status == 200, 'authority-read-or-mutation-rejected')
            r.require(response.getheader('Content-Type', '').split(';')[0].strip() == 'application/json', 'authority-content-type')
            data = response.read(LIMIT+1)
            r.require(len(data) <= LIMIT, 'authority-response-size')
            return r.decode(data)
        finally:
            conn.close()


class Store:
    """Root-owned in deployment; owner-only fixture directories in tests."""
    def __init__(self, path, binding):
        self.path = Path(path)
        st = self.path.lstat()
        r.require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
                  stat.S_IMODE(st.st_mode) == 0o700, 'protocol-journal-directory')
        self.fd = os.open(self.path/'.lock', os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(self.fd)
            r.require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == os.geteuid()
                      and stat.S_IMODE(st.st_mode) == 0o600, 'protocol-journal-lock')
            fcntl.flock(self.fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
            previous = self.read('binding')
            if previous is None:
                r.require(set(p.name for p in self.path.iterdir()) == {'.lock'}, 'protocol-journal-not-empty')
                self.write('binding', binding)
            else:
                r.require(previous == binding, 'protocol-journal-binding')
        except BaseException:
            os.close(self.fd)
            raise

    def read(self, name):
        try:
            return r.decode(r.read_file(self.path/(name+'.json'), maximum=LIMIT,
                                        owner=os.geteuid(), mode=0o600))
        except FileNotFoundError:
            return None

    def write(self, name, value):
        raw = r.canonical(value)
        r.require(len(raw) <= LIMIT, 'protocol-journal-size')
        fd = os.open(self.path/(name+'.json'), os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        fd = os.open(self.path, os.O_RDONLY|os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def close(self):
        os.close(self.fd)


class Protocol:
    """Device callback accepts only (command, public_input); no private-key API.

    The reviewed host callback must authenticate the target, pin the executable,
    enforce its protected storage and prohibit command replay independently.
    Read probes use status/self and GET only. Files are bound to the exact plan.
    """
    def __init__(self, plan, store, authority, device):
        r.fields(plan, ('run_id', 'target', 'records', 'binding'))
        r.require(isinstance(plan['run_id'], str) and ID.fullmatch(plan['run_id']), 'protocol-run-id')
        binding = plan['binding']
        r.require(binding['target'] == plan['target'], 'protocol-target')
        for field, role in (('adoption_ref', 'adoption'), ('policy_ref', 'policy'), ('admission_ref', 'decision')):
            r.require(binding[field] == plan['records'][role]['ref'], 'protocol-record-binding')
        r.require(store.read('binding') == plan, 'protocol-plan-changed')
        self.plan, self.store, self.authority, self.device = plan, store, authority, device

    def status(self):
        value = self.device('status', None)
        r.require(value.get('schema_version') == 'kaiba.pilot-device-client/v1alpha1'
                  and value.get('full_qualification') is False and
                  not value.get('renewal') and not value.get('recovery'), 'client-status')
        try:
            spki = base64.b64decode(value['spki'], validate=True)
        except (ValueError, KeyError):
            raise r.Stop('client-public-key')
        r.require(0 < len(spki) <= 2048 and digest(spki) == value.get('spki_digest'), 'client-public-key')
        return value

    def retained_start(self):
        value = self.store.read('start-enrollment.response')
        if value is None:
            return None
        self.validate_enrollment(value)
        return value

    def validate_enrollment(self, value):
        request = self.store.read('start-enrollment.request')
        r.require(request is not None and value.get('request') == request, 'enrollment-request-mismatch')
        r.require(request['target'] == self.plan['target'] and request['records'] == self.plan['records'], 'enrollment-plan-mismatch')
        r.require(isinstance(value.get('id'), str) and ID.fullmatch(value['id']) and
                  isinstance(value.get('logical_device_id'), str) and ID.fullmatch(value['logical_device_id']), 'enrollment-identity')
        r.require(value.get('intent') == self.plan['binding'], 'enrollment-intent-mismatch')
        retained = self.store.read('start-enrollment.response')
        if retained is not None:
            r.require((value['id'], value['logical_device_id']) ==
                      (retained['id'], retained['logical_device_id']), 'enrollment-identity-changed')
        status = self.status()
        r.require(status['spki'] == request['spki'], 'client-key-changed')
        if status['phase'] != 'initialized':
            r.require(status.get('enrollment_id') == value['id'] and
                      status.get('logical_device_id') == value['logical_device_id'], 'client-identity-changed')
        return value

    def current(self):
        retained = self.retained_start()
        if retained is None:
            return None
        return self.validate_enrollment(self.authority('/api/v1/pilot/enrollments/'+retained['id']))

    def execute(self, step):
        r.require(step in STEPS, 'protocol-step')
        # The runner has its own intent too. This protects a directly invoked hook.
        r.require(self.store.read(step+'.intent') is None, 'protocol-already-attempted')
        self.store.write(step+'.intent', {'step': step})
        if step == 'initialize-device':
            self.device('init', None)
        elif step == 'start-enrollment':
            status = self.status()
            r.require(status['phase'] == 'initialized', 'client-not-initialized')
            request = {'records': self.plan['records'], 'target': self.plan['target'], 'spki': status['spki']}
            self.store.write(step+'.request', request)
            response = self.authority('/api/v1/pilot/enrollments', 'station', request, self.plan['run_id'])
            self.validate_enrollment(response)
            r.require(response['state'] == 'awaiting_proof', 'unexpected-enrollment-state')
            self.store.write(step+'.response', response)
        elif step == 'verify-access':
            r.require(self.probe(step), 'own-access-not-verified')
        else:
            current = self.current()
            r.require(current is not None, 'enrollment-identifier-unavailable')
            path = '/api/v1/pilot/enrollments/'+current['id']
            expected = {'submit-bootstrap': 'awaiting_proof', 'install-credential': 'staged',
                        'prove-installed': 'staged', 'activate': 'verified'}[step]
            r.require(current['state'] == expected, 'unexpected-enrollment-state')
            if step == 'submit-bootstrap':
                challenge = current['challenge']
                r.require(challenge['binding'] == self.plan['binding'] and
                          challenge['enrollment_id'] == current['id'] and
                          challenge['logical_device_id'] == current['logical_device_id'], 'bootstrap-binding')
                proof = self.device('bootstrap', challenge)
                r.fields(proof, ('signature',))
                r.require(isinstance(proof['signature'], str) and 0 < len(proof['signature']) <= 4096, 'bootstrap-proof')
                self.store.write(step+'.proof', proof)
                self.validate_enrollment(self.authority(path+'/proof', 'station', proof))
            elif step == 'install-credential':
                cert = current.get('certificate')
                r.require(isinstance(cert, str) and 0 < len(cert) < 65536, 'staged-certificate')
                self.device('install', cert)
            elif step == 'prove-installed':
                self.device('prove-installed', None)
            elif step == 'activate':
                self.validate_enrollment(self.authority(path+'/activate', 'operator', {}))
        return self.probe(step)

    def probe(self, step):
        r.require(step in STEPS, 'protocol-step')
        if step == 'initialize-device':
            return self.status()['phase'] == 'initialized'
        current = self.current()
        if current is None:
            return False
        expected = {'start-enrollment': 'awaiting_proof', 'submit-bootstrap': 'staged',
                    'install-credential': 'staged', 'prove-installed': 'verified',
                    'activate': 'active', 'verify-access': 'active'}[step]
        if current['state'] != expected:
            return False
        if step in ('install-credential', 'prove-installed'):
            return self.status()['phase'] == ('installed' if step == 'install-credential' else 'verified')
        if step == 'verify-access':
            own = self.device('self', None)
            return (own.get('authorized') == 'pilot' and own.get('instance_id') == current['id']
                    and own.get('binding') == current.get('binding')
                    and own.get('full_qualification') is False)
        return True
