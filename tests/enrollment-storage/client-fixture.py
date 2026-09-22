"""Disposable VM PKI only. The device client owns its private operational key."""
import base64
import datetime as dt
import json
import pathlib
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

client, volume = sys.argv[1:]
root = pathlib.Path('/var/lib/enrollment-fixture')
root.mkdir(mode=0o700)
now = dt.datetime.now(dt.timezone.utc)
issuer_key = ec.generate_private_key(ec.SECP256R1())
issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'disposable VM issuer')])
issuer = (x509.CertificateBuilder().subject_name(issuer_name).issuer_name(issuer_name)
          .public_key(issuer_key.public_key()).serial_number(1)
          .not_valid_before(now-dt.timedelta(hours=1)).not_valid_after(now+dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(issuer_key, hashes.SHA256()))
ca = issuer.public_bytes(serialization.Encoding.PEM).decode()
ref = {'record_id': 'synthetic-record', 'revision': 1, 'digest': 'sha256:'+'a'*64}
config = dict(schema_version='kaiba.device-enrollment-client/v1alpha1', mode='development',
              fleet_url='https://127.0.0.1:9', server_ca_pem=ca, issuer_ca_pem=ca,
              issuer_id='disposable-issuer', provisioning_ref=ref, restart_requirement='boot',
              authority_id='synthetic', transaction_id='candidate-1', target='synthetic-board',
              protected_volume_uuid=volume)
(root/'config.json').write_text(json.dumps(config))
state = '/run/kaiba-enrollment-storage/volume/credentials'

def invoke(action, path=None):
    args = [client, action, '--state', state]
    if path:
        args += ['--input', str(path)]
    return json.loads(subprocess.check_output(args))

status = invoke('initialize', root/'config.json')
challenge = dict(purpose='bootstrap', nonce='a'*48,
                 expires_at=(now+dt.timedelta(minutes=4)).isoformat().replace('+00:00', 'Z'),
                 audience='kaiba-fleet-rehearsal', enrollment_id='vm-enrollment',
                 logical_device_id='vm-device', instance_id='vm-enrollment', storage_generation=1,
                 slot='management', key_generation=1, spki_digest=status['spki_digest'],
                 certificate_profile='rehearsal-management-v1', provisioning_ref=ref)
(root/'challenge.json').write_text(json.dumps(challenge))
invoke('bootstrap', root/'challenge.json')
public = serialization.load_der_public_key(base64.b64decode(status['spki']))
leaf = (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(issuer_name)
        .public_key(public).serial_number(2)
        .not_valid_before(now-dt.timedelta(minutes=1)).not_valid_after(now+dt.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(
            'spiffe://kaiba.test/device/vm-device/instance/vm-enrollment')]), critical=False)
        .sign(issuer_key, hashes.SHA256()))
(root/'certificate.pem').write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
installed = invoke('install', root/'certificate.pem')
assert installed['phase'] == 'installed' and installed['spki'] == status['spki']
(root/'installed.json').write_text(json.dumps(installed))
# Neither the disposable CA key nor the client's operational key is exported.
