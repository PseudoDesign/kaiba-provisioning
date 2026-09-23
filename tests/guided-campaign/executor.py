"""Nix-built, software-only packet wrapper for the native integration check.

Uses a disposable process-mode client state directory. No hardware access,
production authority or host service credentials are used by this fixture.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

request = json.load(sys.stdin)
assert request['schema_version'] == 'kaiba.station-campaign-execution/v1alpha1'
assert request['campaign_id'] == 'software-campaign'
assert request['step_id'] in ('inspect', 'create_identity', 'restart_client', 'verify_identity')
assert request['reconcile'] is False
root = pathlib.Path.cwd()
marker = root / ('called-' + request['step_id'])
# Fixture also refuses repeats independently of the campaign's journal.
with marker.open('x') as file:
    json.dump(request, file)

def client(action, with_config=False):
    args = ['@client@', action, '--state', str(root/'device-state')]
    if with_config:
        args += ['--input', str(root/'client-config.json')]
    completed = subprocess.run(args, check=True, capture_output=True, text=True, timeout=30)
    status = json.loads(completed.stdout)
    assert status['production_enrollment'] is False and status['hardware_qualified'] is False
    return status

if request['step_id'] == 'inspect':
    assert (root/'client-config.json').is_file()
elif request['step_id'] == 'create_identity':
    status = client('initialize', True)
    (root/'initial-public-status.json').write_text(json.dumps(status))
elif request['step_id'] == 'restart_client':
    assert request['input'] == 'ready'
    # A fresh CLI process is only a process-restart observation.
    assert client('status') == json.loads((root/'initial-public-status.json').read_text())
else:
    assert client('status') == json.loads((root/'initial-public-status.json').read_text())

print(json.dumps({
    'schema_version': request['schema_version'], 'campaign_id': request['campaign_id'],
    'step_id': request['step_id'], 'request_id': request['request_id'],
    'outcome': 'succeeded', 'result_code': 'passed',
    'diagnostic_references': ['sha256:'+hashlib.sha256(marker.read_bytes()).hexdigest()],
}))
