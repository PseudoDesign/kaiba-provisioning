"""One authenticated, bounded SSH invocation of the packaged device hook.

The owner packet supplies exact public plan, interpreter and known-hosts bytes.
No SSH configuration, agent, password prompt, forwarding, persistent remote
helper installation or automatic retry is used. Private keys remain SSH inputs.
"""
import base64
import os
from pathlib import Path
import re
import selectors
import shlex
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runner as r

MAX_INPUT = 24*1024*1024
MAX_OUTPUT = 1024*1024
# This constant is the only remote shell command body. The module/plan/request
# bundle travels on stdin, not through shell interpolation or a remote tempfile.
BOOTSTRAP = '''import base64,hashlib,json,sys,types
raw=sys.stdin.buffer.read(25165825)
if len(raw)>25165824: raise RuntimeError('oversize bundle')
q=json.loads(raw)
if set(q)!={'schema','nonce','plan','modules','action','input'} or q['schema']!='kaiba.pilot-ssh/v1alpha1': raise RuntimeError('bundle schema')
names=('runner','device','peer') if 'peer' in q['modules'] else ('runner','device')
if set(q['modules'])!=set(names): raise RuntimeError('module scope')
for name in names:
    source=base64.b64decode(q['modules'][name],validate=True)
    module=types.ModuleType(name);module.__file__='/nonexistent/kaiba-reviewed/'+name+'.py'
    sys.modules[name]=module;exec(compile(source,module.__file__,'exec'),module.__dict__)
r=sys.modules['runner'];d=sys.modules['device']
import os,resource
os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
if 'peer' in q['modules']:
    value=sys.modules['peer'].dispatch(q['plan'],{'action':q['action'],'input':q['input']})
elif q['action']=='observe':
    r.require(q['input'] is None,'unexpected observation input')
    d.host_guard(q['plan']);value={'status':'observed','device_mutated':False}
else:
    value=d.dispatch(q['plan'],{'action':q['action'],'input':q['input']})
print(json.dumps({'schema':q['schema'],'request_sha256':hashlib.sha256(raw).hexdigest(),'value':value}))
'''


def exchange(argv, payload, timeout):
    """Concurrently drain bounded output and send the binary-sized public bundle."""
    r.require(0 < len(payload) <= MAX_INPUT and 0 < timeout <= 120, 'ssh-bounds')
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, close_fds=True,
                               env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    selector = selectors.DefaultSelector()
    sent = 0; output = bytearray(); deadline = time.monotonic()+timeout
    try:
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE)
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline-time.monotonic()
            r.require(remaining > 0, 'ssh-timeout')
            events = selector.select(remaining)
            r.require(bool(events), 'ssh-timeout')
            for key, _ in events:
                if key.fileobj is process.stdin:
                    count = os.write(process.stdin.fileno(), payload[sent:sent+16384])
                    sent += count
                    if sent == len(payload):
                        selector.unregister(process.stdin); process.stdin.close()
                else:
                    chunk = os.read(process.stdout.fileno(), 4096)
                    if chunk:
                        output.extend(chunk)
                        r.require(len(output) <= MAX_OUTPUT, 'ssh-output-too-large')
                    else:
                        selector.unregister(process.stdout)
        r.require(process.wait(timeout=max(.001, deadline-time.monotonic())) == 0, 'ssh-command-failed')
        r.require(sent == len(payload), 'ssh-short-request')
        return bytes(output)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdin.close(); process.stdout.close()


class Device:
    """Construct only inside a reviewed immutable/root-controlled host adapter.

    The SSH identity is never read by this module. The packet chooses its owner,
    metadata and lifetime; only SSH loads it. Each call rechecks public inputs.
    """
    def __init__(self, config, plan):
        r.fields(config, ('ssh', 'host', 'port', 'user', 'identity', 'identity_uid',
                          'known_hosts', 'known_hosts_sha256', 'python', 'timeout_seconds'))
        r.require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}', config['host']), 'ssh-host')
        r.require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', config['user']), 'ssh-user')
        r.require(type(config['port']) is int and 1 <= config['port'] <= 65535, 'ssh-port')
        r.require(type(config['timeout_seconds']) is int and 1 <= config['timeout_seconds'] <= 120, 'ssh-timeout-config')
        r.require(type(config['identity_uid']) is int and config['identity_uid'] >= 0, 'ssh-identity-owner')
        for field in ('ssh', 'python'):
            r.require(isinstance(config[field], str) and re.fullmatch(r'/nix/store/[a-z0-9]{32}-[a-zA-Z0-9+._-]+/bin/(?:ssh|python3)', config[field]), 'ssh-executable-path')
        r.require(config['ssh'].endswith('/bin/ssh') and config['python'].endswith('/bin/python3'), 'ssh-executable-role')
        for field in ('identity', 'known_hosts'):
            r.require(isinstance(config[field], str) and config[field].startswith('/') and
                      not any(c.isspace() for c in config[field]), 'ssh-input-path')
        r.require(isinstance(config['known_hosts_sha256'], str) and r.HEX.fullmatch(config['known_hosts_sha256']), 'ssh-known-hosts-digest')
        self.config = dict(config)
        # Detach approved bytes from caller-owned mutable dictionaries.
        self.plan = r.decode(r.canonical(plan))
        import device
        device.validate(self.plan)
        self.window=self.plan
        source = Path(__file__).resolve().parent
        self.modules = {name: base64.b64encode((source/(name+'.py')).read_bytes()).decode()
                        for name in ('runner', 'device')}

    def argv(self):
        c = self.config
        identity = Path(c['identity']).lstat()
        r.require(stat.S_ISREG(identity.st_mode) and identity.st_nlink == 1 and
                  identity.st_uid == c['identity_uid'] and stat.S_IMODE(identity.st_mode) == 0o600, 'ssh-identity-metadata')
        if not c['known_hosts'].startswith('/nix/store/'):
            r.trusted_parent(Path(c['known_hosts']).parent, 0)
        known = r.read_file(c['known_hosts'], owner=0)
        r.require(r.sha(known) == c['known_hosts_sha256'], 'ssh-known-hosts-changed')
        # Copying/immutability of this public file is a host-packet precondition.
        # OpenSSH still authenticates the server on every invocation.
        options = {'BatchMode':'yes', 'IdentitiesOnly':'yes', 'IdentityAgent':'none',
                   'StrictHostKeyChecking':'yes', 'UserKnownHostsFile':c['known_hosts'],
                   'GlobalKnownHostsFile':'/dev/null', 'KnownHostsCommand':'none',
                   'UpdateHostKeys':'no', 'VerifyHostKeyDNS':'no', 'ForwardAgent':'no',
                   'ClearAllForwardings':'yes', 'ForwardX11':'no', 'PermitLocalCommand':'no',
                   'ProxyCommand':'none', 'ProxyJump':'none', 'ControlMaster':'no',
                   'ControlPath':'none', 'PasswordAuthentication':'no',
                   'KbdInteractiveAuthentication':'no', 'GSSAPIAuthentication':'no',
                   'HostbasedAuthentication':'no', 'AddKeysToAgent':'no',
                   'ConnectionAttempts':'1', 'ConnectTimeout':'10', 'EscapeChar':'none'}
        argv = [c['ssh'], '-F', '/dev/null', '-T', '-i', c['identity'], '-p', str(c['port'])]
        for name, value in options.items():
            argv += ['-o', name+'='+value]
        remote = shlex.join(['/run/wrappers/bin/sudo', '-n', c['python'], '-I', '-B', '-c', BOOTSTRAP])
        return [*argv, c['user']+'@'+c['host'], remote]

    def __call__(self, action, value=None):
        r.require(action in ('observe', 'prepare', 'probe-prepare', 'init', 'status',
                             'bootstrap', 'install', 'prove-installed', 'self', 'check-isolation'), 'ssh-action')
        if action in ('observe', 'probe-prepare', 'init', 'status', 'prove-installed', 'self'):
            r.require(value is None, 'ssh-input-scope')
        if action == 'check-isolation':
            r.require(isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}',value),'ssh-other-instance')
        return self.exchange(action,value)

    def exchange(self,action,value):
        payload = r.canonical({'schema':'kaiba.pilot-ssh/v1alpha1', 'nonce':os.urandom(16).hex(),
                               'plan':self.plan, 'modules':self.modules, 'action':action, 'input':value})
        timeout = min(self.config['timeout_seconds'], r.timestamp(self.window['expires_at'])-time.time())
        r.require(time.time() >= r.timestamp(self.window['issued_at']) and timeout > 0, 'ssh-plan-window')
        raw = exchange(self.argv(), payload, timeout)
        result = r.decode(raw)
        r.fields(result, ('schema', 'request_sha256', 'value'))
        r.require(result['schema'] == 'kaiba.pilot-ssh/v1alpha1' and
                  result['request_sha256'] == r.sha(payload) and isinstance(result['value'], dict), 'ssh-response-binding')
        return result['value']


class ExistingDevice(Device):
    """The same pinned SSH transport with an exclusively read-only dispatcher."""
    def __init__(self,config,plan):
        import peer
        peer.validate(plan)
        super().__init__(config,plan['host'])
        self.plan=r.decode(r.canonical(plan))
        self.modules['peer']=base64.b64encode((Path(__file__).resolve().parent/'peer.py').read_bytes()).decode()

    def __call__(self,action,value=None):
        r.require(action in ('status','self','check-isolation'),'ssh-peer-read-only')
        if action=='check-isolation':
            r.require(isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}',value),'ssh-other-instance')
        else:r.require(value is None,'ssh-input-scope')
        return self.exchange(action,value)
