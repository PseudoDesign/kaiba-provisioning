"""One reviewed unused-grant transition on the existing Ubuntu pilot host.

The caller deploys/initializes the upgraded issuer and fresh record authorities
first. This hook never starts services, resets ledgers, retries apply, or changes
permissions on Fleet credentials. A failed partial run requires reconciliation.
"""
import base64
import json
import os
from pathlib import Path
import pwd
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runner as r

ROOT = Path('/srv/kaiba-pilot')
CONFIG = ROOT/'issuer/config.json'
FLEET_CERT = ROOT/'fleet/reader.crt'
FLEET_KEY = ROOT/'fleet/reader.key'
UNIT = Path('/etc/systemd/system/kaiba-pilot-issuer.service')
STOPPED = ('serving','fleet','issuer')
ACTIVE = ('postgres','observation','admission')
DSN = 'host=/run/kaiba-pilot-pg port=18445 dbname=kaiba_pilot_issuer user=kaiba-pilot-issuer sslmode=disable'
FIELDS = ('old_scope_digest','new_scope_digest','old_config_digest','new_config_digest')


def validate(plan):
    r.fields(plan, ('schema_version','run_id','boot_id','issued_at','expires_at','approval_digest',
                    'issuer','storage_guard','storage_guard_sha256','unit_sha256','old_config_sha256','replacement','replacement_sha256',
                    'old_scope_digest','fleet_certificate_sha256','target'))
    r.require(plan['schema_version']=='kaiba.pilot-issuer-refresh/v1alpha1' and
              r.LABEL.fullmatch(plan['run_id']), 'refresh-plan')
    start,end = r.timestamp(plan['issued_at']),r.timestamp(plan['expires_at'])
    r.require(0<end-start<=43200,'refresh-window')
    for name in ('storage_guard_sha256','unit_sha256','old_config_sha256','replacement_sha256','fleet_certificate_sha256','approval_digest'):
        r.require(isinstance(plan[name],str) and r.HEX.fullmatch(plan[name]),'refresh-digest')
    r.require(plan['old_scope_digest'].startswith('sha256:') and r.HEX.fullmatch(plan['old_scope_digest'][7:]),'refresh-scope')
    for name in ('issuer','replacement','storage_guard'):
        path=Path(plan[name]);r.require(path.is_absolute() and str(path).startswith('/nix/store/') and '..' not in path.parts,'refresh-immutable-input')
    r.require(plan['issuer'].endswith('/bin/kaiba-pilot-issuer') and isinstance(plan['target'],dict),'refresh-input')


def difference(old, new, target):
    """Reject any change beyond this target's three references/selections."""
    r.require(len(old['grants'])==len(new['grants'])==2,'refresh-grant-count')
    matches=[i for i,g in enumerate(old['grants']) if g['binding']['target']==target]
    r.require(len(matches)==1,'refresh-target')
    i=matches[0];restored=r.decode(r.canonical(new));after=restored['grants'][i]
    before=old['grants'][i]
    r.require(after!=before,'refresh-no-change')
    for name in ('adoption_ref','policy_ref','admission_ref'):
        after['binding'][name]=before['binding'][name]
    after['records']=before['records']
    r.require(restored==old,'refresh-peer-or-lifecycle-change')


def collect(process, timeout):
    """Bound both output streams; discard stderr rather than logging secrets."""
    out=bytearray();counts={};selector=selectors.DefaultSelector();deadline=time.monotonic()+timeout
    try:
        for stream in (process.stdout,process.stderr):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ);counts[stream]=0
        while selector.get_map():
            remaining=deadline-time.monotonic();r.require(remaining>0,'refresh-command-timeout')
            events=selector.select(remaining);r.require(events,'refresh-command-timeout')
            for key,_ in events:
                data=os.read(key.fd,4096)
                if not data:selector.unregister(key.fileobj);continue
                counts[key.fileobj]+=len(data);r.require(counts[key.fileobj]<=1024*1024,'refresh-command-output')
                if key.fileobj is process.stdout:out.extend(data)
        r.require(process.wait(timeout=max(.001,deadline-time.monotonic()))==0,'refresh-command-failed')
        return bytes(out)
    finally:
        selector.close()
        if process.poll() is None:process.kill()
        process.wait();process.stdout.close();process.stderr.close()


class Refresh:
    def __init__(self, plan):
        validate(plan);self.plan=r.decode(r.canonical(plan))
        self.state=ROOT/('issuer-refresh-'+plan['run_id'])
        self.inputs=ROOT/'issuer'/('refresh-'+plan['run_id'])
        self.account=pwd.getpwnam('kaiba-pilot-issuer')
        self.fleet=pwd.getpwnam('kaiba-pilot-fleet')

    def call(self, argv):
        process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                 env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},close_fds=True)
        return collect(process,30)

    def guard(self, writers_stopped=True):
        r.require(os.geteuid()==0 and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==self.plan['boot_id'],'refresh-host')
        r.require(r.timestamp(self.plan['issued_at'])<=time.time()<r.timestamp(self.plan['expires_at']),'refresh-expired')
        r.require(len(Path('/proc/swaps').read_text().splitlines())==1,'refresh-swap')
        storage=r.read_file(self.plan['storage_guard'],owner=0)
        r.require(r.sha(storage)==self.plan['storage_guard_sha256'],'refresh-storage-guard-changed')
        self.call(['/usr/bin/python3','-I','-B',self.plan['storage_guard']])
        raw=r.read_file(UNIT,owner=0)
        r.require(r.sha(raw)==self.plan['unit_sha256'] and
                  ('ExecStart='+self.plan['issuer']+' ').encode() in raw,'refresh-writer-unit')
        states=([(x,'inactive') for x in STOPPED]+[(x,'active') for x in ACTIVE]) if writers_stopped else [('postgres','active')]
        for name,wanted in states:
            actual=self.call(['/usr/bin/systemctl','show','kaiba-pilot-'+name+'.service','--property=ActiveState','--value'])
            r.require(actual.strip()==wanted.encode(),'refresh-service-state')
        # Also bind systemd's loaded executable, not just the file awaiting reload.
        command=self.call(['/usr/bin/systemctl','show','kaiba-pilot-issuer.service','--property=ExecStart','--value'])
        r.require(('path='+self.plan['issuer']+' ;').encode() in command,'refresh-loaded-writer')
        pid=self.call(['/usr/bin/systemctl','show','kaiba-pilot-issuer.service','--property=MainPID','--value']).strip()
        r.require(pid.isdigit(),'refresh-writer-pid')
        if pid!=b'0':
            r.require(Path('/proc/'+pid.decode()+'/exe').resolve(strict=True)==Path(self.plan['issuer']).resolve(strict=True),'refresh-running-writer')

    def configuration(self, expected):
        raw=r.read_file(CONFIG,owner=self.account.pw_uid,mode=0o600)
        r.require(r.sha(raw)==expected,'refresh-configuration-changed')
        return raw

    def public_identity(self):
        raw=r.read_file(FLEET_CERT,owner=self.fleet.pw_uid)
        r.require(r.sha(raw)==self.plan['fleet_certificate_sha256'],'refresh-fleet-identity-changed')
        info=FLEET_KEY.lstat()
        r.require(stat.S_ISREG(info.st_mode) and info.st_uid==self.fleet.pw_uid and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'refresh-fleet-key-metadata')
        return raw

    def write(self, path, raw, readable=False):
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o440 if readable else 0o600)
        with os.fdopen(fd,'wb') as out:
            os.fchown(out.fileno(),0,self.account.pw_gid if readable else 0)
            os.fchmod(out.fileno(),0o440 if readable else 0o600)
            out.write(raw);out.flush();os.fsync(out.fileno())
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)

    def admin(self, mode, request):
        r.require(mode in ('plan','apply','inspect'),'refresh-mode')
        self.guard(writers_stopped=mode!='inspect')
        argv=[self.plan['issuer'],'--config',str(CONFIG),'--replacement-config',self.plan['replacement'],
              '--refresh-request',str(request),'--grant-refresh',mode]
        rd=wr=None;feeder=None
        try:
            if mode=='apply':
                self.public_identity()
                rd,wr=os.pipe()
                feeder=os.fork()
                if feeder==0:
                    try:
                        os.close(rd);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
                        cert=self.public_identity()
                        key=r.read_file(FLEET_KEY,maximum=16384,owner=self.fleet.pw_uid,mode=0o600)
                        payload=r.canonical({'certificate_pem':base64.b64encode(cert).decode(),
                                             'private_key_pem':base64.b64encode(key).decode()})
                        r.require(len(payload)<=65536,'refresh-identity-size')
                        while payload:
                            n=os.write(wr,payload);payload=payload[n:]
                        os.close(wr);os._exit(0)
                    except BaseException:os._exit(1)  # never print private inputs/errors
                os.close(wr);wr=None
                argv+=['--fleet-reader-identity-fd',str(rd),'--fleet-reader-certificate-digest','sha256:'+self.plan['fleet_certificate_sha256']]
            process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                user=self.account.pw_uid,group=self.account.pw_gid,extra_groups=[],close_fds=True,
                pass_fds=() if rd is None else (rd,),
                env={'PATH':'/usr/bin:/bin','LC_ALL':'C','KAIBA_ISSUER_DATABASE_URL':DSN})
            if rd is not None:os.close(rd);rd=None
            value=r.decode(collect(process,min(65,r.timestamp(self.plan['expires_at'])-time.time())))
            if feeder is not None:
                _,status=os.waitpid(feeder,0);feeder=None;r.require(status==0,'refresh-identity-feed-failed')
            return value
        finally:
            for fd in (rd,wr):
                if fd is not None:os.close(fd)
            if feeder is not None:
                try:os.kill(feeder,signal.SIGKILL)
                except ProcessLookupError:pass
                os.waitpid(feeder,0)

    def expected(self, prepared, status):
        value={k:prepared[k] for k in FIELDS};value['status']=status
        value['operation_id']=self.plan['run_id'] if status=='committed' else ''
        return value

    def parents(self):
        root=ROOT.lstat();parent=self.inputs.parent.lstat()
        r.require(stat.S_ISDIR(root.st_mode) and root.st_uid==0 and not root.st_mode&0o022 and
                  stat.S_ISDIR(parent.st_mode) and parent.st_uid==self.account.pw_uid and
                  parent.st_dev==root.st_dev and not parent.st_mode&0o022,'refresh-parent')

    def execute(self):
        self.guard();os.umask(0o077)
        old=self.configuration(self.plan['old_config_sha256'])
        new=r.read_file(self.plan['replacement'],owner=0)
        r.require(r.sha(new)==self.plan['replacement_sha256'],'refresh-replacement-changed')
        before,after=r.decode(old),r.decode(new);difference(before,after,self.plan['target'])
        self.public_identity()
        self.parents()
        r.require(not os.path.lexists(self.state) and not os.path.lexists(self.inputs),'refresh-already-attempted')
        self.state.mkdir(mode=0o700);self.write(self.state/'plan.json',r.canonical(self.plan))
        self.write(self.state/'before.json',old);self.write(self.state/'after.json',new)
        self.inputs.mkdir(mode=0o750);os.chown(self.inputs,0,self.account.pw_gid);self.inputs.chmod(0o750)
        reader=r.decode(r.canonical(after['reader']))
        reader['client_cert']=str(FLEET_CERT);reader['client_key']=str(FLEET_KEY)
        request={'operation_id':self.plan['run_id'],'target':self.plan['target'],
                 'approval_digest':'sha256:'+self.plan['approval_digest'],
                 'issued_at':self.plan['issued_at'],'expires_at':self.plan['expires_at'],'fleet_reader':reader}
        self.write(self.inputs/'planning.json',r.canonical(request),True)
        prepared=self.admin('plan',self.inputs/'planning.json')
        r.require(all(isinstance(prepared.get(k),str) and prepared[k].startswith('sha256:') and
                      r.HEX.fullmatch(prepared[k][7:]) for k in FIELDS),'refresh-plan-digest')
        # Use the real issuer's typed canonicalization/scope calculation. Raw
        # input hashes above bind the reviewed bytes, including optional fields.
        r.require(prepared==self.expected(prepared,'prepared') and prepared['old_scope_digest']==self.plan['old_scope_digest'] and
                  prepared['new_scope_digest']!=prepared['old_scope_digest'] and
                  prepared['old_config_digest']!=prepared['new_config_digest'],'refresh-plan-mismatch')
        request.update({k:prepared[k] for k in FIELDS})
        self.write(self.state/'prepared.json',r.canonical(prepared))
        self.write(self.inputs/'request.json',r.canonical(request),True)
        self.write(self.state/'apply.intent.json',r.canonical({'request_sha256':r.sha(r.canonical(request))}))
        committed=self.admin('apply',self.inputs/'request.json')
        r.require(committed==self.expected(prepared,'committed'),'refresh-commit-mismatch')
        r.require(self.admin('inspect',self.inputs/'request.json')==committed,'refresh-audit-mismatch')
        self.configuration(self.plan['old_config_sha256'])
        self.write(self.state/'commit.json',r.canonical(committed))
        # No automatic restore of old config or ledger after this point.
        pending=CONFIG.with_name('config.'+self.plan['run_id']+'.new')
        self.write(self.state/'install.intent.json',r.canonical({'sha256':r.sha(new)}))
        self.write(pending,new);os.chown(pending,self.account.pw_uid,self.account.pw_gid)
        os.replace(pending,CONFIG)
        fd=os.open(CONFIG.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
        r.require(self.probe(),'refresh-postcondition-failed')
        self.write(self.state/'result.json',r.canonical({'status':'passed','certificate_issued':False,'services_started':False}))

    def probe(self):
        self.guard(writers_stopped=False)
        r.require(r.decode(r.read_file(self.state/'plan.json',owner=0,mode=0o600))==self.plan,'refresh-journal-plan')
        prepared=r.decode(r.read_file(self.state/'prepared.json',owner=0,mode=0o600))
        request=r.decode(r.read_file(self.inputs/'request.json',owner=0,mode=0o440))
        intent=r.decode(r.read_file(self.state/'apply.intent.json',owner=0,mode=0o600))
        r.require(intent=={'request_sha256':r.sha(r.canonical(request))},'refresh-request-changed')
        r.require(all(request[k]==prepared[k] for k in FIELDS),'refresh-prepared-binding')
        self.configuration(self.plan['replacement_sha256'])
        return self.admin('inspect',self.inputs/'request.json')==self.expected(prepared,'committed')
