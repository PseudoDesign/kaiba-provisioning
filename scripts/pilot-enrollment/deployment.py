"""Prepare the existing Ubuntu pilot authority for one reviewed enrollment.

Fixed service order, immutable inputs, preserved preimages and one-use stages.
Failures leave services stopped through the outer runner's safe-stop hook; no
configuration/database rollback or automatic mutation replay is performed here.
"""
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
import runner as r
import issuer_refresh as refresh

ROOT=Path('/srv/kaiba-pilot')
UNITS=Path('/etc/systemd/system')
SERVICES=tuple('kaiba-pilot-'+x+'.service' for x in ('postgres','observation','admission','issuer','fleet'))
READERS=SERVICES[1:3]
SUPERVISOR='kaiba-pilot-serving.service'
OWNER={'observation':'kaiba-pilot-observe','admission':'kaiba-pilot-admit','fleet':'kaiba-pilot-fleet','issuer':'kaiba-pilot-issuer'}


def validate(plan):
    r.fields(plan,('schema_version','run_id','boot_id','issued_at','expires_at',
                  'storage_guard','storage_guard_sha256','controller','controller_sha256',
                  'issuer_before','issuer_after','issuer_unit_sha256','units','files','peer_id','refresh_plan'))
    r.require(plan['schema_version']=='kaiba.pilot-host-deployment/v1alpha1' and
              isinstance(plan['run_id'],str) and r.LABEL.fullmatch(plan['run_id']),'deployment-plan')
    r.require(0<r.timestamp(plan['expires_at'])-r.timestamp(plan['issued_at'])<=43200,'deployment-window')
    for name in ('storage_guard','controller','issuer_before','issuer_after'):
        path=Path(plan[name]);r.require(str(path).startswith('/nix/store/') and '..' not in path.parts,'deployment-immutable-tool')
    for name in ('storage_guard_sha256','controller_sha256','issuer_unit_sha256'):
        r.require(isinstance(plan[name],str) and r.HEX.fullmatch(plan[name]),'deployment-digest')
    r.require(isinstance(plan['units'],dict) and set(plan['units'])=={SUPERVISOR,*SERVICES} and all(isinstance(v,str) and r.HEX.fullmatch(v) for v in plan['units'].values()) and plan['units']['kaiba-pilot-issuer.service']==plan['issuer_unit_sha256'],'deployment-unit-pins')
    r.require(plan['issuer_before']!=plan['issuer_after'] and all(plan[x].endswith('/bin/kaiba-pilot-issuer') for x in ('issuer_before','issuer_after')),'deployment-upgrade')
    r.require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',plan['peer_id']),'deployment-peer')
    refresh.validate(plan['refresh_plan']);q=plan['refresh_plan']
    r.require(q['run_id']==plan['run_id'] and q['boot_id']==plan['boot_id'] and
              q['issued_at']==plan['issued_at'] and q['expires_at']==plan['expires_at'] and
              q['issuer']==plan['issuer_after'] and q['storage_guard']==plan['storage_guard'] and
              q['storage_guard_sha256']==plan['storage_guard_sha256'],'deployment-refresh-binding')
    r.require(isinstance(plan['files'],list) and 2<=len(plan['files'])<=128,'deployment-files')
    seen=set()
    for item in plan['files']:
        r.fields(item,('target','source','before_sha256','after_sha256'))
        target=item['target']
        r.require(isinstance(target,str) and re.fullmatch(r'(?:observation|admission)/(?:config\.json|(?:records|evidence)/[A-Za-z0-9._-]+\.json)',target),'deployment-target')
        r.require(target not in seen and '..' not in Path(target).parts,'deployment-duplicate-target');seen.add(target)
        r.require(str(item['source']).startswith('/nix/store/') and '..' not in Path(item['source']).parts,'deployment-source')
        for name in ('before_sha256','after_sha256'):
            r.require((name=='before_sha256' and item[name] is None) or isinstance(item[name],str) and r.HEX.fullmatch(item[name]),'deployment-file-digest')
    r.require({'observation/config.json','admission/config.json'}<=seen,'deployment-reader-configs')


class Deployment:
    """authority is the reviewed HTTPS/mTLS read client, used only for peer GET.

    The outer adapter binds its CA, endpoint and operator identity. No device
    callback is accepted here; authority preparation cannot create a device key.
    """
    def __init__(self,plan,authority):
        validate(plan);self.plan=r.decode(r.canonical(plan));self.authority=authority
        self.cleaning=False
        self.state=ROOT/('deployment-'+plan['run_id'])
        self.upgrade=UNITS/'kaiba-pilot-issuer.service'
        self.refresher=refresh.Refresh(plan['refresh_plan'])

    def call(self,argv,timeout=120):
        process=subprocess.Popen(list(map(str,argv)),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                 close_fds=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        return refresh.collect(process,min(timeout,max(.001,r.timestamp(self.plan['expires_at'])+(60 if self.cleaning else 0)-time.time())))

    def guard(self,cleanup=False):
        r.require(os.geteuid()==0 and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==self.plan['boot_id'],'deployment-host')
        start,end=r.timestamp(self.plan['issued_at']),r.timestamp(self.plan['expires_at'])
        r.require(start<=time.time()<end+(60 if cleanup else 0),'deployment-expired')
        if not cleanup:r.require(len(Path('/proc/swaps').read_text().splitlines())==1,'deployment-swap')
        for path,digest in ((self.plan['storage_guard'],self.plan['storage_guard_sha256']),
                            (self.plan['controller'],self.plan['controller_sha256'])):
            r.require(r.sha(r.read_file(path,owner=0))==digest,'deployment-tool-changed')
        if not cleanup:self.call(['/usr/bin/python3','-I','-B',self.plan['storage_guard']])

    def state_of(self,unit):
        if unit in self.plan['units']:
            digest=r.sha(r.read_file(UNITS/unit,owner=0))
            allowed={self.plan['units'][unit]}
            if unit=='kaiba-pilot-issuer.service':allowed.add(self.plan['refresh_plan']['unit_sha256'])
            r.require(digest in allowed,'deployment-unit-bytes')
        raw=self.call(['/usr/bin/systemctl','show',unit,'--property=Id,LoadState,ActiveState,FragmentPath,DropInPaths,NeedDaemonReload,UnitFileState,MainPID'])
        fields=dict(line.split('=',1) for line in raw.decode().splitlines() if '=' in line)
        r.require(fields.get('Id')==unit and fields.get('LoadState')=='loaded' and
                  fields.get('FragmentPath')==str(UNITS/unit) and not fields.get('DropInPaths') and
                  fields.get('NeedDaemonReload')=='no' and fields.get('UnitFileState') in ('static','disabled'),'deployment-unit-state')
        return fields

    def states(self,units,wanted):
        for unit in units:r.require(self.state_of(unit)['ActiveState']==wanted,'deployment-service-state')

    def listener_ready(self,unit,port,binary=None):
        # Type=simple active can precede migrations or a startup error.
        deadline=min(time.monotonic()+30,time.monotonic()+r.timestamp(self.plan['expires_at'])-time.time())
        while True:
            s=self.state_of(unit);pid=s.get('MainPID','0')
            r.require(s['ActiveState'] in ('active','activating'),'deployment-listener-start-failed')
            if pid.isdigit() and pid!='0':
                if binary is not None:r.require(Path('/proc/'+pid+'/exe').resolve(strict=True)==Path(binary).resolve(strict=True),'deployment-issuer-executable')
                sockets=self.call(['/usr/bin/ss','-H','-lntp','sport = :'+str(port)]).decode().splitlines()
                if len(sockets)==1 and len(sockets[0].split())>=5 and sockets[0].split()[3]=='127.0.0.1:'+str(port) and ('pid='+pid+',') in sockets[0]:return
            r.require(time.monotonic()<deadline,'deployment-listener-not-ready');time.sleep(.1)

    def issuer_ready(self,binary):self.listener_ready('kaiba-pilot-issuer.service',18443,binary)

    def readers_ready(self):
        self.listener_ready('kaiba-pilot-observation.service',18441)
        self.listener_ready('kaiba-pilot-admission.service',18442)

    def stop_children(self):
        self.call(['/usr/bin/systemctl','stop',*SERVICES[1:]])
        self.call(['/usr/bin/systemctl','stop',SERVICES[0]])

    def write(self,path,raw,uid=0,gid=0,mode=0o600):
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
        with os.fdopen(fd,'wb') as out:
            os.fchown(out.fileno(),uid,gid);os.fchmod(out.fileno(),mode)
            out.write(raw);out.flush();os.fsync(out.fileno())
        self.sync(path.parent)

    def sync(self,parent):
        fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)

    def stage(self,name,operation):
        self.guard();self.write(self.state/(name+'.intent.json'),r.canonical({'stage':name}))
        operation();self.write(self.state/(name+'.complete.json'),r.canonical({'stage':name,'status':'complete'}))

    def peer(self):
        value=self.authority('/api/v1/pilot/enrollments/'+self.plan['peer_id'])
        r.require(value.get('id')==self.plan['peer_id'] and value.get('state')=='active' and
                  value.get('binding',{}).get('full_qualification') is False,'deployment-peer-not-active')
        return value

    def metadata(self,item):
        path=ROOT/item['target'];owner=pwd.getpwnam(OWNER[item['target'].split('/')[0]])
        parent=path.parent
        while parent!=ROOT:
            st=parent.lstat();r.require(stat.S_ISDIR(st.st_mode) and st.st_uid in (0,owner.pw_uid) and not st.st_mode&0o022 and st.st_dev==ROOT.stat().st_dev,'deployment-target-parent');parent=parent.parent
        return path,owner

    def check_file(self,item,after=False):
        path,owner=self.metadata(item);expected=item['after_sha256'] if after else item['before_sha256']
        if expected is None:r.require(not os.path.lexists(path),'deployment-new-file-exists');return None
        raw=r.read_file(path,maximum=4*1024*1024,owner=owner.pw_uid,mode=0o600)
        r.require(r.sha(raw)==expected,'deployment-file-changed');return raw

    def replace(self,path,data,uid=0,gid=0,mode=0o600):
        temporary=path.with_name(path.name+'.'+self.plan['run_id']+'.new')
        self.write(temporary,data,uid,gid,mode);os.replace(temporary,path);self.sync(path.parent)

    def install_records(self):
        self.states(SERVICES,'inactive')
        for i,item in enumerate(self.plan['files']):
            self.check_file(item)
            raw=r.read_file(item['source'],maximum=4*1024*1024,owner=0)
            r.require(r.sha(raw)==item['after_sha256'],'deployment-source-changed')
            path,owner=self.metadata(item)
            self.stage('file-'+str(i),lambda:self.replace(path,raw,owner.pw_uid,owner.pw_gid))
            self.check_file(item,after=True)

    def protected_root(self):
        root=ROOT.lstat();r.require(stat.S_ISDIR(root.st_mode) and root.st_uid==0 and not root.st_mode&0o022,'deployment-root')

    def execute(self):
        self.guard();os.umask(0o077)
        r.require(not os.path.lexists(self.state),'deployment-already-attempted')
        self.protected_root()
        self.states((SUPERVISOR,*SERVICES),'active')
        unit=r.read_file(self.upgrade,owner=0)
        r.require(r.sha(unit)==self.plan['issuer_unit_sha256'],'deployment-unit-changed')
        old=('ExecStart='+self.plan['issuer_before']+' ').encode();new=('ExecStart='+self.plan['issuer_after']+' ').encode()
        r.require(unit.count(old)==1,'deployment-upgrade-scope');replacement=unit.replace(old,new,1)
        r.require(r.sha(replacement)==self.plan['refresh_plan']['unit_sha256'],'deployment-upgrade-hash')
        self.refresher.configuration(self.plan['refresh_plan']['old_config_sha256'])
        for item in self.plan['files']:self.check_file(item)
        peer=self.peer();self.state.mkdir(mode=0o700)
        self.write(self.state/'plan.json',r.canonical(self.plan));self.write(self.state/'peer.json',r.canonical(peer))
        self.write(self.state/'issuer-unit.before',unit);self.write(self.state/'issuer-unit.after',replacement)
        for i,item in enumerate(self.plan['files']):
            raw=self.check_file(item)
            if raw is not None:self.write(self.state/('file-'+str(i)+'.before'),raw)
            candidate=r.read_file(item['source'],maximum=4*1024*1024,owner=0)
            r.require(r.sha(candidate)==item['after_sha256'],'deployment-candidate-changed')
            self.write(self.state/('file-'+str(i)+'.after'),candidate)
        self.stage('stop-serving',lambda:self.call([self.plan['controller'],'stop']))
        self.states((SUPERVISOR,*SERVICES),'inactive')
        mode=stat.S_IMODE(self.upgrade.lstat().st_mode)
        self.stage('upgrade-unit',lambda:self.replace(self.upgrade,replacement,mode=mode))
        self.stage('reload',lambda:self.call(['/usr/bin/systemctl','daemon-reload']))
        # Initialize additive scope tables with the unchanged issuer config.
        self.stage('start-old-scope',lambda:self.call(['/usr/bin/systemctl','start',*SERVICES[:-1]]))
        self.issuer_ready(self.plan['issuer_after'])
        self.refresher.configuration(self.plan['refresh_plan']['old_config_sha256'])
        self.stage('stop-old-scope',self.stop_children)
        self.install_records()
        self.stage('start-readers',lambda:self.call(['/usr/bin/systemctl','start',*SERVICES[:3]]))
        self.readers_ready()
        self.stage('refresh-grant',self.refresher.execute)
        self.stage('start-authority',lambda:self.call(['/usr/bin/systemctl','start',*SERVICES[3:]]))
        self.issuer_ready(self.plan['issuer_after'])
        r.require(self.probe(),'deployment-postcondition')
        self.write(self.state/'result.json',r.canonical({'status':'passed','device_contacted':False,'certificate_issued':False,'backup_required':True,'supervisor':'stopped'}))

    def probe(self):
        self.guard()
        r.require(r.decode(r.read_file(self.state/'plan.json',owner=0,mode=0o600))==self.plan,'deployment-journal-binding')
        self.states(SERVICES,'active');self.states((SUPERVISOR,),'inactive')
        self.issuer_ready(self.plan['issuer_after'])
        for item in self.plan['files']:self.check_file(item,after=True)
        r.require(self.refresher.probe(),'deployment-refresh-unconfirmed')
        before=r.decode(r.read_file(self.state/'peer.json',owner=0,mode=0o600))
        r.require(self.peer()==before,'deployment-peer-changed')
        return True

    def safe_stop(self):
        # Read-only preflight failures must not call this; the outer runner only
        # invokes cleanup after a deployment mutation was attempted.
        self.cleaning=True
        try:
            self.guard(cleanup=True)
            self.call([self.plan['controller'],'stop'])
            self.states((SUPERVISOR,*SERVICES),'inactive')
        finally:self.cleaning=False
