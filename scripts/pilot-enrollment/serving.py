"""Guarded two-device serving handoff after one reviewed enrollment and backup.

The immutable owner packet supplies policy, controller config and backup template.
No deadline extension, boot enablement, new credential or automatic replay.
"""
import argparse
import datetime as dt
import ipaddress
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
import runner as r
import deployment as d
import backup as b

ROOT=Path('/srv/kaiba-pilot')
CONFIG=Path('/etc/kaiba-pilot/serving.json')
JOURNALS=Path('/var/lib')
PRESERVED=('policy.json','baseline.json','config.json','config.before')
OWNERS=('root','kaiba-pilot-observe','kaiba-pilot-admit','kaiba-pilot-fleet','kaiba-pilot-issuer','kaiba-pilot-pg')


def trusted_role_parent(path,uid):
    current=Path(path)
    while True:
        st=current.lstat()
        r.require(stat.S_ISDIR(st.st_mode) and st.st_uid in (0,uid) and not st.st_mode&0o022,'serving-untrusted-parent')
        if current.parent==current:return
        current=current.parent


def lines(raw):return [' '.join(s.split()) for s in raw.splitlines() if s.strip()]


def validate(policy):
    r.fields(policy,('schema_version','run_id','boot_id','issued_at','not_after','storage_guard','storage_guard_sha256',
                     'predecessor_config_sha256','units','files','private_metadata','firewall_before','target_rule','backup_template'))
    r.require(policy['schema_version']=='kaiba.pilot-serving-handoff/v1alpha1' and
              isinstance(policy['run_id'],str) and r.LABEL.fullmatch(policy['run_id']),'serving-policy')
    r.require(0<r.timestamp(policy['not_after'])-r.timestamp(policy['issued_at'])<=7*86400,'serving-window')
    r.require(str(policy['storage_guard']).startswith('/nix/store/') and '..' not in Path(policy['storage_guard']).parts and
              isinstance(policy['storage_guard_sha256'],str) and r.HEX.fullmatch(policy['storage_guard_sha256']),'serving-storage-guard')
    r.require(isinstance(policy['predecessor_config_sha256'],str) and r.HEX.fullmatch(policy['predecessor_config_sha256']),'serving-predecessor-digest')
    r.fields(policy['units'],(*d.SERVICES,d.SUPERVISOR))
    for digest in policy['units'].values():r.require(isinstance(digest,str) and r.HEX.fullmatch(digest),'serving-unit-digest')
    r.require(isinstance(policy['files'],dict) and 1<=len(policy['files'])<=256,'serving-files')
    for path,item in policy['files'].items():
        r.fields(item,('sha256','owner','mode'))
        r.require(path.startswith(str(ROOT)+'/') and '..' not in Path(path).parts and
                  (path.endswith(('.json','.crt')) or path.endswith('/client-ca.pem')) and item['owner'] in OWNERS and
                  item['mode'] in (0o600,0o640,0o644,0o440,0o444) and
                  isinstance(item['sha256'],str) and r.HEX.fullmatch(item['sha256']),'serving-public-file')
    required={str(ROOT/x) for x in ('pki/transport.crt','pki/management.crt','issuer/ca.crt','management/operator.crt','management/station.crt')}
    for role in ('observation','admission','fleet','issuer'):
        required.update(str(ROOT/role/name) for name in ('config.json','tls.crt'))
        if role in ('fleet','issuer'):required.add(str(ROOT/role/'reader.crt'))
    r.require(required<=set(policy['files']),'serving-missing-pins')
    r.require(isinstance(policy['private_metadata'],dict),'serving-key-metadata')
    required_keys={str(ROOT/role/(name+'.key')):owner for role,owner in
                   (('observation','kaiba-pilot-observe'),('admission','kaiba-pilot-admit'),('fleet','kaiba-pilot-fleet'),('issuer','kaiba-pilot-issuer'),('management','root'))
                   for name in (('operator','station') if role=='management' else ('tls','reader') if role in ('fleet','issuer') else ('tls',))}
    required_keys[str(ROOT/'issuer/ca.key')]='kaiba-pilot-issuer'
    r.require(all(policy['private_metadata'].get(path)==owner for path,owner in required_keys.items()),'serving-missing-private-metadata')
    r.require(isinstance(policy['private_metadata'],dict) and policy['private_metadata'],'serving-key-metadata')
    for path,owner in policy['private_metadata'].items():
        r.require(path.startswith(str(ROOT)+'/') and '..' not in Path(path).parts and path.endswith('.key') and owner in OWNERS,'serving-private-path')
    rule=policy['target_rule'];r.fields(rule,('interface','source','destination','comment'))
    r.require(re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}',rule['interface']) and re.fullmatch(r'kaiba-[a-z0-9-]{1,60}',rule['comment']),'serving-firewall-label')
    for field in ('source','destination'):
        addr=ipaddress.ip_address(rule[field]);r.require(addr.version==4 and not addr.is_unspecified and not addr.is_multicast,'serving-firewall-address')
    r.require(isinstance(policy['firewall_before'],str) and 'Status: active' in lines(policy['firewall_before']),'serving-firewall-baseline')
    b.validate(policy['backup_template'])
    r.require(not any(path.startswith('serving-'+policy['run_id']+'/') for path in policy['backup_template']['preserved_files']),'serving-reserved-backup-path')
    r.require(policy['backup_template']['run_id']==policy['run_id'] and
              policy['backup_template']['boot_id']==policy['boot_id'],'serving-backup-binding')


def rule_args(policy):
    q=policy['target_rule']
    return ['allow','in','on',q['interface'],'proto','tcp','from',q['source'],'to',q['destination'],
            'port','18444','comment',q['comment']]


def rule_line(policy):
    q=policy['target_rule']
    return q['destination']+' 18444/tcp on '+q['interface']+' ALLOW IN '+q['source']+' # '+q['comment']


def firewall(policy,raw,added):
    actual=lines(raw);expected=lines(policy['firewall_before']);rule=rule_line(policy)
    r.require(rule not in expected,'serving-rule-preexisting')
    if added:
        r.require(actual.count(rule)==1,'serving-rule-missing');actual.remove(rule)
    r.require(actual==expected,'serving-firewall-drift')


class Guard:
    def __init__(self,policy):
        validate(policy);self.policy=r.decode(r.canonical(policy))
        self.state=ROOT/('serving-'+policy['run_id'])

    def call(self,args):
        import subprocess
        p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           env={'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'},close_fds=True)
        return d.refresh.collect(p,30)

    def base(self,network=True):
        p=self.policy
        r.require(os.geteuid()==0 and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==p['boot_id'],'serving-host')
        r.require(r.timestamp(p['issued_at'])<=time.time()<r.timestamp(p['not_after']),'serving-expired')
        r.require(len(Path('/proc/swaps').read_text().splitlines())==1,'serving-swap')
        r.require(r.sha(r.read_file(p['storage_guard'],owner=0))==p['storage_guard_sha256'],'serving-storage-guard-changed')
        self.call(['/usr/bin/python3','-I','-B',p['storage_guard']])
        for unit,digest in p['units'].items():
            r.require(r.sha(r.read_file(d.UNITS/unit,owner=0))==digest,'serving-unit-changed')
        for path,item in p['files'].items():
            trusted_role_parent(Path(path).parent,pwd.getpwnam(item['owner']).pw_uid)
            raw=r.read_file(path,owner=pwd.getpwnam(item['owner']).pw_uid,mode=item['mode'],maximum=4*1024*1024)
            r.require(r.sha(raw)==item['sha256'],'serving-input-changed')
        for path,owner in p['private_metadata'].items():
            trusted_role_parent(Path(path).parent,pwd.getpwnam(owner).pw_uid)
            info=Path(path).lstat()
            r.require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==pwd.getpwnam(owner).pw_uid and
                      stat.S_IMODE(info.st_mode)==0o600,'serving-private-metadata')
        self.trust()
        if network:firewall(p,self.call(['/usr/sbin/ufw','status','verbose']).decode(),True)

    def trust(self):
        roots={name:r.read_file(ROOT/path,owner=pwd.getpwnam(self.policy['files'][str(ROOT/path)]['owner']).pw_uid) for name,path in
               (('transport-ca.crt','pki/transport.crt'),('management-ca.crt','pki/management.crt'),('issuer-ca.crt','issuer/ca.crt'))}
        for role,owner in (('observation','kaiba-pilot-observe'),('admission','kaiba-pilot-admit'),('fleet','kaiba-pilot-fleet'),('issuer','kaiba-pilot-issuer')):
            uid=pwd.getpwnam(owner).pw_uid
            trusted_role_parent(ROOT/role,uid)
            for name,wanted in roots.items():r.require(r.read_file(ROOT/role/name,owner=uid)==wanted,'serving-trust-copy')
            wanted=roots['management-ca.crt']+(roots['issuer-ca.crt'] if role=='fleet' else b'')
            r.require(r.read_file(ROOT/role/'client-ca.pem',owner=uid)==wanted,'serving-client-trust')
        r.require(r.read_file(ROOT/'management/transport-ca.crt',owner=0)==roots['transport-ca.crt'],'serving-management-trust')

    def read(self,name):
        r.trusted_parent(self.state,0)
        return r.decode(r.read_file(self.state/(name+'.json'),owner=0,mode=0o600))

    def check(self):
        self.base()
        r.require(self.read('policy')==self.policy,'serving-retained-policy')
        baseline=self.read('baseline');r.fields(baseline,('config_sha256','enrollments','checked_at'))
        r.require(r.sha(r.read_file(CONFIG,owner=0,mode=0o600))==baseline['config_sha256'],'serving-config-changed')
        r.fields(baseline['enrollments'],('peer','target'))
        checked=r.timestamp(baseline['checked_at'])
        r.require(r.timestamp(self.policy['issued_at'])<=checked<r.timestamp(self.policy['not_after']) and checked<=time.time(),'serving-baseline-time')
        for en in baseline['enrollments'].values():
            r.require(en['state']=='active' and en['binding']['full_qualification'] is False and
                      r.timestamp(en['binding']['credential']['not_before'])<=checked<r.timestamp(en['binding']['credential']['not_after']),'serving-membership-window')
        previous=r.read_file(self.state/'config.before',owner=0,mode=0o600)
        r.require(r.sha(previous)==self.policy['predecessor_config_sha256'] and r.decode(previous)['not_after']==self.policy['not_after'],'serving-deadline-extended')
        plan=self.read('backup-plan');expected=r.decode(r.canonical(self.policy['backup_template']))
        for name in PRESERVED:
            expected['preserved_files'][str(self.state.relative_to(ROOT))+'/'+name]=r.sha(r.read_file(self.state/name,owner=0,mode=0o600))
        r.require(plan==expected,'serving-backup-plan-changed')
        result_path=JOURNALS/('kaiba-backup-'+plan['run_id'])/'result.json'
        result=r.decode(r.read_file(result_path,owner=0,mode=0o600))
        r.require(result==self.read('backup-result') and result.get('status')=='passed' and
                  result.get('plan_sha256')==r.sha(r.canonical(plan)) and result.get('services_started') is False and
                  result.get('recovery_passphrase_test')=='passed','serving-backup-unconfirmed')
        return True


class Handoff:
    """Calls are bound by the outer adapter and one-use journal, not a CLI."""
    def __init__(self,policy,host,access,config,before_sha256):
        self.guard=Guard(policy);self.policy=self.guard.policy;self.host=host;self.access=access
        self.config=r.decode(r.canonical(config));self.before=before_sha256
        self.state=self.guard.state;self.journal=JOURNALS/('kaiba-serving-'+policy['run_id'])
        r.require(host.plan['run_id']==policy['run_id'] and host.plan['boot_id']==policy['boot_id'] and
                  (access is None or access.plan['run_id']==policy['run_id']),'serving-run-binding')
        r.fields(config,('schema','issued_at','not_after','guard','guard_sha256','units'))
        r.require(config['schema']=='kaiba.pilot-serving/v1alpha1' and config['issued_at']==policy['issued_at'] and
                  config['not_after']==policy['not_after'] and config['units']=={u:policy['units'][u] for u in d.SERVICES} and
                  before_sha256==policy['predecessor_config_sha256'],'serving-config-binding')
        r.require(re.fullmatch(r'/nix/store/[a-z0-9]{32}-[A-Za-z0-9._+-]+/bin/kaiba-pilot-serving-guard',config['guard']) and
                  isinstance(config['guard_sha256'],str) and r.HEX.fullmatch(config['guard_sha256']),'serving-immutable-wrapper')

    def open_access(self):
        self.host.guard();r.trusted_parent(self.journal.parent,0)
        r.require(not os.path.lexists(self.journal),'serving-already-attempted')
        firewall(self.policy,self.host.call(['/usr/sbin/ufw','status','verbose']).decode(),False)
        self.journal.mkdir(mode=0o700)
        self.host.write(self.journal/'policy.json',r.canonical(self.policy))
        self.host.write(self.journal/'rule.intent.json',r.canonical({'rule':rule_args(self.policy)}))
        self.host.call(['/usr/sbin/ufw',*rule_args(self.policy)])
        firewall(self.policy,self.host.call(['/usr/sbin/ufw','status','verbose']).decode(),True)
        self.host.write(self.journal/'rule.complete.json',r.canonical({'status':'passed'}))

    def prepare_backup(self):
        r.require(self.access is not None,'serving-access-checks-required')
        self.host.guard();self.access.probe('test-restart');self.guard.base()
        r.require(not os.path.lexists(self.state),'serving-baseline-exists')
        previous=r.read_file(CONFIG,owner=0)
        r.require(r.sha(previous)==self.before and r.decode(previous)['not_after']==self.policy['not_after'],'serving-predecessor-config')
        r.require(r.sha(r.read_file(self.config['guard'],owner=0))==self.config['guard_sha256'],'serving-wrapper-changed')
        checked=dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00','Z')
        for en in self.access.plan['enrollments'].values():
            r.require(r.timestamp(en['binding']['credential']['not_before'])<=r.timestamp(checked)<r.timestamp(en['binding']['credential']['not_after']),'serving-credential-expired')
        self.host.call([self.host.plan['controller'],'stop']);self.host.states((d.SUPERVISOR,*d.SERVICES),'inactive')
        self.state.mkdir(mode=0o700)
        self.host.write(self.state/'policy.json',r.canonical(self.policy))
        self.host.write(self.state/'config.before',r.read_file(CONFIG,owner=0))
        self.host.write(self.state/'config.json',r.canonical(self.config))
        self.host.write(self.state/'baseline.json',r.canonical({'config_sha256':r.sha(r.canonical(self.config)),
                                                             'enrollments':self.access.plan['enrollments'],'checked_at':checked}))
        self.host.write(self.state/'install.intent.json',r.canonical({'before_sha256':self.before}))
        self.host.replace(CONFIG,r.canonical(self.config))
        plan=r.decode(r.canonical(self.policy['backup_template']))
        for name in PRESERVED:
            plan['preserved_files'][str(self.state.relative_to(ROOT))+'/'+name]=r.sha(r.read_file(self.state/name,owner=0,mode=0o600))
        self.host.write(self.state/'backup-plan.json',r.canonical(plan))
        return b.Backup(plan)

    def resume(self):
        self.host.guard();plan=self.guard.read('backup-plan')
        result=b.Backup(plan).probe()
        self.host.write(self.state/'backup-result.json',r.canonical(result))
        self.guard.check()
        self.host.write(self.journal/'start.intent.json',r.canonical({'run_id':self.policy['run_id']}))
        self.host.call([self.host.plan['controller'],'start'])
        # Type=simple is not readiness. Wait for guard-started children, then
        # perform the same full authority and device-local binding checks.
        end=min(time.monotonic()+45,time.monotonic()+r.timestamp(self.host.plan['expires_at'])-time.time())
        while True:
            states=[self.host.state_of(u)['ActiveState'] for u in (d.SUPERVISOR,*d.SERVICES)]
            r.require(states[0] in ('active','activating'),'serving-start-failed')
            if all(s=='active' for s in states):break
            r.require(time.monotonic()<end,'serving-start-timeout');time.sleep(.1)
        self.verify_live();self.observe();self.verify_live()
        self.host.write(self.journal/'result.json',r.canonical({'status':'passed','not_after':self.policy['not_after'],
                                                             'services':'supervised','boot_enabled':False,'full_qualification':False,'credential_deadlines':self.credential_deadlines()}))

    def credential_deadlines(self):
        return {role:en['binding']['credential']['not_after'] for role,en in self.access.plan['enrollments'].items()}

    def observe(self):
        # Permit two periodic supervisor checks before declaring startup passed.
        end=time.monotonic()+22
        r.require(time.time()+22<r.timestamp(self.host.plan['expires_at']),'serving-observation-window')
        while time.monotonic()<end:
            self.host.guard();self.host.states((d.SUPERVISOR,*d.SERVICES),'active')
            time.sleep(min(1,max(0,end-time.monotonic())))

    def probe(self):
        r.trusted_parent(self.journal,0)
        result=r.decode(r.read_file(self.journal/'result.json',owner=0,mode=0o600))
        r.require(result=={'status':'passed','not_after':self.policy['not_after'],
                          'services':'supervised','boot_enabled':False,'full_qualification':False,'credential_deadlines':self.credential_deadlines()},'serving-handoff-unconfirmed')
        r.require(r.decode(r.read_file(self.journal/'rule.complete.json',owner=0,mode=0o600))=={'status':'passed'},'serving-rule-unconfirmed')
        return self.verify_live()

    def verify_live(self):
        self.host.guard();self.guard.check();self.host.states((d.SUPERVISOR,*d.SERVICES),'active')
        self.host.readers_ready();self.host.issuer_ready(self.host.plan['issuer_after'])
        self.host.listener_ready('kaiba-pilot-fleet.service',18444,address=self.policy['target_rule']['destination'])
        self.access.records();self.access.self_reads();self.access.records()
        return True

    def cleanup(self):
        # No encrypted-state access is needed to stop/remove only this run's rule.
        self.host.safe_stop()
        self.host.cleaning=True
        try:self.remove_rule()
        finally:self.host.cleaning=False

    def remove_rule(self):
        if not os.path.lexists(self.journal):return
        r.trusted_parent(self.journal,0)
        r.require(r.decode(r.read_file(self.journal/'policy.json',owner=0,mode=0o600))==self.policy,'serving-cleanup-binding')
        r.require(r.decode(r.read_file(self.journal/'rule.intent.json',owner=0,mode=0o600))=={'rule':rule_args(self.policy)},'serving-rule-intent')
        raw=self.host.call(['/usr/sbin/ufw','status','verbose']).decode()
        if rule_line(self.policy) in lines(raw):
            self.host.call(['/usr/sbin/ufw','--force','delete',*rule_args(self.policy)])
        firewall(self.policy,self.host.call(['/usr/sbin/ufw','status','verbose']).decode(),False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy',required=True);parser.add_argument('--sha256',required=True)
    args=parser.parse_args();r.trusted_parent(Path(args.policy).parent,0)
    raw=r.read_file(args.policy,owner=0)
    r.require(r.sha(raw)==args.sha256,'serving-policy-digest')
    Guard(r.decode(raw)).check()
    print('SERVING_GUARD passed')


if __name__=='__main__':
    try:main()
    except (r.Stop,OSError,ValueError,KeyError):
        print('SERVING_GUARD denied',file=sys.stderr);sys.exit(1)
