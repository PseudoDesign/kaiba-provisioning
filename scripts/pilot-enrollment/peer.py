"""Read-only existing-device dispatcher for a reviewed pilot enrollment run.

Runs an immutable client locally against the retained protected state. No initial
setup, installed-client replacement, credential export or state mutation route.
"""
import os
from pathlib import Path
import pwd
import re
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import runner as r
import device as d


def validate(plan):
    r.fields(plan,('schema_version','host','client','uid','gid','expected_status'))
    r.require(plan['schema_version']=='kaiba.pilot-existing-device/v1alpha1','peer-schema')
    d.validate(plan['host'])
    r.require(isinstance(plan['client'],str) and re.fullmatch(r'/nix/store/[a-z0-9]{32}-[A-Za-z0-9+._-]+/bin/kaiba-pilot-device',plan['client']),'peer-client-path')
    r.require(type(plan['uid']) is int and plan['uid']>0 and type(plan['gid']) is int and plan['gid']>0,'peer-account')
    status=plan['expected_status']
    required={'schema_version','phase','spki','spki_digest','enrollment_id','logical_device_id','full_qualification'}
    r.require(isinstance(status,dict) and required<=set(status)<=required|{'renewal','recovery'} and
              status['schema_version']=='kaiba.pilot-device-client/v1alpha1' and
              status['phase']=='verified' and status['full_qualification'] is False,'peer-status-binding')


def guard(plan):
    validate(plan);d.host_guard(plan['host'])
    user=pwd.getpwnam(d.USER)
    r.require(user.pw_uid==plan['uid'] and user.pw_gid==plan['gid'],'peer-account-changed')
    d.directory(d.ROOT,user.pw_uid,user.pw_gid,0o700)
    r.require(set(p.name for p in d.ROOT.iterdir())=={'.lock','state.json'},'peer-state-layout')
    r.read_file(d.ROOT/'.lock',owner=user.pw_uid,mode=0o600)
    rows=r.decode(d.command([d.SW+'findmnt','--json','--mountpoint',d.ROOT,'-o','TARGET,SOURCE,FSTYPE,OPTIONS']))['filesystems']
    r.require(len(rows)==1 and rows[0]['target']==str(d.ROOT) and rows[0]['fstype']=='ext4' and
              {'rw','nosuid','nodev','noexec'}<=set(rows[0]['options'].split(',')) and
              d.ROOT.stat().st_dev==d.ROOT.parent.stat().st_dev,'peer-protected-mount')
    client=r.read_file(plan['client'],maximum=16*1024*1024,owner=0)
    r.require(len(client)==plan['host']['client_size'] and r.sha(client)==plan['host']['client_sha256'] and
              os.access(plan['client'],os.X_OK),'peer-client-changed')


def state_digest(plan):
    # Hash only within the device. Never return contents or digest to the station.
    return r.sha(r.read_file(d.ROOT/'state.json',maximum=4*1024*1024,owner=plan['uid'],mode=0o600))


def dispatch(plan,request):
    r.fields(request,('action','input'))
    action=request['action'];value=request['input']
    r.require(action in ('status','self','check-isolation'),'peer-read-only')
    if action=='check-isolation':
        r.require(isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}',value) and
                  value!=plan['expected_status']['enrollment_id'],'peer-other-instance')
    else:r.require(value is None,'peer-unexpected-input')
    guard(plan);before=state_digest(plan)
    argv=[d.SW+'runuser','-u',d.USER,'--',plan['client'],'--state',d.ROOT]
    def status():
        result=r.decode(d.command([*argv,'status']))
        r.require(result==plan['expected_status'],'peer-status-changed')
        return result
    try:
        observed=status()
        if action=='status':return observed
        args=['--other-instance',value] if action=='check-isolation' else []
        result=r.decode(d.command([*argv,*args,action]))
        status()
        return result
    finally:
        r.require(state_digest(plan)==before,'peer-state-changed')
