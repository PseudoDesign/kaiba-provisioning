"""Two-device access and authority-process restart checks for the owner runner.

Callbacks run the bounded client on each device; private credentials never pass
through this hook. The host is the reviewed deployment.Deployment instance.
"""
import ipaddress
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))
import runner as r
import protocol as p
import deployment as d


def validate(plan):
    r.fields(plan,('schema_version','run_id','fleet_address','enrollments'))
    r.require(plan['schema_version']=='kaiba.pilot-access-checks/v1alpha1' and
              isinstance(plan['run_id'],str) and r.LABEL.fullmatch(plan['run_id']),'access-plan')
    address=ipaddress.ip_address(plan['fleet_address'])
    r.require(address.version==4 and not address.is_unspecified and not address.is_multicast,'access-fleet-address')
    r.fields(plan['enrollments'],('peer','target'))
    ids=[]
    for record in plan['enrollments'].values():
        r.require(isinstance(record,dict) and isinstance(record.get('id'),str) and
                  p.ID.fullmatch(record['id']) and record.get('state')=='active' and
                  isinstance(record.get('binding'),dict) and record['binding'].get('full_qualification') is False,'access-active-enrollment')
        ids.append(record['id'])
    r.require(ids[0]!=ids[1],'access-distinct-enrollments')


class Checks:
    def __init__(self,plan,store,host,authority,devices):
        validate(plan);r.fields(devices,('peer','target'))
        r.require(host.plan['run_id']==plan['run_id'] and host.plan['peer_id']==plan['enrollments']['peer']['id'],'access-host-binding')
        self.plan=r.decode(r.canonical(plan));self.store=store;self.host=host
        self.authority=authority;self.devices=devices
        # Store is separately bound to these exact public snapshots. A completed
        # enrollment supplies target; the reviewed predecessor supplies peer.
        r.require(store.read('binding')==self.plan,'access-store-binding')

    def guard(self):
        self.host.guard();self.host.states((d.SUPERVISOR,),'inactive')
        self.host.states(d.SERVICES,'active')

    def records(self):
        for expected in self.plan['enrollments'].values():
            current=self.authority('/api/v1/pilot/enrollments/'+expected['id'])
            r.require(current==expected,'access-authority-drift')

    def own(self,role,value):
        expected=self.plan['enrollments'][role]
        r.fields(value,('authorized','instance_id','binding','full_qualification'))
        r.require(value.get('full_qualification') is False and value=={'authorized':'pilot','instance_id':expected['id'],
                         'binding':expected['binding'],'full_qualification':False},'access-self-binding')

    def self_reads(self):
        values={}
        for role,client in self.devices.items():
            values[role]=client('self');self.own(role,values[role])
        return values

    def isolation(self):
        self.guard();self.records()
        self.store.write('isolation-intent',{'run_id':self.plan['run_id']})
        results={}
        for role,other in (('peer','target'),('target','peer')):
            other_id=self.plan['enrollments'][other]['id']
            value=self.devices[role]('check-isolation',other_id)
            r.fields(value,('schema_version','self','other_instance_id','http_status'))
            r.require(value['schema_version']=='kaiba.pilot-isolation/v1alpha1' and
                      value['other_instance_id']==other_id and value['http_status']==403,'access-isolation-result')
            self.own(role,value['self']);results[role]=value
        self.records();self.store.write('isolation-result',results)
        return results

    def invocations(self):
        values={}
        for unit in d.SERVICES:
            state=self.host.state_of(unit);value=state.get('InvocationID','')
            r.require(state['ActiveState']=='active' and isinstance(value,str) and
                      len(value)==32 and all(c in '0123456789abcdef' for c in value) and value!='0'*32,'access-service-invocation')
            values[unit]=value
        return values

    def restart(self):
        self.probe('test-isolation')
        before=self.invocations()
        self.store.write('restart-intent',{'before':before})
        self.host.stop_children()
        self.host.states(d.SERVICES,'inactive')
        self.host.guard()
        self.host.call(['/usr/bin/systemctl','start',*d.SERVICES])
        self.host.readers_ready();self.host.issuer_ready(self.host.plan['issuer_after'])
        self.host.listener_ready('kaiba-pilot-fleet.service',18444,address=self.plan['fleet_address'])
        after=self.invocations()
        r.require(all(before[u]!=after[u] for u in d.SERVICES),'access-service-not-restarted')
        self.records();reads=self.self_reads();self.records()
        result={'after':after,'self':reads,'restart_kind':'authority_processes','device_rebooted':False}
        self.store.write('restart-result',result)
        return result

    def probe(self,step):
        r.require(step in ('test-isolation','test-restart'),'access-probe-step')
        self.guard();self.records()
        r.require(self.store.read('isolation-intent')=={'run_id':self.plan['run_id']},'access-isolation-intent')
        isolated=self.store.read('isolation-result')
        r.fields(isolated,('peer','target'))
        for role,other in (('peer','target'),('target','peer')):
            value=isolated[role]
            r.fields(value,('schema_version','self','other_instance_id','http_status'))
            r.require(value['schema_version']=='kaiba.pilot-isolation/v1alpha1' and value['http_status']==403 and
                      value['other_instance_id']==self.plan['enrollments'][other]['id'],'access-isolation-unconfirmed')
            self.own(role,value['self'])
        if step=='test-restart':
            intent=self.store.read('restart-intent');result=self.store.read('restart-result')
            r.fields(intent,('before',));r.fields(result,('after','self','restart_kind','device_rebooted'))
            r.fields(intent['before'],d.SERVICES);r.fields(result['after'],d.SERVICES)
            r.require(result['restart_kind']=='authority_processes' and result['device_rebooted'] is False and
                      result['after']==self.invocations() and all(intent['before'][u]!=result['after'][u] for u in d.SERVICES),'access-restart-unconfirmed')
            r.fields(result['self'],('peer','target'))
            for role,value in result['self'].items():self.own(role,value)
        self.self_reads();self.records()
        return True
