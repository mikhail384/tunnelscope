"""Block known application connections, independently of full Internet denials."""
import collections
import functools
import hashlib
import ipaddress
import json
import pathlib
import re
from .adult import CID, STATE_DIR, atomic_json, hostname
from .common import uid

PREFIX='tunnelscope-app-'
TABLE='tunnelscope_apps'
STATE=STATE_DIR+'/apps.json'

@functools.lru_cache(maxsize=1)
def catalog():
    raw=pathlib.Path(__file__).with_name('app_catalog.json').read_bytes()
    if len(raw)>180000:raise ValueError('Application catalog too large')
    value=json.loads(raw);seen=set()
    for app in value['apps']:
        key=app['id']
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,39}',key) or key in seen:raise ValueError('Invalid application ID')
        seen.add(key)
        if not 1<=len(app['domains'])<=1000:raise ValueError('Invalid application domains')
        for rule in app['domains']:
            kind,sep,name=rule.partition(':')
            if kind not in ('domain','full') or not sep or hostname(name)!=name:raise ValueError('Invalid application domain')
        for raw_net in app.get('networks',[]):
            net=ipaddress.ip_network(raw_net,strict=True)
            if not net.is_global or net.prefixlen<(16 if net.version==4 else 32):raise ValueError('Invalid application network')
    if not 1<=len(seen)<=100:raise ValueError('Invalid catalog size')
    return value


def validate(request):
    action=request.get('action');cid=request.get('client_id')
    if not isinstance(cid,str) or cid and not CID.fullmatch(cid):raise ValueError('Некорректный клиент')
    if action=='apps_inherit' and cid and set(request)=={'action','client_id'}:return action
    if action=='apps' and set(request)=={'action','client_id','app_ids'}:
        values=request['app_ids'];known={a['id'] for a in catalog()['apps']}
        if not isinstance(values,list) or len(values)>len(known) or any(not isinstance(x,str) or x not in known for x in values) or len(set(values))!=len(values):raise ValueError('Выберите приложения из каталога')
        return action
    raise ValueError('Некорректная настройка приложений')


def effective(settings,cid):
    if not settings.get('enabled',False) or cid in settings.get('exempt_client_ids',[]):return []
    return settings.get('clients',{}).get(cid,settings.get('app_ids',[]))


def matches(rule,name):
    kind,_,host=rule.partition(':')
    return name==host or kind=='domain' and name.endswith('.'+host)


def read_status(config):
    settings=config.get('apps_policy',{})
    if not settings:return {'error':'','applied':[],'unsupported':[],'events':[],'updated':0}
    path=pathlib.Path(settings.get('state_file',STATE))
    if not path.exists():return {'error':'','applied':[],'unsupported':[],'events':[],'updated':0}
    data=json.loads(path.read_text(encoding='utf8'))
    return {k:data.get(k,[] if k in ('applied','unsupported','events') else '') for k in ('error','applied','unsupported','events','updated')}


def nft_script(entries,replace=False):
    lines=(['delete table inet '+TABLE] if replace else [])+['table inet '+TABLE+' {']
    forward=[];output=[];incoming=[]
    for version in (4,6):
        family='ip' if version==4 else 'ip6';address='ipv4_addr' if version==4 else 'ipv6_addr'
        lines.append('set flows'+str(version)+' { type ifname . '+address+' . '+address+' . inet_service . inet_service; flags timeout; timeout 10s; size 4096; }')
        lines.append('set mita'+str(version)+' { type '+address+' . inet_service . inet_service; flags timeout; timeout 10s; size 4096; }')
        original='iifname . '+family+' saddr . '+family+' daddr . tcp sport . tcp dport'
        reply='oifname . '+family+' daddr . '+family+' saddr . tcp dport . tcp sport'
        def mark(key,name):return 'meta l4proto tcp '+key+' @'+name+' ct label set ct label | 127 delete @'+name+' { '+key+' }'
        forward.extend([mark(original,'flows'+str(version)),mark(reply,'flows'+str(version))]);output.append(mark(reply,'flows'+str(version)))
        if any(e['source']=='mieru' for e in entries):
            group='socket cgroupv2 level 2 "system.slice/mita.service" '
            output.append(group+mark(family+' daddr . tcp sport . tcp dport','mita'+str(version)))
            incoming.append(group+mark(family+' saddr . tcp dport . tcp sport','mita'+str(version)))
    for e in entries:
        for version in (4,6):
            family='ip' if version==4 else 'ip6';nets=[str(ipaddress.ip_network(x)) for x in e['networks'] if ipaddress.ip_network(x).version==version]
            if not nets:continue
            dest=family+' daddr { '+', '.join(nets)+' } reject';source=family+' saddr { '+', '.join(nets)+' } reject'
            if e['source']=='mieru':output.append('socket cgroupv2 level 2 "system.slice/mita.service" '+dest)
            for iface,addr in e['endpoints']:
                if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}',iface):raise ValueError('Invalid interface')
                parsed=ipaddress.ip_address(addr)
                if parsed.version!=version:continue
                forward+=['iifname "'+iface+'" '+family+' saddr '+str(parsed)+' '+dest,'oifname "'+iface+'" '+family+' daddr '+str(parsed)+' '+source]
                output.append('oifname "'+iface+'" '+family+' daddr '+str(parsed)+' '+source)
    for name,hook,rules in [('f','forward',forward),('out','output',output),('in','input',incoming)]:
        lines+=['chain '+name+' { type filter hook '+hook+' priority -15; policy accept;']+rules+['ct label & 127 == 127 meta l4proto tcp reject with tcp reset','}']
    return '\n'.join(lines+['}'])+'\n'


class AppPolicy:
    def __init__(self,owner):
        self.owner=owner;self.settings=owner.config.get('apps_policy',{});self.enabled=bool(self.settings.get('enabled',False))
        self.catalog=catalog();self.index={a['id']:a for a in self.catalog['apps']};self.path=self.settings.get('state_file',STATE)
        self.state={'routes':{},'nft_signature':'','applied':[],'unsupported':[],'events':[],'error':'','updated':0}
        if self.settings and pathlib.Path(self.path).exists():self.state.update(json.loads(pathlib.Path(self.path).read_text(encoding='utf8')))
        self.plans={};self.next_check=0;self.table_ready=False;self.seen=collections.OrderedDict()
    @staticmethod
    def command(*args,**kwargs):
        from .policy import command
        return command(*args,**kwargs)
    def save(self):self.state['updated']=self.owner.clock();atomic_json(self.path,self.state)
    def plan(self):
        plans={};unsupported=[];clients=list(self.owner.clients.values());claimed={};kinds={}
        for c in clients:
            for addr in c.get('ips',[]):claimed.setdefault((c['source'],addr),set()).add(c['id'])
        for c in clients:
            cid=c['id'];ids=effective(self.settings,cid)
            if not ids:continue
            if not CID.fullmatch(cid):unsupported.append({'client_id':cid,'reason':'Нет надёжной привязки к клиенту'});continue
            apps=[self.index[a] for a in ids if a in self.index]
            e={'client_id':cid,'label':c['label'],'source':c['source'],'app_ids':list(ids),'endpoints':[],
               'domains':sorted({r for a in apps for r in a['domains']}),'networks':sorted({n for a in apps for n in a.get('networks',[])})}
            reason=''
            if c['source']=='mieru':
                users=json.loads(self.command(['mita','describe','config']).stdout).get('users',[])
                if not self.owner.backend.mieru or len(users)!=1 or uid('mieru',users[0]['name'])!=cid:reason='Mieru: необходима единственная учётная запись'
            elif c['source']!='xray':
                for item in self.owner.config.get('interfaces',[]):
                    iface=item['name']
                    if item.get('source')!=c['source'] or not item.get('network') or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}',iface):continue
                    if iface not in kinds:
                        links=json.loads(self.command(['ip','-j','-d','link','show','dev',iface]).stdout);kinds[iface]=links[0].get('linkinfo',{}).get('info_kind','') if links else ''
                    if kinds[iface] not in ('tun','wireguard','amneziawg'):continue
                    net=ipaddress.ip_network(item['network'])
                    for raw in c.get('ips',[]):
                        try:addr=ipaddress.ip_address(raw)
                        except ValueError:continue
                        if addr in net and len(claimed[(c['source'],raw)])==1:e['endpoints'].append((iface,str(addr)))
                if not e['endpoints']:reason='Нет уникального адреса на индивидуальном туннеле; контейнерные мосты не поддерживаются'
            if reason:unsupported.append({'client_id':cid,'reason':reason})
            else:plans[cid]=e
        return plans,unsupported
    def tick(self):
        if not self.settings or not getattr(self.owner,'clients_loaded',False) or self.owner.clock()<self.next_check:return
        self.next_check=self.owner.clock()+15;b=self.owner.backend
        try:
            plans,unsupported=self.plan();rules=json.loads(b.xray('lsrules').stdout).get('rules',[])
            target=lambda r:r.get('outboundTag',r.get('tag',''))
            safe=all(target(r) in ('api','blocked') or r.get('ruleTag','').startswith('tunnelscope-speed-') for r in rules)
            desired={};fingerprints={}
            for cid,e in list(plans.items()):
                if e['source']!='xray':continue
                if not safe:unsupported.append({'client_id':cid,'reason':'Ранние маршруты Xray могут обходить блокировку'});del plans[cid];continue
                for suffix,key in [('domains','domain'),('networks','ip')]:
                    values=e[suffix]
                    if values:
                        tag=PREFIX+cid+'-'+suffix;desired[tag]={'type':'field','ruleTag':tag,'user':['regexp:^'+re.escape(e['label'])+'$' if e['label'].startswith('regexp:') else e['label']],'outboundTag':'blocked',key:values}
                        fingerprints[tag]=hashlib.sha256(json.dumps(desired[tag],sort_keys=True).encode()).hexdigest()
            native=[e for e in plans.values() if e['source']!='xray'];exists=self.command(['nft','list','table','inet',TABLE],required=False).returncode==0
            signature=hashlib.sha256(json.dumps(native,sort_keys=True).encode()).hexdigest()
            if signature!=self.state.get('nft_signature') or bool(native)!=exists:
                if native:
                    text=nft_script(native,exists);self.command(['nft','-c','-f','-'],text=text);self.command(['nft','-f','-'],text=text)
                elif exists:self.command(['nft','delete','table','inet',TABLE])
                self.state['nft_signature']=signature
            self.table_ready=bool(native)
            actual={r.get('ruleTag'):r for r in rules if r.get('ruleTag','').startswith(PREFIX)}
            dirty={tag for tag in desired if tag not in actual or target(actual[tag])!='blocked' or self.state['routes'].get(tag)!=fingerprints[tag]}
            for tag in actual:
                if tag not in desired or tag in dirty:b.xray('rmrules',tag)
            rate_tags={r.get('ruleTag') for r in rules if r.get('ruleTag','').startswith('tunnelscope-speed-')}
            for tag in dirty:
                rule=desired[tag];cid=tag[len(PREFIX):].rsplit('-',1)[0];speed_tag='tunnelscope-speed-'+cid
                if speed_tag in rate_tags:b.xray('rmrules',speed_tag);rate_tags.discard(speed_tag);self.owner.speed.next_check=0
                b.xray('adrules','-append','stdin:',text=json.dumps({'routing':{'rules':[rule]}}))
            self.plans=plans;self.state.update(routes=fingerprints,applied=[{'client_id':e['client_id'],'app_ids':e['app_ids'],'source':e['source']} for e in plans.values()],unsupported=unsupported,error='');self.save()
        except Exception as error:self.state['error']=str(error)[:240];self.save()
    def handle(self,f,c,peers):
        e=self.plans.get(c['id'])
        if not e:return
        name=hostname(f.get('domain',''));direct=f.get('evidence') in ('TLS SNI','HTTP Host','Xray access')
        try:dest=ipaddress.ip_address(f.get('destination',''))
        except ValueError:dest=None
        found=next((key for key in e['app_ids'] if direct and name and any(matches(r,name) for r in self.index[key]['domains']) or dest and any(dest in ipaddress.ip_network(n) for n in self.index[key].get('networks',[]))),None)
        if not found:return
        state='Соединение распознано; правило Xray активно'
        if c['source']!='xray':
            if not direct or not name or not dest or f.get('protocol')!='TCP' or not self.table_ready:return
            local=f.get('local_port');remote=f.get('port')
            if type(local) is not int or type(remote) is not int or not 1<=local<=65535 or not 1<=remote<=65535:return
            if c['source']=='mieru':
                users=json.loads(self.command(['mita','describe','config']).stdout).get('users',[])
                if len(users)!=1 or uid('mieru',users[0]['name'])!=c['id']:return
                name_set='mita'+str(dest.version);key=str(dest)+' . '+str(local)+' . '+str(remote)
            else:
                iface=f.get('interface','');internal=f.get('internal','')
                if (iface,internal) not in e['endpoints'] or internal not in c.get('ips',[]):return
                if ipaddress.ip_address(internal).version!=dest.version:return
                name_set='flows'+str(dest.version);key='"'+iface+'" . '+internal+' . '+str(dest)+' . '+str(local)+' . '+str(remote)
            signature=(c['id'],name_set,key)
            if signature in self.seen and self.owner.clock()-self.seen[signature]<10:return
            self.command(['nft','-f','-'],text='add element inet '+TABLE+' '+name_set+' { '+key+' timeout 10s }\n')
            self.seen[signature]=self.owner.clock()
            while len(self.seen)>4096:self.seen.popitem(last=False)
            state='Выбранное TCP-соединение сбрасывается'
        event={'client_id':c['id'],'label':c['label'],'app_id':found,'domain':name or str(dest),'time':self.owner.clock(),'state':state}
        self.state['events']=(self.state.get('events',[])+[event])[-20:]
    def status(self):
        return {'source':'apps-policy','enabled':self.enabled,'ok':not self.state.get('error'),'message':'Блокировка известных соединений выбранных приложений',
          'error':self.state.get('error',''),'applied':self.state.get('applied',[]),'unsupported':self.state.get('unsupported',[]),'events':self.state.get('events',[])}
