"""Per-account bandwidth ceilings. Own nft table and Xray tags only."""
import copy
import hashlib
import ipaddress
import json
import math
import pathlib
import re
from .adult import CID, STATE_DIR, atomic_json, PREFIX as DENY_PREFIX

TABLE='tunnelscope_speed'
PREFIX='tunnelscope-speed-'
MARK=0x54530000
MASK=0xffff0000
STATE=STATE_DIR+'/speed.json'


def rate(value):
    if type(value) not in (int,float) or not math.isfinite(value) or not (value==0 or .1<=value<=10000):
        raise ValueError('Скорость: 0 (без лимита) или от 0,1 до 10000 Мбит/с')
    return round(float(value),3)


def validate(request):
    action=request.get('action')
    if action=='speed_toggle' and set(request)=={'action','enabled'} and type(request['enabled']) is bool:return action
    if action in ('speed','speed_inherit'):
        cid=request.get('client_id')
        if not isinstance(cid,str) or cid and not CID.fullmatch(cid):raise ValueError('Некорректный клиент')
        if action=='speed_inherit' and cid and set(request)=={'action','client_id'}:return action
        if action=='speed' and set(request)=={'action','client_id','download_mbps','upload_mbps'}:
            rate(request['download_mbps']);rate(request['upload_mbps']);return action
    raise ValueError('Некорректная настройка скорости')


def effective(settings,cid):
    if not settings.get('enabled',False):return (0,0)
    values=settings.get('clients',{}).get(cid,settings)
    return rate(values.get('download_mbps',0)),rate(values.get('upload_mbps',0))


def read_status(config):
    settings=config.get('speed_limits',{})
    path=pathlib.Path(settings.get('state_file',STATE))
    try:
        s=json.loads(path.read_text(encoding='utf8'))
        return {k:s.get(k,[] if k in ('applied','unsupported') else '') for k in ('applied','unsupported','error','updated')}
    except FileNotFoundError:return {'applied':[],'unsupported':[],'error':'','updated':0}


def nft_script(entries,replace=False):
    # Named byte buckets are shared across all flows/addresses of the account.
    lines=(['delete table inet '+TABLE] if replace else [])+['table inet '+TABLE+' {']
    pre=[];output=[];forward=[]
    for e in entries:
        slot=e['slot'];mark=MARK+slot
        for direction,key in [('u','upload_mbps'),('d','download_mbps')]:
            value=e[key]
            if not value:continue
            byte_rate=max(1,round(value*125000));burst=max(65536,min(1048576,byte_rate//4))
            lines.append('limit '+direction+str(slot)+' { rate over '+str(byte_rate)+' bytes/second burst '+str(burst)+' bytes; }')
        if e['source'] in ('xray','mieru'):
            if e['source']=='mieru':output.append('ct direction original socket cgroupv2 level 2 "system.slice/mita.service" ct mark set '+str(mark))
            if e['upload_mbps']:output.append('ct direction original ct mark '+str(mark)+' limit name u'+str(slot)+' counter drop')
            if e['download_mbps']:pre.append('ct direction reply ct mark '+str(mark)+' limit name d'+str(slot)+' counter drop')
        else:
            for iface,addr in e['endpoints']:
                if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}',iface):raise ValueError('Invalid interface')
                parsed=ipaddress.ip_address(addr);family='ip' if parsed.version==4 else 'ip6'
                if e['upload_mbps']:pre.append('iifname "'+iface+'" '+family+' saddr '+str(parsed)+' limit name u'+str(slot)+' counter drop')
                if e['download_mbps']:
                    term='oifname "'+iface+'" '+family+' daddr '+str(parsed)+' limit name d'+str(slot)+' counter drop'
                    forward.append(term);output.append(term)
    output.insert(0,'meta mark & '+str(MASK)+' == '+str(MARK)+' ct mark set meta mark')
    for name,hook,rules in [('pre','prerouting',pre),('out','output',output),('forward','forward',forward)]:
        lines+=['chain '+name+' { type filter hook '+hook+' priority -149; policy accept;']+rules+['}']
    return '\n'.join(lines+['}'])+'\n'


class SpeedManager:
    def __init__(self,owner):
        self.owner=owner;self.settings=owner.config.get('speed_limits',{})
        self.path=self.settings.get('state_file',STATE)
        self.state={'slots':{},'outbounds':[],'applied':[],'unsupported':[],'error':'','updated':0}
        if self.settings and pathlib.Path(self.path).exists():self.state.update(json.loads(pathlib.Path(self.path).read_text(encoding='utf8')))
        self.signature=None;self.next_check=0

    def save(self):
        self.state['updated']=self.owner.clock();atomic_json(self.path,self.state)

    def slot(self,cid):
        slots=self.state['slots']
        if cid not in slots:
            used=set(slots.values());value=1
            while value in used:value+=1
            if value>65535:raise ValueError('Speed mark space exhausted')
            slots[cid]=value
        return slots[cid]

    def plan(self):
        entries=[];unsupported=[];claimed={}
        clients=list(self.owner.clients.values())
        for c in clients:
            for addr in c.get('ips',[]):claimed.setdefault((c['source'],addr),set()).add(c['id'])
        for c in clients:
            cid=c['id'];down,up=effective(self.settings,cid)
            if not (up or down):continue
            entry={'client_id':cid,'label':c['label'],'source':c['source'],'download_mbps':down,'upload_mbps':up,'endpoints':[]}
            reason=''
            if not CID.fullmatch(cid):reason='Нет надёжной привязки к учётной записи'
            elif c['source']=='mieru':
                if cid!=getattr(self.owner,'mieru_only','') or not self.owner.backend.mieru:reason='Mieru: требуется единственная учётная запись и cgroup'
            elif c['source']!='xray':
                for item in self.owner.config.get('interfaces',[]):
                    if item.get('source')!=c['source'] or not item.get('network'):continue
                    net=ipaddress.ip_network(item['network'])
                    for addr in c.get('ips',[]):
                        try:p=ipaddress.ip_address(addr)
                        except ValueError:continue
                        if p in net and len(claimed[(c['source'],addr)])==1:entry['endpoints'].append((item['name'],str(p)))
                if not entry['endpoints']:reason='Нет уникального адреса на настроенном интерфейсе туннеля'
            if reason:unsupported.append({'client_id':cid,'reason':reason});continue
            entry['slot']=self.slot(cid);entries.append(entry)
        return entries,unsupported

    def tick(self):
        if not self.settings or not getattr(self.owner,'clients_loaded',False) or self.owner.clock()<self.next_check:return
        self.next_check=self.owner.clock()+15
        b=self.owner.backend
        try:
            entries,unsupported=self.plan()
            link_kinds={}
            for e in list(entries):
                if e['source'] in ('xray','mieru'):continue
                safe_endpoints=[]
                for iface,addr in e['endpoints']:
                    if iface not in link_kinds:
                        links=json.loads(self.command(['ip','-j','-d','link','show','dev',iface]).stdout)
                        link_kinds[iface]=links[0].get('linkinfo',{}).get('info_kind','') if links else ''
                    if link_kinds[iface] in ('tun','wireguard','amneziawg'):safe_endpoints.append((iface,addr))
                e['endpoints']=safe_endpoints
                if not safe_endpoints:
                    entries.remove(e);unsupported.append({'client_id':e['client_id'],'reason':'Интерфейс является мостом/контейнером, а не индивидуальным туннелем'})
            if any(e['source']=='mieru' for e in entries):
                from .common import uid
                users=json.loads(self.command(['mita','describe','config']).stdout).get('users',[])
                only=uid('mieru',users[0]['name']) if len(users)==1 else ''
                for e in list(entries):
                    if e['source']=='mieru' and e['client_id']!=only:
                        entries.remove(e);unsupported.append({'client_id':e['client_id'],'reason':'Конфигурация пользователей Mieru изменилась'})
            rules=json.loads(b.xray('lsrules').stdout).get('rules',[])
            target=lambda r:r.get('outboundTag',r.get('tag',''))
            blocked={u for r in rules if target(r)=='blocked' and not r.get('ruleTag','').startswith('tunnelscope-app-') for u in r.get('user',[])}
            blocked_ids={r['ruleTag'][len(prefix):] for r in rules if target(r)=='blocked' for prefix in (DENY_PREFIX,'tunnelscope-supercell-') if r.get('ruleTag','').startswith(prefix)}
            safe=all(target(r) in ('api','blocked') or r.get('ruleTag','').startswith(PREFIX) for r in rules)
            if not safe:
                for e in list(entries):
                    if e['source']=='xray':entries.remove(e);unsupported.append({'client_id':e['client_id'],'reason':'Ранние маршруты Xray могут обходить лимит; требуется проверка'})
            desired={PREFIX+e['client_id']:e for e in entries if e['source']=='xray' and e['label'] not in blocked and e['client_id'] not in blocked_ids}
            actual={r.get('ruleTag'):r for r in rules if r.get('ruleTag','').startswith(PREFIX)}
            for tag,r in actual.items():
                if tag not in desired or target(r)!=tag or ('user' in r and r['user']!=[desired[tag]['label']]):b.xray('rmrules',tag)
            exists=self.command(['nft','list','table','inet',TABLE],required=False).returncode==0
            signature=hashlib.sha256(json.dumps(entries,sort_keys=True).encode()).hexdigest()
            if signature!=self.signature or bool(entries)!=exists:
                if entries:
                    script=nft_script(entries,exists);self.command(['nft','-c','-f','-'],text=script);self.command(['nft','-f','-'],text=script)
                elif exists:self.command(['nft','delete','table','inet',TABLE])
                self.signature=signature
            default=None
            for tag,e in desired.items():
                if tag in actual and target(actual[tag])==tag and ('user' not in actual[tag] or actual[tag]['user']==[e['label']]):continue
                if default is None:
                    runtime=json.loads(pathlib.Path(b.runtime).read_text(encoding='utf8'));default=runtime['outbounds'][0]
                    if default.get('protocol')!='freedom' or default.get('streamSettings',{}).get('sockopt',{}).get('mark',0):raise ValueError('Default outbound must be unmarked freedom')
                outbound=copy.deepcopy(default);outbound['tag']=tag
                outbound.setdefault('streamSettings',{}).setdefault('sockopt',{})['mark']=MARK+e['slot']
                known=tag in self.state['outbounds']
                if not known:self.state['outbounds'].append(tag);self.save()
                try:b.xray('ado','stdin:',text=json.dumps({'outbounds':[outbound]}))
                except Exception as error:
                    if not any(x in str(error).lower() for x in ('already exists','existing tag','already registered')):raise
                    if not known:
                        b.xray('rmo',tag)
                        b.xray('ado','stdin:',text=json.dumps({'outbounds':[outbound]}))
                rule={'type':'field','ruleTag':tag,'user':[e['label']],'outboundTag':tag}
                b.xray('adrules','-append','stdin:',text=json.dumps({'routing':{'rules':[rule]}}))
            self.state.update(applied=entries,unsupported=unsupported,error='');self.save()
        except Exception as error:
            self.state.update(error=str(error)[:240],applied=[]);self.save()

    @staticmethod
    def command(*args,**kwargs):
        from .policy import command
        return command(*args,**kwargs)

    def status(self):
        return {'source':'speed-policy','enabled':bool(self.settings.get('enabled',False)),
          'ok':not self.state.get('error'),'message':'Лимиты скорости в Мбит/с: отдельно скачивание и отдача',
          'error':self.state.get('error',''),'applied':self.state.get('applied',[]),
          'unsupported':self.state.get('unsupported',[])}
