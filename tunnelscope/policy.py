"""Root-only, temporary per-client Supercell enforcement. No shell commands."""
import argparse
import collections
import ipaddress
import json
import pathlib
import queue
import re
import socket
import struct
import subprocess
import threading
import time
from .common import domain, ip, uid, dns_answers
from .adult import AdultPolicy, atomic_json, PREFIX as ADULT_PREFIX, TABLE as ADULT_TABLE
from .speed import SpeedManager, PREFIX as SPEED_PREFIX
from .apps import AppPolicy

PREFIX = 'tunnelscope-supercell-'
TABLE = 'tunnelscope_policy'
DEFAULT_DOMAINS = ['supercell.com','supercell.net','supercellid.com','supercellgames.com',
    'supercellstore.com','supercellcreators.com','clashroyale.com','clashroyaleapp.com',
    'clashofclans.com','brawlstars.com','brawlstarsgame.com','hayday.com','haydaygame.com',
    'boombeach.com','boombeachgame.com','squadbusters.com','clashmini.com','mo.co']
GAME_HOSTS = ['game.clashroyaleapp.com','game.brawlstarsgame.com','game.clashofclans.com',
              'game.haydaygame.com','game.boombeachgame.com']


def command(args, text=None, timeout=3, required=True):
    r = subprocess.run(args, input=text, capture_output=True, text=True, timeout=timeout)
    if required and r.returncode:
        raise RuntimeError(args[0] + ': ' + r.stderr[:160])
    return r


def matches_domain(name, suffixes=DEFAULT_DOMAINS):
    name = domain(name)
    return bool(name) and any(name == s or name.endswith('.' + s) for s in suffixes)


def dns_records(host, resolver='127.0.0.53'):
    """Use DNS TTLs; never infer ownership from a provider's address range."""
    records = {}
    for qtype in (1,28):
        ident = int.from_bytes(__import__('os').urandom(2),'big')
        query = struct.pack('!HHHHHH',ident,0x100,1,0,0,0)
        query += b''.join(bytes([len(x)]) + x.encode('ascii') for x in host.split('.')) + b'\0'
        query += struct.pack('!HH',qtype,1)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.connect((resolver,53)); s.send(query); reply=s.recv(65535)
        if len(reply)<12 or int.from_bytes(reply[:2],'big')!=ident or reply[3]&15:
            continue
        for addr,name,ttl in dns_answers(reply):
            if ipaddress.ip_address(addr).is_global and ttl>0:
                records[addr]=time.time()+min(ttl,300)
    return records


def nft_script(mieru=True):
    lines = ['table inet '+TABLE+' {',
      'set clients4 { type ifname . ipv4_addr; flags timeout; timeout 20s; }',
      'set clients6 { type ifname . ipv6_addr; flags timeout; timeout 20s; }',
      'set mita_block { typeof numgen inc mod 1; flags timeout; timeout 20s; }',
      'chain input { type filter hook input priority -20; policy accept;',
      'iifname . ip saddr @clients4 drop', 'iifname . ip6 saddr @clients6 drop', '}',
      'chain forward { type filter hook forward priority -20; policy accept;',
      'iifname . ip saddr @clients4 drop', 'iifname . ip6 saddr @clients6 drop',
      'oifname . ip daddr @clients4 drop', 'oifname . ip6 daddr @clients6 drop', '}',
      'chain output { type filter hook output priority -20; policy accept;',
      'oifname . ip daddr @clients4 drop', 'oifname . ip6 daddr @clients6 drop']
    if mieru:
        lines.append('socket cgroupv2 level 2 "system.slice/mita.service" numgen inc mod 1 @mita_block drop')
    return '\n'.join(lines+['}','}'])+'\n'


class Backend:
    def __init__(self, config):
        self.config=config
        self.binary=config.get('xray_binary','/usr/local/x-ui/bin/xray-linux-amd64')
        self.api=config.get('xray_api','127.0.0.1:62789')
        self.runtime=config.get('xray_config','/usr/local/x-ui/bin/config.json')
        self.mieru=False
        self.ports={}
        self.errors=[]

    def xray(self, action, *args, text=None):
        return command([self.binary,'api',action,'--server='+self.api,'-t=2',*args],text=text)

    def cleanup(self):
        result=command(['nft','delete','table','inet',TABLE],required=False)
        if result.returncode and 'No such file or directory' not in result.stderr:
            raise RuntimeError('Unable to clear temporary firewall table')
        data=json.loads(self.xray('lsrules').stdout)
        for r in data.get('rules',[]):
            tag=r.get('ruleTag','')
            if tag.startswith(PREFIX): self.xray('rmrules',tag)

    def initialize(self):
        self.cleanup()
        r=command(['nft','-c','-f','-'],text=nft_script(True),required=False)
        self.mieru=r.returncode==0
        command(['nft','-f','-'],text=nft_script(self.mieru))
        runtime=json.loads(pathlib.Path(self.runtime).read_text())
        self.ports={i['tag']:int(i['port']) for i in runtime.get('inbounds',[])
                    if i.get('protocol') in ('vless','trojan') and isinstance(i.get('port'),int) and i['port']>0}
        if not any(o.get('tag')=='blocked' and o.get('protocol')=='blackhole' for o in runtime.get('outbounds',[])):
            raise RuntimeError('Xray blackhole outbound is unavailable')
        # Appending is safe only when earlier rules do not explicitly allow other traffic.
        self.xray_ready=all(r.get('outboundTag') in ('api','blocked') for r in runtime.get('routing',{}).get('rules',[]))
        if not self.xray_ready:self.errors.append('Ранние маршруты Xray требуют проверки; блокировка Xray не включена')

    def block(self, event, seconds, peers):
        source=event['source']; cid=event['client_id']
        permanent=seconds is None; table=ADULT_TABLE if permanent else TABLE
        prefix=ADULT_PREFIX if permanent else PREFIX
        expiry='' if permanent else ' timeout '+str(seconds)+'s'
        if permanent:self.ensure_adult()
        if source=='xray':
            if not self.xray_ready:raise RuntimeError('Xray routing prerequisite failed')
            if self.config.get('speed_limits'):
                tags={r.get('ruleTag') for r in json.loads(self.xray('lsrules').stdout).get('rules',[])}
                if SPEED_PREFIX+cid in tags:self.xray('rmrules',SPEED_PREFIX+cid)
            email=event['label']; tag=prefix+cid
            config={'routing':{'rules':[{'type':'field','ruleTag':tag,'user':[email],'outboundTag':'blocked'}]}}
            self.xray('adrules','-append','stdin:',text=json.dumps(config))
            # Close only authenticated peer endpoints. Never disconnect an entire public IP.
            terms=[]
            for peer in peers:
                if len(peer)!=3:continue
                addr,port,inbound=peer; local_port=self.ports.get(inbound)
                if not local_port or not ip(addr) or not 1<=port<=65535:continue
                terms.append('( dst '+addr+' and dport = :'+str(port)+' and sport = :'+str(local_port)+' )')
            if terms:
                try:
                    r=command(['ss','-Knt','( '+' or '.join(terms[:64])+' )'],required=False)
                    if r.returncode:event['close_warning']='Сброс TCP: '+r.stderr[:160]
                except Exception:event['close_warning']='Не удалось сбросить активные TCP-сокеты'
            event['method']='Xray: правило по учётной записи + сброс известных TCP-соединений'
            if not terms:event['close_warning']='Старые соединения без известного TCP endpoint могут сохраниться'
        elif source=='mieru':
            if not self.mieru:raise RuntimeError('Mieru cgroup is unavailable')
            users=json.loads(command(['mita','describe','config']).stdout).get('users',[])
            if len(users)!=1 or uid('mieru',users[0]['name'])!=cid:
                raise RuntimeError('Mieru single-user mapping changed')
            command(['nft','-f','-'],text='add element inet '+table+' mita_block { 0'+expiry+' }\n')
            event['method']='Mieru: единственная учётная запись, cgroup службы'
        else:
            iface=event.get('interface',''); addr=ip(event.get('internal',''))
            net=next((x.get('network') for x in self.config.get('interfaces',[])
                     if x['name']==iface and x['source']==source),None)
            if not net or not addr or ipaddress.ip_address(addr) not in ipaddress.ip_network(net):
                raise RuntimeError('Unverified tunnel endpoint')
            if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}',iface):raise ValueError('interface')
            version=ipaddress.ip_address(addr).version
            command(['nft','-f','-'],text='add element inet '+table+' clients'+str(version)+
                    ' { "'+iface+'" . '+addr+expiry+' }\n')
            event['method']='Туннель: '+iface+' / '+addr

    def ensure_adult(self):
        result=command(['nft','list','table','inet',ADULT_TABLE],required=False)
        if result.returncode:
            if 'No such file or directory' not in result.stderr:raise RuntimeError('Cannot inspect persistent firewall')
            script=nft_script(self.mieru).replace(TABLE,ADULT_TABLE).replace(' flags timeout; timeout 20s;','')
            command(['nft','-f','-'],text=script)

    def unblock_permanent(self,event):
        if event['source']=='xray':
            tags={r.get('ruleTag') for r in json.loads(self.xray('lsrules').stdout).get('rules',[])}
            if ADULT_PREFIX+event['client_id'] in tags:self.xray('rmrules',ADULT_PREFIX+event['client_id'])
            return
        if event['source']=='mieru':element='mita_block { 0 }'
        else:
            iface=event.get('interface','');addr=ip(event.get('internal',''))
            net=next((x.get('network') for x in self.config.get('interfaces',[]) if x['name']==iface and x['source']==event['source']),None)
            if not net or not addr or ipaddress.ip_address(addr) not in ipaddress.ip_network(net) or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}',iface):raise ValueError('Unverified endpoint')
            element='clients'+str(ipaddress.ip_address(addr).version)+' { "'+iface+'" . '+addr+' }'
        r=command(['nft','-f','-'],text='delete element inet '+ADULT_TABLE+' '+element+'\n',required=False)
        if r.returncode and 'No such file or directory' not in r.stderr:raise RuntimeError('Cannot release permanent firewall element')

    def unblock(self, event):
        if event['source']=='xray': self.xray('rmrules',PREFIX+event['client_id'])
        # nft set elements expire inside the kernel even if the collector stops.


class Policy:
    def __init__(self, config, backend=None, start=True, clock=time.time):
        self.config=config; self.settings=config.get('supercell_policy',{})
        self.clock=clock; self.seconds=int(self.settings.get('seconds',20))
        if not 1<=self.seconds<=3600:raise ValueError('Invalid block duration')
        self.exempt=set(self.settings.get('exempt_client_ids',[]))
        self.backend=backend or Backend(config)
        self.queue=queue.Queue(4096); self.submitted=collections.OrderedDict(); self.clients={}; self.active={}; self.seen=collections.OrderedDict()
        self.peers={}; self.addresses={}; self.events=collections.deque(maxlen=100)
        self.error=''; self.ready=False; self.stopping=threading.Event(); self.lock=threading.RLock()
        self.enabled=bool(self.settings.get('enabled',False))
        self.adult=AdultPolicy(self);self.speed=SpeedManager(self);self.apps=AppPolicy(self);self.catalog_next=0
        if start and (config.get('apps_policy') or config.get('speed_limits') or self.enabled or self.adult.enabled or self.adult.custom_enabled or self.adult.state['blocked']):
            threading.Thread(target=self.worker,daemon=True,name='supercell-policy').start()
            if self.enabled:threading.Thread(target=self.resolve,daemon=True,name='supercell-dns').start()

    def set_clients(self, clients, mieru_only):
        with self.lock:
            self.clients={c['id']:c.copy() for c in clients}; self.mieru_only=mieru_only;self.clients_loaded=True
            path=self.config.get('client_catalog')
            if path and self.clock()>=self.catalog_next:
                atomic_json(path,[{k:c.get(k,[]) if k=='ips' else c.get(k,'') for k in ('id','source','label','ips')} for c in self.clients.values()])
                self.catalog_next=self.clock()+15

    def submit(self, flow, interface='', internal='', peer=None):
        if not (self.apps.enabled or self.enabled or self.adult.enabled or self.adult.custom_enabled or self.adult.state['blocked']):return
        signature=(flow.get('id'),flow.get('domain'),flow.get('evidence'))
        if signature in self.submitted:return
        self.submitted[signature]=True
        while len(self.submitted)>20000:self.submitted.popitem(last=False)
        item={k:flow.get(k) for k in ('id','client_id','source','destination','domain','port','protocol','local_port','evidence','first_seen')}
        item.update(interface=interface,internal=internal,peer=peer)
        try:self.queue.put_nowait(item)
        except queue.Full:self.error='Переполнена очередь правил; часть наблюдений пропущена'

    def resolve(self):
        # Separate DNS thread: DNS failure cannot delay the 20 second unblock timer.
        while not self.stopping.is_set():
            found={}
            for host in GAME_HOSTS:
                try:
                    for addr,expiry in dns_records(host).items():found[addr]=(host,expiry)
                except Exception:pass
            with self.lock:
                now=self.clock()
                self.addresses={a:v for a,v in self.addresses.items() if v[1]>now}
                self.addresses.update(found)
            self.stopping.wait(30)

    def handle(self, f):
        now=self.clock(); cid=f.get('client_id'); source=f.get('source')
        with self.lock:c=self.clients.get(cid); only=getattr(self,'mieru_only','')
        peer=f.get('peer')
        if source=='xray' and cid and peer and ip(peer[0]):
            key=tuple(peer); entry=self.peers.setdefault(key,{})
            entry[cid]=now
        if not cid or not c or c['source']!=source:return
        if source not in ('xray','csqtt','wireguard','amnezia','mieru'):return
        if source=='mieru' and cid!=only:return
        peers=[p for p,owners in self.peers.items() if cid in owners and len(owners)==1 and now-owners[cid]<600]
        self.adult.handle(f,c,peers)
        self.apps.handle(f,c,peers)
        if not self.enabled or cid in self.exempt:return
        name=f.get('domain') or f.get('destination','')
        evidence=f.get('evidence','')
        direct=evidence in ('Xray access','TLS SNI','HTTP Host') and matches_domain(name)
        resolved=self.addresses.get(f.get('destination',''))
        game_ip=resolved and resolved[1]>now and int(f.get('port') or 0)==9339
        if not direct and not game_ip:return
        # A flow triggers once, and repeated attempts cannot extend an active block.
        fid=f.get('id')
        if fid in self.seen:return
        self.seen[fid]=now
        while len(self.seen)>20000:self.seen.popitem(last=False)
        if cid in self.active:return
        event={'client_id':cid,'label':c['label'],'source':source,'domain':name if direct else resolved[0],
               'destination':f.get('destination',''),'evidence':evidence if direct else 'DNS игрового сервера + порт 9339',
               'started':now,'until':now+self.seconds,'state':'blocking','interface':f.get('interface',''),'internal':f.get('internal','')}
        peers=[p for p,owners in self.peers.items() if cid in owners and len(owners)==1 and now-owners[cid]<600]
        try:
            # Retain the cleanup target before the API mutation, including partial failures.
            self.active[cid]=event
            self.backend.block(event,self.seconds,peers)
            event['until']=self.clock()+self.seconds;event['state']='blocked'
        except Exception as e:
            event['state']='error';event['error']=str(e)[:200];event['until']=now
            self.error=event['error']
        self.events.append(event)
        self.persist()

    def tick(self):
        self.adult.tick()
        now=self.clock()
        for cid,event in list(self.active.items()):
            if event['until']>now:continue
            try:
                self.backend.unblock(event)
                event['state']='released' if event['state']!='error' else 'error'
                event['released']=now;del self.active[cid];self.persist();self.speed.next_check=0
            except Exception as e:self.error='Снятие блокировки: '+str(e)[:180]
        self.peers={p:{cid:t for cid,t in owners.items() if now-t<600} for p,owners in self.peers.items()}
        self.peers={p:o for p,o in self.peers.items() if o}
        self.apps.tick()
        self.speed.tick()

    def persist(self):
        path=self.settings.get('state_file')
        if not path:return
        p=pathlib.Path(path);tmp=p.with_suffix('.tmp')
        tmp.write_text(json.dumps(list(self.events),ensure_ascii=False),encoding='utf8');tmp.chmod(0o600);tmp.replace(p)

    def worker(self):
        # Xray may start later than the collector at boot; retry without a VPN restart.
        while not self.stopping.is_set():
            try:
                self.backend.initialize();self.ready=True;self.error='';break
            except Exception as e:
                self.error='Правило ожидает запуска служб: '+str(e)[:160]
                self.stopping.wait(5)
        if not self.ready:return
        try:
            while not self.stopping.is_set():
                self.tick()
                try:self.handle(self.queue.get(timeout=.2))
                except queue.Empty:pass
                except Exception as e:self.error=type(e).__name__+': '+str(e)[:160]
        except Exception as e:self.error='Правило остановлено: '+str(e)[:180]
        finally:
            self.ready=False
            try:self.backend.cleanup()
            except Exception as e:self.error='Очистка правил: '+str(e)[:160]

    def statuses(self):return [self.status(),self.adult.status(),self.adult.custom_status(),self.speed.status(),self.apps.status()]

    def status(self):
        now=self.clock()
        return {'source':'supercell-policy','ok':not self.enabled or (self.ready and not self.error),
          'message':('Supercell → отключение VPN на '+str(self.seconds)+' сек. Исключения: '+str(len(self.exempt))+'.' if self.enabled else 'Автоматическая блокировка выключена'),
          'enabled':self.enabled,'seconds':self.seconds,'exempt_client_ids':sorted(self.exempt),
          'active':[{k:v for k,v in e.items() if k not in ('interface','internal')} for e in list(self.active.values())],
          'events':list(self.events)[-20:],'error':self.error,'game_addresses':sum(v[1]>now for v in self.addresses.values()),
          'limitations':'ECH/QUIC и неизвестные IP могут скрывать Supercell. OpenFlux и Docker без привязки к клиенту не блокируются.',
          'backend_errors':self.backend.errors if hasattr(self.backend,'errors') else []}


def main():
    p=argparse.ArgumentParser();p.add_argument('--cleanup',action='store_true');p.add_argument('--config',default='/etc/tunnelscope/collector.json')
    args=p.parse_args();config=json.loads(pathlib.Path(args.config).read_text())
    if args.cleanup:Backend(config).cleanup()

if __name__=='__main__':main()
