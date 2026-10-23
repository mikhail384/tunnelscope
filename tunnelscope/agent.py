"""Privileged collector. Reads VPN counters and network metadata; never stores payloads."""
import argparse
import collections
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import selectors
import socket
import sqlite3
import struct
import subprocess
import time
import uuid
from .common import uid, domain, ip, parse_ip, tls_sni, http_host, dns_answers
from .policy import Policy


def run(args, timeout=8):
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if r.returncode:
        raise RuntimeError('command failed: ' + args[0])
    return r.stdout


def readonly(path):
    c = sqlite3.connect('file:' + path + '?mode=ro', uri=True, timeout=1)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA query_only=ON')
    return c


def native_clients(config):
    clients, statuses = [], []
    # Read only selected columns, never users/passwords/keys or subscription URLs.
    try:
        with readonly(config['xui_db']) as c:
            rows = c.execute('SELECT email,SUM(up) up,SUM(down) down,MAX(last_online) last_online FROM client_traffics GROUP BY email').fetchall()
            for row in rows:
                clients.append({'id':uid('xray',row['email']), 'label':row['email'], 'source':'xray', 'ips':[], 'up':row['up'] or 0, 'down':row['down'] or 0, 'last_seen':(row['last_online'] or 0)/1000})
        statuses.append({'source':'xray','ok':True,'message':'Счётчики 3x-ui, чтение базы','clients':len(rows)})
    except Exception as e:
        statuses.append({'source':'xray','ok':False,'message':'Нет доступа к счётчикам: '+type(e).__name__})
    try:
        with readonly(config['csqtt_db']) as c:
            rows=c.execute('SELECT d.device_id,d.ip,d.up_bytes,d.down_bytes,MAX(p.name) name FROM devices d LEFT JOIN passwords p ON p.device_id=d.device_id GROUP BY d.device_id').fetchall()
            for row in rows:
                clients.append({'id':uid('csqtt',row['device_id']), 'label':row['name'] or ('CSQTT '+row['ip']), 'source':'csqtt', 'ips':[row['ip']], 'up':row['up_bytes'] or 0, 'down':row['down_bytes'] or 0})
        statuses.append({'source':'csqtt','ok':True,'message':'Счётчики устройств и адреса туннеля','clients':len(rows)})
    except Exception as e:
        statuses.append({'source':'csqtt','ok':False,'message':type(e).__name__})
    try:
        metrics=json.loads(run(['mita','get','metrics']))
        rows=[(k[7:],v) for k,v in metrics.items() if k.startswith('user - ')]
        for name, values in rows:
            clients.append({'id':uid('mieru',name),'label':name,'source':'mieru','ips':[], 'up':values.get('UploadBytes',0),'down':values.get('DownloadBytes',0)})
        statuses.append({'source':'mieru','ok':True,'message':'mita get metrics · индивидуальные счётчики','clients':len(rows)})
    except Exception as e:
        statuses.append({'source':'mieru','ok':False,'message':type(e).__name__})
    return clients, statuses


def sockets_by_process():
    """Map local ephemeral endpoints to a service, not falsely to a user."""
    inode_source={}
    allowed={'xray-linux-amd6':'xray-egress','xray-linux-amd64':'xray-egress','mita':'mieru-egress','openflux':'openflux','csqtt':'csqtt-egress'}
    for p in pathlib.Path('/proc').iterdir():
        if not p.name.isdigit():
            continue
        try:
            source=allowed.get((p/'comm').read_text().strip())
            if not source:
                continue
            for fd in (p/'fd').iterdir():
                try:
                    dest=os.readlink(fd)
                    if dest.startswith('socket:['):
                        inode_source[dest[8:-1]]=source
                except OSError:
                    pass
        except OSError:
            pass
    mapping,listening={},set()
    for name in ('tcp','tcp6','udp','udp6'):
        try:
            lines=pathlib.Path('/proc/net/'+name).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields=line.split()
            try:
                port=int(fields[1].split(':')[1],16)
                if name.startswith('tcp') and fields[3]=='0A':
                    listening.add(port)
                if name.startswith('udp') and int(fields[2].split(':')[1],16)==0:
                    listening.add(port)
                if fields[9] in inode_source:
                    mapping[('TCP' if name.startswith('tcp') else 'UDP',port)]=inode_source[fields[9]]
            except (ValueError,IndexError):
                pass
    return mapping,listening


def send_batch(path, batch):
    raw=json.dumps(batch,separators=(',',':'),ensure_ascii=False).encode()
    if len(raw)>4*1024*1024:
        raise ValueError('batch too large')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(path)
        s.sendall(struct.pack('!I',len(raw))+raw)
        if s.recv(2)!=b'OK':
            raise RuntimeError('ingest rejected')


class Collector:
    def __init__(self, config):
        self.config=config
        self.policy=Policy(config)
        self.selector=selectors.DefaultSelector()
        self.boot=uuid.uuid4().hex[:12]
        self.flows=collections.OrderedDict()
        self.pending={}
        self.dns={}
        self.clients=[]
        self.ip_clients={}
        self.packet_clients={}
        self.status=[]
        self.logs={}
        self.processes={}
        self.listening=set()
        self.local_ips=set()
        self.mieru_only=''
        self.networks=[]
        self.capture_errors=[]
        self.packets=0
        self.dropped=0
        self.native_at=0
        self.socket_at=0
        self.flush_at=0
        self.window_at=time.monotonic()
        self.window_packets=0
        self.retry=None
        for item in config.get('interfaces',[]):
            net=ipaddress.ip_network(item['network']) if item.get('network') else None
            self.networks.append((item['name'],net,item['source']))
            try:
                s=socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(0x0003))
                s.bind((item['name'],0))
                s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,2*1024*1024)
                s.setblocking(False)
                self.selector.register(s,selectors.EVENT_READ,item)
            except OSError as e:
                self.capture_errors.append(item['name']+': '+type(e).__name__)
        try:
            for entry in json.loads(run(['ip','-json','address','show'])):
                self.local_ips.update(a['local'] for a in entry.get('addr_info',[]))
        except Exception:
            pass

    def refresh(self):
        present={k.data['name'] for k in self.selector.get_map().values()}
        self.capture_errors=[]
        for item in self.config.get('interfaces',[]):
            if item['name'] not in present:
                try:
                    s=socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(0x0003))
                    s.bind((item['name'],0))
                    s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,2*1024*1024)
                    s.setblocking(False)
                    self.selector.register(s,selectors.EVENT_READ,item)
                except OSError as e:
                    s.close()
                    self.capture_errors.append(item['name']+': '+type(e).__name__)
        for key in self.selector.get_map().values():
            try:
                stats=key.fileobj.getsockopt(263,6,12)
                self.dropped+=struct.unpack('II',stats[:8])[1]
            except OSError:
                pass
        self.clients,self.status=native_clients(self.config)
        try:
            users=json.loads(run(['mita','describe','config'])).get('users',[])
            candidate=uid('mieru',users[0]['name']) if len(users)==1 else ''
            self.mieru_only=candidate if any(c['id']==candidate for c in self.clients) else ''
        except Exception:
            self.mieru_only=''
        self.ip_clients={addr:c for c in self.clients for addr in c.get('ips',[]) if ip(addr)}
        for iface,net,source in self.networks:
            if source!='wireguard':
                continue
            try:
                allowed=run(['wg','show',iface,'allowed-ips'])
                transfer={row[0]:(int(row[1]),int(row[2])) for line in run(['wg','show',iface,'transfer']).splitlines() if len(row:=line.split())==3}
                for line in allowed.splitlines():
                    key,addresses=line.split(None,1)
                    addresses=[a.split('/')[0] for a in addresses.replace(',',' ').split() if ip(a.split('/')[0])]
                    up,down=transfer.get(key,(0,0))
                    c={'id':uid('wireguard',key),'source':'wireguard','label':'WireGuard '+(', '.join(addresses) or key[:6]),'ips':addresses,'up':up,'down':down}
                    self.clients.append(c)
                    self.ip_clients.update({a:c for a in addresses})
            except Exception:
                pass
        self.policy.set_clients(self.clients+list(self.packet_clients.values()),self.mieru_only)
        self.status.append({'source':'capture','ok':bool(self.selector.get_map()),'message':'DNS / TLS SNI / HTTP · IP-байты в точке наблюдения', 'interfaces':[k.data['name'] for k in self.selector.get_map().values()], 'packets':self.packets,'dropped':self.dropped,'errors':self.capture_errors,'flow_limit':self.config.get('max_flows',12000)})
        try:
            runtime=json.loads(pathlib.Path('/usr/local/x-ui/bin/config.json').read_text())
            log_enabled=runtime.get('log',{}).get('access')==self.config['xray_log']
        except Exception:
            log_enabled=False
        self.status.append({'source':'xray-log','ok':log_enabled,'message':('Домены и IP по учётным записям; журнал не содержит объёмы отдельных соединений' if log_enabled else 'Access-журнал Xray отключён: доступен только общий трафик пользователей')})

    def read_log(self):
        path=self.config['xray_log']
        try:
            p=pathlib.Path(path)
            stat=p.stat()
            state=self.logs.get(path)
            if not state or state[0]!=stat.st_ino or state[1]>stat.st_size:
                self.logs[path]=[stat.st_ino,stat.st_size if state is None else 0]
            state=self.logs[path]
            with p.open('r',encoding='utf8',errors='replace') as f:
                f.seek(state[1])
                for _ in range(3000):
                    line=f.readline()
                    if not line:
                        break
                    self.log_line(line)
                state[1]=f.tell()
        except OSError:
            pass

    def log_line(self,line):
        m=re.search(r'\baccepted\s+(tcp|udp):(.+?):(\d+)\s+.*?email:\s*(\S+)',line)
        if not m:
            return
        proto,dest,port,email=m.groups()
        dest=dest.strip('[]')
        now=time.time()
        fid=self.boot+':log:'+uuid.uuid4().hex
        self.pending[fid]={'id':fid,'client_id':uid('xray',email),'source':'xray','destination':dest,'port':int(port),'protocol':proto.upper(),'domain':domain(dest),'evidence':'Xray access','first_seen':now,'last_seen':now,'up':0,'down':0,'packets':0,'measurement':'log'}
        if hasattr(self,'policy'):
            peer=None
            match=re.search(r'\bfrom\s+(?:tcp:|udp:)?(\[[^\]]+\]|[^\s:]+):(\d+)\s+accepted',line)
            inbound=re.search(r'\[([^\s\]]+)\s+(?:>>|->|==>)',line)
            if match and inbound and ip(match[1].strip('[]')):peer=(match[1].strip('[]'),int(match[2]),inbound[1])
            self.policy.submit(self.pending[fid],peer=peer)

    def packet(self,item,raw):
        pkt=parse_ip(raw)
        if not pkt:
            return
        now=time.time()
        if item.get('network'):
            net=ipaddress.ip_network(item['network'])
            if ipaddress.ip_address(pkt['src']) in net and pkt['dst'] not in self.local_ips:
                internal,remote,lport,rport,upload=pkt['src'],pkt['dst'],pkt['sport'],pkt['dport'],True
            elif ipaddress.ip_address(pkt['dst']) in net and pkt['src'] not in self.local_ips:
                internal,remote,lport,rport,upload=pkt['dst'],pkt['src'],pkt['dport'],pkt['sport'],False
            else:
                return
            c=self.ip_clients.get(internal)
            if not c:
                cid=uid(item['source'],internal)
                c=self.packet_clients.setdefault(cid,{'id':cid,'source':item['source'],'label':item['source'].upper()+' '+internal,'ips':[internal],'up':0,'down':0})
                c['up' if upload else 'down']+=pkt['size']
            cid=c['id']; source=item['source']
            c['last_seen']=now
        else:
            if pkt['src'] in self.local_ips:
                internal,remote,lport,rport,upload=pkt['src'],pkt['dst'],pkt['sport'],pkt['dport'],True
            elif pkt['dst'] in self.local_ips:
                internal,remote,lport,rport,upload=pkt['dst'],pkt['src'],pkt['dport'],pkt['sport'],False
            else:
                return
            source=self.processes.get((pkt['protocol'],lport),'server')
            if (lport in self.listening and (pkt['protocol']=='TCP' or source in ('server','csqtt-egress'))) or lport==22 or remote in self.local_ips:
                return
            if source=='mieru-egress' and self.mieru_only:
                cid,source=self.mieru_only,'mieru'
            else:
                cid=''
        # Addresses inside the same tunnel are infrastructure, not site destinations.
        try:
            if ipaddress.ip_address(remote).is_loopback or ipaddress.ip_address(remote).is_link_local:
                return
        except ValueError:
            return
        key=(item['name'],internal,lport,remote,rport,pkt['protocol'])
        f=self.flows.get(key)
        if not f or now-f['last_seen']>120 or (upload and pkt['flags'] & 2 and not pkt['flags'] & 16 and now-f['first_seen']>2):
            f={'local_port':lport,'id':self.boot+':'+uuid.uuid4().hex,'client_id':cid,'source':source,'destination':remote,'port':rport,'protocol':pkt['protocol'],'domain':'','evidence':'IP','first_seen':now,'last_seen':now,'up':0,'down':0,'packets':0,'measurement':'observed','buffer':b'','nextseq':None}
            self.flows[key]=f
        if cid and not f['client_id']:
            f['client_id']=cid;f['source']=source
        f['last_seen']=now
        self.flows.move_to_end(key)
        if pkt['protocol']=='UDP' and pkt['sport']==53:
            for addr,name,ttl in dns_answers(pkt['payload']):
                if name:
                    self.dns[(internal,addr)]=(name,now+ttl)
        if upload and pkt['payload'] and (not f['domain'] or f['evidence'].startswith('DNS')) and pkt['protocol']=='TCP' and now-f['first_seen']<5:
            payload=pkt['payload']
            if not f['buffer'] and payload[:1]==b'\x16':
                f['buffer']=payload[:8192]
                f['nextseq']=(pkt['seq']+len(payload)) & 0xffffffff
            elif f['buffer'] and f['nextseq']==pkt['seq'] and len(f['buffer'])<8192:
                f['buffer']+=payload[:8192-len(f['buffer'])]
                f['nextseq']=(pkt['seq']+len(payload)) & 0xffffffff
            name=tls_sni(f['buffer']) if f['buffer'] else http_host(payload)
            if name:
                f['domain']=name
                f['evidence']='TLS SNI' if f['buffer'] else 'HTTP Host'
                f['buffer']=b''
        if not f['domain']:
            cached=self.dns.get((internal,remote))
            if cached and cached[1]>now:
                f['domain'],f['evidence']=cached[0],'DNS · предположение'
        if cid and upload and (f['domain'] or rport==9339):
            if cid in self.packet_clients:self.policy.set_clients(self.clients+list(self.packet_clients.values()),self.mieru_only)
            self.policy.submit(f,item['name'],internal)
        row=self.pending.get(f['id'])
        if not row:
            row={k:v for k,v in f.items() if k not in ('buffer','nextseq')}
            row.update(up=0,down=0,packets=0)
            self.pending[f['id']]=row
        row['domain'],row['evidence'],row['last_seen']=f['domain'],f['evidence'],now
        row['up' if upload else 'down']+=pkt['size']
        row['packets']+=1
        while len(self.flows)>self.config.get('max_flows',12000):
            self.flows.popitem(last=False)
        if len(self.pending)>15000:
            self.pending.pop(next(iter(self.pending)))
            self.dropped+=1

    def loop(self):
        while True:
            now=time.monotonic()
            if now-self.native_at>30:
                self.refresh(); self.native_at=now
                self.dns={k:v for k,v in self.dns.items() if v[1]>time.time()}
                for key in list(self.flows):
                    if time.time()-self.flows[key]['last_seen']>180:
                        del self.flows[key]
                    elif time.time()-self.flows[key]['first_seen']>5:
                        self.flows[key]['buffer']=b''
                if len(self.dns)>20000:
                    self.dns=dict(list(self.dns.items())[-20000:])
            if now-self.socket_at>5:
                self.processes,self.listening=sockets_by_process(); self.socket_at=now
            self.read_log()
            for key,_ in self.selector.select(.1):
                for _ in range(200):
                    try:
                        raw,_=key.fileobj.recvfrom(65535)
                    except BlockingIOError:
                        break
                    if now-self.window_at>=1:
                        self.window_at=now; self.window_packets=0
                    self.window_packets+=1
                    self.packets+=1
                    if self.window_packets>self.config.get('max_packets_per_second',4000):
                        self.dropped+=1
                        continue
                    self.packet(key.data,raw)
            if now-self.flush_at>3:
                if self.retry is None:
                    self.retry={'id':uuid.uuid4().hex,'clients':self.clients+list(self.packet_clients.values()),'flows':list(self.pending.values()),'status':self.status+self.policy.statuses()}
                    self.pending={}
                try:
                    send_batch(self.config['ingest_socket'],self.retry)
                    self.retry=None
                except Exception as e:
                    print('ingest: '+type(e).__name__,flush=True)
                self.flush_at=now


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--config',default='/etc/tunnelscope/collector.json')
    args=p.parse_args()
    Collector(json.loads(pathlib.Path(args.config).read_text())).loop()


if __name__=='__main__':
    main()
