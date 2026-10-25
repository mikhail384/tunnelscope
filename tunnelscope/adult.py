"""Persistent per-account restrictions and bounded-memory domain classification."""
import argparse
import functools
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import sqlite3
import tempfile
import time
import urllib.request
from .common import domain

PREFIX = 'tunnelscope-adult-'
TABLE = 'tunnelscope_adult'
CID = re.compile(r'^(xray|csqtt|mieru|wireguard|amnezia):[0-9a-f]{20}$')
SOURCE = 'https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt'
STATE_DIR = '/var/lib/tunnelscope-policy'


def atomic_json(path, value):
    path=pathlib.Path(path)
    with tempfile.NamedTemporaryFile(mode='w',encoding='utf8',dir=path.parent,prefix='.state-',delete=False) as f:
        temporary=pathlib.Path(f.name)
        try:
            os.chmod(temporary,0o600);json.dump(value,f,ensure_ascii=False);f.flush();os.fsync(f.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True);raise
    try:os.replace(temporary,path)
    finally:temporary.unlink(missing_ok=True)


def read_state(path):
    p=pathlib.Path(path)
    if not p.exists():return {'blocked':{},'history':[]}
    value=json.loads(p.read_text(encoding='utf8'))
    if not isinstance(value,dict) or not isinstance(value.get('blocked'),dict):raise ValueError('Invalid denial state')
    return value


def hostname(name):
    name=str(name).strip().lower().rstrip('.')
    if len(name)>253 or '.' not in name:return ''
    try:ipaddress.ip_address(name);return ''
    except ValueError:pass
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in name.split('.')):return ''
    return name if len(name.rsplit('.',1)[1])>=2 else ''


class DomainList:
    def __init__(self,path):self.path=pathlib.Path(path);self.db=None;self.version=0;self.count=0;self.checked=None
    def refresh(self):
        now=time.monotonic()
        if self.checked is not None and now-self.checked<60:return
        self.checked=now
        version=self.path.stat().st_mtime_ns
        if version==self.version:return
        db=sqlite3.connect(self.path.resolve().as_uri()+'?mode=ro',uri=True,check_same_thread=False)
        db.execute('PRAGMA cache_size=-2048');db.execute('PRAGMA mmap_size=0')
        count=int(db.execute('select value from metadata where key="count"').fetchone()[0])
        old=self.db;self.db=db;self.version=version;self.count=count;self.contains.cache_clear()
        if old:old.close()
    @functools.lru_cache(maxsize=4096)
    def contains(self,name):
        name=hostname(name)
        if not name or not self.db:return False
        parts=name.split('.');suffixes=['.'.join(parts[i:]) for i in range(len(parts)-1)]
        return self.db.execute('select 1 from domains where name in ('+','.join('?'*len(suffixes))+') limit 1',suffixes).fetchone() is not None


def update_list(path,source=SOURCE):
    """Data only: fixed HTTPS source, complete download, atomic SQLite replacement."""
    path=pathlib.Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.adult-list-',dir=path.parent);os.close(fd)
    db=sqlite3.connect(tmp);digest=hashlib.sha256();size=0;count=0;expected=0
    try:
        db.execute('PRAGMA journal_mode=OFF');db.execute('PRAGMA cache_size=-4096')
        db.execute('create table domains(name text primary key) without rowid');db.execute('create table metadata(key text primary key,value text)')
        request=urllib.request.Request(source,headers={'User-Agent':'TunnelScope/1.1 domain-list updater'})
        with urllib.request.urlopen(request,timeout=45) as response:
            if not response.url.startswith('https://raw.githubusercontent.com/'):raise ValueError('Unexpected redirect')
            length=int(response.headers.get('Content-Length') or 0)
            batch=[]
            for raw in response:
                size+=len(raw);digest.update(raw)
                if size>64000000 or len(raw)>4096:raise ValueError('List exceeds size limit')
                line=raw.decode('utf8').strip()
                if line.startswith('# Entries:'):
                    expected=int(line.split(':',1)[1].strip().replace(',',''))
                fields=line.split('#',1)[0].split()
                if len(fields)==2 and fields[0] in ('0.0.0.0','127.0.0.1'):
                    name=hostname(fields[1])
                    if name:batch.append((name,))
                if len(batch)>=5000:
                    db.executemany('insert or ignore into domains values(?)',batch);batch=[]
            if length and size!=length:raise ValueError('Incomplete download')
            if batch:db.executemany('insert or ignore into domains values(?)',batch)
        count=db.execute('select count(*) from domains').fetchone()[0]
        if count<100000 or expected and count<expected*.98:raise ValueError('Incomplete or invalid domain list')
        metadata={'count':str(count),'sha256':digest.hexdigest(),'updated':str(time.time()),'source':source}
        db.executemany('insert into metadata values(?,?)',metadata.items());db.commit();db.close();db=None
        os.chmod(tmp,0o600)
        with open(tmp,'rb') as f:os.fsync(f.fileno())
        os.replace(tmp,path)
        return metadata
    finally:
        if db:db.close()
        pathlib.Path(tmp).unlink(missing_ok=True)


class AdultPolicy:
    def __init__(self,owner):
        self.owner=owner;self.settings=owner.config.get('adult_policy',{})
        self.enabled=bool(self.settings.get('enabled',False));self.exempt=set(self.settings.get('exempt_client_ids',[]))
        self.custom=owner.config.get('custom_policy',{})
        self.custom_enabled=bool(self.custom.get('enabled',False));self.custom_exempt=set(self.custom.get('exempt_client_ids',[]))
        self.global_sites=set(self.custom.get('domains',[]))
        self.client_sites={cid:set(values) for cid,values in self.custom.get('client_domains',{}).items()}
        self.path=self.settings.get('state_file',STATE_DIR+'/denials.json')
        # Legacy installations and unit tests do not have this rule configured.
        self.state=read_state(self.path) if self.settings or self.custom else {'blocked':{},'history':[]}
        self.domains=DomainList(self.settings.get('list_file',STATE_DIR+'/adult-domains.db'))
        self.error='';self.next_check=0;self.table_ready=False
    def save(self):atomic_json(self.path,self.state)
    def handle(self,f,c,peers):
        cid=c['id']
        if cid in self.state['blocked']:
            event=self.state['blocked'][cid]
            if c['source'] not in ('xray','mieru') and f.get('internal') in c.get('ips',[]) and (event.get('internal')!=f['internal'] or event.get('interface')!=f.get('interface')):
                self.owner.backend.unblock_permanent(event)
                event.update(internal=f['internal'],interface=f.get('interface',''),state='pending')
                self.save();self.apply(event,peers);self.save()
            return
        if not (self.enabled or self.custom_enabled):return
        if f.get('evidence') not in ('TLS SNI','HTTP Host','Xray access'):return
        name=hostname(f.get('domain',''))
        if not name:return
        from .sites import match_domain
        custom=self.custom_enabled and cid not in self.custom_exempt and (match_domain(name,self.global_sites) or match_domain(name,self.client_sites.get(cid,set())))
        adult=self.enabled and cid not in self.exempt and self.domains.contains(name)
        if not custom and not adult:return
        event={'client_id':cid,'source':c['source'],'label':c['label'],'domain':name,
          'evidence':f['evidence'],'rule':'custom' if custom else 'adult','started':self.owner.clock(),'state':'pending',
          'interface':f.get('interface',''),'internal':f.get('internal','')}
        self.state['blocked'][cid]=event;self.save()  # Durable intent before firewall/API changes.
        self.apply(event,peers);self.save()
    def apply(self,event,peers):
        try:
            self.owner.backend.block(event,None,peers);event['state']='blocked';event.pop('error',None)
        except Exception as e:
            event['state']='pending';event['error']=str(e)[:180];self.error=event['error']
    def tick(self):
        now=self.owner.clock()
        if not (self.settings or self.custom) or now<self.next_check or not getattr(self.owner,'clients_loaded',False):return
        self.next_check=now+15;self.error=''
        if self.enabled:
            try:self.domains.refresh()
            except Exception as e:self.error='Список доменов недоступен: '+str(e)[:140]
        if not self.state['blocked']:return
        try:
            b=self.owner.backend;b.ensure_adult()
            tags={r.get('ruleTag') for r in json.loads(b.xray('lsrules').stdout).get('rules',[])}
            for cid,event in self.state['blocked'].items():
                c=self.owner.clients.get(cid)
                if not c or c['source']!=event['source']:
                    # Native account was removed: do not keep dropping an IP reused by another user.
                    if event['source']!='xray':b.unblock_permanent(event)
                    event['state']='pending';event['error']='Учётная запись не найдена';continue
                if c['source']=='mieru' and getattr(self.owner,'mieru_only','')!=cid:
                    b.unblock_permanent(event);event['state']='pending';event['error']='Несколько пользователей Mieru: блокировка службы снята';continue
                if c['source'] not in ('xray','mieru') and event.get('internal') not in c.get('ips',[]):
                    b.unblock_permanent(event);event['state']='pending';event['error']='Адрес устройства изменился; ожидается новое обращение';continue
                if c['source']!='xray' or PREFIX+cid not in tags:
                    self.apply(event,[])
                elif event['state']!='blocked':event['state']='blocked';event.pop('error',None)
            self.save()
        except Exception as e:self.error='Применение постоянных блокировок: '+str(e)[:160]
    def status(self):
        return {'source':'adult-policy','ok':not self.error,'enabled':self.enabled,
          'message':'Домены 18+ → отключение интернета до ручного разрешения' if self.enabled else 'Новые блокировки 18+ выключены; ранее заблокированные клиенты остаются заблокированы',
          'error':self.error,'list_count':self.domains.count,'exempt_client_ids':sorted(self.exempt),
          'blocked':list(self.state['blocked'].values()),'list_source':'https://github.com/blocklistproject/Lists'}

    def custom_status(self):
        return {'source':'custom-policy','enabled':self.custom_enabled,'ok':not self.error,
          'message':'Запрещённые сайты → отключение интернета до ручного разрешения' if self.custom_enabled else 'Новые блокировки по вашим спискам выключены',
          'error':self.error,'global_count':len(self.global_sites),
          'personal_count':sum(len(v) for v in self.client_sites.values())}


def main():
    p=argparse.ArgumentParser();p.add_argument('--update-list',action='store_true');p.add_argument('--path',default=STATE_DIR+'/adult-domains.db');a=p.parse_args()
    if a.update_list:print(json.dumps(update_list(a.path)))
if __name__=='__main__':main()
