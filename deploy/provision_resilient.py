"""Add an isolated 3x-ui test account and two transports; retain existing inbounds."""
import argparse
import base64
import copy
import datetime
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

ROOT=pathlib.Path('/etc/tunnelscope/resilient-client')
DB=pathlib.Path('/etc/x-ui/x-ui.db')
RUNTIME=pathlib.Path('/usr/local/x-ui/bin/config.json')
STREAM=pathlib.Path('/etc/nginx/stream-enabled/stream.conf')
SITE=pathlib.Path('/etc/nginx/sites-enabled/vpn.example.org')
XRAY='/usr/local/x-ui/bin/xray-linux-amd64'
HOST='vpn.example.org'
ADDRESS='203.0.113.10'
COVER='www.microsoft.com'
EMAIL='RU-Resilient-Test'
PORTS=(18443,18081)


def run(args,stdin=None,timeout=12):
 r=subprocess.run(args,input=stdin,text=True,capture_output=True,timeout=timeout)
 if r.returncode:raise RuntimeError(args[0]+': '+r.stderr[-240:])
 return r.stdout


def api(action,*args,data=None):
 return run([XRAY,'api',action,'--server=127.0.0.1:62789','-t=4',*args],json.dumps(data) if data is not None else None)


def write(path,text):
 p=pathlib.Path(path);p.write_text(text,encoding='utf8');p.chmod(0o600)


def dump(path,value):write(path,json.dumps(value,ensure_ascii=False,indent=2)+'\n')

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=True).encode()).hexdigest()

def connect_db():
 c=sqlite3.connect(DB,timeout=10);c.row_factory=sqlite3.Row;return c


def core_inbound(row):
 stream=json.loads(row['stream_settings']);stream.pop('externalProxy',None)
 if stream.get('security')=='reality':stream['realitySettings'].pop('settings',None)
 settings=json.loads(row['settings'])
 settings['clients']=[{k:v for k,v in c.items() if k in ('id','email','flow','level')} for c in settings['clients']]
 return {'tag':row['tag'],'listen':row['listen'],'port':row['port'],'protocol':'vless',
         'settings':settings,'streamSettings':stream,'sniffing':json.loads(row['sniffing'])}


def client_config(manifest,kind,address=ADDRESS,local_port=10808):
 reality=kind=='reality'
 settings={'vnext':[{'address':address,'port':443,'users':[{'id':manifest['uuid'],'encryption':'none',**({'flow':'xtls-rprx-vision'} if reality else {})}]}]}
 stream={'network':'tcp' if reality else 'xhttp','security':'reality' if reality else 'tls'}
 if reality:stream['realitySettings']={'serverName':COVER,'fingerprint':'chrome','password':manifest['public_key'],'shortId':manifest['short_id'],'spiderX':'/'}
 else:
  stream['tlsSettings']={'serverName':HOST,'fingerprint':'chrome','allowInsecure':False,'alpn':['h2']}
  stream['xhttpSettings']={'host':HOST,'path':manifest['path'],'mode':'packet-up'}
 return {'log':{'loglevel':'warning'},'inbounds':[{'tag':'local-socks','listen':'127.0.0.1','port':local_port,'protocol':'socks','settings':{'auth':'noauth','udp':True}}],
         'outbounds':[{'tag':'proxy','protocol':'vless','settings':settings,'streamSettings':stream},
                      {'tag':'direct','protocol':'freedom','settings':{}},{'tag':'blocked','protocol':'blackhole','settings':{}}]}


def uri(manifest,kind):
 reality=kind=='reality'
 params={'encryption':'none','type':'tcp' if reality else 'xhttp','security':'reality' if reality else 'tls','fp':'chrome','sni':COVER if reality else HOST}
 if reality:params.update(flow='xtls-rprx-vision',pbk=manifest['public_key'],sid=manifest['short_id'],spx='/')
 else:params.update(host=HOST,path=manifest['path'],mode='packet-up',alpn='h2')
 label='RU TEST - REALITY Vision' if reality else 'RU TEST - XHTTP TLS'
 return 'vless://'+manifest['uuid']+'@'+ADDRESS+':443?'+urllib.parse.urlencode(params)+'#'+urllib.parse.quote(label)


def prepare():
 if (ROOT/'manifest.json').exists():
  m=json.loads((ROOT/'manifest.json').read_text());print('Existing prepared account:',m['email'],'applied:',m.get('applied',False),flush=True);return m
 ROOT.mkdir(mode=0o700);backup=ROOT/'backup';backup.mkdir(mode=0o700);exports=ROOT/'exports';exports.mkdir(mode=0o700)
 c=connect_db();rows=[dict(r) for r in c.execute('select * from inbounds')];settings=dict(c.execute('select key,value from settings'))
 if any(EMAIL==x.get('email') for r in rows for x in json.loads(r['settings']).get('clients',[])):raise RuntimeError('Account already exists outside manifest')
 if any(r['port'] in PORTS for r in rows):raise RuntimeError('Test ports already assigned')
 for port in PORTS:
  with socket.socket() as probe:probe.bind(('127.0.0.1',port))
 target=sqlite3.connect(backup/'x-ui.db');c.backup(target);target.close();(backup/'x-ui.db').chmod(0o600)
 for src,name in [(RUNTIME,'runtime.json'),(STREAM,'stream.conf'),(SITE.resolve(),'site.conf')]:shutil.copy2(src,backup/name);(backup/name).chmod(0o600)
 old=json.loads(RUNTIME.read_text());keylines=run([XRAY,'x25519']).splitlines();keys={k.lower().replace(' ',''):v.strip() for line in keylines if ':' in line for k,v in [line.split(':',1)]}
 private=keys.get('privatekey','');public=next((v for k,v in keys.items() if k.startswith('password') or k=='publickey'),'')
 if not re.fullmatch(r'[A-Za-z0-9_-]{43}',private) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',public):raise ValueError('Unexpected key generation format')
 m={'email':EMAIL,'uuid':str(uuid.uuid4()),'sub_id':secrets.token_urlsafe(24),'short_id':secrets.token_hex(8),'public_key':public,
    'path':'/ru-'+secrets.token_hex(12),'created':time.time(),'baseline':{str(r['id']):digest({k:v for k,v in r.items() if k not in ('up','down','last_traffic_reset_time')}) for r in rows},
    'old_tags':sorted(i['tag'] for i in old['inbounds']),'xray_pid':run(['systemctl','show','x-ui','-p','MainPID','--value']).strip(),
    'subscription':settings['subURI'].rstrip('/')+'/'+str('PLACEHOLDER'),'applied':False,'inserted_ids':[]}
 m['subscription']=settings['subURI'].rstrip('/')+'/'+m['sub_id']
 sample=json.loads(next(r for r in rows if r['id']==1)['settings'])['clients'][0]
 client={k:copy.deepcopy(v) for k,v in sample.items()};client.update(id=m['uuid'],email=EMAIL,enable=True,expiryTime=0,totalGB=0,limitIp=0,subId=m['sub_id'],tgId='',reset=0,comment='Separate test account',created_at=int(time.time()*1000),updated_at=int(time.time()*1000),password='',auth='')
 planned=[]
 for kind,port,template_id in [('reality',PORTS[0],1),('xhttp',PORTS[1],3)]:
  row=copy.deepcopy(next(r for r in rows if r['id']==template_id));row.pop('id');row.update(up=0,down=0,total=0,enable=1,expiry_time=0,listen='127.0.0.1',port=port,tag='in-'+str(port)+'-tcp',remark='RU TEST - '+('REALITY Vision' if kind=='reality' else 'XHTTP TLS'),sub_sort_index=0,exclude_from_sub=0)
  cc=copy.deepcopy(client)
  if kind=='reality':cc['flow']='xtls-rprx-vision'
  else:cc.pop('flow',None)
  row['settings']=json.dumps({'clients':[cc],'decryption':'none','fallbacks':[]})
  if kind=='reality':
   stream={'network':'tcp','security':'reality','tcpSettings':{'acceptProxyProtocol':True,'header':{'type':'none'}},
    'realitySettings':{'show':False,'xver':0,'target':COVER+':443','serverNames':[COVER],'privateKey':private,'shortIds':[m['short_id']],
       'settings':{'publicKey':public,'fingerprint':'chrome','serverName':COVER,'spiderX':'/','mldsa65Verify':''}},
    'externalProxy':[{'forceTls':'same','dest':ADDRESS,'port':443,'remark':''}]}
  else:
   stream={'network':'xhttp','security':'none','xhttpSettings':{'host':HOST,'path':m['path'],'mode':'auto','xPaddingBytes':'100-1000','scMaxBufferedPosts':30,'scMaxEachPostBytes':'1000000'},
    'externalProxy':[{'forceTls':'tls','dest':HOST,'port':443,'remark':''}]}
  row['stream_settings']=json.dumps(stream);row['sniffing']=json.dumps({'enabled':True,'destOverride':['http','tls','quic'],'routeOnly':True});planned.append(row)
 m['rows']=planned
 stream=STREAM.read_text()
 if 'ru_test_reality' in stream or COVER in stream:raise RuntimeError('SNI route already exists')
 match=re.search(r'^\s*default\s+xray;[^\n]*$',stream,re.M)
 if not match:raise RuntimeError('Unexpected stream routing layout')
 stream=stream[:match.start()]+'    '+COVER+' ru_test_reality;\n'+stream[match.start():]
 stream+='\n# Isolated RU test profile\nupstream ru_test_reality { server 127.0.0.1:'+str(PORTS[0])+'; }\n'
 write(ROOT/'stream.new.conf',stream)
 site=SITE.resolve().read_text();idx=site.rfind('}')
 location='\n    # Isolated RU XHTTP test profile\n    location ^~ '+m['path']+' {\n        client_max_body_size 0;\n        client_body_timeout 1h;\n        grpc_pass grpc://127.0.0.1:'+str(PORTS[1])+';\n        grpc_buffer_size 16k;\n        grpc_socket_keepalive on;\n        grpc_read_timeout 1h;\n        grpc_send_timeout 1h;\n        grpc_set_header Connection "";\n        grpc_set_header Host $host;\n        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        grpc_set_header X-Forwarded-Proto https;\n    }\n'
 write(ROOT/'site.new.conf',site[:idx]+location+site[idx:])
 candidate=copy.deepcopy(old);candidate['inbounds'] += [core_inbound(row) for row in planned];dump(ROOT/'candidate.json',candidate)
 run([XRAY,'run','-test','-config',str(ROOT/'candidate.json')])
 for kind in ('reality','xhttp'):
  dump(exports/(kind+'.json'),client_config(m,kind));run([XRAY,'run','-test','-config',str(exports/(kind+'.json'))])
 links=[uri(m,'reality'),uri(m,'xhttp')];write(exports/'connections.txt','\n'.join(links)+'\n');write(exports/'subscription-url.txt',m['subscription']+'\n')
 write(exports/'subscription-base64.txt',base64.b64encode('\n'.join(links).encode()).decode()+'\n')
 write(exports/'README-ru.txt','RU-Resilient-Test\n\n1. Сначала попробуйте REALITY Vision. Запасной профиль: XHTTP TLS.\n2. Добавьте адрес из subscription-url.txt в совместимое приложение либо импортируйте ссылки из connections.txt.\n3. Нужен клиент с поддержкой VLESS REALITY Vision / XHTTP и актуальным ядром Xray.\n4. JSON-файлы содержат локальный SOCKS на 127.0.0.1:10808. Запускайте один профиль за раз.\n5. Существующие аккаунты не заменены. Новый аккаунт подчиняется текущим правилам TunnelScope.\n6. Проверка на сервере не доказывает доступность у вашего оператора. При блокировке IP потребуются другой адрес или отдельный маршрут.\n\nФайлы содержат ключи доступа: не публикуйте их.\n')
 dump(ROOT/'manifest.json',m);c.close();print('Prepared:',EMAIL,'profiles:',2,'public port: 443; old inbounds preserved',flush=True);return m


def socks_connect(port,host,target_port):
 s=socket.create_connection(('127.0.0.1',port),timeout=15);s.settimeout(20);s.sendall(b'\x05\x01\x00')
 if s.recv(2)!=b'\x05\x00':raise RuntimeError('SOCKS greeting')
 name=host.encode();s.sendall(b'\x05\x01\x00\x03'+bytes([len(name)])+name+target_port.to_bytes(2,'big'))
 def read(n):
  out=b''
  while len(out)<n:
   data=s.recv(n-len(out))
   if not data:raise RuntimeError('SOCKS response truncated')
   out+=data
  return out
 header=read(4)
 if header[1]:raise RuntimeError('SOCKS connect rejected: '+str(header[1]))
 length={1:4,4:16}.get(header[3])
 if header[3]==3:length=read(1)[0]
 if length is None:raise RuntimeError('SOCKS address type')
 read(length+2);return s


def test_profile(m,kind):
 with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
 path=ROOT/('check-'+kind+'.json');dump(path,client_config(m,kind,local_port=port))
 log=open(ROOT/('check-'+kind+'.log'),'w');os.chmod(ROOT/('check-'+kind+'.log'),0o600)
 process=subprocess.Popen([XRAY,'run','-config',str(path)],stdout=log,stderr=log)
 try:
  for _ in range(50):
   if process.poll() is not None:raise RuntimeError(kind+' client exited')
   try:
    with socket.create_connection(('127.0.0.1',port),timeout=.2):break
   except OSError:time.sleep(.1)
  sock=socks_connect(port,'example.com',443)
  with ssl.create_default_context().wrap_socket(sock,server_hostname='example.com') as s:
   s.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n');data=b''
   while len(data)<100000:
    part=s.recv(8192)
    if not part:break
    data+=part
   if b'200 OK' not in data or b'Example Domain' not in data:raise RuntimeError(kind+' HTTPS content verification failed')
  print('PASS',kind,'VLESS -> HTTPS with certificate verification',flush=True)
 finally:
  process.terminate()
  try:process.wait(timeout=5)
  except subprocess.TimeoutExpired:process.kill();process.wait()
  log.close()


def rollback(m):
 for row in m['rows']:
  try:api('rmi',row['tag'])
  except Exception:pass
 c=connect_db()
 with c:
  if m.get('client_record_id'):
   record=c.execute('select id from clients where id=? and email=? and uuid=?',(m['client_record_id'],EMAIL,m['uuid'])).fetchone()
   if record:
    for ident in m.get('inserted_ids',[]):c.execute('delete from client_inbounds where client_id=? and inbound_id=?',(record['id'],ident))
    if not c.execute('select 1 from client_inbounds where client_id=?',(record['id'],)).fetchone():c.execute('delete from clients where id=?',(record['id'],))
  c.execute('delete from client_traffics where email=?',(EMAIL,))
  for ident in m.get('inserted_ids',[]):c.execute('delete from inbounds where id=? and remark like ?',(ident,'RU TEST - %'))
 c.close()
 for src,name,newname in [(STREAM,'stream.conf','stream.new.conf'),(SITE.resolve(),'site.conf','site.new.conf'),(RUNTIME,'runtime.json','candidate.json')]:
  current=src.read_text();original=(ROOT/'backup'/name).read_text();ours=(ROOT/newname).read_text()
  if current==ours:src.write_text(original)
  elif current!=original:
   if src==RUNTIME:
    value=json.loads(current);tags={r['tag'] for r in m['rows']};value['inbounds']=[i for i in value.get('inbounds',[]) if i.get('tag') not in tags];src.write_text(json.dumps(value,indent=2))
   elif src==STREAM:
    current=current.replace('    '+COVER+' ru_test_reality;\n','').replace('\n# Isolated RU test profile\nupstream ru_test_reality { server 127.0.0.1:'+str(PORTS[0])+'; }\n','');src.write_text(current)
   else:
    marker='    # Isolated RU XHTTP test profile'
    if marker in current:
     start=current.index(marker);end=current.index('\n    }',start)+len('\n    }');src.write_text(current[:start]+current[end:])
 run(['nginx','-t']);run(['systemctl','reload','nginx']);m['applied']=False;m['inserted_ids']=[];dump(ROOT/'manifest.json',m)
 print('Rolled back only the new test profiles',flush=True)


def apply(m):
 if m.get('applied'):print('Already applied; use --verify for connectivity checks',flush=True);return
 c=connect_db();existing=[dict(r) for r in c.execute('select * from inbounds')]
 baseline={str(r['id']):digest({k:v for k,v in r.items() if k not in ('up','down','last_traffic_reset_time')}) for r in existing}
 if baseline!=m['baseline']:raise RuntimeError('Panel changed since preparation; refusing to overwrite concurrent changes')
 for src,name in [(STREAM,'stream.conf'),(SITE.resolve(),'site.conf'),(RUNTIME,'runtime.json')]:
  if src.read_bytes()!=(ROOT/'backup'/name).read_bytes():raise RuntimeError('Configuration changed since preparation')
 try:
  with c:
   for row in m['rows']:
    keys=list(row);q='insert into inbounds ('+','.join('"'+k+'"' for k in keys)+') values ('+','.join('?' for _ in keys)+')'
    ident=c.execute(q,[row[k] for k in keys]).lastrowid;m['inserted_ids'].append(ident)
   # 3x-ui v3 resolves subscriptions from normalized records, not legacy settings.clients.
   if c.execute("select 1 from sqlite_master where type='table' and name='client_inbounds'").fetchone():
    now_ms=int(time.time()*1000)
    m['client_record_id']=c.execute('insert into clients (email,sub_id,uuid,password,auth,flow,security,reverse,limit_ip,total_gb,expiry_time,enable,tg_id,comment,created_at,updated_at) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
      (EMAIL,m['sub_id'],m['uuid'],'','','','auto','',0,0,0,1,0,'Separate RU test account',now_ms,now_ms)).lastrowid
    for index,ident in enumerate(m['inserted_ids']):
     c.execute('insert into client_inbounds (client_id,inbound_id,flow_override,created_at) values (?,?,?,?)',(m['client_record_id'],ident,'xtls-rprx-vision' if index==0 else '',now_ms))
   c.execute('insert into client_traffics (inbound_id,enable,email,up,down,expiry_time,total) values (?,?,?,?,?,?,?)',(m['inserted_ids'][0],1,EMAIL,0,0,0,0))
  dump(ROOT/'manifest.json',m)
  api('adi','stdin:',data={'inbounds':[core_inbound(row) for row in m['rows']]})
  for port in PORTS:
   with socket.create_connection(('127.0.0.1',port),timeout=2):pass
  STREAM.write_text((ROOT/'stream.new.conf').read_text());SITE.resolve().write_text((ROOT/'site.new.conf').read_text())
  run(['nginx','-t']);run(['systemctl','reload','nginx'])
  RUNTIME.write_text((ROOT/'candidate.json').read_text());RUNTIME.chmod(0o600)
  test_profile(m,'reality');test_profile(m,'xhttp')
  # Validate the panel-generated native subscription, including external port and TLS.
  req=urllib.request.Request(m['subscription'],headers={'User-Agent':'v2rayNG/1.10.0'})
  data=urllib.request.urlopen(req,timeout=15).read(500000).strip()
  try:decoded=base64.b64decode(data+b'='*((-len(data))%4)).decode()
  except Exception:decoded=data.decode()
  links=[x.strip() for x in decoded.splitlines() if x.startswith('vless://')]
  if len(links)!=2:raise RuntimeError('Native subscription must contain exactly two profiles')
  seen=set()
  for link in links:
   url=urllib.parse.urlsplit(link);params=urllib.parse.parse_qs(url.query)
   if url.port!=443 or url.username!=m['uuid']:raise RuntimeError('Subscription address or account mismatch')
   network=params.get('type',[''])[0];security=params.get('security',[''])[0];seen.add((network,security))
   if network in ('tcp','raw') and (security!='reality' or params.get('flow')!=['xtls-rprx-vision'] or params.get('sni')!=[COVER] or params.get('pbk')!=[m['public_key']]):raise RuntimeError('Native REALITY subscription mismatch')
   if network=='xhttp' and security!='tls':raise RuntimeError('Native XHTTP TLS mismatch')
  if ('xhttp','tls') not in seen:raise RuntimeError('XHTTP missing from subscription')
  now=[dict(r) for r in c.execute('select * from inbounds where id not in (?,?)',m['inserted_ids'])]
  if {str(r['id']):digest({k:v for k,v in r.items() if k not in ('up','down','last_traffic_reset_time')}) for r in now}!=m['baseline']:raise RuntimeError('Existing inbound settings changed')
  m['applied']=True;m['verified_at']=time.time();dump(ROOT/'manifest.json',m)
  with zipfile.ZipFile(ROOT/'RU-Test-private.zip','w',zipfile.ZIP_DEFLATED) as z:
   for p in (ROOT/'exports').iterdir():z.write(p,arcname=p.name)
  (ROOT/'RU-Test-private.zip').chmod(0o600)
  run(['systemctl','restart','tunnelscope-agent.service'],timeout=20)
  print('SUCCESS: new account',EMAIL,'two profiles; original settings unchanged; x-ui was not restarted',flush=True)
 except BaseException:
  rollback(m);raise
 finally:c.close()


def main():
 p=argparse.ArgumentParser();p.add_argument('--apply',action='store_true');p.add_argument('--verify',action='store_true');p.add_argument('--rollback',action='store_true');args=p.parse_args()
 if os.geteuid()!=0:raise SystemExit('Run as root')
 m=prepare()
 if args.apply:apply(m)
 elif args.verify:test_profile(m,'reality');test_profile(m,'xhttp')
 elif args.rollback:rollback(m)
if __name__=='__main__':main()
