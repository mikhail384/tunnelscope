"""Isolated application blocking checks; all test traffic terminates on the same server."""
import copy
import http.server
import json
import pathlib
import socket
import subprocess
import tempfile
import threading
import uuid
from types import SimpleNamespace
from tunnelscope.common import uid
from tunnelscope.policy import Backend,Policy
from tunnelscope.apps import PREFIX,TABLE,nft_script
from tunnelscope.speed import PREFIX as SPEED_PREFIX,MARK

class HTTP(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  try:self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'OK')
  except OSError:pass
 def log_message(self,*args):pass

def main():
 config=json.loads(pathlib.Path('/etc/tunnelscope/collector.json').read_text());b=Backend(config);b.xray_ready=True;b.mieru=True
 if config.get('apps_policy',{}).get('enabled'):raise RuntimeError('Live application rules enabled; do not interfere')
 if subprocess.run(['nft','list','table','inet',TABLE],capture_output=True).returncode==0:raise RuntimeError('Existing application table; leave it untouched')
 label='app-test-'+uuid.uuid4().hex[:12];other=label+'-control';cid=uid('xray',label);oid=uid('xray',other);accounts=[cid,oid]
 users=[uuid.uuid4(),uuid.uuid4()];tag='tunnelscope-appcheck-'+uuid.uuid4().hex
 public=json.loads(subprocess.check_output(['ip','-j','route','get','1.1.1.1']))[0]['prefsrc'];web=http.server.ThreadingHTTPServer((public,0),HTTP);threading.Thread(target=web.serve_forever,daemon=True).start()
 with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
 # The production collector owns all normal speed routes; pause only collection while using test accounts.
 running=subprocess.run(['systemctl','is-active','--quiet','tunnelscope-agent']).returncode==0
 added=False;table=False
 original=b.xray
 def own_api(action,*args,**kw):
  result=original(action,*args,**kw)
  if action=='lsrules':
   data=json.loads(result.stdout);data['rules']=[r for r in data.get('rules',[]) if not r.get('ruleTag','').startswith((PREFIX,SPEED_PREFIX)) or any(account in r.get('ruleTag','') for account in accounts)]
   return SimpleNamespace(stdout=json.dumps(data))
  return result
 b.xray=own_api
 def request(account,host):
  try:
   with socket.create_connection(('127.0.0.1',port),timeout=2) as s:
    s.settimeout(2)
    try:addr=b'\x01'+socket.inet_aton(host)
    except OSError:raw=host.encode();addr=b'\x02'+bytes([len(raw)])+raw
    s.sendall(b'\x00'+account.bytes+b'\x00\x01'+(80).to_bytes(2,'big')+addr+b'GET / HTTP/1.0\r\nHost: test.invalid\r\n\r\n')
    raw=b''
    while True:
     part=s.recv(8192)
     if not part:break
     raw+=part
    return b'200 OK' in raw
  except OSError:return False
 try:
  if running:subprocess.run(['systemctl','stop','tunnelscope-agent'],check=True,timeout=20)
  inbound={'inbounds':[{'tag':tag,'listen':'127.0.0.1','port':port,'protocol':'vless','settings':{'decryption':'none','clients':[{'id':str(users[0]),'email':label},{'id':str(users[1]),'email':other}]},'streamSettings':{'network':'tcp','security':'none'}}]}
  b.xray('adi','stdin:',text=json.dumps(inbound));added=True
  with tempfile.TemporaryDirectory(prefix='tunnelscope-appcheck-') as td:
   root=pathlib.Path(td);runtime=json.loads(pathlib.Path(b.runtime).read_text());runtime['outbounds'][0].setdefault('settings',{}).pop('finalRules',None);runtime['outbounds'][0]['settings']['redirect']=public+':'+str(web.server_port);(root/'runtime.json').write_text(json.dumps(runtime));b.runtime=str(root/'runtime.json')
   tc=dict(config,client_catalog=str(root/'catalog.json'),adult_policy={'enabled':False,'state_file':str(root/'denials.json')},supercell_policy={'enabled':False},custom_policy={'enabled':False},
     apps_policy={'enabled':False,'app_ids':['clash-royale','telegram'],'clients':{oid:[]},'exempt_client_ids':[],'state_file':str(root/'apps.json')},
     speed_limits={'enabled':True,'download_mbps':1000,'upload_mbps':1000,'clients':{},'state_file':str(root/'speed.json')})
   b.config=tc;p=Policy(tc,b,start=False);p.set_clients([{'id':cid,'label':label,'source':'xray','ips':[]},{'id':oid,'label':other,'source':'xray','ips':[]}],'')
   used=set()
   try:used=set(json.loads(pathlib.Path(config.get('speed_limits',{}).get('state_file','/var/lib/tunnelscope-policy/speed.json')).read_text()).get('slots',{}).values())
   except FileNotFoundError:pass
   slots=[n for n in range(65535,65000,-1) if n not in used];p.speed.state['slots']={cid:slots[0],oid:slots[1]}
   # Test routing compatibility without replacing the production speed firewall.
   p.speed.command=lambda *a,**kw:SimpleNamespace(returncode=1 if a[0][:3]==['nft','list','table'] else 0,stdout='',stderr='')
   p.speed.tick();assert not p.speed.state['error'],p.speed.state['error']
   baseline={h:request(users[0],h) for h in ('example.org','game.clashroyaleapp.com','149.154.167.51')};assert all(baseline.values()),str(baseline)
   tc['apps_policy']['enabled']=True;p.apps.enabled=True;p.apps.tick();assert not p.apps.state['error'],p.apps.state['error'];p.speed.next_check=0;p.speed.tick();assert not p.speed.state['error'],p.speed.state['error']
   assert not request(users[0],'game.clashroyaleapp.com'),'selected game must be blocked'
   assert not request(users[0],'149.154.167.51'),'dedicated application IP must be blocked'
   assert request(users[0],'example.org'),'other traffic of the same account must work'
   assert request(users[1],'game.clashroyaleapp.com') and request(users[1],'149.154.167.51'),'control account must remain unrestricted'
   print('PASS: app domain and dedicated IP blocked only for selected account; other traffic and control account work',flush=True)
   tc['apps_policy']['enabled']=False;p.apps.enabled=False;p.apps.next_check=0;p.apps.tick();assert not p.apps.state['error'];assert request(users[0],'game.clashroyaleapp.com'),'disable restores app'
   print('PASS: switching application rule off restores application access',flush=True)
   # Exercise the generated per-connection firewall on two TCP sockets from one local address.
   entry={'source':'csqtt','endpoints':[('lo','127.0.0.2')],'networks':[]};script=nft_script([entry]);subprocess.run(['nft','-c','-f','-'],input=script,text=True,check=True);subprocess.run(['nft','-f','-'],input=script,text=True,check=True);table=True
   with socket.create_connection((public,web.server_port),source_address=('127.0.0.2',0),timeout=2) as one, socket.create_connection((public,web.server_port),source_address=('127.0.0.2',0),timeout=2) as two:
    key='"lo" . 127.0.0.2 . '+public+' . '+str(one.getsockname()[1])+' . '+str(web.server_port)
    subprocess.run(['nft','-f','-'],input='add element inet '+TABLE+' flows4 { '+key+' timeout 10s }\n',text=True,check=True)
    def get(s):
     try:
      s.settimeout(2);s.sendall(b'GET / HTTP/1.0\r\n\r\n');data=b''
      while True:
       part=s.recv(8192)
       if not part:break
       data+=part
      return b'200 OK' in data
     except OSError:return False
    assert not get(one) and get(two),'only the exact classified TCP connection may be reset'
   print('PASS: classified native TCP connection reset; another connection to the same IP/port remains usable',flush=True)
 finally:
  for account in accounts:
   for suffix in ('domains','networks'):
    try:original('rmrules',PREFIX+account+'-'+suffix)
    except Exception:pass
   for action in ('rmrules','rmo'):
    try:original(action,SPEED_PREFIX+account)
    except Exception:pass
  if table:subprocess.run(['nft','delete','table','inet',TABLE],capture_output=True)
  if added:
   try:original('rmi',tag)
   except Exception:pass
  web.shutdown();web.server_close()
  if running:subprocess.run(['systemctl','start','tunnelscope-agent'],check=True,timeout=20)
  print('Application integration cleanup complete; collector restored',flush=True)
if __name__=='__main__':main()
