"""Real speed and ban isolation test; temporary localhost inbound and two disposable users."""
import http.server
import json
import pathlib
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from tunnelscope.common import uid
from tunnelscope.policy import Backend,Policy
from tunnelscope.speed import TABLE,PREFIX

SIZE=2*1024*1024
DATA=bytes(65536)
class HTTP(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.send_header('Content-Length',str(SIZE));self.end_headers()
  try:
   for n in range(SIZE//len(DATA)):self.wfile.write(DATA)
  except (OSError,ConnectionError):pass
 def do_POST(self):
  size=int(self.headers['Content-Length'])
  while size:
   raw=self.rfile.read(min(65536,size))
   if not raw:return
   size-=len(raw)
  self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'OK')
 def log_message(self,*args):pass

def main():
 config=json.loads(pathlib.Path('/etc/tunnelscope/collector.json').read_text())
 if config.get('speed_limits',{}).get('enabled'):raise RuntimeError('Test requires production speed limits disabled')
 b=Backend(config);b.xray_ready=True;b.mieru=True
 initial=json.loads(b.xray('lsrules').stdout).get('rules',[])
 if any(r.get('ruleTag','').startswith(PREFIX) for r in initial):raise RuntimeError('Existing speed routes: do not interfere with active limits')
 label='speed-test-'+uuid.uuid4().hex[:10];other=label+'-control';cid=uid('xray',label);oid=uid('xray',other);user=uuid.uuid4();control=uuid.uuid4();tag='tunnelscope-rate-test-'+uuid.uuid4().hex
 public=json.loads(subprocess.check_output(['ip','-j','route','get','1.1.1.1']))[0]['prefsrc']
 web=http.server.ThreadingHTTPServer((public,0),HTTP);threading.Thread(target=web.serve_forever,daemon=True).start()
 with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
 added=False;event=None;p=None
 def request(account,upload=False):
  start=time.monotonic()
  with socket.create_connection(('127.0.0.1',port),timeout=3) as s:
   s.settimeout(35)
   header=b'\x00'+account.bytes+b'\x00\x01'+web.server_port.to_bytes(2,'big')+b'\x01'+socket.inet_aton(public)
   h=(('POST' if upload else 'GET')+' / HTTP/1.0\r\nHost: speed-test.invalid\r\n'+('Content-Length: '+str(SIZE)+'\r\n' if upload else '')+'\r\n').encode()
   s.sendall(header+h)
   if upload:
    for n in range(SIZE//len(DATA)):s.sendall(DATA)
   raw=bytearray()
   while True:
    chunk=s.recv(65536)
    if not chunk:break
    raw.extend(chunk)
   assert b'200 OK' in raw[:300] and (upload or len(raw)>=SIZE),'request did not complete'
  return time.monotonic()-start
 try:
  inbound={'inbounds':[{'tag':tag,'listen':'127.0.0.1','port':port,'protocol':'vless','settings':{'decryption':'none','clients':[{'id':str(user),'email':label},{'id':str(control),'email':other}]},'streamSettings':{'network':'tcp','security':'none'}}]}
  b.xray('adi','stdin:',text=json.dumps(inbound));added=True
  baseline=request(control);print('BASELINE_DOWNLOAD',round(baseline,3),flush=True)
  with tempfile.TemporaryDirectory(prefix='tunnelscope-speed-check-') as td:
   root=pathlib.Path(td);tc=dict(config,client_catalog=str(root/'catalog.json'),supercell_policy={'enabled':False},adult_policy={'enabled':False,'state_file':str(root/'denials.json')},custom_policy={'enabled':False},speed_limits={'enabled':True,'download_mbps':0,'upload_mbps':0,'clients':{cid:{'download_mbps':8,'upload_mbps':4}},'state_file':str(root/'speed.json')})
   b.config=tc;p=Policy(tc,b,start=False);p.set_clients([{'id':cid,'source':'xray','label':label,'ips':[]},{'id':oid,'source':'xray','label':other,'ips':[]}],'');p.speed.tick();assert not p.speed.state['error'],p.speed.state['error']
   down=request(user);up=request(user,True);unlimited=request(control)
   print('LIMITED_DOWNLOAD',round(SIZE*8/down/1000000,2),'Mbps',round(down,3),'seconds',flush=True)
   print('LIMITED_UPLOAD',round(SIZE*8/up/1000000,2),'Mbps',round(up,3),'seconds',flush=True)
   print('UNLIMITED_CONTROL',round(unlimited,3),'seconds',flush=True)
   assert down>1.2 and up>2.5 and unlimited<down*.7,'speed ceiling/isolation failed'
   event={'client_id':cid,'label':label,'source':'xray','domain':'test.invalid'};b.block(event,None,[]);p.speed.next_check=0;p.speed.tick()
   try:request(user)
   except (OSError,AssertionError):pass
   else:raise AssertionError('A speed route bypassed the permanent deny')
   request(control);b.unblock_permanent(event);event=None
   p.speed.settings['enabled']=False;p.speed.next_check=0;p.speed.tick();assert not p.speed.state['error'],p.speed.state['error']
   restored=request(user);assert restored<down*.7,'disabling speed must restore bandwidth'
   print('PASS: per-account download/upload ceilings, independent control, permanent deny priority, disable restores bandwidth',flush=True)
 finally:
  if event:
   try:b.unblock_permanent(event)
   except Exception:pass
  for account in (cid,oid):
   for action in ('rmrules','rmo'):
    try:b.xray(action,PREFIX+account)
    except Exception:pass
  if p:
   subprocess.run(['nft','delete','table','inet',TABLE],capture_output=True)
  if added:
   try:b.xray('rmi',tag)
   except Exception:pass
  web.shutdown();web.server_close();print('Speed integration cleanup complete',flush=True)
if __name__=='__main__':main()
