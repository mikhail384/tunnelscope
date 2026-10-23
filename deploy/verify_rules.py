"""Local test inbound and HTTP HEAD to 1.1.1.1; no real VPN account is blocked."""
import http.server
import json
import pathlib
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import uuid
from tunnelscope.adult import atomic_json,read_state,PREFIX
from tunnelscope.common import uid
from tunnelscope.policy import Backend,Policy
from tunnelscope.control import Controller

class HTTP(http.server.BaseHTTPRequestHandler):
 def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(b'TunnelScope integration OK')
 def log_message(self,*args):pass

def main(custom=False):
 config=json.loads(pathlib.Path('/etc/tunnelscope/collector.json').read_text());b=Backend(config);b.xray_ready=True;b.mieru=True
 label='tunnelscope-test-'+uuid.uuid4().hex[:12];cid=uid('xray',label);other=label+'-exempt';oid=uid('xray',other)
 user=uuid.uuid4();control=uuid.uuid4();tag='tunnelscope-test-'+uuid.uuid4().hex
 web=http.server.ThreadingHTTPServer(('127.0.0.1',0),HTTP);threading.Thread(target=web.serve_forever,daemon=True).start()
 with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
 b.ports={tag:port};added=False;event=None;native=None
 def request(user):
  try:
   with socket.create_connection(('127.0.0.1',port),timeout=2) as s:
    s.settimeout(2);header=b'\x00'+user.bytes+b'\x00\x01'+(80).to_bytes(2,'big')+b'\x01'+socket.inet_aton('1.1.1.1')
    s.sendall(header+b'HEAD / HTTP/1.0\r\nHost: one.one.one.one\r\n\r\n');out=b''
    while True:
     part=s.recv(8192)
     if not part:break
     out+=part
     if b'HTTP/' in out and b'\r\n\r\n' in out:break
    return b'HTTP/' in out
  except (OSError,TimeoutError) as e:
   print('VLESS test request:',type(e).__name__,flush=True);return False
 try:
  inbound={'inbounds':[{'tag':tag,'listen':'127.0.0.1','port':port,'protocol':'vless','settings':{'decryption':'none','clients':[{'id':str(user),'email':label},{'id':str(control),'email':other}]},'streamSettings':{'network':'tcp','security':'none'}}]}
  b.xray('adi','stdin:',text=json.dumps(inbound));added=True
  assert request(user) and request(control),'local VLESS baseline'
  with tempfile.TemporaryDirectory(prefix='tunnelscope-verify-') as td:
   root=pathlib.Path(td);state=root/'denials.json';catalog=root/'catalog.json';cp=root/'config.json'
   testconfig=dict(config,client_catalog=str(catalog),supercell_policy={'enabled':False},adult_policy=dict(config['adult_policy'],enabled=True,exempt_client_ids=[oid],state_file=str(state)))
   if custom:testconfig.update(adult_policy=dict(testconfig['adult_policy'],enabled=False),custom_policy={'enabled':True,'domains':['restricted-test.invalid'],'client_domains':{cid:['personal-test.invalid']},'exempt_client_ids':[oid]})
   cp.write_text(json.dumps(testconfig));p=Policy(testconfig,b,start=False);clients=[{'id':cid,'source':'xray','label':label,'ips':[]},{'id':oid,'source':'xray','label':other,'ips':[]}];p.set_clients(clients,'');p.adult.domains.refresh()
   db=sqlite3.connect('file:'+config['adult_policy']['list_file']+'?mode=ro',uri=True);name=db.execute("select name from domains where name like 'pornhub.%' limit 1").fetchone()[0];db.close()
   if custom:name='sub.restricted-test.invalid'
   f={'id':'integration','client_id':cid,'source':'xray','domain':name,'destination':'127.0.0.1','port':443,'evidence':'TLS SNI'}
   p.handle(f);event=p.adult.state['blocked'][cid];assert event['state']=='blocked',event
   p.handle(dict(f,id='exempt',client_id=oid));assert oid not in p.adult.state['blocked']
   assert not request(user) and request(control),'per-account isolation'
   print('PASS: classified domain -> persistent Xray ban; exempt account works',flush=True)
   # Cleanup of temporary rules must leave permanent rules intact.
   subprocess.run(['systemctl','restart','tunnelscope-agent.service'],check=True,timeout=20)
   started=time.monotonic()
   while time.monotonic()-started<21:time.sleep(.25)
   assert not request(user) and request(control),'ban must outlive 20 seconds and collector restart'
   p2=Policy(testconfig,b,start=False);p2.set_clients(clients,'');p2.adult.tick();assert cid in p2.adult.state['blocked']
   print('PASS: denial survives 20 seconds and collector/engine restart',flush=True)
   controller=Controller(cp,runner=lambda *a,**kw:None,backend_factory=lambda c:b)
   result=controller.request({'action':'unblock','client_id':cid});assert result['ok'],result
   assert cid not in read_state(state)['blocked'] and request(user),'manual release restores internet'
   print('PASS: manual release restores only the selected test account',flush=True)
   # A second localhost source address verifies nftables persistence without touching VPN clients.
   native={'client_id':uid('csqtt','local-test'),'source':'csqtt','label':'local nft test','interface':'lo','internal':'127.0.0.2'}
   b.config=dict(config,interfaces=config.get('interfaces',[])+[{'name':'lo','source':'csqtt','network':'127.0.0.0/8'}])
   def local_request(source):
    try:
     with socket.create_connection(('127.0.0.1',web.server_port),timeout=1,source_address=(source,0)) as s:
      s.settimeout(1);s.sendall(b'GET / HTTP/1.0\r\n\r\n');return b'200 OK' in s.recv(8192)
    except OSError:return False
   assert local_request('127.0.0.2') and local_request('127.0.0.3')
   b.block(native,None,[]);assert not local_request('127.0.0.2') and local_request('127.0.0.3')
   b.unblock_permanent(native);native=None;assert local_request('127.0.0.2')
   print('PASS: persistent nftables tuple isolates one endpoint; manual removal restores it',flush=True)
   if p.adult.domains.db:p.adult.domains.db.close()
   if p2.adult.domains.db:p2.adult.domains.db.close()
 finally:
  if event:
   try:b.unblock_permanent(event)
   except Exception:pass
  if native:
   try:b.unblock_permanent(native)
   except Exception:pass
  if added:
   try:b.xray('rmi',tag)
   except Exception:pass
  web.shutdown();web.server_close()
  print('Integration test cleanup complete',flush=True)
if __name__=='__main__':
 import argparse
 parser=argparse.ArgumentParser();parser.add_argument('--custom',action='store_true');main(parser.parse_args().custom)
