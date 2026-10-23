import json
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
from tunnelscope.common import uid
from tunnelscope.policy import Backend,Policy,PREFIX as BLOCK_PREFIX
from tunnelscope.speed import effective,validate,rate,nft_script,PREFIX,MARK
from tunnelscope.control import Controller

class SpeedTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=pathlib.Path.cwd());self.root=pathlib.Path(self.tmp.name);self.now=1000
  self.a=uid('xray','alice');self.b=uid('xray','bob');self.c=uid('csqtt','device')
  self.clients=[{'id':self.a,'label':'alice','source':'xray','ips':[]},{'id':self.b,'label':'bob','source':'xray','ips':[]},{'id':self.c,'label':'device','source':'csqtt','ips':['10.66.67.8']}]
  self.cfg={'client_catalog':str(self.root/'catalog.json'),'interfaces':[{'name':'csqtt1','source':'csqtt','network':'10.66.67.0/24'}],'speed_limits':{'enabled':True,'download_mbps':10,'upload_mbps':2,'clients':{},'state_file':str(self.root/'speed.json')}}
  self.config=self.root/'config.json';self.config.write_text(json.dumps(self.cfg));self.runtime=self.root/'runtime.json';self.runtime.write_text(json.dumps({'outbounds':[{'tag':'direct','protocol':'freedom','settings':{'domainStrategy':'UseIPv4'}}]}))
  self.rules=[{'ruleTag':'private','outboundTag':'blocked','ip':['geoip:private']}];self.outbounds={};self.calls=[];self.nft=[];self.exists=False
  self.backend=Backend(self.cfg);self.backend.runtime=str(self.runtime);self.backend.xray_ready=True;self.backend.mieru=True;self.backend.xray=Mock(side_effect=self.xray)
  self.p=Policy(self.cfg,self.backend,start=False,clock=lambda:self.now);self.p.set_clients(self.clients,'');self.p.speed.command=self.command
 def tearDown(self):self.tmp.cleanup()
 def xray(self,action,*args,text=None):
  self.calls.append((action,args,text))
  if action=='lsrules':return SimpleNamespace(stdout=json.dumps({'rules':self.rules}))
  if action=='ado':
   item=json.loads(text)['outbounds'][0]
   if item['tag'] in self.outbounds:raise RuntimeError('already exists')
   self.outbounds[item['tag']]=item
  if action=='rmo':self.outbounds.pop(args[0],None)
  if action=='adrules':self.rules.extend(json.loads(text)['routing']['rules'])
  if action=='rmrules':self.rules[:]=[r for r in self.rules if r.get('ruleTag')!=args[0]]
  return SimpleNamespace(stdout='{}')
 def command(self,args,text=None,**kw):
  if args[0]=='ip':return SimpleNamespace(returncode=0,stdout='[{"linkinfo":{"info_kind":"tun"}}]')
  if args[:3]==['nft','list','table']:return SimpleNamespace(returncode=0 if self.exists else 1,stdout='',stderr='')
  if args[:3]==['nft','delete','table']:self.exists=False
  if args==['nft','-f','-']:self.exists=True;self.nft.append(text)
  return SimpleNamespace(returncode=0,stdout='{}',stderr='')
 def test_validation_rejects_boolean_nan_negative_and_injection(self):
  for v in [True,'10',-.1,.01,float('nan'),float('inf'),10001,None]:
   with self.subTest(v=v),self.assertRaises(ValueError):rate(v)
  for req in [{'action':'speed','client_id':self.a,'download_mbps':1,'upload_mbps':2,'command':'id'},{'action':'speed_toggle','enabled':'false'},{'action':'speed_inherit','client_id':''},{'action':'speed','client_id':'xray:;id','download_mbps':1,'upload_mbps':2}]:
   with self.assertRaises(ValueError):validate(req)
 def test_defaults_personal_override_unlimited_and_master_off(self):
  s=self.cfg['speed_limits'];self.assertEqual(effective(s,self.a),(10,2));s['clients'][self.a]={'download_mbps':3,'upload_mbps':0};self.assertEqual(effective(s,self.a),(3,0));s['clients'][self.b]={'download_mbps':0,'upload_mbps':0};self.assertEqual(effective(s,self.b),(0,0));s['enabled']=False;self.assertEqual(effective(s,self.a),(0,0))
 def test_xray_accounts_get_distinct_socket_marks_and_nft_buckets(self):
  self.p.speed.tick();self.assertFalse(self.p.speed.state['error']);a=self.outbounds[PREFIX+self.a];b=self.outbounds[PREFIX+self.b]
  self.assertNotEqual(a['streamSettings']['sockopt']['mark'],b['streamSettings']['sockopt']['mark']);self.assertEqual(a['settings']['domainStrategy'],'UseIPv4')
  self.assertTrue(any(r.get('user')==['alice'] for r in self.rules));self.assertIn('ct direction reply',self.nft[-1]);self.assertIn('iifname "csqtt1" ip saddr 10.66.67.8',self.nft[-1]);self.assertNotIn('203.0.113.',self.nft[-1])
 def test_no_rebuild_on_poll_and_disable_removes_only_own_rules(self):
  self.p.speed.tick();old=list(self.nft);self.now+=16;self.p.speed.tick();self.assertEqual(self.nft,old)
  self.cfg['speed_limits']['enabled']=False;self.now+=16;self.p.speed.tick();self.assertFalse(self.exists);self.assertEqual(self.rules,[{'ruleTag':'private','outboundTag':'blocked','ip':['geoip:private']}])
 def test_speed_route_is_removed_before_block_is_added(self):
  self.p.speed.tick();self.calls=[];self.backend.ensure_adult=Mock()
  self.backend.block({'source':'xray','client_id':self.a,'label':'alice'},None,[])
  commands=[c[0] for c in self.calls];self.assertLess(commands.index('rmrules'),commands.index('adrules'))
  self.assertNotIn(PREFIX+self.a,{r.get('ruleTag') for r in self.rules});self.now+=16;self.p.speed.tick();self.assertNotIn(PREFIX+self.a,{r.get('ruleTag') for r in self.rules})
 def test_temporary_unblock_restores_speed_route_without_waiting(self):
  self.p.enabled=True;self.p.seconds=20;self.p.speed.tick()
  self.p.handle({'id':'game','client_id':self.a,'source':'xray','domain':'supercell.com','evidence':'Xray access'})
  self.assertIn(BLOCK_PREFIX+self.a,{r.get('ruleTag') for r in self.rules});self.p.speed.next_check=100000;self.now+=21;self.p.tick()
  self.assertIn(PREFIX+self.a,{r.get('ruleTag') for r in self.rules});self.assertNotIn(BLOCK_PREFIX+self.a,{r.get('ruleTag') for r in self.rules})
 def test_earlier_unknown_allow_route_is_reported_and_not_bypassed(self):
  self.rules.insert(0,{'ruleTag':'operator-route','outboundTag':'special'});self.p.speed.tick()
  self.assertFalse(self.outbounds);self.assertEqual(len(self.p.speed.state['unsupported']),2);self.assertEqual(len(self.p.speed.state['applied']),1)
 def test_conflicting_tunnel_address_never_limits_another_account(self):
  self.p.set_clients(self.clients+[dict(self.clients[2],id=uid('csqtt','other'))],'');entries,problems=self.p.speed.plan();self.assertEqual(len(problems),2);self.assertTrue(all(e['source']=='xray' for e in entries))
 def test_current_xray_summary_schema_keeps_rates_and_respects_deny(self):
  original=self.xray
  def api(action,*args,**kw):
   if action=='lsrules':return SimpleNamespace(stdout=json.dumps({'rules':[{'tag':r.get('outboundTag',''),'ruleTag':r.get('ruleTag','')} for r in self.rules]}))
   return original(action,*args,**kw)
  self.backend.xray=Mock(side_effect=api);self.p.speed.tick();self.assertEqual(len(self.outbounds),2);self.assertFalse(self.p.speed.state['error'])
  count=len(self.calls);self.now+=16;self.p.speed.tick();self.assertFalse(self.calls[count:],'Polling must not recreate current Xray routes')
  self.backend.ensure_adult=Mock();self.backend.block({'source':'xray','client_id':self.a,'label':'alice'},None,[]);self.now+=16;self.p.speed.tick();self.assertNotIn(PREFIX+self.a,{r.get('ruleTag') for r in self.rules});self.assertIn(PREFIX+self.b,{r.get('ruleTag') for r in self.rules})
 def test_container_bridge_is_not_treated_as_one_vpn_user(self):
  original=self.command
  def command(args,**kw):
   if args[0]=='ip':return SimpleNamespace(returncode=0,stdout='[{"linkinfo":{"info_kind":"bridge"}}]')
   return original(args,**kw)
  self.p.speed.command=command;self.p.speed.tick();self.assertEqual(len(self.p.speed.state['unsupported']),1);self.assertTrue(all(e['source']=='xray' for e in self.p.speed.state['applied']))
 def test_mark_slots_survive_restart_and_are_not_reused(self):
  self.p.speed.tick();slots=dict(self.p.speed.state['slots']);p=Policy(self.cfg,self.backend,start=False);self.assertEqual(p.speed.state['slots'],slots);new=uid('xray','new');self.assertNotIn(p.speed.slot(new),slots.values())
 def test_controller_preserves_policies_and_supports_inheritance(self):
  self.cfg['adult_policy']={'enabled':True,'exempt_client_ids':[self.a],'state_file':str(self.root/'denials.json')};self.config.write_text(json.dumps(self.cfg))
  runner=Mock();c=Controller(self.config,runner)
  self.assertTrue(c.request({'action':'speed','client_id':self.a,'download_mbps':3,'upload_mbps':1})['ok']);self.assertEqual(c.status()['speed']['clients'][self.a],{'download_mbps':3,'upload_mbps':1})
  self.assertTrue(c.request({'action':'speed_inherit','client_id':self.a})['ok']);self.assertNotIn(self.a,c.status()['speed']['clients']);self.assertEqual(json.loads(self.config.read_text())['adult_policy'],self.cfg['adult_policy'])
  runner.reset_mock();r=c.request({'action':'speed','client_id':uid('xray','unknown'),'download_mbps':1,'upload_mbps':1});self.assertFalse(r['ok']);runner.assert_not_called()
 def test_download_and_upload_share_buckets_across_ipv4_ipv6_addresses(self):
  entry={'slot':1,'source':'csqtt','download_mbps':8,'upload_mbps':4,'endpoints':[('csqtt1','10.66.67.8'),('csqtt1','2001:db8::8')]};s=nft_script([entry]);self.assertEqual(s.count('limit u1 {'),1);self.assertEqual(s.count('limit d1 {'),1);self.assertIn('ip6 daddr 2001:db8::8 limit name d1',s);self.assertIn('rate over 1000000 bytes/second',s)
  with self.assertRaises(ValueError):nft_script([dict(entry,endpoints=[('csqtt1; flush ruleset','10.66.67.8')])])
 def test_mieru_multiple_users_are_not_limited_together(self):
  cid=uid('mieru','one');c={'id':cid,'label':'one','source':'mieru','ips':[]};self.p.set_clients([c],'');entries,problems=self.p.speed.plan();self.assertFalse(entries);self.assertEqual(len(problems),1)

if __name__=='__main__':unittest.main()
