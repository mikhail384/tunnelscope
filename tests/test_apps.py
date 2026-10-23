import json
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock
from tunnelscope.common import uid
from tunnelscope.policy import Policy
from tunnelscope.adult import PREFIX as DENY_PREFIX
from tunnelscope.apps import PREFIX,TABLE,catalog,effective,matches,validate,nft_script
from tunnelscope.control import Controller

class ApplicationTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=pathlib.Path.cwd());self.root=pathlib.Path(self.tmp.name);self.now=1000
  self.a=uid('xray','alice');self.b=uid('xray','bob');self.c=uid('csqtt','device');self.h=uid('xray','Honor')
  self.clients=[{'id':self.a,'label':'alice','source':'xray','ips':[]},{'id':self.b,'label':'bob','source':'xray','ips':[]},{'id':self.c,'label':'device','source':'csqtt','ips':['10.66.67.8']},{'id':self.h,'label':'Honor','source':'xray','ips':[]}]
  self.cfg={'client_catalog':str(self.root/'catalog.json'),'interfaces':[{'name':'csqtt1','source':'csqtt','network':'10.66.67.0/24'}],'apps_policy':{'enabled':True,'app_ids':['youtube'],'clients':{self.b:[]},'exempt_client_ids':[self.h],'state_file':str(self.root/'apps.json')}}
  self.rules=[{'ruleTag':'private','outboundTag':'blocked','ip':['geoip:private']}];self.calls=[];self.tables=set();self.nft=[];self.outbounds={}
  self.runtime=self.root/'runtime.json';self.runtime.write_text(json.dumps({'outbounds':[{'tag':'direct','protocol':'freedom','settings':{}}]}))
  self.backend=SimpleNamespace(xray=Mock(side_effect=self.xray),mieru=True,runtime=str(self.runtime))
  self.p=self.make();self.path=self.root/'config.json';self.path.write_text(json.dumps(self.cfg));self.runner=Mock();self.control=Controller(self.path,self.runner)
 def make(self):
  p=Policy(self.cfg,self.backend,start=False,clock=lambda:self.now);p.set_clients(self.clients,'');p.apps.command=self.command;p.speed.command=self.command;return p
 def tearDown(self):self.tmp.cleanup()
 def xray(self,action,*args,text=None):
  self.calls.append((action,args,text))
  if action=='lsrules':return SimpleNamespace(stdout=json.dumps({'rules':[{'tag':r['outboundTag'],'ruleTag':r.get('ruleTag','')} for r in self.rules]}))
  if action=='rmrules':self.rules[:]=[r for r in self.rules if r.get('ruleTag')!=args[0]]
  if action=='adrules':self.rules.extend(json.loads(text)['routing']['rules'])
  if action=='ado':
   item=json.loads(text)['outbounds'][0]
   if item['tag'] in self.outbounds:raise RuntimeError('existing tag')
   self.outbounds[item['tag']]=item
  if action=='rmo':self.outbounds.pop(args[0],None)
  return SimpleNamespace(stdout='{}')
 def command(self,args,text=None,**kw):
  if args[0]=='ip':return SimpleNamespace(returncode=0,stdout='[{"linkinfo":{"info_kind":"tun"}}]')
  if args[:3]==['mita','describe','config']:return SimpleNamespace(returncode=0,stdout='{"users":[]}')
  if args[:3]==['nft','list','table']:return SimpleNamespace(returncode=0 if args[-1] in self.tables else 1,stdout='',stderr='')
  if args[:3]==['nft','delete','table']:self.tables.discard(args[-1])
  if args==['nft','-f','-']:
   self.nft.append(text)
   if 'table inet '+TABLE in text:self.tables.add(TABLE)
   if 'table inet tunnelscope_speed' in text:self.tables.add('tunnelscope_speed')
  return SimpleNamespace(returncode=0,stdout='{}',stderr='')
 def flow(self,**kw):
  f={'id':'flow','client_id':self.c,'source':'csqtt','domain':'www.youtube.com','destination':'142.250.1.1','protocol':'TCP','port':443,'local_port':32001,'evidence':'TLS SNI','interface':'csqtt1','internal':'10.66.67.8'};f.update(kw);return f
 def test_catalog_is_bounded_and_does_not_block_entire_shared_cdns(self):
  data=catalog();self.assertEqual(len(data['apps']),21);self.assertEqual(len({a['id'] for a in data['apps']}),21)
  rules={r for a in data['apps'] for r in a['domains']};self.assertFalse(rules&{'domain:cloudfront.net','domain:amazonaws.com','domain:akamaized.net','domain:google.com','domain:googleusercontent.com'})
  self.assertTrue(next(a for a in data['apps'] if a['id']=='telegram')['networks'])
 def test_effective_global_override_allow_exempt_and_disabled(self):
  p=self.cfg['apps_policy'];self.assertEqual(effective(p,self.a),['youtube']);self.assertEqual(effective(p,self.b),[]);self.assertEqual(effective(p,self.h),[])
  p['clients'][self.a]=['telegram'];self.assertEqual(effective(p,self.a),['telegram']);p['enabled']=False;self.assertEqual(effective(p,self.a),[])
 def test_validation_strict_ids_catalog_and_no_arbitrary_commands(self):
  for req in [{'action':'apps','client_id':'','app_ids':['unknown']},{'action':'apps','client_id':'','app_ids':['youtube','youtube']},{'action':'apps','client_id':'','app_ids':'youtube'},{'action':'apps','client_id':'xray:;id','app_ids':[]},{'action':'apps_inherit','client_id':''},{'action':'apps','client_id':'','app_ids':[],'command':'id'}]:
   with self.assertRaises(ValueError):validate(req)
 def test_domain_boundary_and_exact_cdn_host(self):
  self.assertTrue(matches('domain:youtube.com','www.youtube.com'));self.assertFalse(matches('domain:youtube.com','notyoutube.com'));self.assertFalse(matches('domain:youtube.com','youtube.com.evil'))
  self.assertTrue(matches('full:asset.cloudfront.net','asset.cloudfront.net'));self.assertFalse(matches('full:asset.cloudfront.net','sub.asset.cloudfront.net'))
 def test_xray_rules_are_app_specific_and_do_not_cut_whole_internet(self):
  self.p.apps.tick();self.assertFalse(self.p.apps.state['error']);rules=[r for r in self.rules if r.get('ruleTag','').startswith(PREFIX)]
  self.assertEqual(len(rules),1);self.assertEqual(rules[0]['user'],['alice']);self.assertIn('domain:youtube.com',rules[0]['domain']);self.assertTrue(all(r.get('domain') or r.get('ip') for r in rules))
 def test_domains_and_dedicated_ranges_use_separate_or_rules(self):
  self.cfg['apps_policy']['clients'][self.a]=['telegram'];self.p.apps.tick();rules=[r for r in self.rules if r.get('user')==['alice']]
  self.assertEqual(len(rules),2);self.assertTrue(any('domain' in r for r in rules));self.assertTrue(any('ip' in r for r in rules));self.assertFalse(any('ip' in r and 'domain' in r for r in rules))
 def test_existing_rate_is_reordered_after_app_deny_and_stays_active(self):
  self.cfg['speed_limits']={'enabled':True,'download_mbps':10,'upload_mbps':2,'clients':{},'state_file':str(self.root/'speed.json')};self.p=self.make();self.p.speed.tick();self.assertFalse(self.p.speed.state['error'])
  self.p.apps.tick();self.p.speed.next_check=0;self.p.speed.tick();self.assertFalse(self.p.speed.state['error'])
  tags=[r.get('ruleTag') for r in self.rules];self.assertLess(tags.index(PREFIX+self.a+'-domains'),tags.index('tunnelscope-speed-'+self.a));self.assertIn('tunnelscope-speed-'+self.b,tags)
  self.assertFalse(any(c[0]=='rmo' for c in self.calls),'Changing app routes must preserve the known speed outbound')
 def test_disable_removes_only_app_rules_and_preserves_permanent_denial(self):
  self.p.apps.tick();self.rules.append({'ruleTag':DENY_PREFIX+self.a,'outboundTag':'blocked','user':['alice']});self.cfg['apps_policy']['enabled']=False;self.now+=16;self.p.apps.tick()
  self.assertFalse(any(r.get('ruleTag','').startswith(PREFIX) for r in self.rules));self.assertIn(DENY_PREFIX+self.a,{r.get('ruleTag') for r in self.rules});self.assertNotIn(TABLE,self.tables)
 def test_native_recognition_uses_exact_tunnel_and_tcp_tuple(self):
  self.p.apps.tick();self.nft.clear();self.p.apps.handle(self.flow(),self.clients[2],[]);self.assertEqual(len(self.nft),1)
  self.assertIn('"csqtt1" . 10.66.67.8 . 142.250.1.1 . 32001 . 443',self.nft[0]);self.assertNotIn('delete table',self.nft[0]);self.assertNotIn('clients4',self.nft[0])
 def test_dns_guesses_invalid_ports_wrong_client_and_shared_ip_do_not_drop(self):
  self.p.apps.tick();self.nft.clear()
  for kw in [{'evidence':'DNS'},{'local_port':0},{'protocol':'UDP'},{'internal':'10.66.67.9'},{'destination':'example.org'},{'domain':'notyoutube.com'}]:self.p.apps.handle(self.flow(**kw),self.clients[2],[])
  self.assertFalse(self.nft)
 def test_pending_tuple_is_consumed_and_connection_label_preserves_speed_marks(self):
  e={'source':'csqtt','endpoints':[('csqtt1','10.66.67.8')],'networks':[]};s=nft_script([e]);self.assertIn('ct label set ct label | 127 delete @flows4',s);self.assertIn('reject with tcp reset',s);self.assertNotIn('ct mark set',s)
 def test_poll_and_restart_reuse_unchanged_routes(self):
  self.p.apps.tick();self.calls.clear();self.now+=16;self.p.apps.tick();self.assertFalse([c for c in self.calls if c[0]=='adrules']);self.calls.clear();p=self.make();p.apps.tick();self.assertFalse([c for c in self.calls if c[0]=='adrules'])
 def test_unknown_allow_route_causes_warning_instead_of_false_success(self):
  self.rules.insert(0,{'ruleTag':'operator','outboundTag':'other'});self.p.apps.tick();self.assertEqual(len(self.p.apps.state['unsupported']),1);self.assertFalse(any(r.get('ruleTag','').startswith(PREFIX) for r in self.rules))
 def test_controller_saves_global_and_client_override_and_inheritance(self):
  self.assertTrue(self.control.request({'action':'apps','client_id':'','app_ids':['telegram']})['ok']);r=self.control.request({'action':'apps','client_id':self.a,'app_ids':[]});self.assertTrue(r['ok']);self.assertEqual(r['apps']['clients'][self.a],[])
  r=self.control.request({'action':'apps_inherit','client_id':self.a});self.assertTrue(r['ok']);self.assertNotIn(self.a,r['apps']['clients']);self.assertEqual(r['apps']['app_ids'],['telegram']);self.assertEqual(r['apps']['exempt_client_ids'],[self.h])
 def test_unknown_client_is_rejected_before_config_write_or_restart(self):
  original=self.path.read_bytes();r=self.control.request({'action':'apps','client_id':uid('xray','unknown'),'app_ids':['youtube']});self.assertFalse(r['ok']);self.runner.assert_not_called();self.assertEqual(self.path.read_bytes(),original)
 def test_adding_app_exception_does_not_release_full_internet_denial(self):
  state=self.root/'denials.json';state.write_text(json.dumps({'blocked':{self.a:{'client_id':self.a,'source':'xray','state':'blocked'}},'history':[]}));self.cfg['adult_policy']={'enabled':True,'state_file':str(state)};self.path.write_text(json.dumps(self.cfg))
  r=self.control.request({'action':'update','rule':'apps','exempt_client_ids':[self.a,self.h]});self.assertTrue(r['ok']);self.assertIn(self.a,json.loads(state.read_text())['blocked'])
 def test_submission_preserves_transport_and_client_port(self):
  self.p.submit(self.flow(),interface='csqtt1',internal='10.66.67.8');item=self.p.queue.get_nowait();self.assertEqual(item['local_port'],32001);self.assertEqual(item['protocol'],'TCP')
 def test_shared_tunnel_address_and_container_bridge_are_unsupported(self):
  self.p.set_clients(self.clients+[dict(self.clients[2],id=uid('csqtt','other'))],'');plans,problems=self.p.apps.plan();self.assertNotIn(self.c,plans);self.assertEqual(len(problems),2)
  self.p=self.make();original=self.command
  def command(args,**kw):
   if args[0]=='ip':return SimpleNamespace(stdout='[{"linkinfo":{"info_kind":"bridge"}}]')
   return original(args,**kw)
  self.p.apps.command=command;plans,problems=self.p.apps.plan();self.assertNotIn(self.c,plans)

if __name__=='__main__':unittest.main()
