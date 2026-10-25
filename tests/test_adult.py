import json
import pathlib
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock,patch
from types import SimpleNamespace
from tunnelscope.common import uid
from tunnelscope.policy import Policy,Backend,PREFIX
from tunnelscope.adult import DomainList,hostname,atomic_json,read_state,PREFIX as APREFIX
from tunnelscope.control import Controller,validate_request

class AdultTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir=pathlib.Path.cwd());self.root=pathlib.Path(self.temp.name)
  self.alice=uid('xray','alice');self.honor=uid('xray','Honor-magic-8-pro');self.bob=uid('xray','bob')
  self.state=self.root/'denials.json';self.catalog=self.root/'catalog.json';self.cfg=self.root/'collector.json'
  self.list=self.root/'list.db'
  db=sqlite3.connect(self.list);db.executescript('create table domains(name text primary key);create table metadata(key text primary key,value text);')
  db.execute('insert into domains values(?)',('adult-test.invalid',));db.execute('insert into metadata values(?,?)',('count','1'));db.commit();db.close()
  self.config={'client_catalog':str(self.catalog),'supercell_policy':{'enabled':True,'seconds':20,'exempt_client_ids':[self.honor]},'adult_policy':{'enabled':True,'exempt_client_ids':[self.honor],'state_file':str(self.state),'list_file':str(self.list)}}
  self.clients=[{'id':cid,'label':label,'source':'xray','ips':[]} for cid,label in [(self.alice,'alice'),(self.honor,'Honor-magic-8-pro'),(self.bob,'bob')]]
  self.backend=Mock();self.backend.xray.return_value=SimpleNamespace(stdout='{"rules":[]}')
  self.policy=self.make();self.cfg.write_text(json.dumps(self.config),encoding='utf8');self.runner=Mock()
  self.control=Controller(self.cfg,self.runner,lambda c:self.backend)
 def make(self):
  p=Policy(self.config,self.backend,start=False,clock=lambda:1000);p.set_clients(self.clients,'');p.adult.domains.refresh();return p
 def tearDown(self):
  if self.policy.adult.domains.db:self.policy.adult.domains.db.close()
  self.temp.cleanup()
 def flow(self,cid=None,**kw):
  f={'id':'flow','client_id':cid or self.alice,'source':'xray','domain':'sub.adult-test.invalid','destination':'192.0.2.1','port':443,'evidence':'Xray access'};f.update(kw);return f
 def test_first_refresh_during_first_minute_after_boot(self):
  d=DomainList(self.list)
  try:
   with patch('tunnelscope.adult.time.monotonic',return_value=1):d.refresh()
   self.assertTrue(d.contains('sub.adult-test.invalid'))
   with patch('tunnelscope.adult.time.monotonic',return_value=2),patch('tunnelscope.adult.sqlite3.connect') as connect:d.refresh();connect.assert_not_called()
  finally:
   if d.db:d.db.close()
 def test_domain_suffix_boundary_and_ip_rejected(self):
  d=self.policy.adult.domains
  self.assertTrue(d.contains('sub.adult-test.invalid'));self.assertFalse(d.contains('notadult-test.invalid'));self.assertFalse(d.contains('adult-test.invalid.example'));self.assertFalse(d.contains('192.0.2.1'))
  for x in ['http://x.com','x.com/path','com','127.0.0.1','a;drop.com']:self.assertFalse(hostname(x))
 def test_honor_is_exempt_from_both_independent_rules(self):
  self.policy.handle(self.flow(self.honor));self.policy.handle(self.flow(self.honor,domain='supercell.com'));self.backend.block.assert_not_called()
 def test_persistent_block_survives_engine_restart_and_never_expires(self):
  self.policy.handle(self.flow());self.assertIn(self.alice,read_state(self.state)['blocked'])
  self.assertIsNone(self.backend.block.call_args.args[1])
  p=self.make();p.clock=lambda:1000000;p.adult.tick()
  self.assertIn(self.alice,p.adult.state['blocked']);self.backend.unblock.assert_not_called();p.adult.domains.db.close()
 def test_dns_guess_unknown_user_and_shared_ip_do_not_trigger(self):
  for f in [self.flow(evidence='DNS'),self.flow(client_id=''),self.flow(domain='',evidence='IP')]:self.policy.handle(f)
  self.backend.block.assert_not_called()
 def test_failed_block_keeps_durable_pending_intent(self):
  self.backend.block.side_effect=RuntimeError('API unavailable');self.policy.handle(self.flow())
  self.assertEqual(read_state(self.state)['blocked'][self.alice]['state'],'pending')
 def test_disable_auto_does_not_release_existing_ban(self):
  self.policy.handle(self.flow());self.assertTrue(self.control.request({'action':'update','rule':'adult','enabled':False})['ok'])
  self.assertIn(self.alice,read_state(self.state)['blocked']);self.backend.unblock_permanent.assert_not_called()
 def test_manual_release_only_releases_selected_client(self):
  self.policy.handle(self.flow());self.policy.handle(self.flow(self.bob,id='bob'))
  r=self.control.request({'action':'unblock','client_id':self.alice});self.assertTrue(r['ok'])
  self.assertEqual(set(read_state(self.state)['blocked']),{self.bob});self.assertTrue(r['rules']['supercell']['enabled'])
  self.backend.unblock_permanent.assert_called_once();self.runner.assert_any_call(['systemctl','start','tunnelscope-agent.service'],timeout=14)
 def test_adding_adult_exception_releases_client_and_preserves_other_rule(self):
  self.policy.handle(self.flow());r=self.control.request({'action':'update','rule':'adult','exempt_client_ids':[self.honor,self.alice]})
  self.assertTrue(r['ok']);self.assertFalse(read_state(self.state)['blocked']);self.assertEqual(r['rules']['supercell']['exempt_client_ids'],[self.honor])
 def test_unknown_ids_and_commands_rejected_before_service_mutation(self):
  r=self.control.request({'action':'update','rule':'adult','exempt_client_ids':[uid('xray','unknown')]});self.assertFalse(r['ok']);self.runner.assert_not_called()
  for x in [{'action':'update','rule':'adult','enabled':1},{'action':'update','rule':'adult','exempt_client_ids':['x; id']},{'action':'unblock','client_id':self.alice,'command':'id'},{'action':'update','rule':'adult','path':'/root'}]:
   with self.assertRaises(ValueError):validate_request(x)
 def test_start_is_attempted_after_apply_failure(self):
  self.policy.handle(self.flow());self.backend.unblock_permanent.side_effect=RuntimeError('nft failed')
  r=self.control.request({'action':'unblock','client_id':self.alice});self.assertFalse(r['ok']);self.runner.assert_any_call(['systemctl','start','tunnelscope-agent.service'],timeout=14)
 def test_verified_tunnel_address_change_reapplies_existing_ban(self):
  cid=uid('csqtt','device');c={'id':cid,'label':'device','source':'csqtt','ips':['10.66.67.8']}
  self.policy.set_clients([c],'');event={'client_id':cid,'label':'device','source':'csqtt','internal':'10.66.67.7','interface':'csqtt1','state':'pending','started':1}
  self.policy.adult.state['blocked'][cid]=event;self.policy.adult.enabled=False
  self.policy.adult.handle({'internal':'10.66.67.8','interface':'csqtt1'},c,[])
  self.backend.unblock_permanent.assert_called_once();self.assertEqual(event['internal'],'10.66.67.8');self.assertEqual(event['state'],'blocked')
  self.assertIsNone(self.backend.block.call_args.args[1])
 def test_mieru_ambiguity_releases_shared_service_block(self):
  cid=uid('mieru','old');c={'id':cid,'label':'old','source':'mieru','ips':[]}
  self.policy.set_clients([c],'');self.policy.adult.state['blocked'][cid]={'client_id':cid,'source':'mieru','state':'blocked','started':1}
  self.policy.adult.tick();self.backend.unblock_permanent.assert_called_once();self.backend.block.assert_not_called()
  self.assertEqual(self.policy.adult.state['blocked'][cid]['state'],'pending')
 def test_temporary_cleanup_never_removes_adult_rules(self):
  b=Backend({});b.xray=Mock(return_value=SimpleNamespace(stdout=json.dumps({'rules':[{'ruleTag':APREFIX+self.alice},{'ruleTag':PREFIX+self.alice}]})))
  with patch('tunnelscope.policy.command',return_value=SimpleNamespace(returncode=0)):b.cleanup()
  self.assertEqual(b.xray.call_args_list[-1].args,('rmrules',PREFIX+self.alice))

if __name__=='__main__':unittest.main()
