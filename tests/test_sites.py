import json
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock
from tunnelscope.common import uid
from tunnelscope.policy import Policy
from tunnelscope.control import Controller,validate_request
from tunnelscope.adult import read_state,atomic_json
from tunnelscope.sites import normalize_domains,normalize_site

class SiteTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir=pathlib.Path.cwd());self.root=pathlib.Path(self.temp.name)
  self.a,self.b,self.h=[uid('xray',x) for x in ('alice','bob','Honor-magic-8-pro')]
  self.clients=[{'id':c,'source':'xray','label':n,'ips':[]} for c,n in [(self.a,'alice'),(self.b,'bob'),(self.h,'Honor')]]
  self.state=self.root/'denials.json';self.cfg=self.root/'config.json';self.catalog=self.root/'catalog.json';atomic_json(self.catalog,self.clients)
  self.config={'client_catalog':str(self.catalog),'adult_policy':{'enabled':False,'state_file':str(self.state),'exempt_client_ids':[self.h]},'supercell_policy':{'enabled':False,'exempt_client_ids':[self.h]},'custom_policy':{'enabled':True,'domains':['shared.example'],'client_domains':{self.a:['personal.example']},'exempt_client_ids':[self.h]}}
  self.backend=Mock();self.backend.xray.return_value=SimpleNamespace(stdout='{"rules":[]}');self.runner=Mock();self.save();self.control=Controller(self.cfg,self.runner,lambda c:self.backend)
 def save(self):self.cfg.write_text(json.dumps(self.config),encoding='utf8')
 def make(self):
  p=Policy(self.config,self.backend,start=False,clock=lambda:1000);p.set_clients(self.clients,'');return p
 def flow(self,cid,domain='shared.example',**kw):
  f={'id':cid+domain,'client_id':cid,'source':'xray','domain':domain,'destination':'192.0.2.1','port':443,'evidence':'Xray access'};f.update(kw);return f
 def tearDown(self):self.temp.cleanup()
 def test_global_subdomains_and_exception(self):
  p=self.make()
  for cid in (self.a,self.b,self.h):p.handle(self.flow(cid,'sub.shared.example'))
  self.assertEqual(set(read_state(self.state)['blocked']),{self.a,self.b});self.assertIsNone(self.backend.block.call_args.args[1])
 def test_personal_list_is_additive_and_isolated(self):
  p=self.make();p.handle(self.flow(self.b,'personal.example'));self.backend.block.assert_not_called()
  p.handle(self.flow(self.a,'sub.personal.example'));self.assertEqual(set(read_state(self.state)['blocked']),{self.a})
  self.assertEqual(p.adult.state['blocked'][self.a]['rule'],'custom')
 def test_lookalike_dns_and_unknown_accounts_do_not_trigger(self):
  p=self.make()
  for domain in ['notshared.example','shared.example.evil','192.0.2.1']:p.handle(self.flow(self.a,domain))
  p.handle(self.flow(self.a,evidence='DNS'));p.handle(self.flow(uid('xray','unknown')));self.backend.block.assert_not_called()
 def test_lists_normalize_unicode_urls_and_reject_injection(self):
  self.assertEqual(normalize_domains(['https://Пример.РФ/path?q=1','EXAMPLE.com.','example.com']),['example.com','xn--e1afmkfd.xn--p1ai'])
  for v in ['com','*.example.com','127.0.0.1','file:///etc/passwd','https://u:p@example.com','a;id.com','x y.com','example.com/path','https://example.com:99999','https://example.com\\evil']:
   with self.subTest(v=v),self.assertRaises(ValueError):normalize_site(v)
 def test_list_edits_do_not_release_ban_and_manual_button_does(self):
  p=self.make();p.handle(self.flow(self.a));p.handle(self.flow(self.b))
  r=self.control.request({'action':'sites','client_id':'','domains':[]});self.assertTrue(r['ok']);self.assertEqual(len(read_state(self.state)['blocked']),2)
  self.assertTrue(self.control.request({'action':'update','rule':'custom','enabled':False})['ok'])
  self.assertTrue(self.control.request({'action':'update','rule':'adult','exempt_client_ids':[self.a,self.h]})['ok'])
  self.backend.unblock_permanent.assert_not_called()
  r=self.control.request({'action':'unblock','client_id':self.a});self.assertTrue(r['ok']);self.assertEqual(set(read_state(self.state)['blocked']),{self.b})
 def test_custom_exception_does_not_silently_release_existing_ban(self):
  p=self.make();p.handle(self.flow(self.a));self.assertTrue(self.control.request({'action':'update','rule':'custom','exempt_client_ids':[self.a,self.h]})['ok'])
  self.assertIn(self.a,read_state(self.state)['blocked']);self.backend.unblock_permanent.assert_not_called()
 def test_domain_save_scopes_and_old_settings_preserved(self):
  r=self.control.request({'action':'sites','client_id':self.b,'domains':['https://New.Example/path']});self.assertTrue(r['ok'])
  cfg=json.loads(self.cfg.read_text());self.assertEqual(cfg['custom_policy']['client_domains'][self.b],['new.example']);self.assertEqual(cfg['custom_policy']['domains'],['shared.example'])
  for rule in ('adult','supercell'):self.assertEqual(cfg[rule+'_policy'],self.config[rule+'_policy'])
  self.assertEqual(r['rules']['custom']['client_domains'][self.a],['personal.example'])
 def test_unknown_account_and_oversized_lists_rejected_before_restart(self):
  self.assertFalse(self.control.request({'action':'sites','client_id':uid('xray','unknown'),'domains':['x.example']})['ok']);self.runner.assert_not_called()
  for req in [{'action':'sites','client_id':'','domains':['x.example']*101},{'action':'sites','client_id':'','domains':['x.example'],'path':'/etc/passwd'}]:
   with self.assertRaises(ValueError):validate_request(req)
 def test_persisted_ban_reapplies_with_rule_disabled_after_restart(self):
  p=self.make();p.handle(self.flow(self.a));self.config['custom_policy']['enabled']=False;p2=self.make();p2.adult.tick()
  self.assertIn(self.a,p2.adult.state['blocked']);self.assertGreaterEqual(self.backend.block.call_count,2);self.backend.unblock_permanent.assert_not_called()

if __name__=='__main__':unittest.main()
