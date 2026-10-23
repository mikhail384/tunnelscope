import http.cookiejar
import json
import pathlib
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import Mock
from tunnelscope.control import Controller,validate_request
from tunnelscope.server import App,Handler,password_hash

class ToggleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=pathlib.Path.cwd());self.path=pathlib.Path(self.temp.name)/'collector.json'
        self.original={'interfaces':[{'name':'test'}],'supercell_policy':{'enabled':True,'seconds':20,'exempt_client_ids':['honor']}}
        self.path.write_text(json.dumps(self.original),encoding='utf8');self.runner=Mock();self.backend=Mock()
        self.control=Controller(self.path,self.runner,lambda config:self.backend)
    def tearDown(self):self.temp.cleanup()
    def test_off_is_persisted_clears_active_rules_and_preserves_exception(self):
        result=self.control.request({'action':'set','enabled':False})
        self.assertTrue(result['ok']);self.assertFalse(result['enabled']);self.backend.cleanup.assert_called_once()
        self.assertEqual(Controller(self.path).status()['enabled'],False)
        stored=json.loads(self.path.read_text());self.assertEqual(stored['supercell_policy']['exempt_client_ids'],['honor'])
        self.assertEqual(stored['interfaces'],self.original['interfaces'])
        self.runner.assert_any_call(['systemctl','restart','tunnelscope-agent.service'],timeout=14)
    def test_on_after_off_uses_the_same_duration_and_exception(self):
        self.control.request({'action':'set','enabled':False});self.control.request({'action':'set','enabled':True})
        self.assertTrue(self.control.status()['enabled']);self.assertEqual(self.control.status()['seconds'],20)
        self.assertEqual(json.loads(self.path.read_text())['supercell_policy']['exempt_client_ids'],['honor'])
    def test_strict_boolean_and_no_arbitrary_actions(self):
        for obj in [None,[],{'action':'exec','command':'id'},{'action':'set','enabled':'false'},{'action':'set','enabled':0}, {'action':'set','enabled':True,'path':'/tmp/test'}, {'action':'get','enabled':False}]:
            with self.assertRaises(ValueError):self.control.request(obj)
        self.runner.assert_not_called();self.assertEqual(json.loads(self.path.read_text()),self.original)
    def test_apply_failure_is_not_reported_as_success_and_retry_applies_again(self):
        self.runner.side_effect=RuntimeError('systemd unavailable')
        self.assertFalse(self.control.request({'action':'set','enabled':False})['ok'])
        self.runner.side_effect=None;self.runner.reset_mock()
        self.assertTrue(self.control.request({'action':'set','enabled':False})['ok'])
        self.runner.assert_any_call(['systemctl','restart','tunnelscope-agent.service'],timeout=14)
    def test_http_auth_origin_validation_and_toggle(self):
        config={'database':str(pathlib.Path(self.temp.name)/'web.db'),'salt':'01'*16,'username':'admin','password_hash':password_hash('pass','01'*16),'owner_lookup':False}
        app=App(config);app.policy_request=self.control.request
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.app=app;threading.Thread(target=server.serve_forever,daemon=True).start()
        opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));url='http://127.0.0.1:'+str(server.server_port)
        def post(path,body,origin=None):
            headers={'Content-Type':'application/json'}
            if origin:headers['Origin']=origin
            return opener.open(urllib.request.Request(url+path,data=json.dumps(body).encode(),headers=headers))
        try:
            for path in ['/api/policy']:
                with self.assertRaises(urllib.error.HTTPError) as e:opener.open(url+path)
                self.assertEqual(e.exception.code,401)
                with self.assertRaises(urllib.error.HTTPError) as e:post(path,{'enabled':False})
                self.assertEqual(e.exception.code,401)
            post('/api/login',{'username':'admin','password':'pass'})
            with self.assertRaises(urllib.error.HTTPError) as e:post('/api/policy',{'enabled':False},'https://evil.example')
            self.assertEqual(e.exception.code,403);self.runner.assert_not_called()
            with self.assertRaises(urllib.error.HTTPError) as e:post('/api/policy',{'enabled':'false'})
            self.assertEqual(e.exception.code,400);self.runner.assert_not_called()
            self.assertFalse(json.load(post('/api/policy',{'enabled':False}))['enabled'])
            self.assertFalse(json.load(opener.open(url+'/api/policy'))['enabled'])
            self.assertTrue(json.load(post('/api/policy',{'enabled':True}))['enabled'])
        finally:server.shutdown();server.server_close();app.store.db.close()

if __name__=='__main__':unittest.main()
