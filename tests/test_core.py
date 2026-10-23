import http.cookiejar
import json
import pathlib
import socket
import struct
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from tunnelscope.common import parse_ip,tls_sni,dns_answers,http_host,domain
from tunnelscope.store import Store
from tunnelscope.server import App,Handler,password_hash
from tunnelscope.agent import Collector


def client_hello(host):
    name=host.encode()
    sn=b'\0'+len(name).to_bytes(2,'big')+name
    extension=len(sn).to_bytes(2,'big')+sn
    extension=b'\0\0'+len(extension).to_bytes(2,'big')+extension
    body=b'\x03\x03'+bytes(32)+b'\0'+b'\0\2\x13\x01'+b'\x01\0'+len(extension).to_bytes(2,'big')+extension
    handshake=b'\x01'+len(body).to_bytes(3,'big')+body
    return b'\x16\x03\x01'+len(handshake).to_bytes(2,'big')+handshake


class ProtocolTests(unittest.TestCase):
    def test_tls_and_truncation(self):
        hello=client_hello('example.org')
        self.assertEqual(tls_sni(hello),'example.org')
        for n in range(len(hello)):
            self.assertEqual(tls_sni(hello[:n]),'')

    def test_dns_answer_compression(self):
        q=b'\7example\3org\0'
        packet=b'\x12\x34\x81\x80\0\1\0\1\0\0\0\0'+q+b'\0\1\0\1'+b'\xc0\x0c\0\1\0\1\0\0\0\x3c\0\4'+socket.inet_aton('1.2.3.4')
        self.assertEqual(dns_answers(packet),[('1.2.3.4','example.org',60)])
        self.assertEqual(dns_answers(packet[:15]),[])

    def test_ipv4_ipv6_transport(self):
        tcp=struct.pack('!HHIIHHHH',12345,443,20,0,0x5018,1024,0,0)+b'abc'
        v4=b'\x45\0'+(20+len(tcp)).to_bytes(2,'big')+bytes(5)+b'\x06'+bytes(2)+socket.inet_aton('10.0.0.2')+socket.inet_aton('1.1.1.1')+tcp
        p=parse_ip(v4)
        self.assertEqual((p['src'],p['dport'],p['payload']),('10.0.0.2',443,b'abc'))
        v6=b'\x60'+bytes(3)+len(tcp).to_bytes(2,'big')+b'\6\x40'+socket.inet_pton(socket.AF_INET6,'2001:db8::1')+socket.inet_pton(socket.AF_INET6,'2001:db8::2')+tcp
        self.assertEqual(parse_ip(v6)['protocol'],'TCP')
        self.assertIsNone(parse_ip(b'bad'))

    def test_host_validation(self):
        self.assertEqual(http_host(b'GET / HTTP/1.1\r\nHost: Example.org:80\r\n'),'example.org')
        self.assertEqual(domain('1.2.3.4'),'')
        self.assertEqual(domain('<script>.com'),'')

    def test_xray_log_no_misattribution(self):
        c=Collector.__new__(Collector);c.pending={};c.boot='test'
        c.log_line('2026/10/19 09:02:01 from 1.2.3.4:1234 accepted tcp:example.org:443 [in >> direct] email: alice')
        c.log_line('2026/10/19 09:02:01 from 1.2.3.4:1234 rejected tcp:other.org:443 email: bob')
        self.assertEqual(len(c.pending),1)
        flow=next(iter(c.pending.values()))
        self.assertEqual(flow['domain'],'example.org')
        self.assertEqual(flow['measurement'],'log')


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=pathlib.Path.cwd())
        self.store=Store(str(pathlib.Path(self.temp.name)/'test.db'))

    def tearDown(self):
        self.store.db.close();self.temp.cleanup()

    def sample(self,batch_id,up,down):
        self.store.ingest({'id':batch_id,'clients':[{'id':'a','source':'xray','label':'Alice','ips':[],'up':up,'down':down}]})

    def test_baseline_idempotency_reset(self):
        self.sample('1',1000,2000)
        self.assertEqual(self.store.snapshot()['usage'],{'up':0,'down':0})
        self.sample('2',1100,2300);self.sample('2',1100,2300)
        self.assertEqual(self.store.snapshot()['usage'],{'up':100,'down':300})
        self.sample('3',10,20)
        self.assertEqual(self.store.snapshot()['usage'],{'up':110,'down':320})

    def test_flow_filters_and_no_double_count(self):
        self.sample('1',0,0)
        flow={'id':'f','source':'xray','client_id':'a','destination':'1.2.3.4','domain':'example.org','up':10,'down':30}
        self.store.ingest({'id':'2','flows':[flow]});self.store.ingest({'id':'2','flows':[flow]})
        self.assertEqual(self.store.snapshot(client='a')['flows'][0]['up'],10)
        self.assertEqual(self.store.snapshot(search='no-match')['flows'],[])
        self.assertEqual(self.store.snapshot(source='csqtt')['totals']['connections'],0)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=pathlib.Path.cwd())
        salt='01'*16
        app=App({'database':str(pathlib.Path(self.temp.name)/'test.db'),'salt':salt,'password_hash':password_hash('test-password',salt),'username':'admin','owner_lookup':False})
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler);self.server.app=app
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.url='http://127.0.0.1:'+str(self.server.server_port)
        self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.server.app.store.db.close();self.temp.cleanup()

    def test_auth_csrf_and_logout(self):
        with self.assertRaises(urllib.error.HTTPError) as e:self.opener.open(self.url+'/api/data')
        self.assertEqual(e.exception.code,401)
        req=urllib.request.Request(self.url+'/api/login',data=json.dumps({'username':'admin','password':'test-password'}).encode(),headers={'Content-Type':'application/json'})
        self.assertEqual(self.opener.open(req).status,200)
        self.assertEqual(self.opener.open(self.url+'/api/data').status,200)
        req=urllib.request.Request(self.url+'/api/alias',data=b'{}',headers={'Origin':'https://evil.example','Content-Type':'application/json'})
        with self.assertRaises(urllib.error.HTTPError) as e:self.opener.open(req)
        self.assertEqual(e.exception.code,403)
        self.opener.open(urllib.request.Request(self.url+'/api/logout',data=b'{}'))
        with self.assertRaises(urllib.error.HTTPError):self.opener.open(self.url+'/api/data')


if __name__=='__main__':unittest.main()
