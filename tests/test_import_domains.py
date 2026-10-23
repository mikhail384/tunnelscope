import base64
import http.cookiejar
import io
import json
import pathlib
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer
from tunnelscope.import_domains import parse_file, decode_upload, MAX_FILE, W
from tunnelscope.server import App, Handler, password_hash


def document(xml):
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:z.writestr('word/document.xml',xml)
    return out.getvalue()


class DomainImportTests(unittest.TestCase):
    def test_text_urls_hosts_comments_duplicates_and_invalid_entries(self):
        r=parse_file('sites.txt',b'# comment\n0.0.0.0 example.org\nhttps://EXAMPLE.org/a\nsub.example.net,example.net\n192.0.2.1\n')
        self.assertEqual(r['domains'],['example.net','example.org','sub.example.net']);self.assertEqual(r['duplicates'],1);self.assertEqual(r['skipped'],1)
    def test_unicode_and_windows_text_encodings(self):
        for enc in ('utf-8-sig','utf-16','cp1251'):
            with self.subTest(enc=enc):self.assertEqual(parse_file('sites.txt','пример.рф\nexample.org'.encode(enc))['domains'],['example.org','xn--e1afmkfd.xn--p1ai'])
    def test_word_paragraphs_tables_and_split_formatting(self):
        xml='<w:document xmlns:w="'+W[1:-1]+'"><w:body><w:p><w:r><w:t>example</w:t></w:r><w:r><w:t>.org</w:t></w:r></w:p><w:tbl><w:tr><w:tc><w:p><w:r><w:t>example.net</w:t></w:r></w:p></w:tc></w:tr></w:tbl></w:body></w:document>'
        self.assertEqual(parse_file('sites.docx',document(xml))['domains'],['example.net','example.org'])
    def test_docs_alias_accepts_word_and_plain_text(self):
        self.assertEqual(parse_file('list.docs',b'example.org')['domains'],['example.org'])
        self.assertEqual(parse_file('list.docs',document('<w:p xmlns:w="'+W[1:-1]+'"><w:t>example.org</w:t></w:p>'))['domains'],['example.org'])
    def test_upload_base64_and_strict_schema(self):
        self.assertEqual(decode_upload({'filename':'a.txt','data':base64.b64encode(b'example.org').decode()})['domains'],['example.org'])
        for body in ({'filename':'x.txt','data':'@@@'},{'filename':'x.txt','data':'','command':'x'},{'filename':'x.txt','data':[]}):
            with self.subTest(body=body),self.assertRaises(ValueError):decode_upload(body)
    def test_unknown_binary_empty_and_oversized_files(self):
        for name,raw in [('x.doc',b'example.org'),('x.exe',b'example.org'),('x.txt',b''),('x.txt',b'a'*(MAX_FILE+1)),('x.txt',b'\x00example.org')]:
            with self.subTest(name=name,size=len(raw)),self.assertRaises(ValueError):parse_file(name,raw)
    def test_too_many_unique_domains_are_rejected_without_truncation(self):
        with self.assertRaisesRegex(ValueError,'100'):parse_file('sites.txt','\n'.join('site'+str(i)+'.org' for i in range(101)).encode())
        self.assertEqual(len(parse_file('sites.txt',('example.org\n'*200).encode())['domains']),1)
    def test_word_rejects_corrupt_archives_entities_and_oversized_xml(self):
        for raw in (b'PKbad',document('<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>'),document('a'*(2*1024*1024+1))):
            with self.subTest(size=len(raw)),self.assertRaises(ValueError):parse_file('sites.docx',raw)
    def test_word_depth_is_bounded(self):
        with self.assertRaises(ValueError):parse_file('a.docx',document('<a>'*70+'example.org'+'</a>'*70))


class ImportHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=pathlib.Path.cwd());salt='01'*16
        app=App({'database':str(pathlib.Path(self.temp.name)/'test.db'),'salt':salt,'password_hash':password_hash('test',salt),'owner_lookup':False})
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler);self.server.app=app;threading.Thread(target=self.server.serve_forever,daemon=True).start();self.url='http://127.0.0.1:'+str(self.server.server_port)
        self.op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.server.app.store.db.close();self.temp.cleanup()
    def post(self,path,body,extra=None):
        return self.op.open(urllib.request.Request(self.url+path,data=json.dumps(body).encode(),headers=dict({'Content-Type':'application/json'},**(extra or {}))))
    def test_auth_csrf_and_preview_without_policy_mutation(self):
        payload={'filename':'a.txt','data':base64.b64encode(b'example.org').decode()}
        with self.assertRaises(urllib.error.HTTPError) as err:self.post('/api/import-domains',payload)
        self.assertEqual(err.exception.code,401)
        self.post('/api/login',{'username':'admin','password':'test'})
        with self.assertRaises(urllib.error.HTTPError) as err:self.post('/api/import-domains',payload,{'Origin':'https://evil.example'})
        self.assertEqual(err.exception.code,403)
        self.server.app.policy_request=lambda request:(_ for _ in ()).throw(AssertionError('Import must not change rules'))
        self.assertEqual(json.load(self.post('/api/import-domains',payload))['domains'],['example.org'])
    def test_word_import_and_invalid_request(self):
        self.post('/api/login',{'username':'admin','password':'test'})
        raw=document('<w:p xmlns:w="'+W[1:-1]+'"><w:t>example.org</w:t></w:p>')
        self.assertEqual(json.load(self.post('/api/import-domains',{'filename':'a.docx','data':base64.b64encode(raw).decode()}))['domains'],['example.org'])
        with self.assertRaises(urllib.error.HTTPError) as err:self.post('/api/import-domains',{'filename':'a.docx','data':'not base64'})
        self.assertEqual(err.exception.code,400)

if __name__=='__main__':unittest.main()
