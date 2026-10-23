"""Check an installed instance without changing rules or exposing credentials."""
import base64
import http.cookiejar
import io
import json
import pathlib
import ssl
import time
import urllib.request
import zipfile


def main():
    config=json.loads(pathlib.Path('/etc/tunnelscope/web.json').read_text())
    tls=bool(config.get('tls_cert'));base=('https://localhost:' if tls else 'http://127.0.0.1:')+str(config['port'])
    context=ssl.create_default_context(cafile=config['tls_cert']) if tls else None
    handlers=[urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
    if context:handlers.append(urllib.request.HTTPSHandler(context=context))
    op=urllib.request.build_opener(*handlers)
    for attempt in range(30):
        try:
            assert json.load(op.open(base+'/api/health',timeout=3))['ok'];break
        except (OSError,AssertionError):
            if attempt==29:raise
            time.sleep(.5)
    credentials=dict(line.split(': ',1) for line in pathlib.Path('/etc/tunnelscope/access.txt').read_text().splitlines() if ': ' in line)
    def post(path,body,headers=None):
        return op.open(urllib.request.Request(base+path,data=json.dumps(body).encode(),headers=dict({'Content-Type':'application/json'},**(headers or {}))),timeout=10)
    response=post('/api/login',{'username':credentials['Login'],'password':credentials['Password']})
    if tls:assert 'Secure' in response.headers['Set-Cookie']
    # Copy session cookie explicitly for installations mounted under a proxy path.
    cookie=response.headers['Set-Cookie'].split(';',1)[0];headers={'Cookie':cookie}
    for filename,raw in [('sites.txt',b'example.org\nexample.org\nhttps://example.net/path')]:
        result=json.load(post('/api/import-domains',{'filename':filename,'data':base64.b64encode(raw).decode()},headers));assert result['domains']==['example.net','example.org']
    doc=io.BytesIO()
    with zipfile.ZipFile(doc,'w',zipfile.ZIP_DEFLATED) as archive:archive.writestr('word/document.xml','<w:p xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:r><w:t>example.org</w:t></w:r></w:p>')
    result=json.load(post('/api/import-domains',{'filename':'sites.docx','data':base64.b64encode(doc.getvalue()).decode()},headers));assert result['domains']==['example.org']
    html=op.open(base+'/',timeout=10).read();assert b'sites-import' in html and b'apps-dialog' not in html and b'Supercell' not in html
    print('PASS: service health, TLS where configured, login, TXT/DOCX previews and current interface')

if __name__=='__main__':main()
