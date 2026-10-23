import argparse
import csv
import gzip
import hashlib
import hmac
import http.cookies
import io
import ipaddress
import json
import logging
import os
import pathlib
import queue
import secrets
import socketserver
import struct
import ssl
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .store import Store
from .import_domains import decode_upload, MAX_BODY
from .control import rpc, SOCKET, validate_request


ROOT=pathlib.Path(__file__).resolve().parent.parent


def password_hash(password,salt):
    return hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),240000).hex()


class Owners:
    def __init__(self,store):
        self.store=store
        self.tasks=queue.Queue(maxsize=200)
        self.pending=set()
        self.lock=threading.Lock()
        threading.Thread(target=self.worker,daemon=True).start()

    def schedule(self,addr):
        try:
            if not ipaddress.ip_address(addr).is_global:
                return
        except ValueError:
            return
        cached=self.store.owner(addr)
        if cached and time.time()-cached['updated']<(1800 if cached['error'] else 7*86400):
            return
        with self.lock:
            if addr in self.pending or self.tasks.full():
                return
            self.pending.add(addr)
            self.tasks.put_nowait(addr)

    def worker(self):
        while True:
            addr=self.tasks.get()
            result={'ip':addr}
            try:
                url='https://stat.ripe.net/data/prefix-overview/data.json?resource='+urllib.parse.quote(addr,safe='')
                req=urllib.request.Request(url,headers={'User-Agent':'TunnelScope/1.0 (network owner lookup)'})
                with urllib.request.urlopen(req,timeout=8) as r:
                    data=json.loads(r.read(1024*1024))['data']
                values=data.get('asns',[])
                result.update(asn=', '.join('AS'+str(v['asn']) for v in values),holder=' / '.join(v.get('holder','') for v in values),prefix=data.get('prefix',''))
                if not values:
                    result['error']='Нет объявления BGP'
            except Exception:
                result['error']='Сервис владельцев сети временно недоступен'
            self.store.set_owner(result)
            with self.lock:
                self.pending.discard(addr)
            self.tasks.task_done()
            time.sleep(3)  # At most 20 lookups/minute, cached. No client IDs or domains leave the server.


class App:
    def __init__(self,config):
        self.config=config
        self.store=Store(config['database'])
        self.sessions={}
        self.attempts={}
        self.lock=threading.Lock()
        self.owners=Owners(self.store) if config.get('owner_lookup',True) else None
        self.started=time.time()

    def auth(self,headers):
        try:
            cookies=http.cookies.SimpleCookie(headers.get('Cookie',''))
            token=cookies['ts_session'].value
            with self.lock:
                return self.sessions.get(hashlib.sha256(token.encode()).hexdigest(),0)>time.time()
        except (KeyError,http.cookies.CookieError):
            return False

    def policy_request(self, request):
        return rpc(self.config.get('policy_control_socket',SOCKET),request)

    def snapshot(self,params):
        try:
            hours=min(336,max(1,int(params.get('hours',['24'])[0])))
        except ValueError:
            hours=24
        data=self.store.snapshot(hours,params.get('client',[''])[0],params.get('search',[''])[0],params.get('source',[''])[0],fresh=params.get('fresh',[''])[0]=='1',background=params.get('fresh',[''])[0]!='1' and params.get('_export',[''])[0]!='1')
        if self.owners:
            for row in data['flows'][:100]:
                self.owners.schedule(row['destination'])
        data['server']={'started':self.started,'retention_days':self.config.get('retention_days',14),'owner_lookup':bool(self.owners),'name':self.config.get('server_name','Ubuntu')}
        return data


class Handler(BaseHTTPRequestHandler):
    server_version='TunnelScope/1.0'

    @property
    def app(self):
        return self.server.app

    def log_message(self,fmt,*args):
        # Do not log URLs/query strings, client identifiers or credentials.
        pass

    def send(self,status,body,kind='application/json; charset=utf-8',extra=None):
        if not isinstance(body,bytes):
            body=json.dumps(body,ensure_ascii=False).encode()
        if len(body)>4096 and 'gzip' in self.headers.get('Accept-Encoding','') and kind.startswith('application/json'):
            body=gzip.compress(body,compresslevel=1);extra=dict(extra or {},**{'Content-Encoding':'gzip','Vary':'Accept-Encoding'})
        self.send_response(status)
        self.send_header('Content-Type',kind)
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        for k,v in (extra or {}).items():
            self.send_header(k,v)
        self.end_headers()
        self.wfile.write(body)

    def body(self, limit=32768):
        size=int(self.headers.get('Content-Length','0'))
        if not 0<size<=limit:
            raise ValueError('size')
        return json.loads(self.rfile.read(size))

    def same_origin(self):
        origin=self.headers.get('Origin')
        if origin:
            return urllib.parse.urlsplit(origin).netloc==self.headers.get('Host')
        return self.headers.get('Sec-Fetch-Site') not in ('cross-site',)

    def do_GET(self):
        path=urllib.parse.urlsplit(self.path)
        if path.path in ('/','/app.js','/style.css','/favicon.svg'):
            name={'/':'index.html'}.get(path.path,path.path[1:])
            file=ROOT/'static'/name
            types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml'}
            return self.send(200,file.read_bytes(),types[file.suffix])
        if path.path=='/api/health':
            return self.send(200,{'ok':True})
        if not self.app.auth(self.headers):
            return self.send(401,{'error':'Нужен вход'})
        if path.path=='/api/session':
            return self.send(200,{'user':self.app.config.get('username','admin')})
        if path.path=='/api/policy':
            try:result=self.app.policy_request({'action':'get'})
            except Exception:return self.send(503,{'error':'Переключатель временно недоступен'})
            return self.send(200,result)
        if path.path in ('/api/data','/api/export'):
            params=urllib.parse.parse_qs(path.query)
            if path.path=='/api/export':params['_export']=['1']
            data=self.app.snapshot(params)
            if path.path=='/api/export':
                buf=io.StringIO()
                writer=csv.writer(buf)
                cols=['client_label','source','domain','destination','port','protocol','holder','asn','up','down','measurement','evidence','last_seen']
                writer.writerow(cols)
                for row in data['flows']:
                    vals=[str(row.get(c,'') or '') for c in cols]
                    writer.writerow(["'"+v if v.startswith(('=','+','-','@')) else v for v in vals])
                return self.send(200,('\ufeff'+buf.getvalue()).encode(),'text/csv; charset=utf-8',{'Content-Disposition':'attachment; filename="tunnelscope.csv"'})
            return self.send(200,data)
        return self.send(404,{'error':'Не найдено'})

    def do_POST(self):
        if not self.same_origin():
            return self.send(403,{'error':'Запрос с другого сайта отклонён'})
        path=urllib.parse.urlsplit(self.path).path
        if path=='/api/import-domains' and not self.app.auth(self.headers):
            return self.send(401,{'error':'Нужен вход'})
        try:
            body=self.body(MAX_BODY if path=='/api/import-domains' else 32768)
            if not isinstance(body,dict):
                raise ValueError('object required')
        except (ValueError,TypeError):
            return self.send(400,{'error':'Некорректный запрос'})
        path=urllib.parse.urlsplit(self.path).path
        if path=='/api/login':
            peer=self.headers.get('X-Real-IP',self.client_address[0]) if self.client_address[0] in ('127.0.0.1','::1') else self.client_address[0]
            now=time.time()
            with self.app.lock:
                attempts=[t for t in self.app.attempts.get(peer,[]) if now-t<300]
                self.app.attempts={k:v for k,v in self.app.attempts.items() if v and now-v[-1]<300}
                if len(attempts)>=8:
                    return self.send(429,{'error':'Слишком много попыток. Повторите через 5 минут.'})
                attempts.append(now)
                self.app.attempts[peer]=attempts
            password=str(body.get('password',''))[:500]
            valid=hmac.compare_digest(str(body.get('username','')),self.app.config.get('username','admin')) and hmac.compare_digest(password_hash(password,self.app.config['salt']),self.app.config['password_hash'])
            if not valid:
                return self.send(401,{'error':'Неверный логин или пароль'})
            token=secrets.token_urlsafe(32)
            with self.app.lock:
                self.app.attempts.pop(peer,None)
                self.app.sessions={k:v for k,v in self.app.sessions.items() if v>now}
                self.app.sessions[hashlib.sha256(token.encode()).hexdigest()]=now+8*3600
            secure='; Secure' if (self.headers.get('X-Forwarded-Proto')=='https' or isinstance(self.connection,ssl.SSLSocket)) else ''
            cookie='ts_session='+token+'; HttpOnly; SameSite=Strict; Max-Age=28800; Path='+self.app.config.get('cookie_path','/')+secure
            return self.send(200,{'ok':True},extra={'Set-Cookie':cookie})
        if not self.app.auth(self.headers):
            return self.send(401,{'error':'Нужен вход'})
        if path=='/api/import-domains':
            try:result=decode_upload(body)
            except ValueError as error:return self.send(400,{'error':str(error)})
            return self.send(200,result)
        if path=='/api/policy':
            request={'action':'set','enabled':body['enabled']} if set(body)=={'enabled'} else body
            try:validate_request(request)
            except ValueError as e:return self.send(400,{'error':str(e) if request.get('action') in ('sites','apps','apps_inherit') or str(request.get('action','')).startswith('speed') else 'Некорректная настройка правила'})
            if request.get('action')=='get':return self.send(400,{'error':'Используйте GET'})
            try:result=self.app.policy_request(request)
            except Exception:return self.send(503,{'error':'Не удалось связаться со службой переключателя'})
            return self.send(200 if result.get('ok') else 503,result)
        if path=='/api/logout':
            cookies=http.cookies.SimpleCookie(self.headers.get('Cookie',''))
            with self.app.lock:
                self.app.sessions.pop(hashlib.sha256(cookies['ts_session'].value.encode()).hexdigest(),None)
            return self.send(200,{'ok':True},extra={'Set-Cookie':'ts_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path='+self.app.config.get('cookie_path','/')})
        if path=='/api/alias':
            key,label=str(body.get('id',''))[:200],str(body.get('label','')).strip()[:100]
            if not key or not label:
                return self.send(400,{'error':'Укажите имя клиента'})
            if not self.app.store.rename(key,label):return self.send(404,{'error':'Клиент не найден'})
            return self.send(200,{'ok':True})
        return self.send(404,{'error':'Не найдено'})


class IngestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        def read(n):
            raw=bytearray()
            while len(raw)<n:
                part=self.request.recv(n-len(raw))
                if not part:
                    raise ValueError('incomplete frame')
                raw.extend(part)
            return bytes(raw)
        try:
            size=struct.unpack('!I',read(4))[0]
            if not 0<size<=4*1024*1024:
                return
            self.server.app.store.ingest(json.loads(read(size)))
            self.request.sendall(b'OK')
        except Exception as e:
            logging.warning('ingest failed: %s',type(e).__name__)


class DashboardServer(ThreadingHTTPServer):
    tls_context=None
    def get_request(self):
        connection,address=super().get_request();connection.settimeout(15)
        if self.tls_context:connection=self.tls_context.wrap_socket(connection,server_side=True,do_handshake_on_connect=False)
        return connection,address


def serve(config):
    app=App(config)
    if hasattr(socketserver,'UnixStreamServer') and config.get('ingest_socket'):
        path=pathlib.Path(config['ingest_socket'])
        path.parent.mkdir(parents=True,exist_ok=True)
        path.unlink(missing_ok=True)
        uds=socketserver.UnixStreamServer(str(path),IngestHandler)
        uds.app=app
        os.chmod(path,0o600)
        threading.Thread(target=uds.serve_forever,daemon=True).start()
    server=DashboardServer((config.get('host','127.0.0.1'),config.get('port',9180)),Handler)
    if config.get('tls_cert') and config.get('tls_key'):
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.minimum_version=ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(config['tls_cert'],config['tls_key']);server.tls_context=tls
    server.daemon_threads=True
    server.app=app
    def cleanup():
        while True:
            app.store.cleanup(config.get('retention_days',14))
            time.sleep(3600)
    threading.Thread(target=cleanup,daemon=True).start()
    print('TunnelScope listening on %s:%s'%server.server_address,flush=True)
    server.serve_forever()


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--config',default='/etc/tunnelscope/web.json')
    args=p.parse_args()
    serve(json.loads(pathlib.Path(args.config).read_text()))


if __name__=='__main__':
    main()
