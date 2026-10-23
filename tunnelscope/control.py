"""Private root helper: read or change one boolean, never arbitrary commands."""
import argparse
import json
import logging
import os
import pathlib
import socket
import socketserver
import stat
import struct
import tempfile
import threading
from .policy import Backend, command
from .adult import CID, read_state, atomic_json, STATE_DIR
from .sites import normalize_domains, MAX_TOTAL
from .speed import validate as validate_speed, rate, read_status as speed_status
from .apps import validate as validate_apps, catalog as app_catalog, read_status as app_status
import time

SOCKET='/run/tunnelscope-control/policy.sock'
CONFIG='/etc/tunnelscope/collector.json'


def validate_request(request):
    if not isinstance(request,dict):raise ValueError('object required')
    if request.get('action') in ('apps','apps_inherit'):return validate_apps(request)
    if str(request.get('action','')).startswith('speed'):return validate_speed(request)
    if request=={'action':'get'}:return 'get'
    if set(request)=={'action','enabled'} and request['action']=='set' and type(request['enabled']) is bool:return 'set'
    if request.get('action')=='update' and request.get('rule') in ('supercell','adult','custom','apps'):
        keys=set(request)-{'action','rule'}
        if not keys or not keys<={'enabled','exempt_client_ids'}:raise ValueError('invalid settings')
        if 'enabled' in keys and type(request['enabled']) is not bool:raise ValueError('boolean required')
        ids=request.get('exempt_client_ids',[])
        if not isinstance(ids,list) or len(ids)>100 or any(not isinstance(x,str) or not CID.fullmatch(x) for x in ids) or len(set(ids))!=len(ids):raise ValueError('invalid client IDs')
        return 'update'
    if set(request)=={'action','client_id','domains'} and request['action']=='sites':
        if not isinstance(request['client_id'],str) or request['client_id'] and not CID.fullmatch(request['client_id']):raise ValueError('invalid client ID')
        normalize_domains(request['domains']);return 'sites'
    if set(request)=={'action','client_id'} and request['action']=='unblock' and isinstance(request['client_id'],str) and CID.fullmatch(request['client_id']):return 'unblock'
    raise ValueError('unsupported policy command')


def atomic_config(path, config):
    path=pathlib.Path(path)
    with tempfile.NamedTemporaryFile(mode='w',encoding='utf8',dir=path.parent,prefix='.policy-',delete=False) as f:
        temporary=pathlib.Path(f.name)
        try:
            os.chmod(temporary,0o600)
            json.dump(config,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True);raise
    try:os.replace(temporary,path)
    finally:temporary.unlink(missing_ok=True)


class Controller:
    def __init__(self, config_path=CONFIG, runner=command, backend_factory=Backend):
        self.path=pathlib.Path(config_path);self.runner=runner;self.backend_factory=backend_factory
        self.lock=threading.Lock();self.applying=False;self.last_error=''

    def status(self):
        config=json.loads(self.path.read_text(encoding='utf8'))
        p=config.get('supercell_policy',{})
        catalog_path=config.get('client_catalog')
        clients=json.loads(pathlib.Path(catalog_path).read_text(encoding='utf8')) if catalog_path and pathlib.Path(catalog_path).exists() else []
        adult=config.get('adult_policy',{})
        state=read_state(adult.get('state_file',STATE_DIR+'/denials.json')) if adult or config.get('custom_policy') else {'blocked':{}}
        rules={name:{'enabled':bool(config.get(name+'_policy',{}).get('enabled',False)),
                    'exempt_client_ids':config.get(name+'_policy',{}).get('exempt_client_ids',[])} for name in ('supercell','adult','custom','apps')}
        custom=config.get('custom_policy',{})
        rules['custom'].update(domains=custom.get('domains',[]),client_domains=custom.get('client_domains',{}))
        speeds=config.get('speed_limits',{})
        speed={k:speeds.get(k,False if k=='enabled' else {} if k=='clients' else 0) for k in ('enabled','download_mbps','upload_mbps','clients')}
        speed['status']=speed_status(config)
        ap=config.get('apps_policy',{})
        apps={k:ap.get(k,False if k=='enabled' else {} if k=='clients' else []) for k in ('enabled','app_ids','clients','exempt_client_ids')}
        data=app_catalog();apps.update(catalog=data['apps'],version=data['version'],source=data['source'],telegram_source=data['telegram_source'],status=app_status(config))
        return {'apps':apps,'speed':speed,'rules':rules,'clients':clients,'blocked':list(state['blocked'].values()),'panel_links':config.get('panel_links',[]),
                'ok':not self.last_error,'available':True,'enabled':bool(p.get('enabled',False)),
                'seconds':int(p.get('seconds',20)),'applying':self.applying,'error':self.last_error}

    def request(self, request):
        action=validate_request(request)
        if action=='get':return self.status()
        if action.startswith('speed'):return self.change_speed(request)
        if action in ('apps','apps_inherit'):return self.change_apps(request)
        if action!='set':return self.change(request)
        enabled=request['enabled']
        with self.lock:
            self.applying=True;self.last_error=''
            try:
                config=json.loads(self.path.read_text(encoding='utf8'))
                config.setdefault('supercell_policy',{})['enabled']=enabled
                atomic_config(self.path,config)
                self.runner(['systemctl','restart','tunnelscope-agent.service'],timeout=14)
                if not enabled:
                    # Verify cleanup again; never trust a browser-supplied client ID or rule tag.
                    self.backend_factory(config).cleanup()
                self.runner(['systemctl','is-active','--quiet','tunnelscope-agent.service'],timeout=2)
            except Exception:
                self.last_error='Не удалось применить переключатель. Повторите действие.'
                logging.exception('policy toggle failed')
            finally:self.applying=False
            return self.status()


    def change(self,request):
        with self.lock:
            self.applying=True;self.last_error='';stopped=False
            try:
                config=json.loads(self.path.read_text(encoding='utf8'));current=self.status()
                if request['action']=='update':
                    key=request['rule']+'_policy';settings=config.setdefault(key,{})
                    ids=request.get('exempt_client_ids')
                    known={c['id'] for c in current['clients']}|set(settings.get('exempt_client_ids',[]))
                    if ids is not None and not set(ids)<=known:raise ValueError('Unknown device')
                elif request['action']=='sites':
                    settings=config.setdefault('custom_policy',{})
                    cid=request['client_id'];values=normalize_domains(request['domains'])
                    if cid and cid not in {c['id'] for c in current['clients']}:raise ValueError('Unknown device')
                    personal=dict(settings.get('client_domains',{}));global_sites=settings.get('domains',[])
                    if cid:
                        if values:personal[cid]=values
                        else:personal.pop(cid,None)
                    else:global_sites=values
                    if len(global_sites)+sum(len(v) for v in personal.values())>MAX_TOTAL:raise ValueError('Too many domains')
                    if global_sites==settings.get('domains',[]) and personal==settings.get('client_domains',{}):
                        self.applying=False;return self.status()
                else:
                    if request['client_id'] not in {e['client_id'] for e in current['blocked']}:raise ValueError('Client is not blocked')
                self.runner(['systemctl','stop','tunnelscope-agent.service'],timeout=14);stopped=True
                adult=config.get('adult_policy',{});path=adult.get('state_file',STATE_DIR+'/denials.json')
                state=read_state(path) if adult or config.get('custom_policy') else {'blocked':{},'history':[]}
                release=set()
                if request['action']=='unblock':release.add(request['client_id'])
                elif request.get('rule')=='adult':release.update(cid for cid in request.get('exempt_client_ids',[]) if state['blocked'].get(cid,{}).get('rule','adult')=='adult')
                backend=self.backend_factory(config)
                for cid in release:
                    event=state['blocked'].get(cid)
                    if not event:continue
                    backend.unblock_permanent(event)
                    event=dict(event,state='released',released=time.time());state.setdefault('history',[]).append(event)
                    del state['blocked'][cid]
                if release:
                    state['history']=state['history'][-100:];atomic_json(path,state)
                if request['action']=='update':
                    for field in ('enabled','exempt_client_ids'):
                        if field in request:settings[field]=request[field]
                    atomic_config(self.path,config)
                elif request['action']=='sites':
                    settings['domains']=global_sites;settings['client_domains']=personal
                    atomic_config(self.path,config)
            except ValueError:
                self.last_error='Неизвестное устройство или некорректная настройка.'
            except Exception:
                self.last_error='Не удалось применить правило. Повторите действие.';logging.exception('policy update failed')
            finally:
                if stopped:
                    try:
                        self.runner(['systemctl','start','tunnelscope-agent.service'],timeout=14)
                        self.runner(['systemctl','is-active','--quiet','tunnelscope-agent.service'],timeout=2)
                    except Exception:self.last_error='Сборщик не запустился; требуется проверка службы.';logging.exception('agent restart failed')
                self.applying=False
            return self.status()

    def change_speed(self,request):
        with self.lock:
            self.applying=True;self.last_error=''
            try:
                config=json.loads(self.path.read_text(encoding='utf8'));current=self.status()
                cid=request.get('client_id','')
                if cid and cid not in {c['id'] for c in current['clients']}:raise ValueError('Неизвестный клиент')
                speeds=config.setdefault('speed_limits',{'enabled':False,'download_mbps':0,'upload_mbps':0,'clients':{}})
                if request['action']=='speed_toggle':speeds['enabled']=request['enabled']
                elif request['action']=='speed_inherit':speeds.setdefault('clients',{}).pop(cid,None)
                else:
                    values={k:rate(request[k]) for k in ('download_mbps','upload_mbps')}
                    if cid:speeds.setdefault('clients',{})[cid]=values
                    else:speeds.update(values)
                atomic_config(self.path,config)
                self.runner(['systemctl','restart','tunnelscope-agent.service'],timeout=20)
                self.runner(['systemctl','is-active','--quiet','tunnelscope-agent.service'],timeout=2)
            except ValueError as error:self.last_error=str(error)[:200]
            except Exception:
                self.last_error='Настройка сохранена, но сборщик не перезапустился. Требуется проверка службы.';logging.exception('speed update failed')
            finally:self.applying=False
            return self.status()

    def change_apps(self,request):
        with self.lock:
            self.applying=True;self.last_error=''
            try:
                config=json.loads(self.path.read_text(encoding='utf8'));current=self.status();cid=request['client_id']
                if cid and cid not in {c['id'] for c in current['clients']}:raise ValueError('Неизвестный клиент')
                settings=config.setdefault('apps_policy',{'enabled':False,'app_ids':[],'clients':{},'exempt_client_ids':[]})
                if request['action']=='apps_inherit':settings.setdefault('clients',{}).pop(cid,None)
                elif cid:settings.setdefault('clients',{})[cid]=sorted(request['app_ids'])
                else:settings['app_ids']=sorted(request['app_ids'])
                atomic_config(self.path,config)
                self.runner(['systemctl','restart','tunnelscope-agent.service'],timeout=20)
                self.runner(['systemctl','is-active','--quiet','tunnelscope-agent.service'],timeout=2)
            except ValueError as error:self.last_error=str(error)[:200]
            except Exception:
                self.last_error='Настройка приложений сохранена, но не применена. Требуется проверка службы.';logging.exception('application update failed')
            finally:self.applying=False
            return self.status()


def rpc(path, request, timeout=40):
    validate_request(request)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(timeout);s.connect(path)
        s.sendall(json.dumps(request).encode()+b'\n')
        raw=bytearray()
        while b'\n' not in raw and len(raw)<=262144:
            part=s.recv(min(65536,262144-len(raw)+1))
            if not part:break
            raw.extend(part)
        if len(raw)>262144:raise ValueError('response too large')
        reply=json.loads(raw)
        if not isinstance(reply,dict) or type(reply.get('enabled')) is not bool:raise ValueError('invalid response')
        return reply


class ControlHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(40)
        try:
            pid,uid,gid=struct.unpack('3i',self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if uid not in self.server.allowed_uids:return
            raw=bytearray()
            while b'\n' not in raw and len(raw)<=32768:
                part=self.request.recv(32769-len(raw))
                if not part:break
                raw.extend(part)
            if len(raw)>32768:raise ValueError('request too large')
            result=self.server.controller.request(json.loads(raw))
        except (ValueError,TypeError,KeyError):result={'ok':False,'error':'Некорректная команда'}
        except Exception:result={'ok':False,'error':'Управление правилом временно недоступно'}
        try:self.request.sendall(json.dumps(result).encode()+b'\n')
        except OSError:pass


def main():
    import pwd
    p=argparse.ArgumentParser();p.add_argument('--socket',default=SOCKET);p.add_argument('--config',default=CONFIG);args=p.parse_args()
    if os.geteuid()!=0:raise SystemExit('Run as root')
    account=pwd.getpwnam('tunnelscope');path=pathlib.Path(args.socket)
    path.parent.mkdir(mode=0o750,exist_ok=True);os.chown(path.parent,0,account.pw_gid);path.parent.chmod(0o750)
    if path.exists():
        if not stat.S_ISSOCK(path.lstat().st_mode):raise SystemExit('Refusing to replace a non-socket')
        path.unlink()
    server=socketserver.ThreadingUnixStreamServer(str(path),ControlHandler);server.daemon_threads=True
    server.allowed_uids={0,account.pw_uid};server.controller=Controller(args.config)
    os.chown(path,0,account.pw_gid);path.chmod(0o660)
    server.serve_forever()

if __name__=='__main__':main()
