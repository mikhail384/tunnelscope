"""Enable access metadata through 3x-ui's persistent template. Keeps a reversible backup."""
import datetime
import json
import os
import pathlib
import shutil
import sqlite3
import socket
import stat
import subprocess
import time


def restart_panel(cfg):
    subprocess.run(['systemctl','stop','x-ui'],check=True,timeout=60)
    listeners=subprocess.check_output(['ss','-xlp'],text=True)
    for inbound in cfg.get('inbounds',[]):
        name=str(inbound.get('listen','')).split(',')[0]
        if not name.startswith(('/dev/shm/','/run/')):
            continue
        p=pathlib.Path(name)
        if p.exists() and stat.S_ISSOCK(p.stat().st_mode) and name not in listeners:
            p.unlink()  # Only an orphaned socket, recreated by Xray; never a regular file.
    subprocess.run(['systemctl','start','x-ui'],check=True,timeout=30)


def ready(cfg):
    for inbound in cfg.get('inbounds',[]):
        port=inbound.get('port',0)
        network=inbound.get('streamSettings',{}).get('network','tcp')
        if isinstance(port,int) and port>0 and network not in ('kcp','mkcp','quic'):
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.3):pass
            except OSError:return False
    for inbound in cfg.get('inbounds',[]):
        name=str(inbound.get('listen','')).split(',')[0]
        if name.startswith(('/dev/shm/','/run/')) and name not in subprocess.check_output(['ss','-xlp'],text=True):
            return False
    return True


def main():
    dbpath='/etc/x-ui/x-ui.db'
    runtime=pathlib.Path('/usr/local/x-ui/bin/config.json')
    cfg=json.loads(runtime.read_text())
    backup=pathlib.Path('/etc/tunnelscope')/('xray-backup-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(mode=0o700)
    shutil.copy2(runtime,backup/'runtime.json')
    c=sqlite3.connect(dbpath,timeout=10)
    row=c.execute("SELECT id,value FROM settings WHERE key='xrayTemplateConfig'").fetchone()
    old={'template':list(row) if row else None}
    if row:
        template=json.loads(row[1])
    else:
        # The runtime contains the effective base plus panel-generated inbounds.
        # Preserve the entire base; strip dynamic inbounds so the panel adds them once.
        template=dict(cfg)
        api_tag=cfg.get('api',{}).get('tag','api')
        template['inbounds']=[i for i in cfg.get('inbounds',[]) if i.get('tag')==api_tag]
        if len(template['inbounds'])!=1:
            raise RuntimeError('Cannot identify the API inbound safely')
    template.setdefault('log',{})['access']='/var/log/x-ui/tunnelscope-access.log'
    old['sniffing']=c.execute('SELECT id,sniffing FROM inbounds').fetchall()
    (backup/'settings.json').write_text(json.dumps(old),encoding='utf8')
    os.chmod(backup/'settings.json',0o600)
    # Validate complete effective core configuration before changing persistent settings.
    candidate=dict(cfg)
    candidate['log']=dict(cfg.get('log',{}),access=template['log']['access'])
    target=backup/'validation.json'
    target.write_text(json.dumps(candidate),encoding='utf8');os.chmod(target,0o600)
    subprocess.run(['/usr/local/x-ui/bin/xray-linux-amd64','run','-test','-config',str(target)],check=True,stdout=subprocess.DEVNULL)
    with c:
        if row: c.execute('UPDATE settings SET value=? WHERE id=?',(json.dumps(template),row[0]))
        else: c.execute('INSERT INTO settings(key,value) VALUES(?,?)',('xrayTemplateConfig',json.dumps(template)))
    try:
        restart_panel(cfg)
        for _ in range(45):
            time.sleep(1)
            active=json.loads(runtime.read_text())
            if active.get('log',{}).get('access')==template['log']['access'] and ready(active):
                break
        subprocess.run(['systemctl','is-active','--quiet','x-ui'],check=True)
        active=json.loads(runtime.read_text())
        if active.get('log',{}).get('access')!=template['log']['access']:
            raise RuntimeError('The panel did not apply the access log')
        if not ready(active):
            raise RuntimeError('Core inbounds did not start')
        if len(active.get('inbounds',[]))!=len(cfg.get('inbounds',[])):
            raise RuntimeError('Inbound count changed unexpectedly')
        # Core PID and all previous inbound tags must still be present.
        if {x.get('tag') for x in active['inbounds']}!={x.get('tag') for x in cfg['inbounds']}:
            raise RuntimeError('Inbound tags changed unexpectedly')
        print(json.dumps({'enabled':True,'backup':str(backup),'inbounds':len(active['inbounds'])}))
    except Exception:
        with c:
            if row:c.execute('UPDATE settings SET value=? WHERE id=?',(row[1],row[0]))
            else:c.execute("DELETE FROM settings WHERE key='xrayTemplateConfig'")
        restart_panel(cfg)
        raise
    finally:c.close()


if __name__=='__main__':main()
