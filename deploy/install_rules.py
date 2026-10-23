"""Install persistent access rules without restarting any VPN daemon."""
import datetime
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import urllib.request
from tunnelscope.adult import atomic_json,update_list
from tunnelscope.common import uid
from deploy.install_toggle import UNIT

UPDATE_UNIT="""[Unit]
Description=TunnelScope adult domain list update
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
WorkingDirectory=/opt/tunnelscope
ExecStart=/usr/bin/python3 -B -m tunnelscope.adult --update-list
User=root
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/tunnelscope-policy
MemoryMax=96M
CPUQuota=20%
TimeoutStartSec=15min
"""
TIMER="""[Unit]
Description=Refresh TunnelScope adult domain list daily
[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=yes
[Install]
WantedBy=timers.target
"""

CSQTT_LOCATION='\n    # TunnelScope: CSQTT panel through the existing trusted HTTPS listener\n    location = /csqtt { return 302 /csqtt/; }\n    location ^~ /csqtt/ {\n        proxy_pass https://127.0.0.1:46002/;\n        proxy_http_version 1.1;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $proxy_protocol_addr;\n        proxy_set_header X-Forwarded-Proto https;\n        proxy_set_header Accept-Encoding "";\n        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection "upgrade";\n        proxy_intercept_errors off;\n        proxy_read_timeout 90s;\n        proxy_cookie_path / /csqtt/;\n        proxy_redirect ~^(/.*)$ /csqtt$1;\n        sub_filter_once off;\n        sub_filter_types application/javascript application/manifest+json;\n        sub_filter \'"/\' \'"/csqtt/\';\n        sub_filter "\'/" "\'/csqtt/";\n        sub_filter \'`/\' \'`/csqtt/\';\n        sub_filter \'url(/\' \'url(/csqtt/\';\n    }\n'

def install_csqtt_proxy():
 site=pathlib.Path('/etc/nginx/sites-enabled/vpn.example.org').resolve()
 original=site.read_text()
 updated=original.replace('proxy_read_timeout 20s;','proxy_read_timeout 60s;')
 marker='    # TunnelScope: CSQTT panel through the existing trusted HTTPS listener'
 if marker in updated:
  start=updated.index(marker);end=updated.index('\n    }',start)+len('\n    }')
  updated=updated[:start]+CSQTT_LOCATION.lstrip('\n')+updated[end:]
 elif 'location ^~ /csqtt/' not in original:
  index=updated.rfind('}');updated=updated[:index]+CSQTT_LOCATION+updated[index:]
 updated=updated.replace('proxy_pass http://127.0.0.1:9180/;','proxy_pass http://127.0.0.1:9180/;\n        proxy_intercept_errors off;',1) if 'proxy_pass http://127.0.0.1:9180/;\n        proxy_intercept_errors off;' not in updated else updated
 if updated==original:return
 backup=pathlib.Path('/etc/tunnelscope/nginx-before-csqtt-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')+'.conf')
 backup.write_text(original);backup.chmod(0o600)
 site.write_text(updated)
 try:
  subprocess.run(['nginx','-t'],check=True)
  subprocess.run(['systemctl','reload','nginx'],check=True)
 except BaseException:
  site.write_text(original);raise

def main():
 if os.geteuid()!=0:raise SystemExit('Run as root')
 root=pathlib.Path('/var/lib/tunnelscope-policy');root.mkdir(mode=0o700,exist_ok=True);root.chmod(0o700)
 db=root/'adult-domains.db'
 if not db.exists():
  print('Building domain list...',flush=True);meta=update_list(db);print('Domain count:',meta['count'],flush=True)
 config_path=pathlib.Path('/etc/tunnelscope/collector.json')
 backup=config_path.with_name('collector-before-rules-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')+'.json')
 shutil.copy2(config_path,backup);backup.chmod(0o600)
 config=json.loads(config_path.read_text());honor=uid('xray','Honor-magic-8-pro')
 config['client_catalog']=str(root/'client-catalog.json')
 for name in ('supercell','adult'):
  rule=config.setdefault(name+'_policy',{});rule.setdefault('enabled',True)
  ids=set(rule.get('exempt_client_ids',[]));ids.add(honor);rule['exempt_client_ids']=sorted(ids)
 config['adult_policy'].update(state_file=str(root/'denials.json'),list_file=str(db))
 if not (root/'denials.json').exists():atomic_json(root/'denials.json',{'blocked':{},'history':[]})
 # Panel URLs are returned only to authenticated administrators.
 xdb=sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro',uri=True)
 settings=dict(xdb.execute('select key,value from settings').fetchall());xdb.close()
 base=settings.get('webBasePath','/');base='/'+base.strip('/')+'/'
 config['panel_links']=[{'name':'3x-ui','url':'https://vpn.example.org'+base,'description':'VLESS, Trojan и другие протоколы Xray'}]
 install_csqtt_proxy()
 config['panel_links'].append({'name':'CSQTT','url':'https://vpn.example.org/csqtt/','description':'Устройства, профили и настройки CSQTT'})
 atomic_json(config_path,config)
 pathlib.Path('/etc/systemd/system/tunnelscope-control.service').write_text(UNIT)
 pathlib.Path('/etc/systemd/system/tunnelscope-adult-list.service').write_text(UPDATE_UNIT)
 pathlib.Path('/etc/systemd/system/tunnelscope-adult-list.timer').write_text(TIMER)
 subprocess.run(['systemctl','daemon-reload'],check=True)
 subprocess.run(['systemctl','enable','--now','tunnelscope-adult-list.timer'],check=True)
 subprocess.run(['systemctl','restart','tunnelscope-control.service','tunnelscope-web.service'],check=True)
 subprocess.run(['systemctl','restart','tunnelscope-agent.service'],check=True)
 print('Access rules installed; Honor excluded from both; VPN services were not restarted.',flush=True)
if __name__=='__main__':main()
