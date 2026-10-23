"""Upgrade only TunnelScope; no VPN restarts or package installation."""
import datetime
import json
import os
import pathlib
import subprocess
import sys
ROOT=pathlib.Path('/opt/tunnelscope');sys.path.insert(0,str(ROOT))
from tunnelscope.common import uid
from tunnelscope.policy import nft_script

def main():
    if os.geteuid()!=0:raise SystemExit('Run as root')
    conf=pathlib.Path('/etc/tunnelscope/collector.json')
    original=conf.read_text();config=json.loads(original)
    state=pathlib.Path('/var/lib/tunnelscope-policy');state.mkdir(mode=0o700,exist_ok=True);state.chmod(0o700)
    backup=pathlib.Path('/etc/tunnelscope/policy-backup-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(mode=0o700);(backup/'collector.json').write_text(original)
    subprocess.run(['nft','-c','-f','-'],input=nft_script(False),text=True,check=True)
    config['supercell_policy']={'enabled':True,'seconds':20,'exempt_client_ids':[uid('xray','Honor-magic-8-pro')],
                              'state_file':str(state/'events.json')}
    conf.write_text(json.dumps(config,ensure_ascii=False,indent=2)+'\n');conf.chmod(0o600)
    override=pathlib.Path('/etc/systemd/system/tunnelscope-agent.service.d');override.mkdir(exist_ok=True)
    (override/'policy.conf').write_text('[Service]\nReadWritePaths=/var/lib/tunnelscope-policy\nExecStopPost=-/usr/bin/python3 -B -m tunnelscope.policy --cleanup\nTimeoutStopSec=15\n')
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','restart','tunnelscope-agent'],check=True)
    print(json.dumps({'policy':True,'seconds':20,'exception':'Honor-magic-8-pro','backup':str(backup)}))
if __name__=='__main__':main()
