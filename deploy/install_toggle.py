"""Install the private, one-setting control helper. Preserve the current rule state."""
import datetime
import os
import pathlib
import shutil
import subprocess

UNIT="""[Unit]
Description=TunnelScope private Supercell rule switch
After=network.target tunnelscope-web.service
[Service]
User=root
Group=tunnelscope
WorkingDirectory=/opt/tunnelscope
ExecStart=/usr/bin/python3 -B -m tunnelscope.control
Restart=on-failure
RestartSec=3
RuntimeDirectory=tunnelscope-control
RuntimeDirectoryMode=0750
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ReadWritePaths=/etc/tunnelscope /var/lib/tunnelscope-policy
MemoryMax=64M
CPUQuota=10%
UMask=0007
[Install]
WantedBy=multi-user.target
"""

def main():
    if os.geteuid()!=0:raise SystemExit('Run as root')
    backup=pathlib.Path('/etc/tunnelscope/toggle-backup-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(mode=0o700);shutil.copy2('/etc/tunnelscope/collector.json',backup/'collector.json')
    pathlib.Path('/etc/systemd/system/tunnelscope-control.service').write_text(UNIT)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable','--now','tunnelscope-control.service'],check=True)
    # Web restart closes the old ingest socket; restart only the monitoring agent afterwards.
    subprocess.run(['systemctl','restart','tunnelscope-web.service','tunnelscope-agent.service'],check=True)
    print('Control installed; existing policy setting preserved')
if __name__=='__main__':main()
