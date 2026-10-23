"""Portable Ubuntu installation; existing VPN configuration is never rewritten."""
import argparse
import datetime
import ipaddress
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import subprocess
import sys

ROOT = pathlib.Path('/opt/tunnelscope')
sys.path.insert(0, str(ROOT))
from tunnelscope.server import password_hash


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


def detect_interfaces():
    links = json.loads(run('ip', '-j', '-d', 'link', 'show').stdout)
    addresses = {x['ifname']: x.get('addr_info', []) for x in json.loads(run('ip', '-j', 'address', 'show').stdout)}
    result = []
    for link in links:
        name = link['ifname']; kind = link.get('linkinfo', {}).get('info_kind', '')
        if name == 'lo' or kind in ('bridge', 'veth') or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', name): continue
        source = 'csqtt' if name.startswith('csqtt') else 'wireguard' if kind == 'wireguard' else 'amnezia' if kind == 'amneziawg' else 'server'
        item = {'name': name, 'source': source}
        if source != 'server':
            addr = next((a for a in addresses.get(name, []) if a.get('family') == 'inet'), None)
            if addr: item['network'] = str(ipaddress.ip_network(addr['local'] + '/' + str(addr['prefixlen']), strict=False))
        result.append(item)
    return result


def collector_config(interfaces):
    state = '/var/lib/tunnelscope-policy'
    return {'interfaces': interfaces, 'xui_db': '/etc/x-ui/x-ui.db', 'csqtt_db': '/etc/csqtt/csqtt.db',
            'xray_log': '/var/log/x-ui/tunnelscope-access.log', 'ingest_socket': '/run/tunnelscope/ingest.sock',
            'max_flows': 6000, 'max_packets_per_second': 4000, 'client_catalog': state + '/client-catalog.json',
            'supercell_policy': {'enabled': False, 'seconds': 20, 'exempt_client_ids': [], 'state_file': state + '/events.json'},
            'adult_policy': {'enabled': False, 'exempt_client_ids': [], 'state_file': state + '/denials.json', 'list_file': state + '/adult-domains.db'},
            'apps_policy': {'enabled': False, 'app_ids': [], 'clients': {}, 'exempt_client_ids': [], 'state_file': state + '/apps.json'},
            'custom_policy': {'enabled': False, 'domains': [], 'client_domains': {}, 'exempt_client_ids': []},
            'speed_limits': {'enabled': False, 'download_mbps': 0, 'upload_mbps': 0, 'clients': {}, 'state_file': state + '/speed.json'}}


def units():
    common = '\nRestart=on-failure\nRestartSec=5\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nUMask=0077\n'
    def unit(name, module, extra, after='network.target'):
        return '[Unit]\nDescription=TunnelScope ' + name + '\nAfter=' + after + '\n[Service]\nWorkingDirectory=/opt/tunnelscope\nExecStart=/usr/bin/python3 -B -m tunnelscope.' + module + '\n' + extra + common + '[Install]\nWantedBy=multi-user.target\n'
    return {
        'web': unit('web dashboard', 'server', 'User=tunnelscope\nGroup=tunnelscope\nRuntimeDirectory=tunnelscope\nRuntimeDirectoryMode=0700\nReadWritePaths=/var/lib/tunnelscope /run/tunnelscope\nMemoryMax=160M\nCPUQuota=15%'),
        'control': unit('private policy helper', 'control', 'User=root\nGroup=tunnelscope\nRuntimeDirectory=tunnelscope-control\nRuntimeDirectoryMode=0750\nReadWritePaths=/etc/tunnelscope /var/lib/tunnelscope-policy\nMemoryMax=64M\nCPUQuota=10%'),
        'agent': unit('metadata collector', 'agent', 'User=root\nReadWritePaths=-/etc/x-ui -/etc/csqtt -/var/lib/mita /run/tunnelscope /var/lib/tunnelscope-policy\nRestrictAddressFamilies=AF_UNIX AF_PACKET AF_INET AF_INET6 AF_NETLINK\nExecStopPost=-/usr/bin/python3 -B -m tunnelscope.policy --cleanup\nTimeoutStopSec=15\nMemoryMax=180M\nCPUQuota=20%\nNice=10', 'network.target tunnelscope-web.service tunnelscope-control.service')}


def write_private(path, value, gid=None):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    path.chmod(0o600 if gid is None else 0o640)
    if gid is not None: os.chown(path, 0, gid)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--check', action='store_true'); args = parser.parse_args()
    if args.check:
        print(json.dumps({'interfaces': detect_interfaces(), 'services': list(units())})); return
    if os.geteuid() != 0: raise SystemExit('Run as root')
    import pwd
    conf = pathlib.Path('/etc/tunnelscope'); conf.mkdir(mode=0o750, exist_ok=True)
    backup = conf / ('install-backup-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')); backup.mkdir(mode=0o700)
    for name in ('web.json', 'collector.json', 'access.txt'):
        if (conf / name).exists(): shutil.copy2(conf / name, backup / name); (backup / name).chmod(0o600)
    try: account = pwd.getpwnam('tunnelscope')
    except KeyError:
        run('useradd', '--system', '--home-dir', '/var/lib/tunnelscope', '--shell', '/usr/sbin/nologin', 'tunnelscope'); account = pwd.getpwnam('tunnelscope')
    os.chown(conf, 0, account.pw_gid); conf.chmod(0o750)
    state = pathlib.Path('/var/lib/tunnelscope'); state.mkdir(mode=0o750, exist_ok=True); os.chown(state, account.pw_uid, account.pw_gid)
    private = pathlib.Path('/var/lib/tunnelscope-policy'); private.mkdir(mode=0o700, exist_ok=True); private.chmod(0o700)
    if not (conf / 'web.json').exists():
        port = int(os.environ.get('TUNNELSCOPE_PORT', '9180')); host = os.environ.get('TUNNELSCOPE_BIND', '0.0.0.0')
        if not 1024 <= port <= 65535: raise SystemExit('Port must be between 1024 and 65535')
        ipaddress.IPv4Address(host)
        with socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET) as probe: probe.bind((host, port))
        password = secrets.token_urlsafe(24); salt = secrets.token_hex(16)
        tls = conf / 'tls'; tls.mkdir(mode=0o750, exist_ok=True); os.chown(tls, 0, account.pw_gid)
        cert = tls / 'cert.pem'; key = tls / 'key.pem'
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '365', '-keyout', str(key), '-out', str(cert), '-subj', '/CN=TunnelScope', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1')
        for path in (cert, key): path.chmod(0o640); os.chown(path, 0, account.pw_gid)
        web = {'database': str(state / 'history.db'), 'ingest_socket': '/run/tunnelscope/ingest.sock', 'host': host, 'port': port, 'username': 'admin', 'salt': salt, 'password_hash': password_hash(password, salt), 'cookie_path': '/', 'retention_days': 14, 'server_name': 'Ubuntu VPN', 'owner_lookup': True, 'tls_cert': str(cert), 'tls_key': str(key)}
        write_private(conf / 'web.json', web, account.pw_gid)
        public = host
        if host in ('0.0.0.0', '::'):
            try: public = json.loads(run('ip', '-j', 'route', 'get', '1.1.1.1').stdout)[0]['prefsrc']
            except (subprocess.CalledProcessError, KeyError, IndexError): public = socket.gethostname()
        url = 'https://' + ('[' + public + ']' if ':' in public else public) + ':' + str(port) + '/'
        access = conf / 'access.txt'; access.write_text('URL: ' + url + '\nLogin: admin\nPassword: ' + password + '\n', encoding='utf8'); access.chmod(0o600)
    if not (conf / 'collector.json').exists(): write_private(conf / 'collector.json', collector_config(detect_interfaces()))
    for name, content in units().items():
        dest = pathlib.Path('/etc/systemd/system/tunnelscope-' + name + '.service')
        if dest.exists(): shutil.copy2(dest, backup / dest.name)
        dest.write_text(content, encoding='utf8'); dest.chmod(0o644)
    run('systemctl', 'daemon-reload'); run('systemctl', 'enable', 'tunnelscope-web', 'tunnelscope-control', 'tunnelscope-agent')
    run('systemctl', 'stop', 'tunnelscope-agent'); run('systemctl', 'restart', 'tunnelscope-web', 'tunnelscope-control'); run('systemctl', 'start', 'tunnelscope-agent')
    run('systemctl', 'is-active', '--quiet', 'tunnelscope-web', 'tunnelscope-control', 'tunnelscope-agent')
    print('TunnelScope installed. Credentials: /etc/tunnelscope/access.txt')
    if os.environ.get('TUNNELSCOPE_SHOW_ACCESS','1')=='1' and (conf / 'access.txt').exists(): print((conf / 'access.txt').read_text(encoding='utf8'))
    print('New installations use HTTPS with a self-signed certificate; your browser will ask you to trust it. Existing HTTPS proxy settings are preserved.')
    print('Backup: ' + str(backup))

if __name__ == '__main__': main()
