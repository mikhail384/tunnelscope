#!/usr/bin/env bash
set -Eeuo pipefail
umask 022
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
if [[ ${EUID} -ne 0 ]]; then
  echo 'Run this installer as root or with sudo. The complete bootstrap command is in README.md.' >&2
  exit 1
fi
if [[ ! -r /etc/os-release ]]; then echo 'Ubuntu Server is required' >&2; exit 1; fi
. /etc/os-release
if [[ ${ID:-} != ubuntu ]]; then echo 'Ubuntu Server 22.04, 24.04 or 26.04 is required' >&2; exit 1; fi
case ${VERSION_ID:-} in
  22.04|24.04|26.04) ;;
  *) echo "Unsupported Ubuntu release: ${VERSION_ID:-unknown}. Supported: 22.04, 24.04, 26.04." >&2; exit 1 ;;
esac
deps_only=0
if [[ ${1:-} == --dependencies-only && $# == 1 ]]; then deps_only=1
elif (( $# )); then echo 'Usage: bash install.sh [--dependencies-only]' >&2; exit 1; fi
packages=(ca-certificates curl python3 iproute2 nftables openssl passwd util-linux systemd)
commands=(curl python3 ip nft openssl useradd flock systemctl)
missing=()
for package in "${packages[@]}"; do
  [[ $(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true) == installed ]] || missing+=("$package")
done
need_install=0
(( ${#missing[@]} )) && need_install=1
for executable in "${commands[@]}"; do command -v "$executable" >/dev/null || need_install=1; done
[[ -r /etc/ssl/certs/ca-certificates.crt ]] || need_install=1
if (( need_install )); then
  echo "Installing TunnelScope dependencies on Ubuntu $VERSION_ID..."
  apt-get -o Acquire::Retries=3 -o APT::Update::Error-Mode=any update
  apt-get -o DPkg::Lock::Timeout=180 -o Acquire::Retries=3 install -y --no-install-recommends "${packages[@]}"
fi
for executable in "${commands[@]}"; do
  command -v "$executable" >/dev/null || { echo "Dependency is unavailable: $executable" >&2; exit 1; }
done
/usr/bin/python3 - <<'CHECK'
import hashlib, json, socket, sqlite3, ssl, tarfile, urllib.request, xml.etree.ElementTree, zipfile
assert ssl.create_default_context(cafile='/etc/ssl/certs/ca-certificates.crt').get_ca_certs(), 'System CA certificates are unavailable'
with sqlite3.connect(':memory:') as db: db.execute('select 1').fetchone()
CHECK
if (( deps_only )); then echo "DEPENDENCIES_READY Ubuntu $VERSION_ID"; exit 0; fi
if [[ ! -d /run/systemd/system ]]; then
  echo 'Full installation needs Ubuntu Server with systemd running as init. Use --dependencies-only to check packages in a container.' >&2
  exit 1
fi
exec 9>/run/lock/tunnelscope-install.lock
flock -w 180 9 || { echo 'Another TunnelScope installation is running' >&2; exit 1; }
TUNNELSCOPE_TMP=$(mktemp -d /tmp/tunnelscope-install.XXXXXXXX)
trap 'rm -rf -- "$TUNNELSCOPE_TMP"' EXIT
export TUNNELSCOPE_TMP
if [[ -n ${TUNNELSCOPE_SOURCE:-} ]]; then
  export TUNNELSCOPE_SOURCE
else
  ref=${TUNNELSCOPE_REF:-main}
  if [[ ! $ref =~ ^[A-Za-z0-9._-]+$ ]]; then echo 'Invalid source ref' >&2; exit 1; fi
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --max-time 120 \
    "https://codeload.github.com/mikhail384/tunnelscope/tar.gz/$ref" -o "$TUNNELSCOPE_TMP/source.tar.gz"
  /usr/bin/python3 - <<'PY'
import os,pathlib,tarfile
root=pathlib.Path(os.environ['TUNNELSCOPE_TMP'])/'source';root.mkdir()
with tarfile.open(root.parent/'source.tar.gz') as archive:
    entries=archive.getmembers()
    if len(entries)>5000 or sum(m.size for m in entries)>30000000: raise SystemExit('Source archive is too large')
    for member in entries:
        if member.issym() or member.islnk() or not (root/member.name).resolve().is_relative_to(root): raise SystemExit('Unsafe archive')
        if not (member.isfile() or member.isdir()): raise SystemExit('Invalid source entry')
    if hasattr(tarfile,'data_filter'): archive.extractall(root,filter='data')
    else: archive.extractall(root)  # Only regular files/directories inside root were accepted above.
folders=list(root.iterdir())
if len(folders)!=1 or not folders[0].is_dir(): raise SystemExit('Invalid source layout')
(root.parent/'source-path').write_text(str(folders[0]))
PY
  TUNNELSCOPE_SOURCE=$(cat "$TUNNELSCOPE_TMP/source-path")
  export TUNNELSCOPE_SOURCE
fi
/usr/bin/python3 - <<'PY'
import datetime,os,pathlib,shutil
source=pathlib.Path(os.environ['TUNNELSCOPE_SOURCE']).resolve();target=pathlib.Path('/opt/tunnelscope')
for name in ('tunnelscope/server.py','static/index.html','deploy/install.py'):
    if not (source/name).is_file(): raise SystemExit('Incomplete TunnelScope source')
if target.is_symlink(): raise SystemExit('Refusing a symlink at /opt/tunnelscope')
if target.exists():
    backup=pathlib.Path('/var/backups/tunnelscope')/datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S-%f');backup.mkdir(parents=True,mode=0o700)
    for name in ('tunnelscope','static','deploy'):
        if (target/name).exists(): shutil.copytree(target/name,backup/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    print('Code backup:',backup)
target.mkdir(parents=True,exist_ok=True)
for folder in ('tunnelscope','static','deploy'):
    for item in (source/folder).rglob('*'):
        if item.is_symlink(): raise SystemExit('Source symlink rejected')
        if item.is_file() and '__pycache__' not in item.parts:
            dest=target/item.relative_to(source)
            if dest.is_symlink() or not dest.resolve().is_relative_to(target.resolve()): raise SystemExit('Unsafe destination')
            dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(item,dest);dest.chmod(0o644)
for name in ('README.md','config.example.json','install.sh'):
    if (source/name).exists(): shutil.copyfile(source/name,target/name)
PY
cd /opt/tunnelscope
/usr/bin/python3 -B -m deploy.install
