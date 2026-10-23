#!/usr/bin/env bash
set -Eeuo pipefail
umask 022
if [[ ${EUID} -ne 0 ]]; then
  echo 'Run with sudo: curl -fsSL https://raw.githubusercontent.com/mikhail384/tunnelscope/main/install.sh | sudo bash' >&2
  exit 1
fi
if [[ ! -r /etc/os-release ]]; then echo 'Ubuntu is required' >&2; exit 1; fi
. /etc/os-release
if [[ ${ID} != ubuntu ]]; then echo 'This installer supports Ubuntu 22.04 and newer' >&2; exit 1; fi
if ! dpkg --compare-versions "$VERSION_ID" ge 22.04; then echo 'Ubuntu 22.04+ is required' >&2; exit 1; fi
missing=()
for pair in 'python3:python3' 'curl:curl' 'ip:iproute2' 'nft:nftables' 'openssl:openssl'; do
  command -v "${pair%%:*}" >/dev/null || missing+=("${pair#*:}")
done
if [[ ! -f /etc/ssl/certs/ca-certificates.crt ]]; then missing+=(ca-certificates); fi
if (( ${#missing[@]} )); then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
fi
command -v systemctl >/dev/null || { echo 'systemd is required' >&2; exit 1; }
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
  python3 - <<'PY'
import os,pathlib,tarfile
root=pathlib.Path(os.environ['TUNNELSCOPE_TMP'])/'source';root.mkdir()
with tarfile.open(root.parent/'source.tar.gz') as archive:
    entries=archive.getmembers()
    if len(entries)>5000 or sum(m.size for m in entries)>30000000: raise SystemExit('Source archive is too large')
    for member in entries:
        if member.issym() or member.islnk() or not (root/member.name).resolve().is_relative_to(root): raise SystemExit('Unsafe archive')
        if not (member.isfile() or member.isdir()): raise SystemExit('Invalid source entry')
    archive.extractall(root,filter='data')
folders=list(root.iterdir())
if len(folders)!=1 or not folders[0].is_dir(): raise SystemExit('Invalid source layout')
(root.parent/'source-path').write_text(str(folders[0]))
PY
  TUNNELSCOPE_SOURCE=$(cat "$TUNNELSCOPE_TMP/source-path")
  export TUNNELSCOPE_SOURCE
fi
python3 - <<'PY'
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
python3 -B -m deploy.install
