import pathlib
import tarfile
import zipfile

root=pathlib.Path(__file__).resolve().parent.parent
dest=root/'dist';dest.mkdir(exist_ok=True)
files=[]
for folder in ('tunnelscope','static','deploy','tests'):
    files.extend(p for p in (root/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
files.extend(root/p for p in ('README.md','config.example.json','.gitignore','install.sh','install-command.txt','THIRD_PARTY_NOTICES.md'))
def permissions(info):
    info.mode=0o755 if info.isdir() else 0o644
    info.uid=info.gid=0
    info.uname=info.gname='root'
    return info
with tarfile.open(dest/'tunnelscope-1.0.tar.gz','w:gz') as archive:
    for p in files:archive.add(p,arcname=p.relative_to(root).as_posix(),filter=permissions)
with zipfile.ZipFile(dest/'TunnelScope-Ubuntu.zip','w',zipfile.ZIP_DEFLATED) as archive:
    for p in files:archive.write(p,arcname=p.relative_to(root).as_posix())
print('Packaged',len(files),'source files')
