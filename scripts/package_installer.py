#!/usr/bin/env python3
"""Bundle the exact compatible server source into one reviewable shell installer."""
import argparse
import base64
import gzip
import hashlib
import io
from pathlib import Path
import tarfile


DOWNLOAD_URL = "https://raw.githubusercontent.com/mikhail384/tunnelscope/csqtt-compatible/install-csqtt.sh"


def package(root: Path, output: Path) -> str:
    files = [root / "LICENSE", root / "scripts/install_server.py", root / "scripts/csqtt-network-up.sh",
             root / "app/src/main/assets/domains.txt"]
    files += sorted((root / "rust-server").glob("*.rs"))
    files += [root / "rust-server" / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")]
    files += sorted((root / "shared").glob("*.rs"))
    files += sorted(p for p in (root / "rust-server/web").rglob("*") if p.is_file())
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(files):
            data = path.read_bytes()
            info = tarfile.TarInfo("csqtt-compatible/" + path.relative_to(root).as_posix())
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            tar.addfile(info, io.BytesIO(data))
    compressed = gzip.compress(archive.getvalue(), compresslevel=9, mtime=0)
    checksum = hashlib.sha256(compressed).hexdigest()
    template = (root / "scripts/install-server.sh").read_text()
    assert template.count("readonly CSQTT_PAYLOAD_SHA256='@PAYLOAD_SHA256@'") == 1
    template = template.replace("readonly CSQTT_PAYLOAD_SHA256='@PAYLOAD_SHA256@'",
                                f"readonly CSQTT_PAYLOAD_SHA256='{checksum}'")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(template.encode() + b"\n# __CSQTT_SOURCE_PAYLOAD_V1__\n" + base64.encodebytes(compressed))
    output.chmod(0o755)
    return checksum


def package_bootstrap(root: Path, installer: Path, output: Path, url: str = DOWNLOAD_URL):
    if not url.startswith("https://") or any(c in url for c in "'\r\n"):
        raise ValueError("Installer download URL must be HTTPS without quotes or newlines")
    template = (root / "scripts/bootstrap.sh").read_text()
    checksum = hashlib.sha256(installer.read_bytes()).hexdigest()
    template = template.replace("@INSTALLER_URL@", url).replace("@INSTALLER_SHA256@", checksum)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(template)
    output.chmod(0o755)
    return checksum


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--bootstrap", type=Path, help="Also generate a pipe-safe download launcher")
    parser.add_argument("--download-url", default=DOWNLOAD_URL, help="HTTPS URL of the standalone installer")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    print(package(root, args.output))
    if args.bootstrap:
        print(package_bootstrap(root, args.output, args.bootstrap, args.download_url))
