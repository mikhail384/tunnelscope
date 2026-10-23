#!/usr/bin/env python3
"""Install a locally built CSQTT binary with systemd and transactional rollback."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import sqlite3
import ssl
import subprocess
import tempfile
import time
import urllib.request
from urllib.parse import quote

VERSION = "2.5.0-compatible.4"
CONFIG = "/etc/csqtt"
BINARY = "/usr/local/bin/csqtt"
UNIT = "/etc/systemd/system/csqtt.service"
NETWORK = "/usr/local/lib/csqtt-compatible/network-up.sh"
SYSCTL = "/etc/sysctl.d/99-csqtt-compatible.conf"
MANAGED_PATHS = (CONFIG, BINARY, UNIT, NETWORK, SYSCTL)
BACKUPS = "/var/backups/csqtt-compatible"


def read_env(path):
    """Read EnvironmentFile syntax without executing shell expansions or commands."""
    values = {}
    if not path.exists():
        return values
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        line = line.removeprefix("export ")
        key, sep, raw = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Z_][A-Z0-9_]*", key):
            raise ValueError(f"Неподдерживаемый формат EnvironmentFile: {path}")
        # systemd also permits unquoted values containing spaces.
        value = " ".join(shlex.split(raw)) if raw.startswith(('"', "'")) else raw.strip()
        values[key] = value
    return values


def encode_env(values):
    return "".join(key + '="' + value.replace("\\", "\\\\").replace('"', '\\"') + '"\n'
                   for key, value in sorted(values.items()))


def port(value):
    if not re.fullmatch(r"[0-9]{1,5}", str(value)) or not 1 <= int(value) <= 65535:
        raise ValueError("Порты должны быть числами от 1 до 65535")
    return int(value)


def atomic_write(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temp = Path(stream.name)
        try:
            stream.write(data if isinstance(data, bytes) else data.encode())
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)


class Installer:
    def __init__(self, root=Path("/"), run=subprocess.run, environ=None):
        self.root, self.run = Path(root), run
        self.environ = os.environ if environ is None else environ

    def at(self, path):
        return self.root / path.lstrip("/")

    def command(self, *args, check=True):
        return self.run(list(args), check=check, capture_output=True, text=True)

    def unit_text(self):
        return self.command("systemctl", "cat", "csqtt.service", check=False).stdout

    def parameters(self):
        old = self.unit_text()
        peer = re.search(r"--listen\s+0\.0\.0\.0:([0-9]+)", old)
        web = re.search(r"--web-port\s+([0-9]+)", old)
        peer = port(self.environ.get("CSQTT_PEER_PORT") or (peer[1] if peer else 46000))
        web = port(self.environ.get("CSQTT_WEB_PORT") or (web[1] if web else 46002))
        if peer == web:
            raise ValueError("Для UDP и web-панели укажите разные номера портов")
        return peer, web

    def preflight(self, validate_config=True):
        self.command("systemctl", "show-environment")
        unit = self.unit_text()
        if unit and (re.search(r"--desired|--no-web|swg-noded|--iface|--tun-addr", unit)
                     or not re.search(r"ExecStart=/usr/local/bin/csqtt(?:\s|$)", unit)):
            raise RuntimeError("csqtt.service управляется другой установкой или swg-panel")
        if unit and re.search(r"--config-dir(?:\s+|=)(?!/etc/csqtt(?:\s|$))", unit):
            raise RuntimeError("Нестандартный --config-dir; автоматическая замена не выполняется")
        if shutil.which("docker"):
            result = self.command("docker", "ps", "--filter", "name=^/csqtt$", "--format", "{{.ID}}", check=False)
            if result.returncode == 0 and result.stdout.strip():
                raise RuntimeError("Работает Docker-контейнер csqtt; сначала остановите его")
        for filename in MANAGED_PATHS:
            if self.at(filename).is_symlink():
                raise RuntimeError(f"Отказ заменять символьную ссылку: {filename}")
        if self.at(CONFIG).exists() and not self.at(CONFIG).is_dir():
            raise RuntimeError("/etc/csqtt должен быть каталогом")
        peer, web = self.parameters()
        pid = self.command("systemctl", "show", "csqtt.service", "--property=MainPID", "--value", check=False).stdout.strip()
        for flag, number in (("-lunp", peer), ("-ltnp", web)):
            bound = self.command("ss", "-H", flag, f"sport = :{number}").stdout.strip()
            if bound:
                owners = re.findall(r"pid=([0-9]+)", bound)
                if not unit or not pid.isdigit() or pid == "0" or not owners or any(p != pid for p in owners):
                    raise RuntimeError(f"Порт {number} занят другим процессом; он не будет остановлен")
        # Ensure the saved settings can be read before stopping the current service.
        if validate_config:
            self.configuration()

    @contextmanager
    def maintenance_lock(self):
        path = self.at('/run/lock/csqtt-compatible-install.lock')
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('Другой установщик или откат уже работает') from None
            yield

    def binary_version(self, path):
        if not path.is_file() or path.is_symlink():
            return ''
        try:
            result = self.run([str(path), '--version'], capture_output=True, text=True, timeout=5)
            match = re.fullmatch(r'csqtt\s+([0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.-]+)?)', result.stdout.strip())
            return match[1] if result.returncode == 0 and match else ''
        except (OSError, subprocess.TimeoutExpired):
            return ''

    @staticmethod
    def backup_inventory(directory):
        """Hash complete managed trees without following config symlinks."""
        inventory = {}
        def visit(path):
            key = path.relative_to(directory).as_posix()
            if path.is_symlink():
                inventory[key] = {'symlink': os.readlink(path)}
            elif path.is_dir():
                inventory[key] = {'directory': True, 'mode': path.stat().st_mode & 0o7777}
                for child in sorted(path.iterdir()):
                    visit(child)
            elif path.is_file():
                hasher = hashlib.sha256()
                with path.open('rb') as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        hasher.update(chunk)
                inventory[key] = {'sha256': hasher.hexdigest(), 'mode': path.stat().st_mode & 0o7777}
            else:
                raise ValueError(f'Неподдерживаемый файл резервной копии: {key}')
        for index in range(len(MANAGED_PATHS)):
            path = directory / str(index)
            if path.exists() or path.is_symlink():
                visit(path)
        return inventory

    def validate_backup(self, directory):
        base = self.at(BACKUPS)
        directory = Path(directory)
        if base.is_symlink() or directory.is_symlink() or directory.parent != base or not directory.is_dir():
            raise ValueError('Выберите каталог непосредственно в /var/backups/csqtt-compatible')
        state_file = directory / 'state.json'
        if state_file.is_symlink() or not state_file.is_file():
            raise ValueError('Резервная копия не завершена: нет state.json')
        state = json.loads(state_file.read_text())
        if not isinstance(state, dict) or any(type(state.get(key)) is not bool for key in ('active', 'enabled')):
            raise ValueError('Повреждено состояние службы в резервной копии')
        for index in range(len(MANAGED_PATHS)):
            if (directory / str(index)).is_symlink():
                raise ValueError('Основной файл резервной копии не может быть символьной ссылкой')
        if state.get('format') == 2:
            if state.get('files') != self.backup_inventory(directory):
                raise ValueError('Контрольные суммы резервной копии не совпали')
        elif 'format' in state:
            raise ValueError('Неизвестный формат резервной копии')
        # A fresh-install snapshot cannot restore an older application.
        if not (directory / '0').is_dir() or not all((directory / str(i)).is_file() for i in (1, 2)):
            raise ValueError('В копии нет прежнего сервера, базы или unit-файла')
        unit = (directory / '2').read_text()
        if not re.search(r'ExecStart=/usr/local/bin/csqtt(?:\s|$)', unit) or re.search(r'--desired|--no-web|swg-noded', unit):
            raise ValueError('Копия относится к другой установке или swg-panel')
        if re.search(r'--config-dir(?:\s+|=)(?!/etc/csqtt(?:\s|$))', unit):
            raise ValueError('Копия использует нестандартный каталог конфигурации')
        if NETWORK in unit and not (directory / '3').is_file():
            raise ValueError('В копии отсутствует сетевой helper из unit-файла')
        # Earlier installers did not write checksums; validate their structure,
        # SQLite database and actual binary version before stopping anything.
        database = directory / '0/csqtt.db'
        if database.is_symlink():
            raise ValueError('База в копии не может быть символьной ссылкой')
        if database.exists():
            # SQLite may create/update WAL bookkeeping even with mode=ro.
            # Check a private copy so checking a backup never changes its hashes.
            with tempfile.TemporaryDirectory(prefix='csqtt-db-check-') as temporary:
                copied = Path(temporary) / 'csqtt.db'
                shutil.copy2(database, copied)
                for suffix in ('-wal', '-shm'):
                    sidecar = database.with_name(database.name + suffix)
                    if sidecar.is_symlink():
                        raise ValueError('Файлы SQLite в копии не могут быть символьными ссылками')
                    if sidecar.exists():
                        shutil.copy2(sidecar, copied.with_name(copied.name + suffix))
                with sqlite3.connect(copied.as_uri() + '?mode=ro', uri=True) as connection:
                    if connection.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                        raise ValueError('База в резервной копии не прошла проверку SQLite')
        elif not (directory / '0/passwords.json').is_file():
            raise ValueError('В резервной копии отсутствует база CSQTT')
        version = self.binary_version(directory / '1')
        if not version or (state.get('version') and state['version'] != version):
            raise ValueError('Не удалось подтвердить версию сохранённого сервера')
        return {**state, 'version': version, 'directory': directory}

    def available_backups(self):
        base = self.at(BACKUPS)
        if base.is_symlink():
            raise ValueError('Каталог резервных копий не может быть символьной ссылкой')
        if not base.exists():
            return []
        return sorted((p for p in base.iterdir() if p.is_dir()),
                      key=lambda p: p.stat().st_mtime_ns, reverse=True)

    def select_backup(self, selector):
        if re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', selector):
            for directory in self.available_backups():
                try:
                    detail = self.validate_backup(directory)
                except (OSError, ValueError, sqlite3.Error) as error:
                    print(f'Пропущена копия {directory.name}: {error}', flush=True)
                    continue
                if detail['version'] == selector:
                    return detail
            raise RuntimeError(f'Нет исправной резервной копии CSQTT {selector}. Работающий сервер не изменён.')
        if not re.fullmatch(r'[a-zA-Z0-9_-]+', selector):
            raise ValueError('Укажите версию (например 2.1.9) или имя каталога из --list-backups')
        return self.validate_backup(self.at(BACKUPS) / selector)

    def list_backups(self):
        directories = self.available_backups()
        if not directories:
            print('Локальных резервных копий пока нет. Перед обновлением выполните --backup.')
        for directory in directories:
            try:
                info = self.validate_backup(directory)
                checked = 'SHA-256' if info.get('format') == 2 else 'старая копия без SHA-256'
                print(f"{directory.name}  CSQTT {info['version']}  {checked}")
            except (OSError, ValueError, sqlite3.Error) as error:
                print(f'{directory.name}  недоступна для отката: {error}')

    def service_state(self):
        return tuple(self.command('systemctl', action, '--quiet', 'csqtt.service', check=False).returncode == 0
                     for action in ('is-active', 'is-enabled'))

    def stop_service(self):
        self.command('systemctl', 'stop', 'csqtt.service')
        if self.command('systemctl', 'is-active', '--quiet', 'csqtt.service', check=False).returncode == 0:
            raise RuntimeError('Не удалось остановить службу; файлы не заменены')

    def backup_current(self):
        self.preflight(validate_config=False)
        if not self.at(BINARY).is_file() or not self.at(UNIT).is_file() or not self.at(CONFIG).is_dir():
            raise RuntimeError('Не найдена обычная systemd-установка CSQTT для резервного копирования')
        active, enabled = self.service_state()
        self.stop_service()
        try:
            directory = self.backup(active, enabled, reason='manual')
            self.validate_backup(directory)
        finally:
            if active:
                self.command('systemctl', 'start', 'csqtt.service')
        print(f'Локальная копия сохранена: {directory}')
        return directory

    def rollback_health(self, active):
        if not active:
            return
        # Do not assume a 2.5-only certificate, secret URL or TUN interface.
        peer, web = self.parameters()
        consecutive = 0
        for _ in range(30):
            if self.command('systemctl', 'show', 'csqtt.service', '--property=NRestarts', '--value').stdout.strip() not in ('', '0'):
                raise RuntimeError('Восстановленная служба перезапускается')
            ready = self.command('systemctl', 'is-active', '--quiet', 'csqtt.service', check=False).returncode == 0
            pid = self.command('systemctl', 'show', 'csqtt.service', '--property=MainPID', '--value').stdout.strip()
            for flag, number in (('-lunp', peer), ('-ltnp', web)):
                sockets = self.command('ss', '-H', flag, f'sport = :{number}').stdout
                owners = re.findall(r'pid=([0-9]+)', sockets)
                ready &= pid.isdigit() and pid != '0' and bool(owners) and all(owner == pid for owner in owners)
            consecutive = consecutive + 1 if ready else 0
            if consecutive >= 3:
                return
            time.sleep(1)
        raise RuntimeError('После восстановления служба не открыла порты UDP и панели')

    def rollback(self, selector):
        selected = self.select_backup(selector)
        self.preflight(validate_config=False)
        print(f"Восстановление CSQTT {selected['version']} из {selected['directory'].name}", flush=True)
        active, enabled = self.service_state()
        self.stop_service()
        try:
            rescue = self.backup(active, enabled, reason='before-rollback')
        except BaseException:
            if active:
                self.command('systemctl', 'start', 'csqtt.service')
            raise
        print(f'Текущее состояние сохранено: {rescue}', flush=True)
        try:
            self.restore(selected['directory'])
            self.rollback_health(selected['active'])
        except BaseException:
            print('Откат не прошёл проверку; возвращаю состояние перед откатом.', flush=True)
            self.stop_service()
            self.restore(rescue)
            self.rollback_health(active)
            raise
        print(f"Восстановлен CSQTT {selected['version']}. Панель и база возвращены к выбранной копии.")
        if not selected['active']:
            print('В копии служба была остановлена. Запуск: sudo systemctl start csqtt')
        return rescue

    def saved_password(self):
        database = self.at(CONFIG + "/csqtt.db")
        if database.exists():
            with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
                row = connection.execute("SELECT value FROM meta WHERE key='main_password'").fetchone()
                if row and row[0]:
                    return row[0]
        for name in ("passwords.json", "passwords.json.imported"):
            path = self.at(CONFIG + "/" + name)
            if path.exists():
                password = json.loads(path.read_text()).get("main_password")
                if password:
                    return password
        return ""

    def configuration(self):
        previous = read_env(self.at(CONFIG + "/csqtt.env"))
        previous.update(read_env(self.at(CONFIG + "/compatible.env")))
        def value(key, default):
            return self.environ.get(key) or previous.get(key) or default
        values = {
            "CSQTT_WEB_USER": value("CSQTT_WEB_USER", "admin"),
            "CSQTT_WEB_PASS": value("CSQTT_WEB_PASS", secrets.token_hex(16)),
            "CSQTT_MAIN_PASSWORD": value("CSQTT_MAIN_PASSWORD", self.saved_password() or secrets.token_hex(16)),
            "CSQTT_WEB_SECRET_PATH": value("CSQTT_WEB_SECRET_PATH", secrets.token_hex(12)),
            "CSQTT_SECURE_COOKIE": "true",
        }
        # Keep DNS settings from the database unless explicitly set in the environment.
        for key in ("CSQTT_DNS", "CSQTT_PUBLIC_IP"):
            found = value(key, "")
            if found:
                values[key] = found
        for key, text in values.items():
            if not isinstance(text, str) or any(c in text for c in "\r\n\x00"):
                raise ValueError(f"Недопустимое значение {key}")
        if not re.fullmatch(r"[a-zA-Z0-9_/-]+", values["CSQTT_WEB_SECRET_PATH"]):
            raise ValueError("CSQTT_WEB_SECRET_PATH: допустимы буквы, цифры, /, _ и -")
        password = values["CSQTT_MAIN_PASSWORD"]
        if not 1 <= len(password.encode()) <= 128 or "|" in password or any(c.isspace() for c in password):
            raise ValueError("CSQTT_MAIN_PASSWORD: 1..128 байт без пробелов и |")
        if values.get("CSQTT_PUBLIC_IP"):
            ipaddress.IPv4Address(values["CSQTT_PUBLIC_IP"])
        if values.get("CSQTT_DNS"):
            addresses = values["CSQTT_DNS"].split(",")
            if not 1 <= len(addresses) <= 2:
                raise ValueError("CSQTT_DNS: один или два IPv4 через запятую")
            for address in addresses:
                ipaddress.IPv4Address(address.strip())
        return values

    def public_ip(self):
        for endpoint in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
            try:
                with urllib.request.urlopen(endpoint, timeout=5) as response:
                    value = response.read(100).decode().strip()
                return str(ipaddress.IPv4Address(value))
            except (OSError, ValueError):
                pass
        route = self.command("ip", "-4", "route", "get", "77.88.8.8", check=False).stdout
        match = re.search(r"\bsrc\s+([0-9.]+)", route)
        return str(ipaddress.IPv4Address(match[1])) if match else ""

    def unit(self, peer, web):
        return f"""[Unit]
Description=CSQTT compatible server (2.5 / 2.1.9 / Windows / iOS)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
EnvironmentFile=-/etc/csqtt/csqtt.env
EnvironmentFile=/etc/csqtt/compatible.env
Environment=CSQTT_SERVICE_MANAGER=systemd
ExecStartPre={NETWORK} up {peer} {web}
ExecStart={BINARY} --listen 0.0.0.0:{peer} --web-port {web} --config-dir /etc/csqtt
ExecStopPost={NETWORK} down {peer} {web}
Restart=on-failure
RestartSec=3
KillMode=control-group
TimeoutStartSec=30
TimeoutStopSec=15
UMask=0077
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""

    def backup(self, active, enabled, reason='before-update'):
        base = self.at(BACKUPS)
        if base.is_symlink():
            raise ValueError('Каталог резервных копий не может быть символьной ссылкой')
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=base))
        for index, filename in enumerate(MANAGED_PATHS):
            path = self.at(filename)
            if path.is_dir():
                shutil.copytree(path, directory / str(index), symlinks=True)
            elif path.exists():
                shutil.copy2(path, directory / str(index))
        atomic_write(directory / "state.json", json.dumps({
            "format": 2, "active": active, "enabled": enabled,
            "version": self.binary_version(directory / '1'), "reason": reason,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "files": self.backup_inventory(directory),
        }, indent=2) + '\n', 0o600)
        return directory

    def restore(self, backup):
        for index, filename in enumerate(MANAGED_PATHS):
            path, saved = self.at(filename), backup / str(index)
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
            if saved.is_dir():
                shutil.copytree(saved, path, symlinks=True)
            elif saved.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(saved, path)
        state = json.loads((backup / "state.json").read_text())
        self.command("systemctl", "daemon-reload")
        self.command("systemctl", "reset-failed", "csqtt.service", check=False)
        self.command("systemctl", "enable" if state["enabled"] else "disable", "csqtt.service", check=False)
        if state["active"]:
            self.command("systemctl", "start", "csqtt.service")

    def health(self, values, peer, web):
        consecutive = 0
        for _ in range(45):
            try:
                self.command("systemctl", "is-active", "--quiet", "csqtt.service")
                restarts = self.command("systemctl", "show", "csqtt.service", "--property=NRestarts", "--value").stdout.strip()
                if restarts not in ("", "0"):
                    raise RuntimeError("Новая служба перезапускается")
                self.command("ip", "link", "show", "csqtt1")
                if not self.command("ss", "-H", "-lun", f"sport = :{peer}").stdout.strip():
                    raise OSError("UDP сокет ещё не открыт")
                context = ssl.create_default_context(cafile=str(self.at(CONFIG + "/web_cert.pem")))
                # Pin to the locally installed certificate, while probing loopback even for a public-name certificate.
                context.check_hostname = False
                context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
                path = quote(values["CSQTT_WEB_SECRET_PATH"].strip("/"), safe="/")
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
                with opener.open(f"https://127.0.0.1:{web}/{path}/", timeout=2) as response:
                    if response.status != 200:
                        raise OSError("Web-панель ещё не готова")
                consecutive += 1
                if consecutive >= 3:
                    return
            except (OSError, subprocess.CalledProcessError):
                consecutive = 0
            time.sleep(1)
        raise RuntimeError("Сервер не прошёл проверку TUN, UDP и HTTPS")

    def install(self, binary, helper, source):
        self.preflight()
        peer, web = self.parameters()
        values = self.configuration()
        if "CSQTT_PUBLIC_IP" not in values:
            detected = self.public_ip()
            if detected:
                values["CSQTT_PUBLIC_IP"] = detected
        revision = self.command(str(binary), "--protocol-revision").stdout.strip()
        if revision != "CSQTT-WIRE-3":
            raise RuntimeError("Проверка нового бинарника не пройдена")
        active = self.command("systemctl", "is-active", "--quiet", "csqtt.service", check=False).returncode == 0
        enabled = self.command("systemctl", "is-enabled", "--quiet", "csqtt.service", check=False).returncode == 0
        # Compilation and validation finish before the existing service is stopped.
        self.command("systemctl", "stop", "csqtt.service", check=False)
        if self.command("systemctl", "is-active", "--quiet", "csqtt.service", check=False).returncode == 0:
            raise RuntimeError("Не удалось остановить существующую службу")
        try:
            backup = self.backup(active, enabled)
        except BaseException:
            if active:
                self.command("systemctl", "start", "csqtt.service")
            raise
        print(f"Резервная копия: {backup}", flush=True)
        try:
            directory = self.at(CONFIG)
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory.chmod(0o700)
            atomic_write(self.at(CONFIG + "/compatible.env"), encode_env(values), 0o600)
            atomic_write(self.at(BINARY), binary.read_bytes(), 0o755)
            atomic_write(self.at(NETWORK), helper.read_bytes(), 0o755)
            atomic_write(self.at(SYSCTL), "net.ipv4.ip_forward=1\n", 0o644)
            atomic_write(self.at(UNIT), self.unit(peer, web), 0o644)
            self.command("systemctl", "daemon-reload")
            self.command("systemctl", "reset-failed", "csqtt.service", check=False)
            self.command("systemctl", "enable", "--now", "csqtt.service")
            self.health(values, peer, web)
        except BaseException:
            print("Запуск не подтверждён; восстанавливаю прежнюю службу и конфигурацию.", flush=True)
            self.command("systemctl", "stop", "csqtt.service", check=False)
            self.command("systemctl", "disable", "csqtt.service", check=False)
            self.restore(backup)
            raise
        # Keep the exact source and license next to the installation for rebuilding.
        saved_source = self.at("/usr/local/share/csqtt-compatible/source")
        shutil.copytree(source, saved_source, dirs_exist_ok=True)
        atomic_write(self.at(CONFIG + "/compatible-install.json"), json.dumps({
            "installer": VERSION, "peer_port": peer, "web_port": web,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "backup": str(backup)
        }, indent=2) + "\n", 0o600)
        hostname = values.get("CSQTT_PUBLIC_IP", "SERVER_IP")
        path = values["CSQTT_WEB_SECRET_PATH"].strip("/")
        print(f"\nCSQTT установлен и запущен.\nПанель: https://{hostname}:{web}/{path}/")
        print(f"Логин: {values['CSQTT_WEB_USER']}\nПароль панели: {values['CSQTT_WEB_PASS']}")
        print(f"Пароль подключения: {values['CSQTT_MAIN_PASSWORD']}\nUDP-порт: {peer}")
        print("Настройки: /etc/csqtt/compatible.env (root, 0600)")
        print("Статус: systemctl status csqtt\nЛоги: journalctl -u csqtt -f")
        print("Откройте UDP-порт и TCP-порт панели также в firewall/security group провайдера.")
        print("Панель использует существующий или автоматически созданный самоподписанный HTTPS-сертификат.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--install", type=Path)
    parser.add_argument("--network-helper", type=Path)
    parser.add_argument("--source", type=Path)
    maintenance = parser.add_mutually_exclusive_group()
    maintenance.add_argument('--backup', action='store_true')
    maintenance.add_argument('--list-backups', action='store_true')
    maintenance.add_argument('--rollback', metavar='VERSION_OR_ID')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Требуется root")
    installer = Installer()
    if (args.backup or args.list_backups or args.rollback) and any((args.preflight, args.install, args.source, args.network_helper)):
        parser.error('Команды резервного копирования не совмещаются с установкой')
    if args.list_backups:
        installer.list_backups()
    elif args.backup or args.rollback:
        with installer.maintenance_lock():
            if args.backup:
                installer.backup_current()
            else:
                installer.rollback(args.rollback)
    elif args.preflight:
        installer.preflight()
        print("Предварительная проверка пройдена.")
    elif args.install and args.network_helper and args.source:
        installer.install(args.install, args.network_helper, args.source)
    else:
        parser.error("Укажите --preflight или --install с --network-helper и --source")


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise RuntimeError("Установка прервана сигналом")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except (OSError, ValueError, RuntimeError, sqlite3.Error, subprocess.CalledProcessError) as error:
        # Never dump the inherited environment or credentials on failure.
        print(f"Ошибка: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
