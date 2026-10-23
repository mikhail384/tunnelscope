import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('rollback_installer', ROOT / 'scripts/install_server.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ServiceRunner:
    def __init__(self, root):
        self.root = root
        self.active = self.enabled = True
        self.calls = []
        self.fail_start_version = None
        self.socket_reads = 0
        self.ready_after = 0

    def __call__(self, args, check=True, **kwargs):
        self.calls.append(args)
        text, code = '', 0
        binary = self.root / m.BINARY.lstrip('/')
        if args[-1] == '--version':
            text = Path(args[0]).read_text()
        elif args[:2] == ['systemctl', 'cat']:
            text = (self.root / m.UNIT.lstrip('/')).read_text()
        elif args[:2] == ['systemctl', 'is-active']:
            code = 0 if self.active else 3
        elif args[:2] == ['systemctl', 'is-enabled']:
            code = 0 if self.enabled else 1
        elif args[:2] == ['systemctl', 'show']:
            text = '0' if '--property=NRestarts' in args else '123'
        elif args[:2] == ['systemctl', 'stop']:
            self.active = False
        elif args[:2] == ['systemctl', 'start']:
            if self.fail_start_version and self.fail_start_version in binary.read_text():
                code = 1
            else:
                self.active = True
        elif args[:2] == ['systemctl', 'enable']:
            self.enabled = True
        elif args[:2] == ['systemctl', 'disable']:
            self.enabled = False
        elif args[0] == 'ss':
            self.socket_reads += 1
            if self.active and self.socket_reads > self.ready_after:
                text = 'users:(("csqtt",pid=123,fd=9))'
        result = subprocess.CompletedProcess(args, code, text, '')
        if check and code:
            raise subprocess.CalledProcessError(code, args)
        return result


class RollbackTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.runner = ServiceRunner(self.root)
        self.installer = m.Installer(self.root, self.runner, {})
        self.write(m.BINARY, 'csqtt 2.1.9\n')
        self.write(m.UNIT, '[Service]\nExecStart=/usr/local/bin/csqtt --listen 0.0.0.0:47000 --web-port 47002 --config-dir /etc/csqtt\n')
        self.write(m.CONFIG + '/csqtt.env', 'CSQTT_WEB_USER="previous"\nCSQTT_WEB_PASS="old-panel-password"\n')
        self.database = self.installer.at(m.CONFIG + '/csqtt.db')
        with sqlite3.connect(self.database) as db:
            db.execute('CREATE TABLE clients (name TEXT)')
            db.execute("INSERT INTO clients VALUES ('old-access')")
        no_sleep = patch.object(m.time, 'sleep')
        no_sleep.start()
        self.addCleanup(no_sleep.stop)

    def write(self, name, data):
        path = self.installer.at(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)
        return path

    def old_backup_then_new_server(self):
        old = self.installer.backup_current()
        self.write(m.BINARY, 'csqtt 2.5.0\n')
        self.write(m.UNIT, self.installer.unit(47000, 47002))
        self.write(m.NETWORK, '#!/bin/sh\nexit 0\n')
        self.write(m.SYSCTL, 'net.ipv4.ip_forward=1\n')
        self.write(m.CONFIG + '/compatible.env', 'CSQTT_WEB_PASS="new-panel-password"\n')
        with sqlite3.connect(self.database) as db:
            db.execute("INSERT INTO clients VALUES ('new-access')")
        return old

    def users(self, database=None):
        with sqlite3.connect(database or self.database) as db:
            return [row[0] for row in db.execute('SELECT name FROM clients')]

    def test_manual_backup_restarts_service_and_checksums_stay_unchanged(self):
        saved = self.installer.backup_current()
        initial = self.installer.backup_inventory(saved)
        for _ in range(2):
            self.assertEqual(self.installer.validate_backup(saved)['version'], '2.1.9')
        self.assertEqual(initial, self.installer.backup_inventory(saved))
        self.assertTrue(self.runner.active)
        self.assertEqual(saved.stat().st_mode & 0o777, 0o700)
        self.assertEqual((saved / 'state.json').stat().st_mode & 0o777, 0o600)

    def test_rollback_restores_old_panel_and_db_and_preserves_new_data_in_rescue(self):
        self.old_backup_then_new_server()
        rescue = self.installer.rollback('2.1.9')
        self.assertEqual(self.installer.at(m.BINARY).read_text(), 'csqtt 2.1.9\n')
        self.assertEqual(self.users(), ['old-access'])
        self.assertEqual(self.users(rescue / '0/csqtt.db'), ['old-access', 'new-access'])
        self.assertEqual(self.installer.validate_backup(rescue)['version'], '2.5.0')
        self.assertFalse(self.installer.at(m.CONFIG + '/compatible.env').exists())
        self.assertFalse(self.installer.at(m.NETWORK).exists())
        self.assertFalse(self.installer.at(m.SYSCTL).exists())
        self.assertTrue(self.runner.active and self.runner.enabled)
        self.assertIn('old-panel-password', self.installer.at(m.CONFIG + '/csqtt.env').read_text())
        self.installer.rollback(rescue.name)
        self.assertEqual(self.users(), ['old-access', 'new-access'])
        self.assertEqual(self.installer.at(m.BINARY).read_text(), 'csqtt 2.5.0\n')

    def test_previous_installer_backup_without_manifest_can_be_restored(self):
        old = self.old_backup_then_new_server()
        (old / 'state.json').write_text(json.dumps({'active': True, 'enabled': True}))
        self.installer.rollback('2.1.9')
        self.assertEqual(self.users(), ['old-access'])

    def test_failed_old_binary_start_restores_the_running_new_server(self):
        self.old_backup_then_new_server()
        self.runner.fail_start_version = '2.1.9'
        with self.assertRaises(subprocess.CalledProcessError):
            self.installer.rollback('2.1.9')
        self.assertEqual(self.users(), ['old-access', 'new-access'])
        self.assertEqual(self.installer.at(m.BINARY).read_text(), 'csqtt 2.5.0\n')
        self.assertTrue(self.runner.active and self.runner.enabled)

    def test_corrupt_backup_is_rejected_before_stopping_service(self):
        old = self.old_backup_then_new_server()
        (old / '1').write_text('csqtt 2.1.9\ncorrupt')
        self.runner.calls.clear()
        with self.assertRaisesRegex(ValueError, 'Контрольные суммы'):
            self.installer.rollback(old.name)
        self.assertNotIn(['systemctl', 'stop', 'csqtt.service'], self.runner.calls)
        self.assertTrue(self.runner.active)

    def test_missing_219_backup_never_stops_current_server(self):
        self.runner.calls.clear()
        with self.assertRaisesRegex(RuntimeError, 'Нет исправной резервной копии'):
            self.installer.rollback('2.1.9')
        self.assertNotIn(['systemctl', 'stop', 'csqtt.service'], self.runner.calls)

    def test_missing_files_or_symlink_backup_are_rejected(self):
        old = self.old_backup_then_new_server()
        alias = self.installer.at(m.BACKUPS) / 'alias'
        alias.symlink_to(old, target_is_directory=True)
        self.runner.calls.clear()
        with self.assertRaises(ValueError):
            self.installer.rollback('alias')
        (old / '0/csqtt.db').unlink()
        with self.assertRaises(ValueError):
            self.installer.rollback(old.name)
        self.assertNotIn(['systemctl', 'stop', 'csqtt.service'], self.runner.calls)

    def test_backup_disk_failure_restarts_original_service(self):
        with patch.object(self.installer, 'backup', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.installer.backup_current()
        self.assertTrue(self.runner.active)
        self.assertEqual(self.users(), ['old-access'])

    def test_rescue_backup_failure_cannot_replace_current_files(self):
        self.old_backup_then_new_server()
        with patch.object(self.installer, 'backup', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.installer.rollback('2.1.9')
        self.assertTrue(self.runner.active)
        self.assertEqual(self.users(), ['old-access', 'new-access'])
        self.assertEqual(self.installer.at(m.BINARY).read_text(), 'csqtt 2.5.0\n')

    def test_foreign_installation_is_not_replaced(self):
        self.old_backup_then_new_server()
        self.write(m.UNIT, '[Service]\nExecStart=/usr/local/bin/csqtt --desired /etc/panel/desired.json\n')
        self.runner.calls.clear()
        with self.assertRaisesRegex(RuntimeError, 'swg-panel'):
            self.installer.rollback('2.1.9')
        self.assertNotIn(['systemctl', 'stop', 'csqtt.service'], self.runner.calls)

    def test_lock_blocks_concurrent_update_or_rollback(self):
        with self.installer.maintenance_lock():
            with self.assertRaisesRegex(RuntimeError, 'уже работает'):
                with self.installer.maintenance_lock():
                    self.fail('second writer acquired lock')

    def test_health_waits_for_listener_startup(self):
        self.runner.ready_after = 4
        self.installer.rollback_health(True)
        self.assertGreaterEqual(self.runner.socket_reads, 10)

    def test_stopped_snapshot_retains_stopped_and_disabled_state(self):
        self.runner.active = self.runner.enabled = False
        self.old_backup_then_new_server()
        self.runner.active = self.runner.enabled = True
        self.installer.rollback('2.1.9')
        self.assertFalse(self.runner.active or self.runner.enabled)

    def test_backup_selector_cannot_escape_backup_directory(self):
        for selector in ('../elsewhere', '/etc/csqtt', '.'):
            with self.assertRaises(ValueError):
                self.installer.select_backup(selector)

    def test_config_directory_equals_syntax_cannot_bypass_preflight(self):
        self.write(m.UNIT, '[Service]\nExecStart=/usr/local/bin/csqtt --config-dir=/opt/other\n')
        self.runner.calls.clear()
        with self.assertRaisesRegex(RuntimeError, 'Нестандартный'):
            self.installer.backup_current()
        self.assertNotIn(['systemctl', 'stop', 'csqtt.service'], self.runner.calls)


class MaintenanceBundleTests(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0, 'standalone maintenance requires root')
    def test_rollback_launcher_routes_to_python_without_cargo_or_apt(self):
        spec = importlib.util.spec_from_file_location('packager', ROOT / 'scripts/package_installer.py')
        pack = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pack)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            pack.package(ROOT, base / 'installer.sh')
            tools = base / 'tools'
            tools.mkdir()
            fake = tools / 'python3'
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$TEST_MAINTENANCE_ARGS"\n')
            fake.chmod(0o755)
            for tool in ('cargo', 'rustup', 'apt-get'):
                path = tools / tool
                path.write_text('#!/bin/sh\nexit 88\n')
                path.chmod(0o755)
            output = base / 'args'
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'], TEST_MAINTENANCE_ARGS=str(output))
            for args in (['--rollback', '2.1.9'], ['--backup'], ['--list-backups']):
                result = subprocess.run(['bash', str(base / 'installer.sh'), *args], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output.read_text().splitlines()[1:], args)


if __name__ == '__main__':
    unittest.main()
