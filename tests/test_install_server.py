import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('install_server', ROOT / 'scripts/install_server.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Runner:
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.active = False
        self.enabled = False
        self.busy = False
        self.container = False

    def __call__(self, args, check=True, **kwargs):
        self.calls.append(args)
        out, code = '', 0
        if args[:3] == ['systemctl', 'cat', 'csqtt.service']:
            file = self.root / m.UNIT.lstrip('/')
            out = file.read_text() if file.exists() else ''
        elif args[:2] == ['systemctl', 'is-active']:
            code = 0 if self.active else 3
        elif args[:2] == ['systemctl', 'is-enabled']:
            code = 0 if self.enabled else 1
        elif args[:2] == ['systemctl', 'show']:
            out = '123\n'
        elif args[:2] == ['systemctl', 'stop']:
            self.active = False
        elif args[:2] == ['systemctl', 'start']:
            self.active = True
        elif args[:2] == ['systemctl', 'enable']:
            self.enabled = True
            self.active |= '--now' in args
        elif args[:2] == ['systemctl', 'disable']:
            self.enabled = False
        elif args[0] == 'ss' and self.busy:
            out = 'UNCONN 0 0 0.0.0.0:46000 users:(("other",pid=456,fd=3))'
        elif args[:2] == ['docker', 'ps'] and self.container:
            out = 'other-container-id'
        elif '--protocol-revision' in args:
            out = 'CSQTT-WIRE-3\n'
        result = subprocess.CompletedProcess(args, code, out, '')
        if check and code:
            raise subprocess.CalledProcessError(code, args)
        return result


class TestInstaller(m.Installer):
    def health(self, values, peer, web):
        if self.fail_health:
            # Simulate an on-start DB mutation that rollback must undo.
            self.at(m.CONFIG + '/modified-on-start').write_text('new')
            raise RuntimeError('simulated startup failure')


class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.runner = Runner(self.root)
        self.installer = TestInstaller(self.root, self.runner, {'CSQTT_PUBLIC_IP': '203.0.113.7'})
        self.installer.fail_health = False
        self.binary = self.root / 'candidate'
        self.binary.write_bytes(b'new-compatible-binary')
        self.source = self.root / 'source'
        self.source.mkdir()
        (self.source / 'LICENSE').write_text('test license')
        self.helper = self.source / 'network.sh'
        self.helper.write_text('#!/bin/bash\nexit 0\n')

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, value):
        file = self.installer.at(path)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(value)
        return file

    def existing(self):
        self.write(m.UNIT, self.installer.unit(47000, 47002))
        self.write(m.BINARY, 'old-server')
        self.write(m.CONFIG + '/csqtt.env', 'CSQTT_WEB_USER="previous"\nCSQTT_WEB_PASS="old-web-password"\n')
        db = self.installer.at(m.CONFIG + '/csqtt.db')
        with sqlite3.connect(db) as connection:
            connection.execute('CREATE TABLE meta (key TEXT, value TEXT)')
            connection.execute('INSERT INTO meta VALUES (?,?)', ('main_password', 'preserved-client-password'))
        self.runner.active = self.runner.enabled = True
        return db

    def install(self):
        self.installer.install(self.binary, self.helper, self.source)

    def test_fresh_install_generates_credentials_and_enables_service(self):
        self.install()
        env = m.read_env(self.installer.at(m.CONFIG + '/compatible.env'))
        self.assertEqual(env['CSQTT_WEB_USER'], 'admin')
        self.assertEqual(len(env['CSQTT_MAIN_PASSWORD']), 32)
        self.assertEqual(len(env['CSQTT_WEB_PASS']), 32)
        self.assertEqual(self.installer.at(m.CONFIG + '/compatible.env').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.installer.at(m.BINARY).read_bytes(), self.binary.read_bytes())
        self.assertTrue(self.runner.active and self.runner.enabled)
        self.assertIn('0.0.0.0:46000', self.installer.at(m.UNIT).read_text())
        self.assertFalse(any('kill' in command for command in self.runner.calls))

    def test_update_preserves_password_database_ports_and_web_login(self):
        db = self.existing()
        previous_db = db.read_bytes()
        self.install()
        values = m.read_env(self.installer.at(m.CONFIG + '/compatible.env'))
        self.assertEqual(values['CSQTT_MAIN_PASSWORD'], 'preserved-client-password')
        self.assertEqual(values['CSQTT_WEB_PASS'], 'old-web-password')
        self.assertEqual(values['CSQTT_WEB_USER'], 'previous')
        self.assertEqual(db.read_bytes(), previous_db)
        self.assertIn('--web-port 47002', self.installer.at(m.UNIT).read_text())
        self.assertIn('0.0.0.0:47000', self.installer.at(m.UNIT).read_text())

    def test_repeated_install_keeps_generated_secrets(self):
        self.install()
        previous = m.read_env(self.installer.at(m.CONFIG + '/compatible.env'))
        self.install()
        self.assertEqual(m.read_env(self.installer.at(m.CONFIG + '/compatible.env')), previous)

    def test_start_failure_restores_binary_unit_database_and_active_state(self):
        db = self.existing()
        previous_db = db.read_bytes()
        previous_unit = self.installer.at(m.UNIT).read_bytes()
        self.installer.fail_health = True
        with self.assertRaisesRegex(RuntimeError, 'simulated startup failure'):
            self.install()
        self.assertEqual(self.installer.at(m.BINARY).read_text(), 'old-server')
        self.assertEqual(self.installer.at(m.UNIT).read_bytes(), previous_unit)
        self.assertEqual(db.read_bytes(), previous_db)
        self.assertFalse(self.installer.at(m.CONFIG + '/modified-on-start').exists())
        self.assertFalse(self.installer.at(m.CONFIG + '/compatible.env').exists())
        self.assertTrue(self.runner.active and self.runner.enabled)

    def test_failed_fresh_install_removes_its_own_files(self):
        self.installer.fail_health = True
        with self.assertRaises(RuntimeError):
            self.install()
        self.assertFalse(self.installer.at(m.CONFIG).exists())
        self.assertFalse(self.installer.at(m.UNIT).exists())
        self.assertFalse(self.installer.at(m.BINARY).exists())
        self.assertFalse(self.runner.active or self.runner.enabled)

    def test_invalid_input_fails_before_stop(self):
        self.existing()
        self.installer.environ['CSQTT_PEER_PORT'] = '46000;touch /tmp/bad'
        with self.assertRaises(ValueError):
            self.install()
        self.assertTrue(self.runner.active)
        self.assertNotIn(['systemctl', 'stop', 'csqtt.service'], self.runner.calls)

    def test_foreign_port_owner_is_never_stopped(self):
        self.existing()
        self.runner.busy = True
        with self.assertRaisesRegex(RuntimeError, 'занят другим процессом'):
            self.install()
        self.assertTrue(self.runner.active)
        self.assertNotIn(['systemctl', 'stop', 'csqtt.service'], self.runner.calls)

    def test_panel_managed_service_is_rejected(self):
        self.existing()
        self.write(m.UNIT, self.installer.unit(46000, 46002).replace('--config-dir /etc/csqtt', '--desired /etc/panel/desired.json'))
        with self.assertRaisesRegex(RuntimeError, 'swg-panel'):
            self.install()
        self.assertTrue(self.runner.active)

    def test_legacy_json_credentials_are_preserved(self):
        self.write(m.CONFIG + '/passwords.json', json.dumps({'main_password': 'old-json-password'}))
        self.assertEqual(self.installer.configuration()['CSQTT_MAIN_PASSWORD'], 'old-json-password')

    def test_environment_values_are_not_executed(self):
        target = self.root / 'must-not-exist'
        self.write(m.CONFIG + '/csqtt.env', f'CSQTT_WEB_PASS="$(touch {target})"\n')
        self.assertEqual(self.installer.configuration()['CSQTT_WEB_PASS'], f'$(touch {target})')
        self.assertFalse(target.exists())

    def test_quotes_and_unicode_round_trip_environment(self):
        values = {'CSQTT_WEB_PASS': 'p@ss \\ " юникод $literal', 'CSQTT_WEB_USER': 'admin'}
        path = self.write(m.CONFIG + '/test.env', m.encode_env(values))
        self.assertEqual(m.read_env(path), values)

class BundleTests(unittest.TestCase):
    def test_bundle_is_reproducible_extracts_required_assets_and_rejects_corruption(self):
        spec = importlib.util.spec_from_file_location('package_installer', ROOT / 'scripts/package_installer.py')
        pack = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pack)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            first, second = base / 'one.sh', base / 'two.sh'
            pack.package(ROOT, first)
            pack.package(ROOT, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            subprocess.run(['bash', '-n', str(first)], check=True)
            destination = base / 'extracted'
            subprocess.run(['bash', str(first), '--extract', str(destination)], check=True, capture_output=True)
            for name in ['shared/compat.rs', 'shared/flow_frame.rs', 'rust-server/main.rs',
                         'app/src/main/assets/domains.txt', 'scripts/install_server.py', 'LICENSE']:
                self.assertEqual((destination / 'csqtt-compatible' / name).read_bytes(), (ROOT / name).read_bytes())
            marker = b'# __CSQTT_SOURCE_PAYLOAD_V1__\n'
            header, body = first.read_bytes().split(marker)
            body = (b'A' if body[:1] != b'A' else b'B') + body[1:]
            first.write_bytes(header + marker + body)
            result = subprocess.run(['bash', str(first), '--extract', str(base / 'corrupt')], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((base / 'corrupt/csqtt-compatible/rust-server/main.rs').exists())


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.installer = self.base / 'installer.sh'
        self.installer.write_text('#!/bin/bash\nprintf "%s" "$*" > "$TEST_EXECUTED"\n')
        spec = importlib.util.spec_from_file_location('package_installer', ROOT / 'scripts/package_installer.py')
        self.packager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.packager)
        self.bootstrap = self.base / 'install.sh'
        self.packager.package_bootstrap(ROOT, self.installer, self.bootstrap)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        curl = self.bin / 'curl'
        curl.write_text('#!/bin/bash\nset -eu\n'
                        '[[ "${TEST_DOWNLOAD_FAIL:-0}" == 0 ]] || exit 22\n'
                        'while [[ "$1" != -o ]]; do shift; done\ncp "$TEST_DOWNLOAD" "$2"\n')
        curl.chmod(0o755)
        self.downloads = self.base / 'downloads'
        self.downloads.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        TEST_DOWNLOAD=str(self.installer), TEST_EXECUTED=str(self.base / 'executed'),
                        TMPDIR=str(self.downloads))

    def run_bootstrap(self):
        # Deliver the script through stdin, exactly as curl | bash does on the VPS.
        result = subprocess.run(['bash', '-s', '--', '--help'], input=self.bootstrap.read_text(),
                                text=True, capture_output=True, env=self.env)
        self.assertEqual(list(self.downloads.iterdir()), [], result.stderr)
        return result

    def test_stdin_bootstrap_downloads_checks_and_runs_real_file(self):
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.base / 'executed').read_text(), '--help')

    def test_changed_download_is_rejected_without_execution(self):
        self.installer.write_text(self.installer.read_text() + '# corrupted download\n')
        result = self.run_bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Контрольная сумма', result.stderr)
        self.assertFalse((self.base / 'executed').exists())

    def test_failed_download_is_not_executed(self):
        self.env['TEST_DOWNLOAD_FAIL'] = '1'
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 22)
        self.assertFalse((self.base / 'executed').exists())


if __name__ == '__main__':
    unittest.main()
