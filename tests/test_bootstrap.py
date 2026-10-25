import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipIf(os.name=='nt','POSIX bootstrap runs in the Ubuntu verification matrix')
class BootstrapCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=pathlib.Path.cwd());self.root=pathlib.Path(self.tmp.name);self.bin=self.root/'bin';self.bin.mkdir()
        for name in ('bash','env','rm'):(self.bin/name).symlink_to(shutil.which(name))
        self.script('id','echo "${TEST_UID:-0}"')
        self.script('sudo','echo "$*" >> "$TEST_SUDO_LOG"\nexec "$@"')
        self.script('mktemp','f=$(/usr/bin/mktemp "$@"); echo "$f" > "$TEST_TEMP_LOG"; echo "$f"')
        self.script('apt-get','echo "$*" >> "$TEST_APT_LOG"\nif [[ " $* " == *" install "* ]]; then /bin/cp "$TEST_CURL" "$TEST_BIN/curl"; /bin/chmod +x "$TEST_BIN/curl"; fi')
        self.curl=self.root/'curl-fixture';self.curl.write_text('#!/bin/bash\n[[ ${TEST_CURL_FAIL:-0} == 0 ]] || exit 22\nwhile (( $# )); do if [[ $1 == -o ]]; then out=$2; shift 2; else shift; fi; done\n/bin/cp "$TEST_INSTALLER" "$out"\n')
        self.installer=self.root/'installer';self.installer.write_text('echo ready > "$TEST_MARKER"\n')
        self.env=dict(os.environ,PATH=str(self.bin),TEST_BIN=str(self.bin),TEST_CURL=str(self.curl),TEST_INSTALLER=str(self.installer),TEST_MARKER=str(self.root/'marker'),TEST_APT_LOG=str(self.root/'apt'),TEST_SUDO_LOG=str(self.root/'sudo'),TEST_TEMP_LOG=str(self.root/'temp'))
        self.command=pathlib.Path('install-command.txt').read_text().strip()
    def script(self,name,body):
        p=self.bin/name;p.write_text('#!/bin/bash\n'+body+'\n');p.chmod(0o755)
    def tearDown(self):self.tmp.cleanup()
    def execute(self,**extra):return subprocess.run(['/bin/bash','-c',self.command],env=dict(self.env,**extra),capture_output=True,text=True,timeout=15)
    def test_root_without_curl_or_sudo_installs_downloader_then_runs_installer(self):
        (self.bin/'sudo').unlink();self.assertFalse((self.bin/'curl').exists())
        result=self.execute();self.assertEqual(result.returncode,0,result.stderr);self.assertTrue((self.root/'marker').exists());self.assertIn('ca-certificates curl',(self.root/'apt').read_text());self.assertFalse(pathlib.Path((self.root/'temp').read_text().strip()).exists())
    def test_regular_user_elevates_package_install_and_installer(self):
        result=self.execute(TEST_UID='1000');self.assertEqual(result.returncode,0,result.stderr);calls=(self.root/'sudo').read_text();self.assertIn('apt-get',calls);self.assertIn('bash /tmp/tunnelscope-bootstrap.',calls)
    def test_failed_download_does_not_execute_file_and_cleans_temp(self):
        result=self.execute(TEST_CURL_FAIL='1');self.assertNotEqual(result.returncode,0);self.assertFalse((self.root/'marker').exists());self.assertFalse(pathlib.Path((self.root/'temp').read_text().strip()).exists())

if __name__=='__main__':unittest.main()
