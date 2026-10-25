import io
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from deploy import install


class InstallerTests(unittest.TestCase):
    def test_health_waits_for_service_and_retries_transient_failure(self):
        with patch.object(install.urllib.request,'urlopen',side_effect=[OSError('starting'),io.BytesIO(b'{"ok":true}')]) as request,patch.object(install.time,'sleep') as sleep:
            install.wait_for_web({'host':'0.0.0.0','port':9180},attempts=3)
        self.assertEqual(request.call_args.args[0],'http://127.0.0.1:9180/api/health');self.assertEqual(sleep.call_count,1)
    def test_health_failure_is_not_reported_as_success(self):
        with patch.object(install.urllib.request,'urlopen',return_value=io.BytesIO(b'{"ok":false}')):
            with self.assertRaisesRegex(SystemExit,'health check failed'):install.wait_for_web({'port':9180},attempts=1)
    def test_health_trusts_the_configured_tls_certificate(self):
        context=SimpleNamespace(check_hostname=True)
        with patch.object(install.ssl,'create_default_context',return_value=context) as factory,patch.object(install.urllib.request,'urlopen',return_value=io.BytesIO(b'{"ok":true}')) as request:
            install.wait_for_web({'host':'0.0.0.0','port':9280,'tls_cert':'/etc/tunnelscope/tls/cert.pem'})
        factory.assert_called_once_with(cafile='/etc/tunnelscope/tls/cert.pem');self.assertIs(request.call_args.kwargs['context'],context);self.assertTrue(request.call_args.args[0].startswith('https://'))
    def test_loopback_panel_does_not_open_firewall(self):
        with patch.object(install.shutil,'which') as which,patch.object(install,'run') as run:
            install.open_panel_port({'host':'127.0.0.1','port':9180})
        which.assert_not_called();run.assert_not_called()
    def test_inactive_firewall_is_not_enabled(self):
        with patch.object(install.shutil,'which',return_value='/usr/sbin/ufw'),patch.object(install.subprocess,'run',return_value=SimpleNamespace(stdout='Status: inactive\n')),patch.object(install,'run') as run:
            install.open_panel_port({'host':'0.0.0.0','port':9180})
        run.assert_not_called()
    def test_active_firewall_opens_only_the_panel_port(self):
        with patch.object(install.shutil,'which',return_value='/usr/sbin/ufw'),patch.object(install.subprocess,'run',return_value=SimpleNamespace(stdout='Status: active\n')),patch.object(install,'run') as run:
            install.open_panel_port({'host':'0.0.0.0','port':9280})
        run.assert_called_once_with('ufw','allow','9280/tcp','comment','TunnelScope panel')
    def test_interface_discovery_excludes_container_bridges(self):
        links=[{'ifname':'lo'},{'ifname':'ens3'},{'ifname':'docker0','linkinfo':{'info_kind':'bridge'}},{'ifname':'wg0','linkinfo':{'info_kind':'wireguard'}}]
        addresses=[{'ifname':'wg0','addr_info':[{'family':'inet','local':'10.7.0.1','prefixlen':24}]}]
        with patch.object(install,'run',side_effect=[SimpleNamespace(stdout=json.dumps(links)),SimpleNamespace(stdout=json.dumps(addresses))]):result=install.detect_interfaces()
        self.assertEqual(result,[{'name':'ens3','source':'server'},{'name':'wg0','source':'wireguard','network':'10.7.0.0/24'}])

if __name__=='__main__':unittest.main()
