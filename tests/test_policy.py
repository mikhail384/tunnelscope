import unittest
from unittest.mock import patch, Mock
from types import SimpleNamespace
from tunnelscope.common import uid
from tunnelscope.policy import Policy,matches_domain,Backend

class FakeBackend:
    def __init__(self):self.blocks=[];self.releases=[]
    def block(self,e,seconds,peers):self.blocks.append((e.copy(),seconds,list(peers)))
    def unblock(self,e):self.releases.append(e['client_id'])

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.now=100.;self.backend=FakeBackend();self.alice=uid('xray','alice');self.honor=uid('xray','Honor-magic-8-pro')
        self.policy=Policy({'supercell_policy':{'enabled':True,'seconds':20,'exempt_client_ids':[self.honor]}},self.backend,start=False,clock=lambda:self.now)
        self.policy.set_clients([{'id':self.alice,'source':'xray','label':'alice'},
            {'id':self.honor,'source':'xray','label':'Renamed Honor'}],'')
    def flow(self,cid=None,**kwargs):
        f={'id':str(self.now),'client_id':cid or self.alice,'source':'xray','domain':'game.clashroyaleapp.com','destination':'game.clashroyaleapp.com','port':9339,'evidence':'Xray access','peer':('203.0.113.8',45000)}
        f.update(kwargs);return f
    def test_boundary_and_similar_names(self):
        for name in ['SUPERCELL.COM.','game.clashroyaleapp.com','id.supercell.com']:self.assertTrue(matches_domain(name))
        for name in ['evil-supercell.com','supercell.com.attacker.org','notsupercell.com','1.2.3.4','']:self.assertFalse(matches_domain(name))
    def test_honor_exception_survives_rename_and_shared_nat(self):
        self.policy.handle(self.flow(self.honor,peer=('203.0.113.8',45001)))
        self.policy.handle(self.flow())
        self.assertEqual(len(self.backend.blocks),1)
        self.assertEqual(self.backend.blocks[0][0]['client_id'],self.alice)
        self.assertEqual(self.backend.blocks[0][2],[('203.0.113.8',45000)])
    def test_twenty_seconds_and_retry_does_not_extend(self):
        self.policy.handle(self.flow());self.now=119.9
        self.policy.handle(self.flow(id='retry'));self.policy.tick()
        self.assertEqual(len(self.backend.blocks),1);self.assertEqual(self.backend.releases,[])
        self.now=120.01;self.policy.tick()
        self.assertEqual(self.backend.releases,[self.alice]);self.assertFalse(self.policy.active)
        self.policy.handle(self.flow(id='new-connection'));self.assertEqual(len(self.backend.blocks),2)
    def test_unknown_and_dns_guess_never_block(self):
        for f in [self.flow(client_id=''),self.flow(source='server'),self.flow(evidence='DNS · предположение'),self.flow(destination='1.2.3.4',domain='',port=9339)]:self.policy.handle(f)
        self.assertEqual(self.backend.blocks,[])
    def test_game_ip_needs_live_dns_and_game_port(self):
        self.policy.addresses['1.2.3.4']=('game.clashroyaleapp.com',110)
        self.policy.handle(self.flow(id='wrongport',domain='',destination='1.2.3.4',port=443,evidence='IP'))
        self.assertFalse(self.backend.blocks)
        self.policy.handle(self.flow(id='gameport',domain='',destination='1.2.3.4',port=9339,evidence='IP'))
        self.assertEqual(len(self.backend.blocks),1)
        self.now=121;self.policy.tick();self.policy.handle(self.flow(id='stale',domain='',destination='1.2.3.4',port=9339,evidence='IP'))
        self.assertEqual(len(self.backend.blocks),1)
    def test_one_old_flow_does_not_retrigger(self):
        f=self.flow();self.policy.handle(f);self.now=121;self.policy.tick();self.policy.handle(f)
        self.assertEqual(len(self.backend.blocks),1)
    def test_shared_authenticated_socket_never_killed(self):
        self.policy.handle(self.flow(self.honor,peer=('203.0.113.8',45000)))
        self.policy.handle(self.flow())
        self.assertEqual(self.backend.blocks[0][2],[])
    def test_partial_failure_is_cleaned(self):
        def failed(*args):raise RuntimeError('backend unavailable')
        self.backend.block=failed;self.policy.handle(self.flow());self.policy.tick()
        self.assertEqual(self.backend.releases,[self.alice]);self.assertTrue(self.policy.error)
    def test_packet_submissions_are_bounded_and_sni_upgrade_is_seen(self):
        f=self.flow(evidence='IP',domain='');self.policy.submit(f);self.policy.submit(f)
        f.update(evidence='TLS SNI',domain='supercell.com');self.policy.submit(f)
        self.assertEqual(self.policy.queue.qsize(),2)
    def test_disconnect_filter_binds_source_port_to_exact_inbound(self):
        b=Backend({});b.xray_ready=True;b.ports={'in-one':8443,'in-two':15900}
        event={'source':'xray','client_id':self.alice,'label':'alice'}
        with patch.object(b,'xray'),patch('tunnelscope.policy.command',return_value=SimpleNamespace(returncode=0,stderr='')) as cmd:
            b.block(event,20,[('203.0.113.8',45000,'in-one')])
        args=cmd.call_args[0][0];expression=args[-1]
        self.assertIn('sport = :8443',expression);self.assertNotIn(':15900',expression)
        self.assertIn('dport = :45000',expression);self.assertTrue(expression.startswith('( ( '))

    def test_late_xray_start_retries_and_shutdown_cleans_rules(self):
        p=self.policy;p.stopping=Mock();p.stopping.is_set.side_effect=[False,False,True]
        self.backend.initialize=Mock(side_effect=[RuntimeError('starting'),None]);self.backend.cleanup=Mock()
        p.worker()
        self.assertEqual(self.backend.initialize.call_count,2)
        p.stopping.wait.assert_called_once_with(5)
        self.backend.cleanup.assert_called_once();self.assertFalse(p.ready);self.assertEqual(p.error,'')

    def test_invalid_tunnel_target_rejected_before_command(self):
        b=Backend({'interfaces':[{'name':'csqtt1','source':'csqtt','network':'10.66.67.0/24'}]})
        with self.assertRaises(RuntimeError):b.block({'source':'csqtt','client_id':'test','interface':'csqtt1','internal':'203.0.113.10'},20,[])

if __name__=='__main__':unittest.main()
