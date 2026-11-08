"""LAN binding/peer policy, configuration, and verified dual-listener HTTPS."""
from contextlib import contextmanager
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from backend.storage import Store
from demo_app.auth import AccountAuth, account_record
from demo_app.lan import LanSettings, lan_listener, lan_network, CONFIG
from demo_app.server import DemoServer
from demo_app.tests.test_https import CERT, KEY
from demo_app.tls import server_context


class LanPolicyTests(unittest.TestCase):
    def test_only_explicit_private_ipv4_networks_are_allowed(self):
        for address,subnet in [('10.140.132.216','10.140.128.0/20'),('172.16.1.2','172.16.1.0/24'),('192.168.1.2','192.168.1.0/24')]:
            self.assertEqual(str(lan_network(address,subnet)),subnet)
        for address,subnet in [('0.0.0.0','0.0.0.0/0'),('8.8.8.8','8.8.8.0/24'),
                ('127.0.0.2','127.0.0.0/8'),('169.254.1.1','169.254.0.0/16'),
                ('192.168.1.0','192.168.1.0/24'),('192.168.1.255','192.168.1.0/24'),
                ('192.168.2.2','192.168.1.0/24'),('::1','::1/128')]:
            with self.assertRaises(ValueError):
                lan_network(address,subnet)

    def test_lan_requires_account_auth_tls_and_explicit_subnet(self):
        for kwargs in ({},{'tls_context':object()},{'tls_context':object(),'auth':object()}):
            with self.assertRaisesRegex(ValueError,'LAN access requires'):
                DemoServer(('10.0.0.2',0),object(),**kwargs)

    def test_peer_outside_subnet_is_closed_before_tls_or_auth(self):
        server=DemoServer.__new__(DemoServer)
        server.allowed_subnet=ipaddress.ip_network('10.140.128.0/20')
        server.tls_context=mock.Mock()
        connection=mock.Mock()
        with mock.patch('http.server.ThreadingHTTPServer.get_request',return_value=(connection,('10.140.144.5',50000))):
            with self.assertRaises(ConnectionAbortedError):
                server.get_request()
        connection.close.assert_called_once()
        server.tls_context.wrap_socket.assert_not_called()

    def test_private_peer_and_loopback_pass_connection_policy(self):
        for peer in ('10.140.130.5','127.0.0.1'):
            server=DemoServer.__new__(DemoServer)
            server.allowed_subnet=ipaddress.ip_network('10.140.128.0/20')
            server.tls_context=None
            connection=mock.Mock()
            with mock.patch('http.server.ThreadingHTTPServer.get_request',return_value=(connection,(peer,50000))):
                self.assertEqual(server.get_request()[0],connection)
            connection.close.assert_not_called()

    def test_configuration_pins_certificate_and_rejects_changed_address(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            certificate=root/'cert.pem'; certificate.write_bytes(b'fixture-certificate')
            config=root/'lan.json'
            payload={'schema':'iris-lan-v1','address':'192.168.1.2','subnet':'192.168.1.0/24','port':8010,
                     'certificate':str(certificate),'private_key':str(root/'key.pem'),
                     'certificate_sha256':hashlib.sha256(certificate.read_bytes()).hexdigest()}
            config.write_text(json.dumps(payload))
            self.assertEqual(LanSettings.load(config,check_address=False).address,'192.168.1.2')
            with mock.patch('demo_app.lan.socket.socket') as network_socket:
                network_socket.return_value.__enter__.return_value.bind.side_effect=OSError('Not assigned')
                with self.assertRaisesRegex(ValueError,'no longer on this PC'):
                    LanSettings.load(config)
            certificate.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'certificate does not match'):
                LanSettings.load(config,check_address=False)

    def test_lan_command_errors_before_opening_saved_database(self):
        import demo
        with mock.patch('sys.argv',['demo.py','keys','--lan']), mock.patch('demo.settings') as settings:
            with mock.patch('sys.stderr'),self.assertRaises(SystemExit):
                demo.main()
            settings.assert_not_called()


@unittest.skipUnless(os.environ.get('IRIS_TEST_LAN') == '1' and CONFIG.is_file(),
                     'Opt in to actual prepared LAN transport checks with IRIS_TEST_LAN=1')
class PreparedLanHTTPSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lan=LanSettings.load()
        cls.records=[account_record('LanSOC','Synthetic-LAN-test-only!','soc')]

    @contextmanager
    def listeners(self):
        with tempfile.TemporaryDirectory(prefix='iris-dual-https-') as directory:
            engine=SimpleNamespace(store=Store(Path(directory)/'state.sqlite3'),
                status=lambda actor:{'role':actor},settings=SimpleNamespace(role_keys={}))
            auth=AccountAuth(self.records)
            with DemoServer(('127.0.0.1',0),engine,tls_context=server_context(CERT,KEY),auth=auth) as local:
                settings=LanSettings(self.lan.address,self.lan.subnet,local.server_port,self.lan.certificate,self.lan.private_key)
                with lan_listener(settings,engine,server_context(self.lan.certificate,self.lan.private_key),auth) as shared:
                    worker=threading.Thread(target=local.serve_forever,kwargs={'poll_interval':.01},daemon=True)
                    worker.start()
                    try:
                        yield local,shared
                    finally:
                        local.shutdown();worker.join(3)

    def request(self,server,*,local=False,token=None,path='/api/demo/state',body=None,headers=None):
        hostname='127.0.0.1' if local else self.lan.address
        certificate=CERT if local else self.lan.trust_certificate
        request_headers={'Authorization':'Bearer '+token} if token else {}
        if body is not None: request_headers['Content-Type']='application/json'
        request_headers.update(headers or {})
        connection=http.client.HTTPSConnection(hostname,server.server_port,
            context=ssl.create_default_context(cafile=str(certificate)),timeout=5)
        try:
            connection.request('POST' if body is not None else 'GET',path,
                json.dumps(body) if body is not None else None,request_headers)
            response=connection.getresponse()
            raw=response.read()
            return response.status,json.loads(raw) if response.getheader('Content-Type','').startswith('application/json') else raw
        finally:
            connection.close()

    def test_real_lan_https_keeps_auth_chat_and_localhost_compatibility(self):
        with self.listeners() as (local,lan):
            self.assertEqual(self.request(lan)[0],401)
            status,session=self.request(lan,path='/api/demo/auth/login',body={
                'username':'LanSOC','password':'Synthetic-LAN-test-only!','workspace':'soc'})
            self.assertEqual(status,200)
            token=session['access_token']
            self.assertEqual(self.request(local,local=True,token=token)[1]['user']['username'],'LanSOC')
            self.assertEqual(self.request(lan,token=token,headers={
                'Origin':f'https://{self.lan.address}:{lan.server_port}'})[0],200)
            self.assertEqual(self.request(lan,token=token,headers={'Host':'evil.example'})[0],400)
            self.assertEqual(self.request(lan,token=token,headers={'Origin':'http://'+self.lan.address})[0],403)
            self.assertEqual(self.request(lan,token=token,path='/api/demo/chat',body={'text':'Verified LAN chat'})[0],201)
            self.assertEqual(self.request(local,local=True,token=token,path='/api/demo/chat')[1]['items'][0]['text'],'Verified LAN chat')
            self.assertEqual(self.request(lan,token=token,path='/api/demo/chat/logs')[0],403)
            self.assertEqual(self.request(lan,token=token,path='/api/demo/auth/logout',body={})[0],200)
            self.assertEqual(self.request(local,local=True,token=token)[0],401)

    def test_context_stops_both_listeners_without_leaving_lan_socket_open(self):
        with self.listeners() as (local,lan):
            port=lan.server_port
            self.assertEqual(self.request(lan,path='/health')[0],200)
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
            probe.bind((self.lan.address,port))


if __name__ == '__main__':
    unittest.main()
