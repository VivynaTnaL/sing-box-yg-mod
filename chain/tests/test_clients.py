"""Portable nodes must survive crossing hosts without copying server secrets."""
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import clients
import generate
import profiles
from chain import ConfigError, check_config


CORE = Path(os.environ.get('CHAIN_TEST_CORE', '/tmp/sing-box-chain-core'))
REALITY_KEY = base64.urlsafe_b64encode(bytes(range(1, 33))).decode().rstrip('=')


def write_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


class PortableClientsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory(prefix='client-public-cert-')
        cls.fixture_root = Path(cls.fixture.name)
        for name in ('server-b', 'server-a'):
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', str(cls.fixture_root / (name + '.key')),
                            '-out', str(cls.fixture_root / (name + '.pem')),
                            '-days', '1', '-subj', '/CN=' + name + '.example.com'],
                           check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='client-exchange-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cert = self.root / 'cert.pem'
        self.key = self.root / 'key.pem'
        self.cert.write_bytes((self.fixture_root / 'server-b.pem').read_bytes())
        self.key.write_bytes((self.fixture_root / 'server-b.key').read_bytes())
        params = copy.deepcopy(generate.EXAMPLE)
        params['tls'].update(certificate_path='cert.pem', key_path='key.pem')
        params['protocols'][0]['reality']['private_key'] = REALITY_KEY
        self.server = generate.render(params, self.root, 'unused-core')
        vmess = next(i for i in self.server['inbounds'] if i['type'] == 'vmess')
        vmess['transport'].update(headers={'Host': 'ws.example.com', 'X-Source': 'B'},
                                  max_early_data=2048,
                                  early_data_header_name='Sec-WebSocket-Protocol')
        for inbound in self.server['inbounds']:
            tls = inbound.get('tls', {})
            if 'certificate' in tls:
                tls.pop('certificate')
                tls.pop('key')
                tls.update(certificate_path='cert.pem', key_path='key.pem')
        self.source = write_json(self.root / 'server.json', self.server)

    def export(self):
        return clients.export_clients_source(self.source, '192.0.2.20', 'B-direct')

    def import_config(self, config, real_core=False):
        path = write_json(self.root / 'client-exchange.json', config)
        if real_core:
            return clients.import_clients(path, 'B-direct', CORE)
        with patch.object(clients, 'check_version'), patch.object(clients, 'check_config'):
            return clients.import_clients(path, 'B-direct', 'unused-core')

    def test_five_protocols_roundtrip_credentials_and_both_pins(self):
        expected = profiles.import_direct(self.source, '192.0.2.20', 'B-direct')
        exchange = self.export()
        actual = self.import_config(exchange)
        self.assertEqual(len(actual), 5)
        for before, after in zip(expected, actual):
            before['outbound']['tag'] = after['outbound']['tag']
            self.assertEqual(before, after)
        for outbound in exchange['outbounds']:
            tls = outbound.get('tls', {})
            if tls.get('reality', {}).get('enabled'):
                self.assertIn('public_key', tls['reality'])
            else:
                self.assertIn('certificate', tls)
                self.assertNotIn('certificate_public_key_sha256', tls)

    def test_exchange_has_no_server_secrets_paths_or_runtime_settings(self):
        original = self.source.read_bytes()
        exchange = self.export()
        self.assertEqual(set(exchange), {'outbounds'})
        serialized = json.dumps(exchange)
        for forbidden in ('private_key', 'PRIVATE KEY', 'certificate_path', 'key_path',
                          'listen_port', 'users', REALITY_KEY, str(self.source)):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(self.source.read_bytes(), original)

    def test_cross_host_import_uses_b_certificate_when_a_has_same_filenames(self):
        exchange = self.export()
        expected_leaf, expected_spki = profiles.certificate_pins(self.cert.read_text())
        self.cert.write_bytes((self.fixture_root / 'server-a.pem').read_bytes())
        self.key.write_bytes((self.fixture_root / 'server-a.key').read_bytes())
        self.source.unlink()
        items = self.import_config(exchange)
        for item in items:
            if item['outbound']['type'] != 'vless':
                self.assertEqual(item['certificate_fingerprint'], expected_leaf)
                self.assertEqual(item['outbound']['tls']['certificate_public_key_sha256'],
                                 [expected_spki])
        self.cert.unlink()
        self.key.unlink()
        self.assertEqual(self.import_config(exchange), items)

    def test_websocket_headers_and_early_data_are_preserved(self):
        items = self.import_config(self.export())
        vmess = next(i['outbound'] for i in items if i['outbound']['type'] == 'vmess')
        source = next(i for i in self.server['inbounds'] if i['type'] == 'vmess')
        self.assertEqual(vmess['transport'], source['transport'])

    def test_selecting_source_inbounds_and_multiple_users(self):
        vmess = next(i for i in self.server['inbounds'] if i['type'] == 'vmess')
        vmess['users'].append({'uuid': '22222222-2222-4222-8222-222222222222'})
        write_json(self.source, self.server)
        exchange = clients.export_clients_source(self.source, '192.0.2.20', 'B-direct',
                                                 [vmess['tag']])
        self.assertEqual(len(exchange['outbounds']), 2)
        self.assertTrue(all(o['type'] == 'vmess' for o in exchange['outbounds']))

    def test_complete_client_config_only_imports_supported_proxy_outbounds(self):
        config = self.export()
        config['outbounds'].insert(0, {'type': 'selector', 'tag': 'proxy', 'outbounds': ['direct']})
        config['outbounds'].insert(1, {'type': 'urltest', 'tag': 'auto', 'outbounds': ['direct']})
        config['outbounds'].insert(2, {'type': 'direct', 'tag': 'direct'})
        config['inbounds'] = [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': 7890}]
        config['route'] = {'rule_set': [{'type': 'local', 'path': '/not/read/on/A'}]}
        items = self.import_config(config)
        self.assertEqual(len(items), 5)
        self.assertTrue(all(i['outbound']['tag'].startswith('B-direct-') for i in items))

    def test_unknown_proxy_types_and_no_proxy_nodes_are_rejected(self):
        for kind in ('shadowsocks', 'socks', 'http', 'wireguard', 'not-a-proxy'):
            config = self.export()
            config['outbounds'].append({'type': kind})
            with self.subTest(kind=kind), self.assertRaises(ConfigError):
                self.import_config(config)
        with self.assertRaisesRegex(ConfigError, '没有'):
            self.import_config({'outbounds': [{'type': 'direct'}]})

    def test_dependencies_unknown_fields_private_keys_and_insecure_are_rejected(self):
        cases = []
        for field, value in (('detour', 'proxy'), ('bind_interface', 'eth0'),
                             ('routing_mark', 123), ('multiplex', {'enabled': True}),
                             ('unknown', False)):
            config = self.export()
            config['outbounds'][1][field] = value
            cases.append(config)
        for field, value in (('certificate_path', '/same/path/on/A'), ('key_path', '/key'),
                             ('key', ['PRIVATE KEY']), ('ech', {'enabled': True}),
                             ('insecure', True)):
            config = self.export()
            config['outbounds'][1]['tls'][field] = value
            cases.append(config)
        config = self.export()
        config['outbounds'][0]['tls']['reality']['private_key'] = REALITY_KEY
        cases.append(config)
        for config in cases:
            with self.subTest(case=cases.index(config)), self.assertRaises(ConfigError):
                self.import_config(config)

    def test_certificate_must_not_smuggle_private_material(self):
        config = self.export()
        config['outbounds'][1]['tls']['certificate'].extend(self.key.read_text().splitlines())
        with self.assertRaisesRegex(ConfigError, '私钥'):
            self.import_config(config)

    def test_spki_only_fails_with_actionable_export_instruction(self):
        expected = profiles.import_direct(self.source, '192.0.2.20', 'B-direct')
        config = {'outbounds': [i['outbound'] for i in expected]}
        with self.assertRaisesRegex(ConfigError, 'export-nodes'):
            self.import_config(config)

    def test_certificate_and_spki_together_are_explicitly_rejected(self):
        config = self.export()
        tls = config['outbounds'][1]['tls']
        _, spki = profiles.certificate_pins(tls['certificate'])
        tls['certificate_public_key_sha256'] = [spki]
        with self.assertRaisesRegex(ConfigError, '不能同时'):
            self.import_config(config)

    def test_import_cannot_replace_chain_group(self):
        with self.assertRaises(ConfigError):
            clients.export_clients_source(self.source, '192.0.2.20', 'A-to-B')
        with self.assertRaises(ConfigError):
            clients.import_clients(self.source, 'A-to-B', 'unused-core')

    def test_plain_vmess_and_public_ca_tls_need_no_certificate(self):
        config = self.export()
        config['outbounds'] = [config['outbounds'][1]]
        config['outbounds'][0].pop('tls')
        self.assertIsNone(self.import_config(config)[0]['certificate_fingerprint'])
        config['outbounds'][0]['tls'] = {'enabled': True, 'server_name': 'server.example.com',
                                         'insecure': False}
        self.assertIsNone(self.import_config(config)[0]['certificate_fingerprint'])

    @unittest.skipUnless(CORE.is_file(), 'sing-box 1.14 test binary not available')
    def test_real_core_accepts_exchange_and_reconstructed_all_protocols(self):
        exchange = self.export()
        check_config(CORE, exchange)
        self.assertEqual(len(self.import_config(exchange, real_core=True)), 5)

    @unittest.skipUnless(CORE.is_file(), 'sing-box 1.14 test binary not available')
    def test_real_core_rejects_certificate_and_spki_combination(self):
        exchange = self.export()
        tls = exchange['outbounds'][1]['tls']
        _, spki = profiles.certificate_pins(tls['certificate'])
        tls['certificate_public_key_sha256'] = [spki]
        with self.assertRaises(ConfigError):
            check_config(CORE, exchange)


if __name__ == '__main__':
    unittest.main()
