"""Exercise node exchange through the actual parser, manager, and sing-box core."""
import base64
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import addon
import generate
import profiles
from chain import ConfigError, check_config
from test_addon import plain_source, write_json


CORE = Path(os.environ.get('CHAIN_TEST_CORE', '/tmp/sing-box-chain-core'))


@unittest.skipUnless(CORE.is_file(), 'sing-box 1.14 test binary not available')
class NodesCLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory(prefix='nodes-cli-certificate-')
        cls.fixture_root = Path(cls.fixture.name)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(cls.fixture_root / 'key.pem'),
                        '-out', str(cls.fixture_root / 'cert.pem'),
                        '-days', '1', '-subj', '/CN=b.example.com'],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='nodes-cli-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.a_store = addon.Store(self.root / 'a-state')
        self.b_store = addon.Store(self.root / 'b-state')
        self.b_files = self.root / 'b-private'
        self.b_files.mkdir()
        for name in ('cert.pem', 'key.pem'):
            (self.b_files / name).write_bytes((self.fixture_root / name).read_bytes())
        params = copy.deepcopy(generate.EXAMPLE)
        params['tls'].update(certificate_path='cert.pem', key_path='key.pem')
        params['protocols'][0]['reality']['private_key'] = base64.urlsafe_b64encode(bytes(range(1, 33))).decode().rstrip('=')
        self.b_server = generate.render(params, self.b_files, CORE)
        for inbound in self.b_server['inbounds']:
            tls = inbound.get('tls', {})
            if 'certificate' in tls:
                tls.pop('certificate')
                tls.pop('key')
                tls.update(certificate_path='cert.pem', key_path='key.pem')
        vmess = next(i for i in self.b_server['inbounds'] if i['type'] == 'vmess')
        vmess['transport'].update(headers={'Host': 'ws.example.com', 'X-Source': 'B'},
                                  max_early_data=2048,
                                  early_data_header_name='Sec-WebSocket-Protocol')
        self.b_source = write_json(self.b_files / 'server.json', self.b_server)
        self.a_source = write_json(self.root / 'a-source.json', plain_source())
        _, handoff = profiles.exit_config('192.0.2.20', 22000, ['192.0.2.10'])
        self.link = write_json(self.root / 'handoff.json', handoff)
        self.exchange = self.root / 'B-client-nodes.json'
        # The production CLI is exercised, while any accidental service use fails.
        for target in ('runtime.Runtime', 'publish.Publisher'):
            guard = patch(target, side_effect=AssertionError('node operations must not manage services'))
            guard.start()
            self.addCleanup(guard.stop)

    def execute(self, store, *args):
        parsed = addon.parser().parse_args(['--state', str(store.root), *map(str, args)])
        with redirect_stdout(io.StringIO()):
            addon.execute(parsed)

    def initialize_a(self):
        self.execute(self.a_store, 'init-entry', '--config', self.a_source,
                     '--address', '192.0.2.10', '--link', self.link, '--binary', CORE)
        self.execute(self.a_store, 'rules', '--mode', 'lan-direct')

    def export_b(self, output=None):
        self.execute(self.b_store, 'export-nodes', '--config', self.b_source,
                     '--address', '192.0.2.20', '--label', 'B-direct',
                     '--output', output or self.exchange, '--binary', CORE)

    def test_b_export_without_state_then_a_import_and_three_independent_profiles(self):
        before = self.b_source.read_bytes()
        self.export_b()
        self.assertEqual(self.b_source.read_bytes(), before)
        self.assertFalse((self.b_store.root / 'state.json').exists())
        self.assertEqual(self.exchange.stat().st_mode & 0o777, 0o600)
        exchange = json.loads(self.exchange.read_text())
        self.assertEqual(set(exchange), {'outbounds'})
        self.assertEqual(len(exchange['outbounds']), 5)
        check_config(CORE, exchange)
        leaf, spki = profiles.certificate_pins((self.b_files / 'cert.pem').read_text())
        for path in self.b_files.iterdir():
            path.unlink()
        self.b_files.rmdir()

        self.initialize_a()
        server_before = copy.deepcopy(self.a_store.read()['server_config'])
        source_before = self.a_source.read_bytes()
        self.execute(self.a_store, 'add-direct', '--config', self.a_source,
                     '--address', '192.0.2.10', '--label', 'A-direct')
        self.execute(self.a_store, 'import-nodes', '--config', self.exchange,
                     '--label', 'B-direct', '--binary', CORE)
        state = self.a_store.read()
        self.assertEqual(state['server_config'], server_before)
        self.assertEqual(self.a_source.read_bytes(), source_before)
        self.assertEqual(set(state['groups']), {'A-direct', 'B-direct', 'A-to-B'})
        for item in state['groups']['B-direct']:
            if item['outbound']['type'] != 'vless':
                self.assertEqual(item['certificate_fingerprint'], leaf)
                self.assertEqual(item['outbound']['tls']['certificate_public_key_sha256'], [spki])

        release = addon.build(self.a_store)
        self.assertEqual(set(p.name for p in (release / 'groups').iterdir()),
                         {'A-direct', 'B-direct', 'A-to-B'})
        for group, expected_count in [('A-direct', 1), ('B-direct', 5), ('A-to-B', 1)]:
            path = release / 'groups' / group
            self.assertEqual(set(p.name for p in path.iterdir()),
                             {'mihomo.yaml', 'sing-box.json', 'nodes.txt', 'nodes.base64.txt'})
            config = json.loads((path / 'sing-box.json').read_text())
            check_config(CORE, config)
            actual = [o for o in config['outbounds'] if o['type'] in profiles.PROTOCOLS]
            self.assertEqual(len(actual), expected_count)
            self.assertTrue(all(group in o['tag'] for o in actual))
            self.assertNotIn('private_key', json.dumps(config))
            raw = (path / 'nodes.txt').read_bytes()
            self.assertEqual(base64.b64decode((path / 'nodes.base64.txt').read_text()), raw)
            self.assertEqual(len(raw.splitlines()), expected_count)

        destination = self.root / 'b-client-export'
        self.execute(self.a_store, 'export', '--group', 'B-direct', '--output-dir', destination)
        self.assertEqual((destination / 'nodes.txt').read_bytes(),
                         (release / 'groups' / 'B-direct' / 'nodes.txt').read_bytes())

    def test_existing_and_symlink_exchange_destinations_are_never_overwritten(self):
        self.exchange.write_text('keep this exact file')
        with self.assertRaisesRegex(ConfigError, '不存在'):
            self.export_b()
        self.assertEqual(self.exchange.read_text(), 'keep this exact file')
        symlink = self.root / 'exchange-link.json'
        symlink.symlink_to(self.exchange)
        with self.assertRaises(ConfigError):
            self.export_b(symlink)
        self.assertTrue(symlink.is_symlink())
        self.assertEqual(self.exchange.read_text(), 'keep this exact file')

    def test_failed_import_keeps_exact_previous_state_and_source(self):
        self.initialize_a()
        self.export_b()
        before = (self.a_store.root / 'state.json').read_bytes()
        config = json.loads(self.exchange.read_text())
        config['outbounds'][1]['detour'] = 'missing-and-forbidden'
        write_json(self.exchange, config)
        source_before = self.exchange.read_bytes()
        with self.assertRaises(ConfigError):
            self.execute(self.a_store, 'import-nodes', '--config', self.exchange,
                         '--label', 'B-direct', '--binary', CORE)
        self.assertEqual((self.a_store.root / 'state.json').read_bytes(), before)
        self.assertEqual(self.exchange.read_bytes(), source_before)

    def test_other_writer_creates_target_during_core_check_without_being_overwritten(self):
        def check_and_race(binary, config):
            check_config(binary, config)
            self.exchange.write_text('written by another command')

        with patch.object(addon, 'check_config', side_effect=check_and_race):
            with self.assertRaisesRegex(ConfigError, '存在'):
                self.export_b()
        self.assertEqual(self.exchange.read_text(), 'written by another command')
        self.assertFalse(list(self.root.glob('.nodes-*')))

    def test_failed_core_check_does_not_create_exchange_output(self):
        self.b_server['inbounds'][0]['users'][0]['flow'] = 'unsupported-flow'
        write_json(self.b_source, self.b_server)
        source_before = self.b_source.read_bytes()
        with self.assertRaises(ConfigError):
            self.export_b()
        self.assertFalse(self.exchange.exists())
        self.assertEqual(self.b_source.read_bytes(), source_before)
        self.assertFalse((self.b_store.root / 'state.json').exists())


if __name__ == '__main__':
    unittest.main()
