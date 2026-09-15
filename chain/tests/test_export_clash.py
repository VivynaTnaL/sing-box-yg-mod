import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import export_clash as export
from chain import ConfigError
from policy import load_policy


UUID = '00000000-0000-4000-8000-000000000001'
KEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')


def links():
    vmess = {'v': '2', 'ps': 'CDN', 'add': 'cdn.example.com', 'port': '443',
             'id': UUID, 'aid': '0', 'net': 'ws', 'type': 'none', 'path': '/ws?ed=2048',
             'host': 'tunnel.example.com', 'tls': 'tls', 'sni': 'tunnel.example.com', 'fp': 'chrome'}
    return [
        f'vless://{UUID}@example.com:443?security=reality&sni=www.example.com&pbk={KEY}&sid=abcd&flow=xtls-rprx-vision&type=tcp#same',
        'vmess://' + base64.b64encode(json.dumps(vmess).encode()).decode(),
        'hysteria2://secret@example.com:443?sni=example.com&insecure=0&allowInsecure=0&pinSHA256=' + 'ab' * 32 + '&mport=4000-4010,5000&alpn=h3#same',
        f'tuic://{UUID}:pass%3Aword@[2001:db8::1]:443?insecure=1&allow_insecure=1&congestion_control=bbr&udp_relay_mode=native&alpn=h3',
        'anytls://pass%40word@example.com:443?sni=example.com&insecure=0',
    ]


class ExportTests(unittest.TestCase):
    def test_five_protocols_preserve_transport_and_tls(self):
        vless, vmess, hy2, tuic, anytls = map(export.convert, links())
        self.assertEqual(vless['reality-opts'], {'public-key': KEY, 'short-id': 'abcd'})
        self.assertEqual(vless['flow'], 'xtls-rprx-vision')
        self.assertEqual(vmess['server'], 'cdn.example.com')
        self.assertEqual(vmess['servername'], 'tunnel.example.com')
        self.assertEqual(vmess['ws-opts'], {'path': '/ws?ed=2048', 'headers': {'Host': 'tunnel.example.com'}})
        self.assertTrue(vmess['tls'])
        self.assertEqual(hy2['fingerprint'], 'ab' * 32)
        self.assertFalse(hy2['skip-cert-verify'])
        self.assertEqual(hy2['ports'], '4000-4010,5000')
        self.assertEqual(tuic['server'], '2001:db8::1')
        self.assertEqual(tuic['password'], 'pass:word')
        self.assertTrue(tuic['skip-cert-verify'])
        self.assertEqual(tuic['congestion-controller'], 'bbr')
        self.assertEqual(anytls['password'], 'pass@word')
        self.assertFalse(anytls['skip-cert-verify'])

    def test_reject_unsupported_or_conflicting_security(self):
        for link in [links()[4] + '&ech=secret', links()[4] + '&allowInsecure=1',
                     links()[4] + '&insecure=1', links()[0].replace('pbk=', 'unknown='),
                     links()[2].replace('4000-4010', '9000-8000'),
                     links()[2].replace('ab' * 32, 'bad'),
                     'ss://not-client-interserver-key@example.com:443']:
            with self.subTest(link=link.split('://')[0]):
                with self.assertRaises(ConfigError):
                    export.convert(link)

    def test_groups_base64_duplicate_names_and_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = [Path(tmp) / 'A-direct.txt', Path(tmp) / 'A-to-B.base64.txt', Path(tmp) / 'B-direct.txt']
            raw = '\n'.join(links())
            for i, path in enumerate(paths):
                path.write_text(base64.b64encode(raw.encode()).decode() if i == 1 else raw)
            config = export.profile(paths)
            self.assertEqual(len(config['proxies']), 15)
            self.assertEqual(len({p['name'] for p in config['proxies']}), 15)
            self.assertEqual(len(config['proxy-groups']), 4)
            self.assertEqual(config['rules'][-3:], ['RULE-SET,chain-cn-domain,DIRECT',
                                                  'RULE-SET,chain-cn-ip,DIRECT', 'MATCH,代理选择'])
            text = export.yaml_text(config)
            # Values use JSON flow syntax, a YAML subset; verify escaped strings round-trip.
            decoded = dict((json.loads(k), json.loads(v)) for k, v in
                           (line.split(': ', 1) for line in text.splitlines()[1:]))
            self.assertEqual(decoded, config)

    def test_explicit_global_mode_remains_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'nodes.txt'
            path.write_text('\n'.join(links()))
            config = export.profile([path], load_policy('global'))
            self.assertEqual(config['rules'], ['MATCH,代理选择'])

    def test_cli_routing_exceptions_and_missing_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, target = Path(tmp) / 'nodes.txt', Path(tmp) / 'clash.yaml'
            source.write_text('\n'.join(links()))
            command = [sys.executable, export.__file__, '--input', str(source), '--output', str(target),
                       '--routing', 'lan-direct', '--proxy-domain', 'force.example', '--direct-cidr', '1.2.3.4']
            run = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn('IP-CIDR,1.2.3.4/32,DIRECT', target.read_text())
            target.unlink()
            run = subprocess.run(command + ['--rules-dir', str(Path(tmp) / 'missing')], capture_output=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse(target.exists())

    def test_cli_private_output_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, target = Path(tmp) / 'nodes.txt', Path(tmp) / 'clash.yaml'
            source.write_text('\n'.join(links()))
            command = [sys.executable, export.__file__, '--input', str(source), '--output', str(target)]
            run = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            before = target.read_bytes()
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(target.read_bytes(), before)
            target.unlink()
            source.write_text('anytls://supersecret@example.com:invalid')
            run = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertNotIn('supersecret', run.stdout + run.stderr)
            self.assertFalse(target.exists())


if __name__ == '__main__':
    unittest.main()
