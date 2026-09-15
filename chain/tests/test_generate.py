import base64
import copy
import json
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import generate


ROOT = Path(__file__).resolve().parents[2]
PRIVATE_KEY = base64.urlsafe_b64encode(bytes(range(1, 33))).decode().rstrip('=')


class GenerateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'cert.pem').write_text('certificate fixture\n')
        (self.root / 'key.pem').write_text('private fixture\n')
        self.params = copy.deepcopy(generate.EXAMPLE)
        self.params['protocols'][0]['reality']['private_key'] = PRIVATE_KEY

    def render(self, params=None):
        return generate.render(self.params if params is None else params, self.root, 'unused-core')

    def parameter_file(self, params=None):
        path = self.root / 'params.json'
        path.write_text(json.dumps(self.params if params is None else params))
        return path

    def test_five_protocols_have_independent_credentials_and_embedded_tls(self):
        config = self.render()
        self.assertEqual([i['type'] for i in config['inbounds']], list(generate.DEFAULT_PORTS))
        self.assertEqual([i['listen_port'] for i in config['inbounds']], list(range(20001, 20006)))
        self.assertEqual(config['outbounds'], [{'type': 'direct', 'tag': 'direct'}])
        self.assertEqual(config['route'], {'final': 'direct'})
        uuids, passwords = [], []
        for inbound in config['inbounds']:
            user = inbound['users'][0]
            if 'uuid' in user:
                uuids.append(user['uuid'])
            if 'password' in user:
                passwords.append(user['password'])
            if inbound['type'] != 'vless':
                self.assertEqual(inbound['tls']['certificate'], ['certificate fixture'])
                self.assertEqual(inbound['tls']['key'], ['private fixture'])
                self.assertNotIn('certificate_path', inbound['tls'])
                self.assertNotIn('key_path', inbound['tls'])
        self.assertEqual(len(set(uuids)), 3)
        self.assertEqual(len(set(passwords)), 3)
        self.assertNotEqual(self.render()['inbounds'][0]['users'], config['inbounds'][0]['users'])

    def test_plain_vmess_needs_no_certificate_and_parameters_are_kept(self):
        uid = '11111111-1111-4111-8111-111111111111'
        params = {'schema_version': 1, 'listen': '::1', 'protocols': [
            {'type': 'vmess', 'tls': False, 'uuid': uid, 'port': 23456, 'path': '/custom'}]}
        inbound = self.render(params)['inbounds'][0]
        self.assertEqual(inbound['users'][0]['uuid'], uid)
        self.assertEqual(inbound['transport']['path'], '/custom')
        self.assertEqual(inbound['listen_port'], 23456)
        self.assertEqual(inbound['listen'], '::1')
        self.assertNotIn('tls', inbound)

    def test_reality_keys_are_generated_using_only_supplied_core(self):
        params = {'schema_version': 1, 'protocols': [
            {'type': 'vless', 'reality': {'server_name': 'www.example.com'}}]}
        with patch.object(generate, 'run_core', return_value='PrivateKey: ' + PRIVATE_KEY + '\n') as core:
            reality = self.render(params)['inbounds'][0]['tls']['reality']
        core.assert_called_once_with('unused-core', 'generate', 'reality-keypair')
        self.assertEqual(reality['private_key'], PRIVATE_KEY)
        self.assertEqual(len(reality['short_id'][0]), 16)

    def test_unknown_ambiguous_and_invalid_parameters_fail(self):
        invalid = []
        for key, value in (('schema_version', True), ('listen', 'host.example.com'),
                           ('listen', 'ff02::1'), ('protocols', []), ('warp', True)):
            data = copy.deepcopy(self.params)
            data[key] = value
            invalid.append(data)
        for entry in ({'type': 'vmess', 'tls': 'false'}, {'type': 'vmess', 'uuid': 'bad'},
                      {'type': 'tuic', 'password': None}, {'type': 'vless', 'reality': None},
                      {'type': 'anytls', 'port': True}, {'type': 'hysteria2', 'port': 65536},
                      {'type': 'vmess', 'path': 'bad'}, {'type': 'vmess', 'password': 'unused'},
                      {'type': 'vmess', 'tls': {'enabled': False}}, {'type': 'shadowsocks'}):
            data = copy.deepcopy(self.params)
            data['protocols'] = [entry]
            invalid.append(data)
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(generate.ConfigError):
                self.render(data)
        for field, value in (('short_id', 'abc'), ('private_key', 'bad'), ('unknown', True)):
            data = copy.deepcopy(self.params)
            data['protocols'][0]['reality'][field] = value
            with self.subTest(field=field), self.assertRaises(generate.ConfigError):
                self.render(data)

    def test_duplicate_protocols_ports_or_missing_tls_fail(self):
        cases = []
        duplicate_type = copy.deepcopy(self.params)
        duplicate_type['protocols'].append({'type': 'vmess', 'port': 23456})
        cases.append(duplicate_type)
        duplicate_port = copy.deepcopy(self.params)
        duplicate_port['protocols'][1]['port'] = 20001
        cases.append(duplicate_port)
        missing_tls = copy.deepcopy(self.params)
        del missing_tls['tls']
        cases.append(missing_tls)
        for data in cases:
            with self.subTest(data=data), self.assertRaises(generate.ConfigError):
                self.render(data)

    def test_write_checked_config_with_private_permissions(self):
        target = self.root / 'new.json'
        def check(binary, *args):
            self.assertEqual((binary, args[:2]), ('core', ('check', '-c')))
            checked = Path(args[2])
            self.assertEqual(checked.stat().st_mode & 0o777, 0o600)
            self.assertFalse(target.exists())
            self.assertEqual(len(json.loads(checked.read_text())['inbounds']), 5)
        with patch.object(generate, 'check_version') as version, patch.object(generate, 'run_core', side_effect=check):
            generate.generate(self.parameter_file(), target, 'core')
        version.assert_called_once_with('core')
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.root.glob('.generate-*')))

    def test_failed_core_check_never_creates_output(self):
        target = self.root / 'new.json'
        with patch.object(generate, 'check_version'), patch.object(
                generate, 'run_core', side_effect=generate.ConfigError('check failed')):
            with self.assertRaises(generate.ConfigError):
                generate.generate(self.parameter_file(), target, 'core')
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob('.generate-*')))

    def test_existing_files_and_dangling_symlinks_are_never_overwritten(self):
        params = self.parameter_file()
        target = self.root / 'existing.json'
        target.write_text('keep me')
        link = self.root / 'link.json'
        link.symlink_to(self.root / 'absent.json')
        for path in (target, link):
            with self.subTest(path=path), patch.object(generate, 'check_version') as version:
                with self.assertRaises(generate.ConfigError):
                    generate.generate(params, path, 'core')
                version.assert_not_called()
        self.assertEqual(target.read_text(), 'keep me')
        self.assertTrue(link.is_symlink())
        self.assertFalse((self.root / 'absent.json').exists())

    def test_concurrent_writer_is_preserved(self):
        target = self.root / 'new.json'
        def race(*unused):
            target.write_text('concurrent writer')
        with patch.object(generate, 'check_version'), patch.object(generate, 'run_core', side_effect=race):
            with self.assertRaises(generate.ConfigError):
                generate.generate(self.parameter_file(), target, 'core')
        self.assertEqual(target.read_text(), 'concurrent writer')
        self.assertFalse(list(self.root.glob('.generate-*')))

    def test_wrong_core_version_does_not_generate_output(self):
        core = self.root / 'core'
        core.write_text('#!/bin/sh\nprintf "sing-box version 1.10.7\\n"\n')
        core.chmod(0o700)
        target = self.root / 'new.json'
        with self.assertRaises(generate.ConfigError):
            generate.generate(self.parameter_file(), target, core)
        self.assertFalse(target.exists())

    def test_shell_help_and_example_bypass_legacy_guard(self):
        marker = self.root / 'legacy-managed'
        marker.touch()
        script = self.root / 'sb.sh'
        script.write_text((ROOT / 'sb.sh').read_text().replace('/etc/sing-box-chain/legacy-managed', str(marker)))
        (self.root / 'chain').symlink_to(ROOT / 'chain', target_is_directory=True)
        for argument in ('--help', '--example'):
            result = subprocess.run(['bash', '-x', str(script), '--generate-config', argument],
                                    cwd=self.root, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('legacy-managed', result.stderr)
            self.assertNotIn('systemctl', result.stderr)
            self.assertNotIn('EUID', result.stderr)
            self.assertNotIn('export LANG', result.stderr)
            if argument == '--example':
                example = json.loads(result.stdout)
                self.assertEqual(example, generate.EXAMPLE)
                self.assertNotIn('private_key', result.stdout)
                self.assertNotIn('password', result.stdout)

    def test_installed_shortcut_without_repository_has_clear_error(self):
        script = self.root / 'sb'
        script.write_text((ROOT / 'sb.sh').read_text())
        result = subprocess.run(['bash', str(script), '--generate-config', '--help'],
                                cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn('完整仓库', result.stderr)

    def core_fixture(self, fail_check=False):
        core = self.root / 'fixture-core'
        log = self.root / 'core-calls.jsonl'
        core.write_text('''#!/usr/bin/env python3
import json, sys
from pathlib import Path
with open(%r, 'a') as stream:
    stream.write(json.dumps(sys.argv[1:]) + '\\n')
if sys.argv[1:] == ['version']:
    print('sing-box version %s')
elif sys.argv[1:] == ['generate', 'reality-keypair']:
    print('PrivateKey: %s')
elif sys.argv[1:3] == ['check', '-c']:
    json.loads(Path(sys.argv[3]).read_text())
    sys.exit(%d)
else:
    sys.exit(99)
''' % (str(log), generate.VERSION, PRIVATE_KEY, int(fail_check)))
        core.chmod(0o700)
        return core, log

    def test_chinese_wizard_generates_five_protocols_without_parameter_file(self):
        core, log = self.core_fixture()
        output = self.root / 'server.json'
        with patch('builtins.input', side_effect=[''] * 7), patch('sys.stdout', new_callable=io.StringIO):
            result, used_core = generate.wizard(output, core)
        self.assertEqual((result, used_core), (output, core))
        config = json.loads(output.read_text())
        self.assertEqual([i['type'] for i in config['inbounds']], list(generate.DEFAULT_PORTS))
        self.assertTrue(config['inbounds'][-1]['tls']['certificate'][0].startswith('-----BEGIN CERTIFICATE'))
        self.assertNotIn('certificate_path', output.read_text())
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.root.glob('.sb-cert-*')))
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual([call[0] for call in calls], ['version', 'generate', 'check'])
        self.assertFalse((self.root / 'params.json').exists())

    def test_wizard_failure_cleans_temporary_certificates_and_config(self):
        core, unused = self.core_fixture(fail_check=True)
        output = self.root / 'server.json'
        with patch('builtins.input', side_effect=[''] * 7), patch('sys.stdout', new_callable=io.StringIO):
            with self.assertRaises(generate.ConfigError):
                generate.wizard(output, core)
        self.assertFalse(output.exists())
        self.assertFalse(list(self.root.glob('.sb-cert-*')))
        self.assertFalse(list(self.root.glob('.generate-*')))

    def test_wizard_selected_reality_only_needs_no_tls_files(self):
        core, unused = self.core_fixture()
        output = self.root / 'server.json'
        with patch('builtins.input', side_effect=['1', '23000', '::1', 'www.example.com']), patch('sys.stdout', new_callable=io.StringIO):
            generate.wizard(output, core)
        config = json.loads(output.read_text())
        self.assertEqual(len(config['inbounds']), 1)
        self.assertEqual(config['inbounds'][0]['listen_port'], 23000)
        self.assertEqual(config['inbounds'][0]['listen'], '::1')
        self.assertNotIn('certificate', output.read_text())

    def test_download_core_uses_output_directory_and_reuses_checked_cache(self):
        output = self.root / 'server.json'
        def fetch(args, **kwargs):
            self.assertEqual(Path(args[1]).name, 'fetch-core.py')
            self.assertEqual(args[2], '--output')
            Path(args[3]).write_text('download fixture')
            return subprocess.CompletedProcess(args, 0, '', '')
        with patch.object(generate.subprocess, 'run', side_effect=fetch) as run, patch.object(generate, 'check_version') as check:
            binary = generate.prepare_binary(None, output, download=True)
            self.assertEqual(binary.parent, self.root / '.sb-generator-core')
            self.assertEqual(generate.prepare_binary(None, output, download=True), binary)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(check.call_count, 2)

    def test_wizard_cancellation_and_invalid_protocols(self):
        with patch('builtins.input', side_effect=EOFError), patch('sys.stdout', new_callable=io.StringIO), patch('sys.stderr', new_callable=io.StringIO):
            self.assertEqual(generate.main([]), 130)
        for value in ('0', '1,1', 'vless,unknown'):
            with self.assertRaises(generate.ConfigError):
                generate.selected_protocols(value)
        self.assertEqual(generate.selected_protocols('1,3'), ['vless', 'hysteria2'])

    @unittest.skipUnless(os.environ.get('SB_TEST_CORE'), 'set SB_TEST_CORE for real sing-box validation')
    def test_real_core_accepts_all_five_wizard_protocols(self):
        output = self.root / 'server.json'
        with patch('builtins.input', side_effect=[''] * 7), patch('sys.stdout', new_callable=io.StringIO):
            generate.wizard(output, Path(os.environ['SB_TEST_CORE']))
        config = json.loads(output.read_text())
        self.assertEqual(len(config['inbounds']), 5)


if __name__ == '__main__':
    unittest.main()
