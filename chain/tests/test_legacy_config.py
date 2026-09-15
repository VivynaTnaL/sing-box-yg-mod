"""Exercise extracted legacy templates and installation handoff in /tmp only."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / 'sb.sh').read_text()


def function(name):
    start = SOURCE.index(name + '(){')
    rest = SOURCE[start:]
    next_function = re.search(r'\n[A-Za-z_][A-Za-z_0-9]*\(\)\{', rest)
    return rest[:next_function.start()] if next_function else rest


class LegacyConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / 'output'
        self.output.mkdir()
        self.values = {
            'port_vl_re': '20001', 'port_vm_ws': '20002', 'port_hy2': '20003',
            'port_tu': '20004', 'port_an': '20005',
            'uuid': '11111111-1111-4111-8111-111111111111',
            'ym_vl_re': 'www.apple.com', 'ym_vm_ws': 'proxy.example.com',
            'private_key': 'A' * 43, 'short_id': '01020304', 'tlsyn': 'true',
            'ipv': 'prefer_ipv4', 'endip': '162.159.192.1',
            'v6': '2606:4700:110:1111::1', 'pvk': 'B' * 43 + '=', 'res': '[1,2,3]',
        }
        for kind in ('vmess_ws', 'hy2', 'tuic', 'an'):
            self.values['certificatec_' + kind] = '/fixture/cert.pem'
            self.values['certificatep_' + kind] = '/fixture/key.pem'

    def render(self, version='1.14.0', values=None):
        return subprocess.run(['bash', '-c', '''
systemctl(){ echo forbidden >&2; return 99; }
rc-service(){ echo forbidden >&2; return 99; }
crontab(){ echo forbidden >&2; return 99; }
curl(){ echo forbidden >&2; return 99; }
wget(){ echo forbidden >&2; return 99; }
source "$1"
sb_render_legacy_config "$2" "$3"
''', 'test', str(ROOT / 'lib/sb-config.sh'), str(self.output), version],
            env={**os.environ, **(self.values if values is None else values)},
            capture_output=True, text=True, timeout=10)

    def test_templates_preserve_original_bytes_and_fixed_line_layout(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        # Captured from pre-extraction inssbjsonser with the fixture values above.
        expected = {
            'sb10.json': 'b4ada4df4ce6b6f2f4e0e44aa762bde242a2a005bbd0d6d334d002648ac0deea',
            'sb11.json': 'cd68b02ee3222e6d092c1fc8c14d39f452256d4a92b399af29a842fc0ad6a403',
        }
        for name, digest in expected.items():
            path = self.output / name
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            lines = path.read_text().splitlines()
            self.assertIn('"listen_port": 20001', lines[13])
            self.assertIn('"server_name": "www.apple.com"', lines[22])
        self.assertEqual((self.output / 'sb.json').read_bytes(), (self.output / 'sb11.json').read_bytes())
        self.assertNotIn('forbidden', result.stderr)
        self.assertEqual(sorted(p.name for p in self.output.iterdir()), ['sb.json', 'sb10.json', 'sb11.json'])

    def test_legacy_core_selects_original_four_protocol_template(self):
        self.assertEqual(self.render('1.10.7').returncode, 0)
        selected = json.loads((self.output / 'sb.json').read_text())
        self.assertEqual(len(selected['inbounds']), 4)
        self.assertEqual((self.output / 'sb.json').read_bytes(), (self.output / 'sb10.json').read_bytes())

    def test_invalid_missing_values_and_existing_files_do_not_publish(self):
        for change in ({'uuid': ''}, {'port_vl_re': 'not-a-port'},
                       {'ym_vl_re': 'example.com", "unexpected": true, "x":"'}):
            result = self.render(values={**self.values, **change})
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(self.output.iterdir()), [])
        existing = self.output / 'sb.json'
        existing.write_text('keep')
        self.assertNotEqual(self.render().returncode, 0)
        self.assertEqual(existing.read_text(), 'keep')
        self.assertEqual(list(self.output.iterdir()), [existing])

    def test_sourcing_templates_performs_no_actions(self):
        result = subprocess.run(['bash', '-x', '-c', 'source "$1"', 'test', str(ROOT / 'lib/sb-config.sh')],
                                cwd=self.output, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertNotIn('mktemp', result.stderr)

    def test_install_checks_generated_config_before_service_or_cron(self):
        core_root = self.root / 'etc-sbox'
        core_root.mkdir()
        calls = self.root / 'calls'
        core = core_root / 'sing-box'
        core.write_text('#!/bin/sh\nexit 1\n')
        core.chmod(0o700)
        for name in ('sb.json', 'sb10.json', 'sb11.json'):
            (core_root / name).write_text('original')
        script = function('sb_deploy_generated').replace('/etc/s-box', str(core_root))
        script += '''
red(){ :; }
sbservice(){ echo service >> "$2"; }
cronsb(){ echo cron >> "$2"; }
sb_deploy_generated "$1"
'''
        result = subprocess.run(['bash', '-c', script, 'test', str(self.output), str(calls)],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(calls.exists())
        for name in ('sb.json', 'sb10.json', 'sb11.json'):
            self.assertEqual((core_root / name).read_text(), 'original')

    def test_install_stage_order_and_generator_failure_never_deploys(self):
        calls = self.root / 'calls'
        script = function('instsllsingbox').replace('/etc/s-box', str(self.output)).replace(
            '/etc/systemd/system/sing-box.service', str(self.root / 'absent.service'))
        script += '''
log="$1"
red(){ :; }
sb_prepare_legacy_install(){ echo prepare >> "$log"; }
inssbjsonser(){ echo generate >> "$log"; return 1; }
sb_deploy_generated(){ echo deploy >> "$log"; }
instsllsingbox
'''
        result = subprocess.run(['bash', '-c', script, 'test', str(calls)],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls.read_text().splitlines(), ['prepare', 'generate'])
        self.assertEqual(list(self.output.iterdir()), [])

    def test_local_shortcut_installs_companions_and_works_without_repository(self):
        binary_dir, library_dir = self.root / 'bin', self.root / 'library'
        binary_dir.mkdir()
        library_dir.mkdir()
        def isolate(text):
            return text.replace('/usr/bin', str(binary_dir)).replace('/usr/local/lib', str(library_dir))
        package = self.root / 'source'
        package.mkdir()
        (package / 'chain').mkdir()
        (package / 'lib').mkdir()
        for path in (ROOT / 'chain').glob('*.py'):
            shutil.copyfile(path, package / 'chain' / path.name)
        shutil.copyfile(ROOT / 'chain/core.lock.json', package / 'chain/core.lock.json')
        for name in ('sb-config.sh', 'sb-install.sh'):
            (package / 'lib' / name).write_text(isolate((ROOT / 'lib' / name).read_text()))
        source = package / 'sb.sh'
        # The target tree is entirely in /tmp, so model root for an unprivileged
        # test runner without adding a production bypass to the installer.
        source.write_text(isolate(SOURCE).replace('[[ $EUID == 0 ]]', '[[ 0 == 0 ]]', 1))
        forbidden = self.root / 'forbidden-action'
        for command in ('systemctl', 'rc-service', 'crontab', 'curl', 'wget', 'apt', 'yum'):
            path = binary_dir / command
            path.write_text('#!/bin/sh\ntouch "' + str(forbidden) + '"\nexit 99\n')
            path.chmod(0o700)
        env = {**os.environ, 'PATH': str(binary_dir) + ':' + os.environ['PATH']}
        result = subprocess.run(['bash', str(source), '--install-shortcut'], env=env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(forbidden.exists())
        shutil.rmtree(package)
        installed = binary_dir / 'sb'
        bundle = library_dir / 'sing-box-yg'
        self.assertTrue((bundle / 'lib/sb-config.sh').is_file())
        self.assertTrue((bundle / 'lib/sb-install.sh').is_file())
        self.assertTrue((bundle / 'chain/fetch-core.py').is_file())
        for argument in ('--help', '--example'):
            result = subprocess.run(['bash', str(installed), '--generate-config', argument],
                                    cwd=self.root, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
        example = json.loads(result.stdout)
        self.assertEqual(len(example['protocols']), 5)

    def test_standalone_download_without_modules_fails_before_legacy_setup(self):
        script = self.root / 'sb.sh'
        script.write_text(SOURCE.replace('/usr/local/lib/sing-box-yg', str(self.root / 'absent-modules')))
        for args in ([], ['--install-shortcut']):
            result = subprocess.run(['bash', '-x', str(script), *args], cwd=self.root,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn('完整仓库', result.stderr)
            self.assertNotIn('export LANG', result.stderr)
            self.assertNotIn('apt', result.stderr)
            self.assertNotIn('systemctl', result.stderr)

    def test_self_update_only_prints_local_repository_instructions(self):
        result = subprocess.run(['bash', '-c', function('upsbyg') + '''
yellow(){ printf '%s\\n' "$1"; }
curl(){ exit 99; }
wget(){ exit 99; }
upsbyg
'''], cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertIn('Git', result.stdout)
        self.assertIn('自动覆盖脚本已停用', result.stdout)


if __name__ == '__main__':
    unittest.main()
