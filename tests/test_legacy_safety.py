"""Run isolated legacy functions against temporary files; never source the installer."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'sb.sh').read_text()


def function(name):
    start = SOURCE.index(name + '(){')
    rest = SOURCE[start:]
    match = re.search(r'\n[A-Za-z_][A-Za-z_0-9]*\(\)\{', rest)
    return rest[:match.start()] if match else rest


class LegacySafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'sbox'
        self.config.mkdir()
        self.web = self.root / 'web'
        self.web.mkdir()

    def shell(self, functions, body, *args):
        text = '\n'.join(function(name) for name in functions)
        text = text.replace('/etc/s-box', str(self.config)).replace('/root/websbox', str(self.web))
        return subprocess.run(['/bin/bash', '-c', 'red(){ :; }; green(){ :; }; yellow(){ :; };\n' + text + '\n' + body,
                               'test', *map(str, args)], capture_output=True, text=True,
                               env={**os.environ, 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1'})

    def test_path_traversal_never_deletes_outside_web_root(self):
        sentinel = self.root / 'important'
        sentinel.write_text('keep')
        log = self.config / 'subtoken.log'
        for malicious in ('../important', '../../', '/', '..'):
            log.write_text(malicious)
            result = self.shell(['sb_valid_subtoken', 'subtokenipsub'],
                                'readp(){ menu=abcdefghijklmnop; }; subtokenipsub')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(sentinel.read_text(), 'keep')
            self.assertEqual(log.read_text(), malicious)

    def test_subtoken_invalid_new_input_does_not_rotate_old(self):
        log = self.config / 'subtoken.log'
        log.write_text('abcdefghijklmnop')
        result = self.shell(['sb_valid_subtoken', 'subtokenipsub'],
                            'readp(){ menu="../invalid"; }; subtokenipsub')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(log.read_text(), 'abcdefghijklmnop')

    def test_port_rejects_options_and_out_of_range(self):
        for value in ('0', '65536', '-p 22', '80;touch file', 'abc', '999999999999999999'):
            self.assertNotEqual(self.shell(['sb_valid_port'], 'sb_valid_port "$1"', value).returncode, 0)
        for value in ('1', '65535', '0080'):
            self.assertEqual(self.shell(['sb_valid_port'], 'sb_valid_port "$1"', value).returncode, 0)

    def fixture(self, valid=True):
        core = self.config / 'sing-box'
        core.write_text('#!/bin/sh\nexit ' + ('0' if valid else '1') + '\n')
        core.chmod(0o700)
        text = '{\n"inbounds": [{"users": [{"uuid": "11111111-1111-4111-8111-111111111111"}],\n"transport": {"path": "/old"}}]\n}\n'
        for name in ('sb.json', 'sb10.json', 'sb11.json'):
            (self.config / name).write_text(text)
        return text

    def edit(self, mode, old, new):
        return self.shell(['sb_replace_config_string'],
                          'sbfiles="$1/sb.json $1/sb10.json $1/sb11.json"; sb_replace_config_string "$2" "$3" "$4"',
                          self.config, mode, old, new)

    def test_path_is_json_data_not_sed_or_shell_and_lines_preserved(self):
        original = self.fixture()
        value = '/safe/path?ed=2048&x=1'
        result = self.edit('path', '/old', value)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ('sb.json', 'sb10.json', 'sb11.json'):
            path = self.config / name
            self.assertEqual(json.loads(path.read_text())['inbounds'][0]['transport']['path'], value)
            self.assertEqual(path.read_text().count('\n'), original.count('\n'))
            self.assertEqual(Path(str(path) + '.credentials.previous').read_text(), original)
        self.assertFalse(Path('SHOULD_NOT_EXIST').exists())

    def test_unsupported_path_characters_are_rejected(self):
        original = self.fixture()
        for value in ('/a//b', '/a"b', '/$(touch SHOULD_NOT_EXIST)', '/a\\b', '/a\nb'):
            self.assertNotEqual(self.edit('path', '/old', value).returncode, 0)
            self.assertEqual((self.config / 'sb.json').read_text(), original)

    def test_invalid_uuid_or_core_check_keeps_all_files(self):
        original = self.fixture()
        result = self.edit('uuid', '11111111-1111-4111-8111-111111111111', 'x/e;touch BAD')
        self.assertNotEqual(result.returncode, 0)
        self.fixture(valid=False)
        result = self.edit('path', '/old', '/new')
        self.assertNotEqual(result.returncode, 0)
        for name in ('sb.json', 'sb10.json', 'sb11.json'):
            self.assertEqual((self.config / name).read_text(), original)
        self.assertFalse(list(self.config.glob('.credentials-*')))

    def test_json_reader_keeps_double_slashes_inside_strings(self):
        path = self.config / 'sample.json'
        path.write_text('{"url":"https://example.com/a//b", /* comment */ "x":1 // comment\n}')
        result = self.shell(['sb_read_json'], 'sb_read_json "$1"', path)
        self.assertEqual(json.loads(result.stdout)['url'], 'https://example.com/a//b')

    def test_cloudflared_download_failure_does_not_replace_old_file(self):
        core = self.config / 'cloudflared'
        core.write_text('old damaged file')
        result = self.shell(['cloudflaredargo'], 'curl(){ return 22; }; cloudflaredargo')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(core.read_text(), 'old damaged file')
        self.assertFalse(list(self.config.glob('.cloudflared.*')))

    def test_restart_detects_process_crash_without_enabling_service(self):
        self.fixture()
        log = self.root / 'systemctl-calls'
        counter = self.root / 'show-counter'
        result = self.shell(['restartsb'], '''
log="$1"; counter="$2"
sleep(){ :; }
command(){ [[ "$*" == '-v apk' ]] && return 1; builtin command "$@"; }
systemctl(){
 printf '%s\\n' "$*" >> "$log"
 if [[ "$1" == show ]]; then
   if [[ -f "$counter" ]]; then echo 22; else echo 11; touch "$counter"; fi
 fi
 return 0
}
restartsb
''', log, counter)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('enable', log.read_text())

    def test_gitlab_uses_argv_and_propagates_rejection(self):
        (self.config / 'gitlab-branch').write_text('safe-branch')
        (self.config / 'gitlabtoken.txt').write_text('fake-token')
        (self.config / 'git-askpass.sh').write_text('#!/bin/sh\nexit 1\n')
        (self.config / 'git-askpass.sh').chmod(0o700)
        log = self.root / 'git-args'
        result = self.shell(['sb_gitlab_push'], '''
log="$1"
git(){
 printf '%s\\n' "$*" >> "$log"
 [[ "$*" == *" push "* ]] && return 1
 return 0
}
sb_gitlab_push
''', log)
        self.assertNotEqual(result.returncode, 0)
        commands = log.read_text()
        self.assertIn('HEAD:refs/heads/safe-branch', commands)
        self.assertNotIn('push -f', commands)
        self.assertNotIn('fake-token', commands)

    def test_gitlab_branch_injection_rejected_before_commands(self):
        (self.config / 'gitlab-branch').write_text('main;touch BAD')
        result = self.shell(['sb_gitlab_push'], 'git(){ exit 99; }; sb_gitlab_push')
        self.assertEqual(result.returncode, 1)

    def test_real_git_excludes_staged_secrets_and_preserves_remote_on_conflict(self):
        env = {**os.environ, 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1'}
        def git(*args):
            return subprocess.run(['git', *map(str, args)], check=True, capture_output=True, text=True, env=env).stdout.strip()
        remote = self.root / 'remote.git'
        git('init', '--bare', '--initial-branch=main', remote)
        git('init', '--initial-branch=main', self.config)
        git('-C', self.config, 'config', 'user.name', 'Test')
        git('-C', self.config, 'config', 'user.email', 'test@example.invalid')
        git('-C', self.config, 'remote', 'add', 'origin', remote)
        for name in ('sbox.json', 'clmi.yaml', 'jhsub.txt'):
            (self.config / name).write_text('initial')
        (self.config / 'secret.key').write_text('must-not-publish')
        git('-C', self.config, 'add', 'secret.key')
        (self.config / 'gitlab-branch').write_text('main')
        (self.config / 'gitlabtoken.txt').write_text('fake-token')
        (self.config / 'git-askpass.sh').write_text('#!/bin/sh\nexit 1\n')
        (self.config / 'git-askpass.sh').chmod(0o700)
        result = self.shell(['sb_gitlab_push'], 'sb_gitlab_push')
        self.assertEqual(result.returncode, 0, result.stderr)
        files = git('--git-dir', remote, 'ls-tree', '--name-only', 'main')
        self.assertEqual(set(files.splitlines()), {'sbox.json', 'clmi.yaml', 'jhsub.txt'})
        other = self.root / 'other'
        git('clone', remote, other)
        git('-C', other, 'config', 'user.name', 'Test')
        git('-C', other, 'config', 'user.email', 'test@example.invalid')
        (other / 'sbox.json').write_text('remote-change')
        git('-C', other, 'commit', '-am', 'remote change')
        git('-C', other, 'push')
        remote_head = git('--git-dir', remote, 'rev-parse', 'main')
        (self.config / 'sbox.json').write_text('local-conflict')
        result = self.shell(['sb_gitlab_push'], 'sb_gitlab_push')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(git('--git-dir', remote, 'rev-parse', 'main'), remote_head)


if __name__ == '__main__':
    unittest.main()
