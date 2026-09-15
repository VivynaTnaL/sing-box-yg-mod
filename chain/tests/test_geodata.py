import fcntl
import hashlib
import http.client
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from chain import ConfigError
import geodata
import policy


PAYLOADS = {'geoip.db': b'ip database', 'geosite.db': b'domain database'}


def release(number=123):
    return {'id': number, 'tag_name': 'latest', 'published_at': '2026-09-15T00:47:28Z',
            'assets': [{'name': name, 'id': number * 100 + n, 'size': len(data),
                        'digest': 'sha256:' + hashlib.sha256(data).hexdigest(),
                        'browser_download_url': 'https://github.com/untrusted/mutable/latest/' + name}
                       for n, (name, data) in enumerate(PAYLOADS.items())]}


class Response(io.BytesIO):
    def __init__(self, data, url, *, size=None, status=200):
        super().__init__(data)
        self.headers = {'Content-Length': str(len(data) if size is None else size)}
        self.url, self.status = url, status

    def geturl(self):
        return self.url


class GitHub:
    def __init__(self, data=None):
        self.release = data or release()
        self.calls = []
        self.failed_asset = None
        self.payloads = dict(PAYLOADS)
        self.http_error = None
        self.declared_size = None

    def __call__(self, request, timeout):
        self.calls.append(request)
        if self.http_error:
            raise urllib.error.HTTPError(request.full_url, self.http_error, 'failure', {}, None)
        if request.full_url == geodata.RELEASE_URL:
            return Response(json.dumps(self.release).encode(), request.full_url)
        for asset in self.release['assets']:
            if request.full_url == geodata.API_ROOT + '/releases/assets/' + str(asset['id']):
                if asset['name'] == self.failed_asset:
                    raise urllib.error.URLError('download interrupted')
                return Response(self.payloads[asset['name']], request.full_url, size=self.declared_size)
        raise AssertionError('download must use pinned official API URL: ' + request.full_url)


def core(command, **kwargs):
    if command[1] == 'version':
        return subprocess.CompletedProcess(command, 0, 'sing-box version 1.14.0\n', '')
    data = ({'version': 2, 'rules': [{'ip_cidr': ['1.0.1.0/24', '240e::/20']}]} if command[1] == 'geoip'
            else {'version': 2, 'rules': [{'domain': ['example.cn'], 'domain_suffix': ['.example.cn']}]})
    Path(command[command.index('-o') + 1]).write_text(json.dumps(data))
    return subprocess.CompletedProcess(command, 0, '', '')


class GeodataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / 'cache'
        self.github = GitHub()
        self.core = mock.patch.object(policy.subprocess, 'run', side_effect=core).start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(self.temporary.cleanup)

    def update(self, **kwargs):
        return geodata.update('/core', self.root, opener=self.github, **kwargs)

    def files(self, path):
        return {str(p.relative_to(path)): p.read_bytes() for p in path.rglob('*') if p.is_file()}

    def assert_previous_survives(self, result, before):
        self.assertEqual(geodata.current(self.root)['snapshot'], result['snapshot'])
        self.assertEqual(self.files(Path(result['snapshot']).parent), before)
        self.assertFalse(any(self.root.glob('.download-*')))

    def test_success_pins_assets_and_records_verified_provenance(self):
        result = self.update()
        self.assertTrue(result['changed'])
        self.assertEqual(result['version'], 'latest@123')
        snapshot = Path(result['snapshot'])
        self.assertTrue(snapshot.is_absolute())
        self.assertEqual(policy.load_policy(rules_dir=snapshot)['source'], 'inline')
        self.assertEqual(result['repository'], geodata.REPOSITORY_URL)
        self.assertEqual(result['sources']['geoip.db']['sha256'], hashlib.sha256(PAYLOADS['geoip.db']).hexdigest())
        self.assertIn('+00:00', result['fetched_at'])
        metadata = json.loads((snapshot.parent / 'metadata.json').read_text())
        self.assertIn('GitHub release asset SHA-256', metadata['verification'])
        self.assertEqual(len(self.github.calls), 3)
        for request in self.github.calls:
            self.assertNotIn('Authorization', request.headers)
            self.assertNotIn('untrusted', request.full_url)
        self.assertEqual(self.github.calls[1].get_header('Accept'), 'application/octet-stream')
        for path in snapshot.parent.rglob('*'):
            if path.is_file():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_same_version_reuses_immutable_snapshot_without_conversion(self):
        first = self.update()
        before = self.files(Path(first['snapshot']).parent)
        self.github.calls.clear()
        self.core.reset_mock()
        second = self.update()
        self.assertFalse(second['changed'])
        self.assertEqual(first['snapshot'], second['snapshot'])
        self.assertEqual(len(self.github.calls), 1)
        self.core.assert_not_called()
        self.assert_previous_survives(first, before)

    def test_force_creates_new_generation_and_keeps_previous_files(self):
        first = self.update()
        before = self.files(Path(first['snapshot']).parent)
        second = self.update(force=True)
        self.assertTrue(second['changed'])
        self.assertNotEqual(first['snapshot'], second['snapshot'])
        self.assertEqual(self.files(Path(first['snapshot']).parent), before)
        self.assertEqual(len(list((self.root / 'releases').iterdir())), 2)

    def test_second_database_failure_preserves_previous_generation(self):
        first = self.update()
        before = self.files(Path(first['snapshot']).parent)
        self.github.release = release(124)
        self.github.failed_asset = 'geosite.db'
        with self.assertRaisesRegex(ConfigError, 'HTTPS'):
            self.update()
        self.assert_previous_survives(first, before)
        self.github.failed_asset = None
        self.assertTrue(self.update()['changed'])

    def test_truncated_download_does_not_publish(self):
        self.github.payloads['geosite.db'] = b'domain'
        with self.assertRaisesRegex(ConfigError, '大小|完整'):
            self.update()
        self.assertIsNone(geodata.current(self.root))
        self.assertFalse(list((self.root / 'releases').iterdir()))
        self.assertFalse(any(self.root.glob('.download-*')))

    def test_hash_mismatch_preserves_previous_generation(self):
        first = self.update()
        before = self.files(Path(first['snapshot']).parent)
        self.github.release = release(124)
        self.github.payloads['geoip.db'] = b'XX database'
        with self.assertRaisesRegex(ConfigError, 'SHA-256'):
            self.update()
        self.assert_previous_survives(first, before)

    def test_missing_one_database_fails_before_any_asset_download(self):
        self.github.release['assets'].pop()
        with self.assertRaisesRegex(ConfigError, '同时提供'):
            self.update()
        self.assertEqual(len(self.github.calls), 1)
        self.assertIsNone(geodata.current(self.root))

    def test_no_digest_cannot_silently_skip_verification(self):
        self.github.release['assets'][0]['digest'] = None
        with self.assertRaisesRegex(ConfigError, '缺少 SHA-256'):
            self.update()
        self.assertEqual(len(self.github.calls), 1)

    def test_rate_limit_is_actionable_and_keeps_cache(self):
        first = self.update()
        before = self.files(Path(first['snapshot']).parent)
        for code in (403, 429):
            with self.subTest(code=code):
                self.github.http_error = code
                with self.assertRaisesRegex(ConfigError, '限流.*%s' % code):
                    self.update()
                self.assert_previous_survives(first, before)

    def test_conversion_failure_keeps_both_previous_databases_and_rules(self):
        first = self.update()
        before = self.files(Path(first['snapshot']).parent)
        self.github.release = release(124)
        self.core.side_effect = [subprocess.CompletedProcess([], 0, 'sing-box version 1.14.0\n', ''),
                                 subprocess.CompletedProcess([], 1, '', 'failed conversion')]
        with self.assertRaisesRegex(ConfigError, '转换失败'):
            self.update()
        self.assert_previous_survives(first, before)

    def test_corrupt_cache_is_replaced_by_new_generation_without_overwriting(self):
        first = self.update()
        source = Path(first['snapshot']).parent / 'geoip.db'
        source.write_bytes(b'corrupted')
        with self.assertRaises(ConfigError):
            geodata.current(self.root)
        second = self.update()
        self.assertTrue(second['changed'])
        self.assertNotEqual(first['snapshot'], second['snapshot'])
        self.assertEqual(source.read_bytes(), b'corrupted')

    def test_same_mutable_tag_with_new_asset_ids_gets_new_generation(self):
        first = self.update()
        self.github.release = release(124)
        second = self.update()
        self.assertEqual(second['version'], 'latest@124')
        self.assertNotEqual(first['snapshot'], second['snapshot'])

    def test_asset_and_download_size_limit(self):
        self.github.release['assets'][0]['size'] = geodata.MAX_DATABASE_BYTES + 1
        with self.assertRaisesRegex(ConfigError, '大小限制'):
            self.update()
        self.github.release = release()
        self.github.declared_size = geodata.MAX_DATABASE_BYTES + 1
        with self.assertRaisesRegex(ConfigError, '大小限制'):
            self.update()

    def test_partial_http_status_and_insecure_redirect_are_rejected(self):
        for url, status in [('http://github.com/file', 200), ('https://github.com/file', 206)]:
            with self.subTest(url=url, status=status):
                opener = lambda req, timeout: Response(b'partial', url, status=status)
                with self.assertRaises(ConfigError):
                    geodata.update('/core', self.root, opener=opener)

    def test_cached_snapshot_tampering_is_detected(self):
        result = self.update()
        (Path(result['snapshot']) / 'geoip-cn.json').write_text('{}')
        with self.assertRaisesRegex(ConfigError, '校验失败'):
            geodata.current(self.root)

    def test_cache_pointer_cannot_escape_cache(self):
        self.root.mkdir()
        (self.root / 'current.json').write_text(json.dumps({'generation': '../../outside'}))
        with self.assertRaisesRegex(ConfigError, '索引无效'):
            geodata.current(self.root)

    def test_symlink_cache_is_rejected(self):
        target = Path(self.temporary.name) / 'elsewhere'
        target.mkdir()
        self.root.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ConfigError, '符号链接'):
            self.update()
        self.assertFalse(list(target.iterdir()))

    def test_concurrent_update_fails_without_network_or_modification(self):
        self.root.mkdir()
        with (self.root / '.update.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ConfigError, '更新正在进行'):
                self.update()
        self.assertFalse(self.github.calls)
        self.assertIsNone(geodata.current(self.root))

    def test_interrupted_http_body_is_reported_as_retryable(self):
        response = Response(b'', geodata.RELEASE_URL)
        response.read = mock.Mock(side_effect=http.client.IncompleteRead(b'half'))
        response.headers = {}
        with self.assertRaisesRegex(ConfigError, '重试'):
            geodata.update('/core', self.root, opener=lambda *_a, **_kw: response)

    def test_failed_pointer_write_preserves_last_good_snapshot(self):
        first = self.update()
        before = self.files(Path(first['snapshot']).parent)
        self.github.release = release(124)
        original_write = geodata.write_private

        def write(path, data):
            if Path(path).name == 'current.json':
                raise OSError('disk full')
            return original_write(path, data)

        with mock.patch.object(geodata, 'write_private', side_effect=write):
            with self.assertRaises(ConfigError):
                self.update()
        self.assert_previous_survives(first, before)

    def test_default_https_context_verifies_certificates(self):
        opener = geodata._open_default()
        https_handler = next(h for h in opener.__self__.handlers
                             if isinstance(h, geodata.urllib.request.HTTPSHandler))
        self.assertTrue(https_handler._context.check_hostname)
        self.assertEqual(https_handler._context.verify_mode, geodata.ssl.CERT_REQUIRED)

    def test_default_redirect_handler_refuses_https_downgrade(self):
        req = geodata.urllib.request.Request(geodata.RELEASE_URL)
        with self.assertRaisesRegex(ConfigError, 'HTTPS'):
            geodata._HTTPSRedirect().redirect_request(req, None, 302, 'Found', {}, 'http://github.com/asset')

    def generations(self, count):
        results = []
        for number in range(count):
            self.github.release = release(123 + number)
            results.append(self.update())
        return results

    def test_prune_keeps_latest_three_and_does_not_change_current(self):
        generations = self.generations(5)
        latest = generations[-1]
        before = self.files(Path(latest['snapshot']).parent)
        pointer = (self.root / 'current.json').read_bytes()
        removed = geodata.prune(self.root)
        self.assertEqual(set(removed), {str(Path(r['snapshot']).parent) for r in generations[:2]})
        self.assertEqual((self.root / 'current.json').read_bytes(), pointer)
        self.assert_previous_survives(latest, before)
        for result in generations[2:]:
            self.assertTrue(Path(result['snapshot']).is_dir())

    def test_prune_protects_pending_and_active_snapshots_outside_retention_window(self):
        generations = self.generations(6)
        protected = [generations[0]['snapshot'], generations[1]['snapshot']]
        before = {path: self.files(Path(path).parent) for path in protected}
        removed = geodata.prune(self.root, keep=2, protected=protected)
        self.assertEqual(set(removed), {str(Path(r['snapshot']).parent) for r in generations[2:4]})
        for path in protected:
            self.assertEqual(self.files(Path(path).parent), before[path])
        self.assertTrue(Path(generations[-1]['snapshot']).is_dir())

    def test_prune_preserves_current_even_when_it_is_the_oldest_generation(self):
        generations = self.generations(4)
        first = Path(generations[0]['snapshot']).parent
        metadata = json.loads((first / 'metadata.json').read_text())
        (self.root / 'current.json').write_text(json.dumps(
            {'format': 1, 'generation': first.name, 'identity': metadata['identity']}))
        removed = geodata.prune(self.root, keep=1)
        self.assertEqual(set(removed), {str(Path(r['snapshot']).parent) for r in generations[1:3]})
        self.assertEqual(geodata.current(self.root)['snapshot'], generations[0]['snapshot'])

    def test_prune_skips_unknown_contents_corruption_and_symlinked_generations(self):
        generations = self.generations(5)
        paths = [Path(result['snapshot']).parent for result in generations]
        (paths[0] / 'user-note.txt').write_text('retain user data')
        (paths[1] / 'geoip.db').write_bytes(b'corrupted old database')
        outside = Path(self.temporary.name) / 'outside'
        outside.mkdir()
        (outside / 'retain.txt').write_text('not a cache generation')
        linked = self.root / 'releases' / 'r999-aaaaaaaaaaaaaaaa-bbbbbbbb'
        linked.symlink_to(outside, target_is_directory=True)
        raw = paths[2] / 'snapshot' / 'geoip-cn.json'
        raw.unlink()
        raw.symlink_to(outside / 'retain.txt')
        unknown = self.root / 'releases' / 'unrelated-directory'
        unknown.mkdir()
        before = (outside / 'retain.txt').read_bytes()
        removed = geodata.prune(self.root, keep=0)
        self.assertEqual(removed, [str(paths[3])])
        for path in paths[:3] + [paths[-1], unknown]:
            self.assertTrue(path.is_dir())
        self.assertTrue(linked.is_symlink())
        self.assertTrue(raw.is_symlink())
        self.assertEqual((outside / 'retain.txt').read_bytes(), before)

    def test_prune_rejects_symlink_root_and_protected_paths_before_deletion(self):
        generations = self.generations(3)
        alias = Path(self.temporary.name) / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ConfigError, '符号链接'):
            geodata.prune(alias, keep=0)
        snapshot_alias = Path(self.temporary.name) / 'snapshot-alias'
        snapshot_alias.symlink_to(generations[0]['snapshot'], target_is_directory=True)
        with self.assertRaisesRegex(ConfigError, '符号链接'):
            geodata.prune(self.root, keep=0, protected=[snapshot_alias])
        self.assertTrue(all(Path(r['snapshot']).is_dir() for r in generations))

    def test_prune_refuses_corrupt_current_index_without_deleting_any_generation(self):
        generations = self.generations(3)
        (self.root / 'current.json').write_text('{}')
        with self.assertRaises(ConfigError):
            geodata.prune(self.root, keep=0)
        self.assertTrue(all(Path(r['snapshot']).is_dir() for r in generations))

    def test_prune_deletion_failure_does_not_fail_update_or_change_current(self):
        generations = self.generations(3)
        current = generations[-1]
        before = self.files(Path(current['snapshot']).parent)

        def failure(path):
            raise PermissionError('cleanup denied')

        failure.avoids_symlink_attacks = True
        with mock.patch.object(geodata.shutil, 'rmtree', new=failure):
            self.assertEqual(geodata.prune(self.root, keep=0), [])
        self.assertTrue(all(Path(r['snapshot']).is_dir() for r in generations))
        self.assert_previous_survives(current, before)

    def test_prune_uses_same_lock_as_update(self):
        generations = self.generations(3)
        with (self.root / '.update.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ConfigError, '更新正在进行'):
                geodata.prune(self.root, keep=0)
        self.assertTrue(all(Path(r['snapshot']).is_dir() for r in generations))

    def test_prune_empty_cache_creates_nothing_and_validates_keep(self):
        self.assertEqual(geodata.prune(self.root), [])
        self.assertFalse(self.root.exists())
        for keep in (-1, True, 1.5, '3'):
            with self.subTest(keep=keep), self.assertRaises(ConfigError):
                geodata.prune(self.root, keep=keep)


if __name__ == '__main__':
    unittest.main()
