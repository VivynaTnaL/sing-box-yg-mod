"""Rule updates publish active client nodes while preserving pending deployments."""
import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import addon
from chain import ConfigError
import geodata
import policy
import profiles
import publish
import updates


def snapshot(path, number):
    path.mkdir()
    rules = {'geosite-cn.json': {'version': 2, 'rules': [{'domain_suffix': ['rules%d.cn' % number]}]},
             'geoip-cn.json': {'version': 2, 'rules': [{'ip_cidr': ['1.0.%d.0/24' % number]}]}}
    files = {}
    for name, data in rules.items():
        raw = (json.dumps(data) + '\n').encode()
        (path / name).write_bytes(raw)
        files[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'entries': 1}
    (path / 'manifest.json').write_text(json.dumps({'version': 1, 'files': files}))
    return path


def state_for(binary='/fixture/core'):
    inbound = {'type': 'vmess', 'tag': 'addon-1', 'listen': '0.0.0.0', 'listen_port': 21000,
               'users': [{'uuid': '11111111-1111-4111-8111-111111111111'}],
               'transport': {'type': 'ws', 'path': '/chain'}}
    node = profiles.client(inbound, inbound['users'][0], '192.0.2.10', 'A-to-B-vmess')
    imported = [{'source_tag': 'source', 'inbound': inbound, 'clients': [node]}]
    _, handoff = profiles.exit_config('192.0.2.20', 22000, ['192.0.2.10'])
    return {'schema_version': 1, 'role': 'entry', 'binary': binary,
            'public_host': '192.0.2.10', 'profiles': imported,
            'server_config': profiles.entry_config(imported, handoff['outbounds'][0]),
            'groups': {'A-to-B': [node]}, 'policy': policy.load_policy(), 'rules_source': 'github'}


class UpdatesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='chain-update-unit-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = addon.Store(self.root / 'state')
        self.store.root.mkdir()
        self.store.save(state_for())
        self.snapshots = {n: snapshot(self.root / ('snapshot-%d' % n), n) for n in (1, 2)}
        self.publisher = publish.Publisher(self.root / 'publication')
        self.check = patch('addon.check_config').start()
        self.fetch = patch('geodata.update', return_value=self.metadata(1)).start()
        self.runtime = patch('runtime.Runtime', side_effect=AssertionError('rules must not manage services')).start()
        self.addCleanup(patch.stopall)
        self.stdout = redirect_stdout(io.StringIO())
        self.stderr = redirect_stderr(io.StringIO())
        self.stdout.__enter__()
        self.stderr.__enter__()
        self.addCleanup(self.stdout.__exit__, None, None, None)
        self.addCleanup(self.stderr.__exit__, None, None, None)

    def metadata(self, number, changed=True):
        return {'snapshot': str(self.snapshots[number]), 'version': 'latest@%d' % number,
                'changed': changed, 'repository': geodata.REPOSITORY_URL, 'sources': {},
                'fetched_at': '2026-09-15T00:00:00+00:00'}

    def deployed_with_pending(self):
        active_state = updates.with_snapshot(self.store.read(), self.snapshots[1], 'github', self.metadata(1))
        active_state['policy']['direct_domains'] = ['active-direct.example']
        active_state['policy']['proxy_domains'] = ['active-proxy.example']
        active_state['policy']['direct_cidrs'] = ['192.0.2.1/32']
        active_state['policy']['proxy_cidrs'] = ['192.0.2.2/32']
        release = addon.build(self.store, active_state)
        active = {'release': str(release), 'state': active_state}
        self.store.save(active, 'active.json')
        self.store.save({'root': str(self.publisher.root), 'base_url': 'https://sub.example'}, 'publication.json')
        self.publisher.publish(release)
        pending = copy.deepcopy(active_state)
        pending['server_config']['inbounds'][0]['listen_port'] = 31000
        pending['server_config']['inbounds'][0]['users'][0]['uuid'] = '22222222-2222-4222-8222-222222222222'
        pending['profiles'][0]['inbound']['listen_port'] = 31000
        pending['profiles'][0]['inbound']['users'][0]['uuid'] = '22222222-2222-4222-8222-222222222222'
        pending['groups']['A-to-B'][0]['outbound'].update(
            server_port=31000, uuid='22222222-2222-4222-8222-222222222222')
        pending['profiles'][0]['clients'] = copy.deepcopy(pending['groups']['A-to-B'])
        pending['policy']['direct_domains'] = ['pending-direct.example']
        pending['policy']['proxy_domains'] = ['pending-proxy.example']
        pending['policy']['direct_cidrs'] = ['198.51.100.1/32']
        pending['policy']['proxy_cidrs'] = ['198.51.100.2/32']
        self.store.save(pending)
        self.fetch.reset_mock()
        return active, pending

    def published(self):
        token = self.publisher.state()['token']
        return {name: self.publisher.response('/' + token + '/' + name)[0] for name in publish.FILES}

    def baseline(self):
        return {'state': (self.store.root / 'state.json').read_bytes(),
                'active': (self.store.root / 'active.json').read_bytes(),
                'publication': self.publisher.state(), 'payloads': self.published()}

    def assert_preserved(self, baseline):
        self.assertEqual((self.store.root / 'state.json').read_bytes(), baseline['state'])
        self.assertEqual((self.store.root / 'active.json').read_bytes(), baseline['active'])
        self.assertEqual(self.publisher.state(), baseline['publication'])
        self.assertEqual(self.published(), baseline['payloads'])
        self.runtime.assert_not_called()

    def assert_same_nodes(self, expected, actual):
        for field in ('server_config', 'groups', 'profiles', 'public_host', 'binary'):
            self.assertEqual(expected[field], actual[field], field)

    def test_first_cn_build_fetches_and_persists_inline_rules_then_builds_offline(self):
        addon.build(self.store)
        self.fetch.assert_called_once_with('/fixture/core', self.store.root / 'geodata')
        saved = self.store.read()
        self.assertEqual(saved['policy']['source'], 'inline')
        self.assertEqual(saved['rules_source'], 'github')
        self.assertEqual(saved['geodata']['version'], 'latest@1')
        self.fetch.reset_mock()
        self.fetch.side_effect = AssertionError('offline build must reuse the snapshot')
        release = addon.build(self.store)
        exported = (release / 'mihomo.yaml').read_text()
        self.assertIn('+.rules1.cn', exported)
        self.assertNotIn('raw.githubusercontent', exported)
        self.fetch.assert_not_called()
        self.runtime.assert_not_called()

    def test_first_build_download_failure_keeps_unmaterialized_state(self):
        previous = (self.store.root / 'state.json').read_bytes()
        self.fetch.side_effect = ConfigError('download failed')
        with self.assertRaisesRegex(ConfigError, 'download failed'):
            addon.build(self.store)
        self.assertEqual((self.store.root / 'state.json').read_bytes(), previous)
        self.assertIsNone(self.store.read('active.json', optional=True))
        self.assertFalse((self.store.root / 'releases').exists())

    def test_first_build_core_failure_does_not_persist_downloaded_policy(self):
        previous = (self.store.root / 'state.json').read_bytes()
        self.check.side_effect = ConfigError('invalid config')
        with self.assertRaisesRegex(ConfigError, 'invalid config'):
            addon.build(self.store)
        self.assertEqual((self.store.root / 'state.json').read_bytes(), previous)

    def test_non_cn_and_exit_without_clients_skip_automatic_github_download(self):
        for mode in ('global', 'lan-direct'):
            state = state_for()
            state['policy'] = policy.load_policy(mode)
            addon.build(self.store, state)
        state = state_for()
        state['role'] = 'exit'
        state['groups'] = {}
        addon.build(self.store, state)
        self.fetch.assert_not_called()

    def test_update_preserves_pending_nodes_and_each_states_rule_exceptions(self):
        active, pending = self.deployed_with_pending()
        previous = self.baseline()
        self.fetch.return_value = self.metadata(2)
        updates.update_rules(self.store)
        saved, deployed = self.store.read(), self.store.read('active.json')
        self.assert_same_nodes(pending, saved)
        self.assert_same_nodes(active['state'], deployed['state'])
        for before, after in ((pending, saved), (active['state'], deployed['state'])):
            for field in ('direct_domains', 'proxy_domains', 'direct_cidrs', 'proxy_cidrs', 'mode'):
                self.assertEqual(before['policy'][field], after['policy'][field])
            self.assertEqual(after['geodata']['version'], 'latest@2')
            self.assertEqual(after['policy']['sets']['cn-domain'], [{'domain_suffix': ['rules2.cn']}])
        self.assertEqual(previous['payloads']['nodes.txt'], self.published()['nodes.txt'])
        self.assertEqual(previous['publication']['token'], self.publisher.state()['token'])
        self.assertNotEqual(previous['publication']['generation'], self.publisher.state()['generation'])
        mihomo = self.published()['mihomo.yaml'].decode()
        self.assertIn('active-direct.example', mihomo)
        self.assertNotIn('pending-direct.example', mihomo)
        self.assertIn('+.rules2.cn', mihomo)
        self.runtime.assert_not_called()

    def test_download_or_conversion_failure_keeps_state_active_and_publication(self):
        self.deployed_with_pending()
        previous = self.baseline()
        for problem in ('HTTP 403 limited', 'SHA-256 mismatch', 'geodata conversion failed'):
            with self.subTest(problem=problem):
                self.fetch.side_effect = ConfigError(problem)
                with self.assertRaises(ConfigError):
                    updates.update_rules(self.store)
                self.assert_preserved(previous)

    def test_client_build_failure_keeps_all_metadata_and_published_files(self):
        self.deployed_with_pending()
        previous = self.baseline()
        self.fetch.return_value = self.metadata(2)
        self.check.side_effect = ConfigError('invalid new client')
        with self.assertRaisesRegex(ConfigError, 'invalid new client'):
            updates.update_rules(self.store)
        self.assert_preserved(previous)

    def test_publish_failure_after_manifest_switch_rolls_back_manifest_and_states(self):
        self.deployed_with_pending()
        previous = self.baseline()
        self.fetch.return_value = self.metadata(2)
        original = publish.Publisher.publish

        def late_failure(publisher, release, token=None):
            original(publisher, release, token)
            raise OSError('late publication failure')

        with patch.object(publish.Publisher, 'publish', new=late_failure):
            with self.assertRaisesRegex(OSError, 'late publication failure'):
                updates.update_rules(self.store)
        self.assert_preserved(previous)

    def test_failed_active_save_restores_desired_state_and_publication_manifest(self):
        self.deployed_with_pending()
        previous = self.baseline()
        self.fetch.return_value = self.metadata(2)
        original = self.store.save

        def save(data, name='state.json'):
            if name == 'active.json':
                raise OSError('active metadata full')
            return original(data, name)

        with patch.object(self.store, 'save', side_effect=save):
            with self.assertRaisesRegex(OSError, 'active metadata full'):
                updates.update_rules(self.store)
        self.assert_preserved(previous)

    def test_unchanged_rules_do_not_build_or_republish_even_with_pending_changes(self):
        active, pending = self.deployed_with_pending()
        previous = self.baseline()
        self.fetch.return_value = self.metadata(1, changed=False)
        with (patch('addon.build', side_effect=AssertionError('unchanged rules must not rebuild')),
              patch.object(publish.Publisher, 'publish', side_effect=AssertionError('unchanged rules must not publish'))):
            updates.update_rules(self.store)
        self.assertEqual(self.publisher.state(), previous['publication'])
        self.assertEqual(self.published(), previous['payloads'])
        self.assertEqual(self.store.read('active.json')['release'], active['release'])
        self.assert_same_nodes(pending, self.store.read())

    def test_refresh_clients_applies_desired_rules_only_to_active_nodes(self):
        active, pending = self.deployed_with_pending()
        previous = self.baseline()
        pending['policy']['mode'] = 'global'
        self.store.save(pending)
        release = updates.refresh_clients(self.store)
        deployed = self.store.read('active.json')
        self.assertEqual(deployed['state']['policy'], pending['policy'])
        self.assert_same_nodes(active['state'], deployed['state'])
        self.assert_same_nodes(pending, self.store.read())
        self.assertEqual(str(release), deployed['release'])
        self.assertEqual(self.published()['nodes.txt'], previous['payloads']['nodes.txt'])
        self.assertIn('pending-direct.example', self.published()['mihomo.yaml'].decode())
        self.assertNotIn('active-direct.example', self.published()['mihomo.yaml'].decode())
        self.fetch.assert_not_called()
        self.runtime.assert_not_called()

    def test_refresh_clients_late_state_failure_restores_all_published_state(self):
        self.deployed_with_pending()
        previous = self.baseline()
        original = self.store.save

        def save(data, name='state.json'):
            if name == 'active.json':
                raise OSError('active metadata full')
            return original(data, name)

        with patch.object(self.store, 'save', side_effect=save):
            with self.assertRaisesRegex(OSError, 'active metadata full'):
                updates.refresh_clients(self.store)
        self.assert_preserved(previous)

    def test_update_without_deployment_saves_rules_without_creating_active_or_publication(self):
        self.fetch.return_value = self.metadata(2)
        with patch('addon.build', side_effect=AssertionError('no active nodes to export')):
            updates.update_rules(self.store)
        self.assertEqual(self.store.read()['geodata']['version'], 'latest@2')
        self.assertIsNone(self.store.read('active.json', optional=True))
        self.assertFalse(self.publisher.root.exists())

    def test_refresh_without_deployment_materializes_policy_without_deploying(self):
        self.assertIsNone(updates.refresh_clients(self.store))
        self.assertEqual(self.store.read()['policy']['source'], 'inline')
        self.assertIsNone(self.store.read('active.json', optional=True))
        self.assertFalse(self.publisher.root.exists())

    def test_cache_cleanup_runs_after_commit_and_failure_keeps_new_subscription(self):
        self.deployed_with_pending()
        old_manifest = self.publisher.state()
        self.fetch.return_value = self.metadata(2)
        def fail_cleanup(cache, **kwargs):
            self.assertEqual(self.store.read()['geodata']['version'], 'latest@2')
            self.assertEqual(self.store.read('active.json')['state']['geodata']['version'], 'latest@2')
            self.assertNotEqual(self.publisher.state()['generation'], old_manifest['generation'])
            self.assertIn(str(self.snapshots[2]), kwargs['protected'])
            raise ConfigError('cleanup unavailable')
        with patch('geodata.prune', side_effect=fail_cleanup) as cleanup:
            updates.update_rules(self.store)
        cleanup.assert_called_once()
        self.assertEqual(self.store.read()['geodata']['version'], 'latest@2')
        self.assertEqual(self.publisher.state()['token'], old_manifest['token'])

    def test_partial_local_database_arguments_fail_before_any_update(self):
        for kwargs in ({'geoip': '/geoip.db'}, {'geosite': '/geosite.db'}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ConfigError, '同时指定'):
                updates.update_rules(self.store, **kwargs)
        self.fetch.assert_not_called()

    def test_scheduled_update_skips_local_source_and_empty_groups(self):
        for local, groups in ((True, True), (False, False)):
            state = self.store.read()
            state['rules_source'] = 'local' if local else 'github'
            if not groups:
                state['groups'] = {}
            self.store.save(state)
            previous = (self.store.root / 'state.json').read_bytes()
            self.assertIsNone(updates.update_rules(self.store, scheduled=True))
            self.assertEqual((self.store.root / 'state.json').read_bytes(), previous)
        self.fetch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
