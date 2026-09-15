"""Independent client subscriptions and direct-node publication without deployment."""
import base64
import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import addon
from chain import ConfigError, check_config
import export_clash
import policy
import publish
import updates
from test_updates import snapshot, state_for


GROUPS = ('A-direct', 'B-direct', 'A-to-B')
CORE = Path(os.environ.get('CHAIN_TEST_CORE', '/tmp/sing-box-chain-core'))


def add_direct_nodes(state):
    for group, server, port, uuid in (
            ('A-direct', '192.0.2.10', 20001, '33333333-3333-4333-8333-333333333333'),
            ('B-direct', '192.0.2.20', 20002, '44444444-4444-4444-8444-444444444444')):
        node = copy.deepcopy(state['groups']['A-to-B'][0])
        node['outbound'].update(tag=group + '-vmess', server=server, server_port=port, uuid=uuid)
        state['groups'][group] = [node]
    return state


class GroupClientsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='chain-group-clients-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = addon.Store(self.root / 'state')
        self.store.root.mkdir()
        self.snapshot = snapshot(self.root / 'rules', 1)
        self.state = add_direct_nodes(state_for())
        self.state['policy'] = policy.load_policy('cn-direct', self.snapshot,
            direct_domains=['stay-direct.example'], proxy_domains=['stay-proxy.example'])
        self.state['rules_source'] = 'local'
        self.store.save(self.state)
        core_check = patch('addon.check_config')
        self.check = core_check.start()
        self.addCleanup(core_check.stop)
        runtime = patch('runtime.Runtime', side_effect=AssertionError('client changes cannot manage services'))
        self.runtime = runtime.start()
        self.addCleanup(runtime.stop)
        downloader = patch('geodata.update', side_effect=AssertionError('inline export must work offline'))
        downloader.start()
        self.addCleanup(downloader.stop)

    @staticmethod
    def endpoints(config):
        return {(node['server'], node['server_port'], node['uuid'])
                for node in config['outbounds'] if node['type'] == 'vmess'}

    def execute(self, *arguments):
        args = addon.parser().parse_args(['--state', str(self.store.root), *map(str, arguments)])
        with redirect_stdout(io.StringIO()):
            addon.execute(args)

    def test_each_group_export_contains_only_its_nodes_and_complete_policy(self):
        before = copy.deepcopy(self.state)
        for group in GROUPS:
            with self.subTest(group=group):
                dest = self.root / group
                dest.mkdir()
                with patch('export_clash.yaml_text', wraps=export_clash.yaml_text) as yaml_text:
                    self.assertTrue(addon.export_clients(self.state, dest, group=group))
                mh = yaml_text.call_args.args[0]
                sb = json.loads((dest / 'sing-box.json').read_text())
                expected = self.state['groups'][group][0]['outbound']
                self.assertEqual(self.endpoints(sb), {(expected['server'], expected['server_port'], expected['uuid'])})
                self.assertEqual([(node['server'], node['port'], node['uuid']) for node in mh['proxies']],
                                 [(expected['server'], expected['server_port'], expected['uuid'])])
                self.assertEqual(mh['proxy-groups'][0]['proxies'], [group])
                self.assertEqual(sb['route']['final'], 'proxy')
                self.assertIn('RULE-SET,chain-cn-domain,DIRECT', mh['rules'])
                self.assertIn('RULE-SET,chain-cn-ip,DIRECT', mh['rules'])
                self.assertTrue(sb['dns']['servers'])
                self.assertIn('stay-direct.example', json.dumps(sb))
                self.assertIn('stay-proxy.example', json.dumps(sb))
                self.assertIn('rules1.cn', json.dumps(sb))
                self.assertIn('1.0.1.0/24', json.dumps(sb))
                links = (dest / 'nodes.txt').read_bytes()
                self.assertEqual(len(links.splitlines()), 1)
                self.assertEqual(base64.b64decode((dest / 'nodes.base64.txt').read_bytes()), links)
                for filename in publish.FILES:
                    self.assertEqual((dest / filename).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state, before)
        self.assertEqual(self.check.call_count, len(GROUPS))
        self.runtime.assert_not_called()

    def test_group_export_rejects_missing_group_without_writing_partial_files(self):
        state = copy.deepcopy(self.state)
        del state['groups']['B-direct']
        dest = self.root / 'missing'
        dest.mkdir()
        with self.assertRaises(ConfigError):
            addon.export_clients(state, dest, group='B-direct')
        self.assertEqual(list(dest.iterdir()), [])

    def test_client_core_rejection_does_not_write_group_files(self):
        self.check.side_effect = ConfigError('client core rejected')
        dest = self.root / 'invalid'
        dest.mkdir()
        with self.assertRaisesRegex(ConfigError, 'client core rejected'):
            addon.export_clients(self.state, dest, group='A-to-B')
        self.assertEqual(list(dest.iterdir()), [])

    def test_build_includes_merged_profile_and_three_isolated_bundles(self):
        release = addon.build(self.store)
        merged = json.loads((release / 'sing-box.json').read_text())
        self.assertEqual(len(self.endpoints(merged)), 3)
        for group in GROUPS:
            dest = release / 'groups' / group
            self.assertEqual({path.name for path in dest.iterdir()}, set(publish.FILES))
            selected = json.loads((dest / 'sing-box.json').read_text())
            expected = self.state['groups'][group][0]['outbound']
            self.assertEqual(self.endpoints(selected), {(expected['server'], expected['server_port'], expected['uuid'])})
            self.assertFalse((dest / 'server.json').exists())
            self.assertFalse((dest / 'handoff.json').exists())

    def test_export_cli_group_selects_one_bundle_in_new_output_directory(self):
        dest = self.root / 'export-b'
        self.execute('export', '--group', 'B-direct', '--output-dir', dest)
        self.assertEqual({path.name for path in dest.iterdir()}, set(publish.FILES))
        sb = json.loads((dest / 'sing-box.json').read_text())
        expected = self.state['groups']['B-direct'][0]['outbound']
        self.assertEqual(self.endpoints(sb), {(expected['server'], expected['server_port'], expected['uuid'])})
        with self.assertRaises(ConfigError):
            self.execute('export', '--group', 'A-direct', '--output-dir', dest)

    def test_export_cli_missing_group_does_not_create_output_directory(self):
        state = copy.deepcopy(self.state)
        del state['groups']['B-direct']
        self.store.save(state)
        dest = self.root / 'missing-cli'
        with self.assertRaises(ConfigError):
            self.execute('export', '--group', 'B-direct', '--output-dir', dest)
        self.assertFalse(dest.exists())

    @unittest.skipUnless(CORE.is_file(), 'sing-box test core unavailable')
    def test_all_group_profiles_pass_real_sing_box_validation(self):
        state = copy.deepcopy(self.state)
        state['binary'] = str(CORE)
        with patch('addon.check_config', side_effect=check_config):
            for mode in ('cn-direct', 'lan-direct', 'global'):
                state['policy']['mode'] = mode
                with self.subTest(mode=mode):
                    release = addon.build(self.store, state)
                    self.assertEqual(len(list((release / 'groups').iterdir())), 3)


class PublishClientsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='chain-publish-clients-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = addon.Store(self.root / 'state')
        self.store.root.mkdir()
        self.publisher = publish.Publisher(self.root / 'publication')
        snapshot_path = snapshot(self.root / 'rules', 1)
        self.active_state = state_for()
        self.active_state['policy'] = policy.load_policy('cn-direct', snapshot_path,
                                                        direct_domains=['active-direct.example'])
        self.active_state['rules_source'] = 'local'
        core_check = patch('addon.check_config')
        self.check = core_check.start()
        self.addCleanup(core_check.stop)
        runtime = patch('runtime.Runtime', side_effect=AssertionError('publishing clients cannot manage services'))
        self.runtime = runtime.start()
        self.addCleanup(runtime.stop)
        self.store.save(self.active_state)
        release = addon.build(self.store, self.active_state)
        self.active = {'release': str(release), 'state': copy.deepcopy(self.active_state)}
        self.store.save(self.active, 'active.json')
        self.store.save({'root': str(self.publisher.root), 'base_url': 'https://sub.example'}, 'publication.json')
        self.publisher.publish(release)
        self.desired = add_direct_nodes(copy.deepcopy(self.active_state))
        self.desired['server_config']['inbounds'][0]['listen_port'] = 31000
        self.desired['server_config']['inbounds'][0]['users'][0]['uuid'] = '22222222-2222-4222-8222-222222222222'
        self.desired['server_config']['outbounds'][0]['password'] = 'pending-link-secret'
        self.desired['profiles'][0]['inbound']['listen_port'] = 31000
        self.desired['profiles'][0]['inbound']['users'][0]['uuid'] = '22222222-2222-4222-8222-222222222222'
        self.desired['groups']['A-to-B'][0]['outbound'].update(
            server_port=31000, uuid='22222222-2222-4222-8222-222222222222')
        self.desired['profiles'][0]['clients'] = copy.deepcopy(self.desired['groups']['A-to-B'])
        self.desired['policy'] = policy.load_policy('global', direct_domains=['pending-direct.example'])
        self.store.save(self.desired)

    def payload(self, filename='mihomo.yaml', group=None):
        url = self.publisher.url('https://sub.example', filename, group=group)
        return self.publisher.response(urlsplit(url).path)[0]

    def baseline(self):
        return {'desired': (self.store.root / 'state.json').read_bytes(),
                'active': (self.store.root / 'active.json').read_bytes(),
                'publication': self.publisher.state(),
                'payloads': {name: self.payload(name) for name in publish.FILES}}

    def assert_unchanged(self, baseline):
        self.assertEqual((self.store.root / 'state.json').read_bytes(), baseline['desired'])
        self.assertEqual((self.store.root / 'active.json').read_bytes(), baseline['active'])
        self.assertEqual(self.publisher.state(), baseline['publication'])
        self.assertEqual({name: self.payload(name) for name in publish.FILES}, baseline['payloads'])
        self.runtime.assert_not_called()

    def test_direct_nodes_publish_without_applying_pending_server_or_policy(self):
        before = self.baseline()
        updates.publish_clients(self.store)
        active = self.store.read('active.json')
        self.assertEqual((self.store.root / 'state.json').read_bytes(), before['desired'])
        for field in ('server_config', 'profiles', 'policy', 'rules_source', 'binary', 'public_host'):
            self.assertEqual(active['state'][field], self.active_state[field], field)
        self.assertEqual(active['state']['groups']['A-to-B'], self.active_state['groups']['A-to-B'])
        for group in ('A-direct', 'B-direct'):
            self.assertEqual(active['state']['groups'][group], self.desired['groups'][group])
        self.assertEqual(self.publisher.state()['token'], before['publication']['token'])
        self.assertNotEqual(self.publisher.state()['generation'], before['publication']['generation'])
        merged = json.loads(self.payload('sing-box.json'))
        self.assertEqual(len(GroupClientsTests.endpoints(merged)), 3)
        self.assertIn('active-direct.example', json.dumps(merged))
        self.assertNotIn('pending-direct.example', json.dumps(merged))
        self.assertNotIn('22222222-2222-4222-8222-222222222222', json.dumps(merged))
        self.assertNotIn('pending-link-secret', json.dumps(merged))
        for group in GROUPS:
            selected = json.loads(self.payload('sing-box.json', group=group))
            self.assertEqual(len(GroupClientsTests.endpoints(selected)), 1)
        self.runtime.assert_not_called()

    def test_publish_clients_cli_performs_client_update_without_runtime(self):
        args = addon.parser().parse_args(['--state', str(self.store.root), 'publish-clients'])
        with redirect_stdout(io.StringIO()):
            addon.execute(args)
        self.assertEqual(set(self.store.read('active.json')['state']['groups']), set(GROUPS))
        self.runtime.assert_not_called()

    def test_failed_active_save_rolls_back_publication_and_preserves_desired(self):
        before = self.baseline()
        original = self.store.save

        def fail_save(data, name='state.json'):
            if name == 'active.json':
                raise OSError('active metadata full')
            return original(data, name)

        with patch.object(self.store, 'save', side_effect=fail_save):
            with self.assertRaisesRegex(OSError, 'active metadata full'):
                updates.publish_clients(self.store)
        self.assert_unchanged(before)

    def test_late_publisher_failure_rolls_back_all_published_state(self):
        before = self.baseline()
        original = publish.Publisher.publish

        def fail_publish(publisher, release, token=None):
            original(publisher, release, token)
            raise OSError('late publication failure')

        with patch.object(publish.Publisher, 'publish', new=fail_publish):
            with self.assertRaisesRegex(OSError, 'late publication failure'):
                updates.publish_clients(self.store)
        self.assert_unchanged(before)

    def test_invalid_client_config_keeps_active_and_publication(self):
        before = self.baseline()
        self.check.side_effect = ConfigError('invalid client')
        with self.assertRaisesRegex(ConfigError, 'invalid client'):
            updates.publish_clients(self.store)
        self.assert_unchanged(before)

    def test_without_active_deployment_fails_before_creating_publication(self):
        (self.store.root / 'active.json').unlink()
        (self.store.root / 'publication.json').unlink()
        before = (self.store.root / 'state.json').read_bytes()
        with self.assertRaises(ConfigError):
            updates.publish_clients(self.store)
        self.assertEqual((self.store.root / 'state.json').read_bytes(), before)
        self.assertFalse((self.store.root / 'active.json').exists())
        self.assertFalse((self.store.root / 'publication.json').exists())
        self.runtime.assert_not_called()

    def test_without_existing_publication_prepares_active_files_for_later_publish(self):
        (self.store.root / 'publication.json').unlink()
        before = (self.store.root / 'state.json').read_bytes()
        old_published = self.publisher.state()
        updates.publish_clients(self.store)
        active = self.store.read('active.json')
        self.assertEqual(set(active['state']['groups']), set(GROUPS))
        self.assertTrue((Path(active['release']) / 'groups' / 'B-direct' / 'mihomo.yaml').is_file())
        self.assertEqual(self.publisher.state(), old_published)
        self.assertEqual((self.store.root / 'state.json').read_bytes(), before)
        self.runtime.assert_not_called()


if __name__ == '__main__':
    unittest.main()
