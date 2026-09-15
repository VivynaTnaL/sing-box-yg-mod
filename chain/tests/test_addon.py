"""Exercise independent imports and builds using temporary state only."""
import base64
import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import addon
import generate
import profiles
from chain import ConfigError, METHOD, check_config
from policy import load_policy
from runtime import Runtime as ActualRuntime
from publish import Publisher as ActualPublisher


TOOLS = Path(__file__).resolve().parents[1]
CORE = Path(os.environ.get('CHAIN_TEST_CORE', '/tmp/sing-box-chain-core'))


def plain_source():
    return {'log': {'level': 'warn'}, 'inbounds': [
        {'type': 'vmess', 'tag': 'original-ws', 'listen': '0.0.0.0', 'listen_port': 20002,
         'users': [{'uuid': '11111111-1111-4111-8111-111111111111'}],
         'transport': {'type': 'ws', 'path': '/original'}}],
        # Source runtime settings are deliberately irrelevant to the addon.
        'outbounds': [{'type': 'direct', 'tag': 'source-direct'}],
        'route': {'final': 'source-direct'}}


def write_json(path, value):
    path.write_text(json.dumps(value))
    return path


class AddonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='addon-unit-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.core = self.root / 'core'
        self.core.write_text('unused in unit tests')
        self.source = write_json(self.root / 'source.json', plain_source())
        _, handoff = profiles.exit_config('192.0.2.20', 22000, ['192.0.2.10'])
        self.link = write_json(self.root / 'handoff.json', handoff)
        self.store = addon.Store(self.root / 'state')
        for target in ('addon.check_version', 'profiles.check_version', 'addon.check_config'):
            patcher = patch(target)
            patcher.start()
            self.addCleanup(patcher.stop)
        # Any unexpected attempt to manage a service fails the entire test.
        for target in ('runtime.Runtime', 'publish.Publisher'):
            patcher = patch(target, side_effect=AssertionError('service management is forbidden in this test'))
            patcher.start()
            self.addCleanup(patcher.stop)

    def execute(self, *arguments):
        args = addon.parser().parse_args(['--state', str(self.store.root), *map(str, arguments)])
        with redirect_stdout(io.StringIO()):
            addon.execute(args)

    def initialize(self, *extra):
        self.execute('init-entry', '--config', self.source, '--address', '192.0.2.10',
                     '--link', self.link, '--binary', self.core, *extra)
        self.execute('rules', '--mode', 'lan-direct')
        return self.store.read()

    def test_standard_config_is_the_only_proxy_input(self):
        original = self.source.read_bytes()
        state = self.initialize()
        inbound = state['server_config']['inbounds'][0]
        self.assertEqual(inbound['listen_port'], 21000)
        self.assertEqual(inbound['listen'], '0.0.0.0')
        self.assertNotEqual(inbound['users'][0]['uuid'], plain_source()['inbounds'][0]['users'][0]['uuid'])
        self.assertEqual(inbound['transport'], plain_source()['inbounds'][0]['transport'])
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(len(state['groups']['A-to-B']), 1)
        self.assertEqual([o['type'] for o in state['server_config']['outbounds']], ['shadowsocks'])
        self.assertNotIn('source-direct', json.dumps(state))
        self.assertNotIn('jhsub', json.dumps(state))
        self.assertNotIn(str(self.source), json.dumps(state))
        self.assertEqual((self.store.root / 'state.json').stat().st_mode & 0o777, 0o600)

    def test_build_and_export_work_after_source_and_handoff_are_removed(self):
        self.initialize()
        self.source.unlink()
        self.link.unlink()
        release = addon.build(self.store)
        self.assertTrue((release / 'server.json').is_file())
        client = json.loads((release / 'sing-box.json').read_text())
        self.assertEqual(client['route']['final'], 'proxy')
        target = self.root / 'client-export'
        self.execute('export', '--output-dir', target)
        self.assertEqual({p.name for p in target.iterdir()},
                         {'mihomo.yaml', 'sing-box.json', 'nodes.txt', 'nodes.base64.txt'})
        for path in target.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn('private_key', path.read_text())
        with self.assertRaises(ConfigError):
            self.execute('export', '--output-dir', target)

    def test_refresh_preserves_addon_credentials_and_port_when_source_changes(self):
        before = self.initialize()
        config = plain_source()
        config['inbounds'][0]['users'][0]['uuid'] = '22222222-2222-4222-8222-222222222222'
        config['inbounds'][0]['listen_port'] = 20012
        config['inbounds'][0]['transport']['path'] = '/updated'
        write_json(self.source, config)
        self.execute('import-config', '--config', self.source)
        after = self.store.read()
        self.assertEqual(before['profiles'][0]['inbound']['users'], after['profiles'][0]['inbound']['users'])
        self.assertEqual(before['profiles'][0]['inbound']['listen_port'], after['profiles'][0]['inbound']['listen_port'])
        self.assertEqual(after['profiles'][0]['inbound']['transport']['path'], '/updated')
        self.assertEqual(after['policy'], before['policy'])

    def test_source_port_conflict_rejected_without_creating_state(self):
        with self.assertRaisesRegex(ConfigError, '冲突'):
            self.initialize('--port-start', '20002')
        self.assertFalse((self.store.root / 'state.json').exists())

    def test_unselected_source_ports_are_also_reserved(self):
        config = plain_source()
        config['inbounds'].append({'type': 'mixed', 'tag': 'do-not-import',
                                   'listen': '127.0.0.1', 'listen_port': 21000})
        write_json(self.source, config)
        state = self.initialize('--inbound', 'original-ws')
        self.assertEqual(state['profiles'][0]['inbound']['listen_port'], 21001)

    def test_refresh_preserves_previously_selected_inbound_subset(self):
        config = plain_source()
        config['inbounds'].append({'type': 'mixed', 'tag': 'do-not-import',
                                   'listen': '127.0.0.1', 'listen_port': 21000})
        write_json(self.source, config)
        before = self.initialize('--inbound', 'original-ws')
        self.execute('import-config', '--config', self.source)
        self.assertEqual(self.store.read()['profiles'], before['profiles'])

    def test_legacy_websocket_early_data_and_headers_survive_full_exports(self):
        config = plain_source()
        transport = config['inbounds'][0]['transport']
        transport.update(max_early_data=2048, early_data_header_name='Sec-WebSocket-Protocol',
                         headers={'Host': 'ws.example.com', 'X-Example': 'header-value'})
        write_json(self.source, config)
        self.initialize()
        import export_clash
        with patch('export_clash.yaml_text', wraps=export_clash.yaml_text) as yaml_text:
            release = addon.build(self.store)
        mh = yaml_text.call_args.args[0]
        self.assertEqual(mh['proxies'][0]['ws-opts'], {'path': '/original',
                         'max-early-data': 2048, 'early-data-header-name': 'Sec-WebSocket-Protocol',
                         'headers': {'Host': 'ws.example.com', 'X-Example': 'header-value'}})
        sb = json.loads((release / 'sing-box.json').read_text())
        vmess = next(out for out in sb['outbounds'] if out['type'] == 'vmess')
        self.assertEqual(vmess['transport'], transport)

    def test_invalid_websocket_early_data_is_rejected_before_saving(self):
        for value in (-1, True, '2048'):
            config = plain_source()
            config['inbounds'][0]['transport']['max_early_data'] = value
            write_json(self.source, config)
            with self.subTest(value=value), self.assertRaisesRegex(ConfigError, 'early-data'):
                self.initialize()
            self.assertFalse((self.store.root / 'state.json').exists())

    def test_refresh_collision_keeps_previous_state(self):
        before = self.initialize()
        config = plain_source()
        config['inbounds'][0]['listen_port'] = 21000
        write_json(self.source, config)
        with self.assertRaisesRegex(ConfigError, '冲突'):
            self.execute('import-config', '--config', self.source)
        self.assertEqual(self.store.read(), before)

    def test_handoff_is_one_standard_ss2022_outbound(self):
        data = json.loads(self.link.read_text())
        out = profiles.handoff(self.link)
        self.assertEqual(set(data), {'outbounds'})
        self.assertEqual(out['type'], 'shadowsocks')
        self.assertEqual(out['method'], METHOD)
        self.assertEqual(len(base64.b64decode(out['password'])), 32)
        invalid = []
        for field, value in (('method', 'aes-256-gcm'), ('type', 'socks'),
                             ('detour', 'other'), ('password', 'weak'), ('server_port', True)):
            item = copy.deepcopy(data)
            item['outbounds'][0][field] = value
            invalid.append(item)
        invalid += [{'outbounds': []}, {'outbounds': data['outbounds'] * 2}]
        for item in invalid:
            write_json(self.link, item)
            with self.subTest(item=item), self.assertRaises((ConfigError, ValueError)):
                profiles.handoff(self.link)

    def test_add_direct_uses_source_ports_and_no_server_private_material(self):
        state = self.initialize()
        self.execute('add-direct', '--config', self.source, '--address', '192.0.2.10', '--label', 'A-direct')
        self.execute('add-direct', '--config', self.source, '--address', '192.0.2.20', '--label', 'B-direct')
        updated = self.store.read()
        self.assertEqual(updated['server_config'], state['server_config'])
        self.assertEqual(set(updated['groups']), {'A-to-B', 'A-direct', 'B-direct'})
        self.assertEqual(updated['groups']['A-direct'][0]['outbound']['server_port'], 20002)
        self.assertEqual(updated['groups']['A-to-B'][0]['outbound']['server_port'], 21000)
        private_handoff = json.loads(self.link.read_text())['outbounds'][0]['password']
        self.assertNotIn(private_handoff, json.dumps(updated['groups']))

    def test_entry_route_has_no_direct_fallback(self):
        state = self.initialize()
        server = state['server_config']
        self.assertEqual([o['tag'] for o in server['outbounds']], ['to-exit'])
        self.assertEqual(server['route']['rules'][0]['outbound'], 'to-exit')
        self.assertEqual(server['route']['rules'][-1], {'action': 'reject'})

    def test_update_link_preserves_clients_and_rejects_self_loop(self):
        before = self.initialize()
        _, handoff = profiles.exit_config('192.0.2.30', 23000, ['192.0.2.10'])
        write_json(self.link, handoff)
        self.execute('update-link', '--link', self.link)
        updated = self.store.read()
        self.assertEqual(updated['groups'], before['groups'])
        self.assertEqual(updated['profiles'], before['profiles'])
        self.assertEqual(updated['server_config']['outbounds'][0]['server_port'], 23000)
        handoff['outbounds'][0].update(server='192.0.2.10', server_port=21000)
        write_json(self.link, handoff)
        with self.assertRaisesRegex(ConfigError, '循环'):
            self.execute('update-link', '--link', self.link)
        self.assertEqual(self.store.read(), updated)

    def test_exit_initialization_and_update_preserve_link_key(self):
        self.execute('init-exit', '--address', '192.0.2.20', '--entry-source', '192.0.2.10',
                     '--binary', self.core)
        before = self.store.read()
        self.assertEqual(before['role'], 'exit')
        self.assertEqual((self.store.root / 'handoff.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(before['server_config']['route']['rules'][0]['source_ip_cidr'], ['192.0.2.10/32'])
        self.execute('update-exit', '--address', '192.0.2.21', '--entry-source', '192.0.2.11', '--port', '23000')
        after = self.store.read()
        self.assertEqual(before['handoff']['outbounds'][0]['password'], after['handoff']['outbounds'][0]['password'])
        self.assertEqual(after['handoff']['outbounds'][0]['server'], '192.0.2.21')

    def test_exit_source_port_conflict_is_explicit(self):
        with self.assertRaisesRegex(ConfigError, '冲突'):
            self.execute('init-exit', '--address', '192.0.2.20', '--entry-source', '192.0.2.10',
                         '--binary', self.core, '--config', self.source, '--port', '20002')
        self.assertFalse((self.store.root / 'state.json').exists())

    def test_failed_core_check_preserves_existing_state(self):
        before = self.initialize()
        with patch('addon.check_config', side_effect=ConfigError('invalid config')):
            with self.assertRaises(ConfigError):
                self.execute('import-config', '--config', self.source)
        self.assertEqual(self.store.read(), before)

    def test_menu_initializes_exit_using_same_command_path(self):
        answers = ['1', 'B', str(self.core), '192.0.2.20', '22000', '192.0.2.10', '', '0']
        with patch('builtins.input', side_effect=answers), redirect_stdout(io.StringIO()):
            self.assertEqual(addon.menu(self.store.root), 0)
        self.assertEqual(self.store.read()['role'], 'exit')

    def test_noninteractive_cli_prints_help_without_creating_state(self):
        result = subprocess.run([sys.executable, str(TOOLS / 'addon.py'), '--state', str(self.store.root)],
                                input='', capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('init-entry', result.stdout)
        self.assertFalse(self.store.root.exists())

    def test_rule_changes_preserve_inline_snapshot_and_active_state(self):
        state = self.initialize()
        state['policy'].update(source='inline', sets={
            'cn-domain': [{'domain_suffix': ['example.cn']}],
            'cn-ip': [{'ip_cidr': ['1.0.1.0/24']}]})
        self.store.save(state)
        release = addon.build(self.store)
        active = {'release': str(release), 'state': copy.deepcopy(state)}
        self.store.save(active, 'active.json')
        self.execute('rules', '--mode', 'cn-direct', '--proxy-domain', 'example.com')
        updated = self.store.read()
        self.assertEqual(updated['policy']['source'], 'inline')
        self.assertEqual(updated['policy']['sets'], state['policy']['sets'])
        self.assertEqual(updated['policy']['proxy_domains'], ['example.com'])
        self.assertEqual(self.store.read('active.json'), active)
        addon.build(self.store)
        self.assertEqual(self.store.read('active.json'), active)

    def pending_deployment(self):
        state = self.initialize()
        release = addon.build(self.store)
        active = {'release': str(release), 'state': copy.deepcopy(state)}
        self.store.save(active, 'active.json')
        self.store.save({'root': str(self.root / 'publication'), 'base_url': 'https://sub.example.com'},
                        'publication.json')
        self.execute('rules', '--mode', 'global')
        return active

    def deployment_components(self, active=None):
        from runtime import atomic_write
        from test_runtime import FakeSystem
        system = FakeSystem()
        runtime = ActualRuntime(self.root / 'system', runner=system, health_interval=0)
        atomic_write(runtime.binary, 'fake core', 0o755)
        atomic_write(runtime.unit, runtime._unit_text(), 0o644)
        publisher = ActualPublisher(self.root / 'publication')
        if active:
            runtime.apply(Path(active['release']) / 'server.json')
            publisher.publish(Path(active['release']))
        return runtime, publisher, system

    def test_failed_runtime_deploy_does_not_publish_or_change_active_state(self):
        active = self.pending_deployment()
        runtime, publication, system = self.deployment_components(active)
        previous = (runtime.root / 'config.json').read_bytes()
        system.bad_config = True
        with patch('runtime.Runtime', return_value=runtime), patch('publish.Publisher') as publisher:
            with self.assertRaisesRegex(RuntimeError, '配置校验失败'):
                addon.deploy(self.store)
        publisher.assert_not_called()
        self.assertEqual((runtime.root / 'config.json').read_bytes(), previous)
        self.assertTrue(system.active['sing-box-addon.service'])
        self.assertEqual(self.store.read('active.json'), active)
        self.assertEqual(self.store.read()['policy']['mode'], 'global')

    def test_failed_publication_restores_old_release_and_keeps_active_snapshot(self):
        active = self.pending_deployment()
        runtime, publisher, system = self.deployment_components(active)
        previous_config, previous_publication = (runtime.root / 'config.json').read_bytes(), publisher.state()
        with patch('runtime.Runtime', return_value=runtime), patch('publish.Publisher', return_value=publisher), \
                patch.object(publisher, 'publish', side_effect=RuntimeError('publication refused')):
            with self.assertRaisesRegex(RuntimeError, 'publication refused'):
                addon.deploy(self.store)
        self.assertEqual((runtime.root / 'config.json').read_bytes(), previous_config)
        self.assertEqual(publisher.state(), previous_publication)
        self.assertTrue(system.active['sing-box-addon.service'])
        self.assertTrue(system.enabled['sing-box-addon.service'])
        self.assertEqual(self.store.read('active.json'), active)
        self.assertEqual(self.store.read()['policy']['mode'], 'global')

    def test_first_deploy_publication_failure_stops_service_without_marking_active(self):
        self.initialize()
        self.store.save({'root': str(self.root / 'publication')}, 'publication.json')
        runtime, publisher, system = self.deployment_components()
        with patch('runtime.Runtime', return_value=runtime), patch('publish.Publisher', return_value=publisher), \
                patch.object(publisher, 'publish', side_effect=RuntimeError('publication refused')):
            with self.assertRaisesRegex(RuntimeError, 'publication refused'):
                addon.deploy(self.store)
        self.assertFalse((runtime.root / 'config.json').exists())
        self.assertFalse((publisher.root / 'state.json').exists())
        self.assertFalse(system.active['sing-box-addon.service'])
        self.assertFalse(system.enabled['sing-box-addon.service'])
        self.assertIsNone(self.store.read('active.json', optional=True))

    def test_failed_active_metadata_save_restores_server_publication_and_metadata(self):
        active = self.pending_deployment()
        runtime, publisher, system = self.deployment_components(active)
        previous_config, previous_publication = (runtime.root / 'config.json').read_bytes(), publisher.state()
        pending = self.store.read()
        pending['server_config']['log'] = {'level': 'debug'}
        self.store.save(pending)
        save = self.store.save
        def fail_active(data, name='state.json'):
            if name == 'active.json':
                raise OSError('active metadata full')
            save(data, name)
        with patch('runtime.Runtime', return_value=runtime), patch('publish.Publisher', return_value=publisher), \
                patch.object(self.store, 'save', side_effect=fail_active):
            with self.assertRaisesRegex(OSError, 'active metadata full'):
                addon.deploy(self.store)
        self.assertEqual((runtime.root / 'config.json').read_bytes(), previous_config)
        self.assertEqual(publisher.state(), previous_publication)
        self.assertTrue(system.active['sing-box-addon.service'])
        self.assertTrue(system.enabled['sing-box-addon.service'])
        self.assertEqual(self.store.read('active.json'), active)
        self.assertEqual(self.store.read(), pending)

    def test_successful_deploy_publishes_then_saves_pending_as_active(self):
        active = self.pending_deployment()
        pending = self.store.read()
        operations = []
        runtime, publisher, system = self.deployment_components(active)
        pending['binary'] = str(runtime.binary)
        apply, publish = runtime.apply, publisher.publish
        def apply_pending(path):
            operations.append(('runtime', path.parent))
            return apply(path)
        def publish_pending(path):
            self.assertEqual(self.store.read('active.json'), active)
            operations.append(('publish', path))
            return publish(path)
        with patch('runtime.Runtime', return_value=runtime), patch('publish.Publisher', return_value=publisher), \
                patch.object(runtime, 'apply', side_effect=apply_pending), patch.object(publisher, 'publish', side_effect=publish_pending):
            release = addon.deploy(self.store)
        self.assertEqual(operations, [('runtime', release), ('publish', release)])
        self.assertEqual(self.store.read('active.json'), {'release': str(release), 'state': pending})
        self.assertTrue(system.active['sing-box-addon.service'])
        self.assertTrue(system.enabled['sing-box-addon.service'])

    def test_deploy_and_rebuild_use_installed_core_after_temporary_core_is_deleted(self):
        self.initialize()
        runtime, publisher, system = self.deployment_components()
        self.core.unlink()
        checked = []
        def check_installed(binary, config):
            self.assertEqual(Path(binary), runtime.binary)
            self.assertTrue(Path(binary).is_file())
            checked.append(binary)
        with patch('runtime.Runtime', return_value=runtime), patch('addon.check_config', side_effect=check_installed):
            release = addon.deploy(self.store)
            rebuilt = addon.build(self.store)
        self.assertNotEqual(release, rebuilt)
        self.assertGreaterEqual(len(checked), 4)
        self.assertEqual(self.store.read()['binary'], str(runtime.binary))
        self.assertEqual(self.store.read('active.json')['state']['binary'], str(runtime.binary))
        self.assertTrue(system.active['sing-box-addon.service'])

    def test_deploy_checks_installed_core_before_building_or_fetching_rules(self):
        self.initialize()
        runtime, publisher, system = self.deployment_components()
        runtime.binary.unlink()
        previous = self.store.read()
        with patch('runtime.Runtime', return_value=runtime), patch('addon.build') as build, patch('updates.ensure') as ensure:
            with self.assertRaisesRegex(ConfigError, '先选择安装'):
                addon.deploy(self.store)
        build.assert_not_called()
        ensure.assert_not_called()
        self.assertEqual(self.store.read(), previous)
        self.assertFalse(system.active.get('sing-box-addon.service', False))

    def test_uninstalled_binary_falls_back_to_cache_without_downloading(self):
        with self.store.locked():
            cached = self.store.root / 'core'
            cached.write_text('cached core')
            args = addon.parser().parse_args(['--state', str(self.store.root), 'install'])
            with patch('addon.subprocess.run') as download:
                selected = addon.binary_for(args, self.store, {'binary': str(self.root / 'removed-core')})
        self.assertEqual(selected, str(cached))
        download.assert_not_called()

    def test_uninstalled_binary_download_target_is_independent_cache(self):
        with self.store.locked():
            args = addon.parser().parse_args(['--state', str(self.store.root), 'install'])
            with patch('addon.subprocess.run', return_value=subprocess.CompletedProcess([], 0)) as download:
                with redirect_stdout(io.StringIO()):
                    selected = addon.binary_for(args, self.store, {'binary': str(self.root / 'removed-core')})
        self.assertEqual(selected, str(self.store.root / 'core'))
        self.assertEqual(download.call_args.args[0][-2:], ['--output', str(self.store.root / 'core')])


@unittest.skipUnless(CORE.is_file() and shutil.which('openssl'), 'set CHAIN_TEST_CORE to a sing-box 1.14.0 binary')
class AddonCoreTests(unittest.TestCase):
    def test_all_five_protocols_build_independently_with_inline_rules(self):
        with tempfile.TemporaryDirectory(prefix='addon-core-') as tmp:
            root = Path(tmp)
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                            'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj',
                            '/CN=proxy.example.com', '-keyout', str(root / 'key.pem'),
                            '-out', str(root / 'cert.pem')], check=True, capture_output=True)
            config = generate.render(generate.EXAMPLE, root, CORE)
            config['inbounds'][1]['transport'].update(max_early_data=2048,
                early_data_header_name='Sec-WebSocket-Protocol', headers={'Host': 'ws.example.com'})
            # Import ordinary file-based certificates rather than only generator's embedded form.
            for inbound in config['inbounds'][1:]:
                inbound['tls'].pop('certificate')
                inbound['tls'].pop('key')
                inbound['tls'].update(certificate_path='cert.pem', key_path='key.pem')
            source = write_json(root / 'source.json', config)
            server_b, link = profiles.exit_config('192.0.2.20', 22000, ['192.0.2.10'])
            check_config(CORE, server_b)
            handoff = write_json(root / 'handoff.json', link)
            store = addon.Store(root / 'state')
            args = addon.parser().parse_args(['--state', str(store.root), 'init-entry', '--config', str(source),
                        '--address', '192.0.2.10', '--link', str(handoff), '--binary', str(CORE)])
            addon.execute(args)
            state = store.read()
            original_clients = copy.deepcopy(state['groups']['A-to-B'])
            args = addon.parser().parse_args(['--state', str(store.root), 'import-config', '--config', str(source)])
            addon.execute(args)
            state = store.read()
            self.assertEqual(original_clients, state['groups']['A-to-B'])
            state['groups']['A-direct'] = profiles.import_direct(source, '192.0.2.10', 'A-direct')
            state['policy'] = load_policy('cn-direct')
            state['policy'].update(source='inline', sets={
                'cn-domain': [{'domain_suffix': ['example.cn']}],
                'cn-ip': [{'ip_cidr': ['1.0.1.0/24']}]})
            store.save(state)
            for path in (source, handoff, root / 'cert.pem', root / 'key.pem'):
                path.unlink()
            release = addon.build(store)
            client = json.loads((release / 'sing-box.json').read_text())
            check_config(CORE, client)
            check_config(CORE, json.loads((release / 'server.json').read_text()))
            nodes = [o for o in client['outbounds'] if o['type'] in generate.DEFAULT_PORTS]
            self.assertEqual(len(nodes), 10)
            self.assertEqual({o['type'] for o in nodes}, set(generate.DEFAULT_PORTS))
            secret_values = [config['inbounds'][0]['tls']['reality']['private_key'],
                             state['profiles'][0]['inbound']['tls']['reality']['private_key'],
                             link['outbounds'][0]['password']]
            for filename in ('mihomo.yaml', 'sing-box.json', 'nodes.txt', 'nodes.base64.txt'):
                exported = (release / filename).read_text()
                if filename == 'nodes.base64.txt':
                    exported = base64.b64decode(exported).decode()
                for secret in secret_values:
                    self.assertNotIn(secret, exported)
                self.assertNotIn('PRIVATE KEY', exported)
                self.assertNotIn(str(root), exported)
            mihomo = (release / 'mihomo.yaml').read_text()
            self.assertIn('+.example.cn', mihomo)
            self.assertIn('1.0.1.0/24', mihomo)
            self.assertIn('RULE-SET,chain-cn-domain,DIRECT', mihomo)
            self.assertIn('RULE-SET,chain-cn-ip,DIRECT', mihomo)
            self.assertIn('"max-early-data": 2048', mihomo)
            self.assertIn('Sec-WebSocket-Protocol', mihomo)
            if os.environ.get('CHAIN_TEST_MIHOMO'):
                checked = subprocess.run([os.environ['CHAIN_TEST_MIHOMO'], '-t', '-d', str(root / 'mihomo-cache'),
                                          '-f', str(release / 'mihomo.yaml')],
                                         capture_output=True, text=True, timeout=30)
                self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)


if __name__ == '__main__':
    unittest.main()
