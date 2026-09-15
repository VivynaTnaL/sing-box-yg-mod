import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from chain import ConfigError
import policy


DOMAIN_RULES = {'version': 2, 'rules': [
    {'domain': ['example.cn', 'only.example'],
     'domain_suffix': ['.example.cn', '.sub-only.example', 'other.cn']} ]}
IP_RULES = {'version': 2, 'rules': [{'ip_cidr': ['1.0.1.0/24', '240e::/20']}]}


def snapshot(path):
    path.mkdir()
    files = {}
    for filename, data in [('geosite-cn.json', DOMAIN_RULES), ('geoip-cn.json', IP_RULES)]:
        raw = json.dumps(data).encode()
        (path / filename).write_bytes(raw)
        files[filename] = {'sha256': hashlib.sha256(raw).hexdigest()}
    (path / 'manifest.json').write_text(json.dumps({'version': 1, 'files': files}))
    return path


class PolicyTests(unittest.TestCase):
    def test_default_cn_direct_has_both_datasets_and_ipv6_lan(self):
        cfg = policy.apply_mihomo({}, policy.load_policy())
        self.assertEqual(cfg['mode'], 'rule')
        self.assertEqual(cfg['rules'][-3:], ['RULE-SET,chain-cn-domain,DIRECT',
                                           'RULE-SET,chain-cn-ip,DIRECT', 'MATCH,代理选择'])
        self.assertIn('fc00::/7', cfg['rule-providers']['chain-lan-ip']['payload'])
        self.assertEqual(cfg['rule-providers']['chain-cn-domain']['proxy'], '代理选择')
        self.assertEqual(cfg['rule-providers']['chain-cn-ip']['behavior'], 'ipcidr')
        self.assertTrue(all(p['url'].startswith('https://raw.githubusercontent.com/MetaCubeX/')
                            for p in cfg['rule-providers'].values() if p['type'] == 'http'))

    def test_portable_snapshot_has_no_paths_or_download_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            current = policy.load_policy(rules_dir=snapshot(Path(tmp) / 'rules'))
        # Files have been removed; the serialized policy still exports standalone.
        current = json.loads(json.dumps(current))
        mihomo = policy.apply_mihomo({}, current)
        singbox = policy.apply_singbox({}, current)
        for result in (mihomo, singbox, current):
            serialized = json.dumps(result)
            for forbidden in (tmp, '/root/', 'private_key', 'geosite.db', 'geoip.db', 'raw.githubusercontent'):
                self.assertNotIn(forbidden, serialized)
        self.assertTrue(all(p['type'] == 'inline' for p in mihomo['rule-providers'].values()))
        self.assertTrue(all(p['type'] == 'inline' for p in singbox['route']['rule_set']))

    def test_exact_and_suffix_conversion_preserves_apex_semantics(self):
        normalized = policy.normalize_ruleset(copy.deepcopy(DOMAIN_RULES), 'domain')
        rule = normalized['rules'][0]
        self.assertEqual(rule['domain'], ['only.example'])
        self.assertEqual(rule['domain_suffix'], ['.sub-only.example', 'example.cn', 'other.cn'])
        provider = policy._mihomo_domain_provider(normalized['rules'])
        self.assertEqual(provider['behavior'], 'domain')
        self.assertEqual(set(provider['payload']), {'only.example', '.sub-only.example', '+.example.cn', '+.other.cn'})

    def test_classical_conversion_keeps_keyword_regex_and_subdomain_semantics(self):
        raw = {'version': 2, 'rules': [{'domain_keyword': 'keyword', 'domain_regex': '^news[0-9]+\\.cn$',
                                     'domain_suffix': '.sub-only.example'}]}
        normalized = policy.normalize_ruleset(raw, 'domain')
        result = policy._mihomo_domain_provider(normalized['rules'])
        self.assertEqual(result['behavior'], 'classical')
        self.assertIn('DOMAIN-REGEX,^news[0-9]+\\.cn$', result['payload'])
        self.assertIn('DOMAIN-KEYWORD,keyword', result['payload'])
        self.assertIn('DOMAIN-REGEX,^.+\\.sub\\-only\\.example$', result['payload'])

    def test_refuse_lossy_or_empty_rule_conversion(self):
        for rule in ({'invert': True, 'domain_suffix': ['cn']}, {'source_ip_cidr': '1.0.1.0/24'},
                     {'domain_regex': 'a{0,4}'}, {'domain': ['bad\nvalue']}, {}):
            with self.subTest(rule=rule):
                with self.assertRaises(ConfigError):
                    policy.normalize_ruleset({'version': 2, 'rules': [rule]}, 'domain')
        with self.assertRaises(ConfigError):
            policy.normalize_ruleset({'version': 2, 'rules': []}, 'ip')

    def test_overrides_precede_lan_cn_and_proxy_wins_overlap(self):
        current = policy.load_policy(direct_domains=['example.cn'], proxy_domains=['private.example.cn'],
                                     proxy_cidrs=['10.0.0.9/32'], direct_cidrs=['192.168.1.0/24'])
        clash_rules = policy.apply_mihomo({}, current)['rules']
        self.assertEqual(clash_rules[:4], ['RULE-SET,chain-proxy-domains,代理选择',
                                         'IP-CIDR,10.0.0.9/32,代理选择',
                                         'RULE-SET,chain-direct-domains,DIRECT',
                                         'IP-CIDR,192.168.1.0/24,DIRECT'])
        rules = policy.apply_singbox({}, current)['route']['rules']
        routes = [r for r in rules if r.get('action') == 'route']
        self.assertEqual([r['outbound'] for r in routes[:4]], ['proxy', 'proxy', 'direct', 'direct'])
        # Resolve before route matching makes IP overrides work for domain requests.
        self.assertEqual(rules[1], {'action': 'resolve'})

    def test_dns_uses_proxy_for_unknown_and_direct_for_cn_node_bootstrap(self):
        current = policy.load_policy(proxy_domains=['force.example.cn'], direct_domains=['other.example'])
        clash = policy.apply_mihomo({}, current)['dns']
        self.assertEqual(clash['nameserver'], ['https://1.1.1.1/dns-query#代理选择'])
        self.assertEqual(clash['proxy-server-nameserver'], ['https://223.5.5.5/dns-query#DIRECT'])
        self.assertEqual(list(clash['nameserver-policy']), ['rule-set:chain-proxy-domains',
                         'rule-set:chain-direct-domains', 'rule-set:chain-lan-domains', 'rule-set:chain-cn-domain'])
        config = {'outbounds': [{'type': 'socks', 'tag': 'proxy', 'server': 'node.example', 'server_port': 1080}]}
        policy.apply_singbox(config, current)
        self.assertEqual(config['outbounds'][0]['domain_resolver'], 'chain-dns-direct')
        self.assertEqual(config['route']['default_domain_resolver'], 'chain-dns-direct')
        self.assertEqual(config['dns']['final'], 'chain-dns-proxy')
        servers = {s['tag']: s for s in config['dns']['servers']}
        self.assertEqual(servers['chain-dns-proxy']['detour'], 'proxy')
        self.assertEqual(servers['chain-dns-direct']['detour'], 'direct')
        self.assertEqual([r['server'] for r in config['dns']['rules']],
                         ['chain-dns-proxy', 'chain-dns-direct', 'chain-dns-system', 'chain-dns-direct'])
        self.assertNotIn('independent_cache', config['dns'])

    def test_global_and_lan_modes_have_no_cn_downloads(self):
        for mode in ('global', 'lan-direct'):
            current = policy.load_policy(mode)
            clash = policy.apply_mihomo({}, current)
            singbox = policy.apply_singbox({}, current)
            self.assertNotIn('raw.githubusercontent', json.dumps([clash, singbox]))
            self.assertEqual(singbox['route']['rule_set'], [])
            if mode == 'global':
                self.assertEqual(clash['rules'], ['MATCH,代理选择'])
                self.assertFalse(any('outbound' in r for r in singbox['route']['rules']))
            else:
                self.assertIn('RULE-SET,chain-lan-ip,DIRECT', clash['rules'])

    def test_missing_or_modified_snapshot_cannot_become_global(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError):
                policy.load_policy(rules_dir=Path(tmp) / 'missing')
            directory = snapshot(Path(tmp) / 'rules')
            (directory / 'geoip-cn.json').write_text('{}')
            with self.assertRaisesRegex(ConfigError, '校验失败'):
                policy.load_policy(rules_dir=directory)
            (directory / 'geoip-cn.json').unlink()
            with self.assertRaises(ConfigError):
                policy.load_policy(rules_dir=directory)

    def test_invalid_and_conflicting_exceptions_fail(self):
        for kwargs in ({'mode': 'bad'}, {'direct_domains': ['https://example.com']},
                       {'proxy_domains': ['a.cn,DIRECT']}, {'direct_domains': ['192.168.1.1']},
                       {'direct_cidrs': ['1.2.3.4/99']},
                       {'direct_domains': ['a.cn'], 'proxy_domains': ['A.cn.']},
                       {'direct_cidrs': ['1.2.3.4'], 'proxy_cidrs': ['1.2.3.4/32']}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ConfigError):
                policy.load_policy(**kwargs)

    def test_import_checks_both_databases_and_records_hashes(self):
        def core(command, **_kwargs):
            if command[1] == 'version':
                return subprocess.CompletedProcess(command, 0, 'sing-box version 1.14.0\n', '')
            self.assertEqual(command[2:4], ['export', 'cn'])
            Path(command[command.index('-o') + 1]).write_text(json.dumps(
                IP_RULES if command[1] == 'geoip' else DOMAIN_RULES))
            return subprocess.CompletedProcess(command, 0, '', '')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            geoip, geosite = root / 'geoip.db', root / 'geosite.db'
            geoip.write_bytes(b'ip-data')
            geosite.write_bytes(b'domain-data')
            with mock.patch.object(policy.subprocess, 'run', side_effect=core):
                result = policy.import_geodata('/core', geoip, geosite, root / 'rules')
                self.assertEqual(result['sources']['geoip'], hashlib.sha256(b'ip-data').hexdigest())
                self.assertEqual(result['files']['geosite-cn.json']['entries'], 4)
                self.assertEqual(policy.load_policy(rules_dir=root / 'rules')['source'], 'inline')
                self.assertEqual((root / 'rules' / 'manifest.json').stat().st_mode & 0o777, 0o600)
                self.assertEqual(geoip.read_bytes(), b'ip-data')
                with self.assertRaises(ConfigError):
                    policy.import_geodata('/core', geoip, geosite, root / 'rules')
                with self.assertRaises(ConfigError):
                    policy.import_geodata('/core', geoip, root / 'missing', root / 'new')

    def test_failed_import_does_not_leave_partial_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('geoip.db', 'geosite.db'):
                (root / name).write_bytes(b'data')
            responses = [subprocess.CompletedProcess([], 0, 'sing-box version 1.14.0\n', ''),
                         subprocess.CompletedProcess([], 1, '', 'private path must not leak')]
            with mock.patch.object(policy.subprocess, 'run', side_effect=responses):
                with self.assertRaises(ConfigError) as error:
                    policy.import_geodata('/core', root / 'geoip.db', root / 'geosite.db', root / 'rules')
            self.assertNotIn('private path', str(error.exception))
            self.assertFalse((root / 'rules').exists())
            self.assertEqual(len(list(root.iterdir())), 2)


if __name__ == '__main__':
    unittest.main()
