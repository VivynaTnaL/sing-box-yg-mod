"""Portable client routing policies; DIRECT always means the client device.

Only import reads legacy GeoIP/GeoSite databases. Exported profiles contain
inline rules or fixed upstream rule URLs, never server filesystem paths.
"""
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from chain import ConfigError, write_text_private


MODES = ('cn-direct', 'lan-direct', 'global')
LAN_CIDRS = ('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
             '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4',
             '240.0.0.0/4', '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8')
LAN_DOMAINS = ('localhost', 'local', 'lan', 'home.arpa')
DOMAIN_FIELDS = ('domain', 'domain_suffix', 'domain_keyword', 'domain_regex')
SNAPSHOT_FILES = {'cn-domain': 'geosite-cn.json', 'cn-ip': 'geoip-cn.json'}
MIHOMO_URLS = {
    'cn-domain': 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.list',
    'cn-ip': 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.list',
}
SINGBOX_URLS = {
    'cn-domain': 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs',
    'cn-ip': 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs',
}


def require(condition, message):
    if not condition:
        raise ConfigError(message)


def _strings(value):
    value = [value] if isinstance(value, str) else value
    require(isinstance(value, (list, tuple)) and all(isinstance(v, str) and v for v in value),
            '规则字段必须为非空字符串或字符串列表')
    return list(value)


def _domains(values):
    result = []
    for value in _strings(values):
        try:
            value = value.strip().removeprefix('+.').strip('.').encode('idna').decode().lower()
        except UnicodeError:
            raise ConfigError('例外域名格式无效') from None
        require(len(value) <= 253 and all(re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', p)
                                        for p in value.split('.')), '例外域名格式无效（填写域名，不含协议或路径）')
        try:
            ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            raise ConfigError('IP 地址请填写到 CIDR 例外中')
        result.append(value)
    return sorted(set(result))


def _cidrs(values):
    result = []
    for value in _strings(values):
        try:
            result.append(str(ipaddress.ip_network(value, strict=False)))
        except ValueError:
            raise ConfigError('规则中的 IP/CIDR 无效') from None
    return sorted(set(result))


def normalize_ruleset(data, kind):
    """Accept only losslessly portable domain OR rules or destination CIDRs."""
    require(isinstance(data, dict) and data.get('version') in (1, 2, 3, 4), '规则集版本无效')
    rules = data.get('rules')
    require(isinstance(rules, list) and rules, '规则集为空')
    allowed = set(DOMAIN_FIELDS if kind == 'domain' else ('ip_cidr',))
    merged = {}
    for rule in rules:
        require(isinstance(rule, dict) and rule and not (set(rule) - allowed),
                '规则集含无法无损转换的字段')
        for key, value in rule.items():
            values = _strings(value)
            require(all(not any(c in v for c in '\r\n\x00') for v in values), '规则值含无效字符')
            if key == 'ip_cidr':
                values = _cidrs(values)
            elif key != 'domain_regex':
                require(all(',' not in v for v in values), '域名规则含无效分隔符')
            else:
                # Classical Mihomo rules use commas as separators. Do not silently
                # truncate an expression whose syntax cannot be preserved.
                require(all(',' not in v for v in values), '正则包含逗号，无法可靠转换为 Mihomo 规则')
                try:
                    for value in values:
                        re.compile(value)
                except re.error:
                    raise ConfigError('域名正则无效') from None
            merged.setdefault(key, set()).update(values)
    # Legacy export encodes domain+subdomains as exact "a.cn" and suffix ".a.cn".
    # Merge only complete pairs: a leading dot alone intentionally excludes apex.
    exact = merged.get('domain', set())
    suffixes = merged.get('domain_suffix', set())
    paired = {suffix for suffix in suffixes if suffix.startswith('.') and suffix[1:] in exact}
    suffixes.difference_update(paired)
    suffixes.update(suffix[1:] for suffix in paired)
    if 'domain' in merged:
        merged['domain'] -= suffixes
    result = {key: sorted(merged[key]) for key in (*DOMAIN_FIELDS, 'ip_cidr') if merged.get(key)}
    require(result, '规则集没有可用规则')
    return {'version': 2, 'rules': [result]}


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _run(command):
    try:
        run = subprocess.run([str(x) for x in command], capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        raise ConfigError('无法运行 geodata 转换内核') from None
    require(run.returncode == 0, 'geodata 转换失败：请检查数据库格式及 cn 分类')
    return run.stdout


def import_geodata(binary, geoip_path, geosite_path, output_dir):
    """Create a checked snapshot in a new directory without changing inputs."""
    output_dir = Path(output_dir)
    require(not output_dir.exists() and not output_dir.is_symlink(), '规则快照目录已存在，请使用新目录')
    sources = {'geoip': Path(geoip_path), 'geosite': Path(geosite_path)}
    require(all(p.is_file() for p in sources.values()), 'GeoIP 和 GeoSite 数据库都必须存在')
    version = _run([binary, 'version'])
    require(re.search(r'^sing-box version 1\.14\.0\s*$', version, re.M), 'geodata 导入要求 sing-box 1.14.0')
    hashes = {name: _sha256(path) for name, path in sources.items()}
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.geodata-', dir=output_dir.parent) as tmp:
        stage = Path(tmp) / 'snapshot'
        stage.mkdir(mode=0o700)
        manifest = {'version': 1, 'core_version': '1.14.0', 'sources': hashes, 'files': {}}
        for tag, filename in SNAPSHOT_FILES.items():
            kind = 'geoip' if tag == 'cn-ip' else 'geosite'
            raw = Path(tmp) / filename
            _run([binary, kind, 'export', 'cn', '-f', sources[kind], '-o', raw])
            try:
                data = normalize_ruleset(json.loads(raw.read_text()), 'ip' if kind == 'geoip' else 'domain')
            except ConfigError:
                raise
            except (OSError, ValueError):
                raise ConfigError('内核导出的 geodata 不是有效 JSON 规则集') from None
            path = stage / filename
            write_text_private(path, json.dumps(data, ensure_ascii=False, separators=(',', ':')) + '\n')
            manifest['files'][filename] = {'sha256': _sha256(path),
                                          'entries': sum(len(v) for v in data['rules'][0].values())}
        require(hashes == {name: _sha256(path) for name, path in sources.items()},
                '导入期间源数据库发生变化，请重新导入')
        write_text_private(stage / 'manifest.json', json.dumps(manifest, indent=2) + '\n')
        require(not output_dir.exists() and not output_dir.is_symlink(), '规则快照目录已存在')
        os.rename(stage, output_dir)
    return manifest


def load_policy(mode='cn-direct', rules_dir=None, direct_domains=(), proxy_domains=(),
                direct_cidrs=(), proxy_cidrs=()):
    require(mode in MODES, '分流模式无效')
    policy = {'version': 1, 'mode': mode, 'source': 'remote' if mode == 'cn-direct' else 'builtin',
              'direct_domains': _domains(direct_domains), 'proxy_domains': _domains(proxy_domains),
              'direct_cidrs': _cidrs(direct_cidrs), 'proxy_cidrs': _cidrs(proxy_cidrs), 'sets': {}}
    require(not (set(policy['direct_domains']) & set(policy['proxy_domains'])), '同一域名不能同时强制直连和代理')
    require(not (set(policy['direct_cidrs']) & set(policy['proxy_cidrs'])), '同一网段不能同时强制直连和代理')
    if rules_dir is not None:
        try:
            directory = Path(rules_dir)
            manifest = json.loads((directory / 'manifest.json').read_text())
            require(isinstance(manifest, dict) and manifest.get('version') == 1, '规则快照清单无效')
            for tag, filename in SNAPSHOT_FILES.items():
                path = directory / filename
                require(not path.is_symlink(), '规则快照不能引用符号链接')
                require(_sha256(path) == manifest['files'][filename]['sha256'], '规则快照校验失败')
                policy['sets'][tag] = normalize_ruleset(json.loads(path.read_text()),
                                                       'ip' if tag == 'cn-ip' else 'domain')['rules']
        except ConfigError:
            raise
        except (OSError, KeyError, TypeError, ValueError):
            raise ConfigError('规则快照缺失或损坏，请重新导入 GeoIP 和 GeoSite') from None
        policy['source'] = 'inline'
    return policy


def _mihomo_domain_provider(rules):
    merged = rules[0]
    if set(merged) <= {'domain', 'domain_suffix'}:
        return {'type': 'inline', 'behavior': 'domain', 'payload':
                merged.get('domain', []) + [d if d.startswith('.') else '+.' + d
                                           for d in merged.get('domain_suffix', [])]}
    mapping = dict(zip(DOMAIN_FIELDS, ('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX')))
    payload = []
    for key in DOMAIN_FIELDS:
        for value in merged.get(key, []):
            if key == 'domain_suffix' and value.startswith('.'):
                payload.append('DOMAIN-REGEX,^.+' + re.escape(value) + '$')
            else:
                payload.append(mapping[key] + ',' + value)
    return {'type': 'inline', 'behavior': 'classical', 'payload': payload}


def apply_mihomo(config, policy, proxy_tag='代理选择', direct_tag='DIRECT'):
    """Replace client DNS/routing, preserving inbound and proxy definitions."""
    mode, providers, rules, dns_policy = policy['mode'], {}, [], {}
    direct_dns = 'https://223.5.5.5/dns-query#' + direct_tag
    proxy_dns = 'https://1.1.1.1/dns-query#' + proxy_tag
    # Forced proxy precedes forced direct, including overlapping suffixes/CIDRs.
    for action, target, resolver in [('proxy', proxy_tag, proxy_dns), ('direct', direct_tag, direct_dns)]:
        domains, cidrs = policy[action + '_domains'], policy[action + '_cidrs']
        if domains:
            tag = 'chain-' + action + '-domains'
            providers[tag] = _mihomo_domain_provider([{'domain_suffix': domains}])
            rules.append(f'RULE-SET,{tag},{target}')
            dns_policy['rule-set:' + tag] = [resolver]
        for cidr in cidrs:
            kind = 'IP-CIDR6' if ':' in cidr else 'IP-CIDR'
            rules.append(f'{kind},{cidr},{target}')
    if mode != 'global':
        providers['chain-lan-domains'] = {'type': 'inline', 'behavior': 'classical', 'payload':
            ['DOMAIN-SUFFIX,' + d for d in LAN_DOMAINS] + ['DOMAIN-REGEX,^[^.]+$']}
        providers['chain-lan-ip'] = {'type': 'inline', 'behavior': 'ipcidr', 'payload': list(LAN_CIDRS)}
        rules += [f'RULE-SET,chain-lan-domains,{direct_tag}', f'RULE-SET,chain-lan-ip,{direct_tag}']
        dns_policy['rule-set:chain-lan-domains'] = ['system']
    if mode == 'cn-direct':
        for tag in SNAPSHOT_FILES:
            name = 'chain-' + tag
            if policy['source'] == 'inline':
                providers[name] = (_mihomo_domain_provider(policy['sets'][tag]) if tag == 'cn-domain' else
                                   {'type': 'inline', 'behavior': 'ipcidr',
                                    'payload': policy['sets'][tag][0]['ip_cidr']})
            else:
                providers[name] = {'type': 'http', 'behavior': 'domain' if tag == 'cn-domain' else 'ipcidr',
                                   'format': 'text', 'url': MIHOMO_URLS[tag],
                                   'path': './chain-rules/' + tag + '.list', 'interval': 86400, 'proxy': proxy_tag}
            rules.append(f'RULE-SET,{name},{direct_tag}')
        dns_policy['rule-set:chain-cn-domain'] = [direct_dns]
    rules.append('MATCH,' + proxy_tag)
    config.update({'mode': 'rule', 'rules': rules, 'rule-providers': providers,
                   'dns': {'enable': True, 'ipv6': True, 'enhanced-mode': 'redir-host',
                           'default-nameserver': ['223.5.5.5'],
                           'proxy-server-nameserver': [direct_dns],
                           'nameserver': [proxy_dns], 'nameserver-policy': dns_policy,
                           'direct-nameserver': [direct_dns], 'direct-nameserver-follow-policy': True}})
    return config


def apply_singbox(config, policy, proxy_tag='proxy', direct_tag='direct'):
    """Apply a sing-box 1.14 policy with independent bootstrap/target DNS."""
    mode, rules, sets, dns_rules = policy['mode'], [], [], []
    outbounds = config.setdefault('outbounds', [])
    if not any(o.get('tag') == direct_tag for o in outbounds):
        outbounds.append({'type': 'direct', 'tag': direct_tag})
    for outbound in outbounds:
        if outbound.get('server'):
            outbound['domain_resolver'] = 'chain-dns-direct'
        elif outbound.get('type') == 'direct':
            # A selected LAN domain must keep its system DNS answer; routing's
            # resolve action below handles all destinations before direct dial.
            outbound['domain_resolver'] = 'chain-dns-direct'
    # 1.14's resolve action without a named server evaluates dns.rules/final.
    # Resolve once, then both domain and destination-IP overrides can precede
    # all built-in rules. Proxy node bootstrap uses its explicit resolver above.
    rules += [{'port': 53, 'action': 'hijack-dns'}, {'action': 'resolve'}]
    for action, target, resolver in [('proxy', proxy_tag, 'chain-dns-proxy'),
                                     ('direct', direct_tag, 'chain-dns-direct')]:
        if policy[action + '_domains']:
            match = {'domain_suffix': policy[action + '_domains']}
            dns_rules.append(dict(match, action='route', server=resolver))
            rules.append(dict(match, action='route', outbound=target))
        if policy[action + '_cidrs']:
            rules.append({'ip_cidr': policy[action + '_cidrs'], 'action': 'route', 'outbound': target})
    if mode != 'global':
        lan = {'domain_suffix': list(LAN_DOMAINS), 'domain_regex': ['^[^.]+$']}
        dns_rules.append(dict(lan, action='route', server='chain-dns-system'))
        rules += [dict(lan, action='route', outbound=direct_tag),
                  {'ip_cidr': list(LAN_CIDRS), 'action': 'route', 'outbound': direct_tag}]
    if mode == 'cn-direct':
        for tag in SNAPSHOT_FILES:
            if policy['source'] == 'inline':
                sets.append({'type': 'inline', 'tag': 'chain-' + tag, 'rules': copy.deepcopy(policy['sets'][tag])})
            else:
                sets.append({'type': 'remote', 'tag': 'chain-' + tag, 'format': 'binary',
                             'url': SINGBOX_URLS[tag], 'http_client': {'detour': proxy_tag}, 'update_interval': '1d'})
        dns_rules.append({'rule_set': 'chain-cn-domain', 'action': 'route', 'server': 'chain-dns-direct'})
        rules += [{'rule_set': 'chain-cn-domain', 'action': 'route', 'outbound': direct_tag},
                  {'rule_set': 'chain-cn-ip', 'action': 'route', 'outbound': direct_tag}]
    config['route'] = {'rules': rules, 'rule_set': sets, 'final': proxy_tag,
                       'default_domain_resolver': 'chain-dns-direct', 'auto_detect_interface': True}
    config['dns'] = {'servers': [
        {'type': 'local', 'tag': 'chain-dns-system'},
        {'type': 'https', 'tag': 'chain-dns-direct', 'server': '223.5.5.5', 'path': '/dns-query', 'detour': direct_tag},
        {'type': 'https', 'tag': 'chain-dns-proxy', 'server': '1.1.1.1', 'path': '/dns-query', 'detour': proxy_tag}],
        'rules': dns_rules, 'final': 'chain-dns-proxy'}
    if mode == 'cn-direct' and policy['source'] == 'remote':
        config.setdefault('experimental', {}).setdefault('cache_file', {})['enabled'] = True
    return config
