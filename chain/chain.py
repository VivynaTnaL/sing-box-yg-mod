#!/usr/bin/env python3
"""Build A-direct / B-direct / A-to-B subscriptions with a private SS2022 link."""
import argparse
import base64
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
from urllib.parse import quote, unquote, urlsplit, urlunsplit, urlencode
import uuid

VERSION = json.loads(Path(__file__).with_name('core.lock.json').read_text())['version']
METHOD = '2022-blake3-aes-256-gcm'
PROTOCOLS = {'vless', 'vmess', 'hysteria2', 'tuic', 'anytls'}
SS_TAG = 'chain-ss-in'


class ConfigError(ValueError):
    """Safe, deliberately secret-free user-facing error."""


def run_core(binary, *args):
    result = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ConfigError('sing-box ' + args[0] + ' 失败；请检查版本、参数和证书。诊断未显示以免泄露凭据。')
    return result.stdout


def check_version(binary):
    if not re.search(r'^sing-box version ' + re.escape(VERSION) + r'\s*$', run_core(binary, 'version'), re.M):
        raise ConfigError('本工具要求 sing-box ' + VERSION)


def exact(obj, fields, name):
    if not isinstance(obj, dict) or set(obj) != set(fields.split()):
        raise ConfigError(name + ' 字段缺失或含未知字段')


def address(value):
    if not isinstance(value, str) or '%' in value:
        raise ConfigError('IP 地址格式错误')
    ip = ipaddress.ip_address(value)
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local:
        raise ConfigError('服务器地址必须是可路由的单播 IP')
    return str(ip)


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ConfigError('端口必须是 1–65535 的整数')
    return value


def domain(value):
    if not isinstance(value, str) or len(value) > 253 or not re.fullmatch(
            r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value):
        raise ConfigError('SNI 必须是有效域名')
    if '.' not in value or any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-')
                               for label in value.split('.')):
        raise ConfigError('SNI 必须是有效域名')


def read_json(path):
    # JSONC comments are permitted in legacy configs; never strip // inside URLs.
    raw = Path(path).read_text()
    clean = re.sub(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*[\s\S]*?\*/',
                   lambda m: m[0] if m[0].startswith('"') else ' ', raw)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ConfigError('JSON 含重复字段')
            result[key] = value
        return result
    return json.loads(clean, object_pairs_hook=unique)


def write_text_private(path, content):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix='.chain-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_private(path, data):
    write_text_private(path, json.dumps(data, indent=2, ensure_ascii=False) + '\n')


def decode64(text):
    return base64.b64decode(text + '=' * (-len(text) % 4), altchars=b'-_', validate=True)


def parse_link(link):
    if not isinstance(link, str) or any(c.isspace() for c in link):
        raise ConfigError('节点链接含空白字符')
    if link.startswith('vmess://'):
        data = json.loads(decode64(link[8:]))
        return 'vmess', (data['id'],), data
    parsed = urlsplit(link)
    protocol = 'hysteria2' if parsed.scheme == 'hy2' else parsed.scheme
    if protocol not in PROTOCOLS or not parsed.hostname or not parsed.port:
        raise ConfigError('不支持或不完整的节点链接')
    credential = unquote(parsed.username or '')
    creds = (credential, unquote(parsed.password or '')) if protocol == 'tuic' else (credential,)
    return protocol, creds, parsed


def credentials(protocol, user):
    if protocol in ('vless', 'vmess'):
        return (user['uuid'],)
    if protocol == 'tuic':
        return (user['uuid'], user['password'])
    return (user['password'],)


def rewrite_link(link, user, label):
    protocol, _, parsed = parse_link(link)
    creds = credentials(protocol, user)
    if protocol == 'vmess':
        data = dict(parsed, id=creds[0], ps=label + '-' + parsed.get('ps', 'vmess'))
        return 'vmess://' + base64.b64encode(json.dumps(data, separators=(',', ':')).encode()).decode()
    info = ':'.join(quote(c, safe='') for c in creds)
    # Keep public host, port, WS/CDN/Argo settings and TLS parameters exactly as imported.
    netloc = info + '@' + parsed.netloc.rsplit('@', 1)[-1]
    return urlunsplit(parsed._replace(netloc=netloc, fragment=quote(label + '-' + unquote(parsed.fragment), safe='')))


def new_user(protocol, original, name):
    user = copy.deepcopy(original)
    user['name'] = name
    if protocol in ('vless', 'vmess', 'tuic'):
        user['uuid'] = str(uuid.uuid4())
    if protocol in ('hysteria2', 'tuic', 'anytls'):
        user['password'] = secrets.token_urlsafe(32)
    return user


def normalize_inbounds(config, base):
    inbounds = copy.deepcopy(config.get('inbounds'))
    if not isinstance(inbounds, list) or not inbounds:
        raise ConfigError('配置必须包含客户端入站')
    for inbound in inbounds:
        if inbound.get('type') not in PROTOCOLS or not inbound.get('users'):
            raise ConfigError('仅支持 VLESS、VMess、HY2、TUIC、AnyTLS 的有认证入站')
        # These old listen fields implement sniffing, not authentication. Routing is rebuilt below.
        for key in ('sniff', 'sniff_override_destination', 'sniff_timeout', 'domain_strategy'):
            inbound.pop(key, None)
        # Bundle certificate material so the low-privilege service never reads /root.
        tls = inbound.get('tls', {})
        for field in ('certificate', 'key'):
            filename = tls.pop(field + '_path', None)
            if filename:
                path = Path(filename)
                tls[field] = (path if path.is_absolute() else base / path).read_text().splitlines()
    return inbounds


def fresh_profile(binary, server, listen_port, sni):
    address(server)
    port(listen_port)
    domain(sni)
    keys = dict(re.findall(r'(PrivateKey|PublicKey):\s*(\S+)', run_core(binary, 'generate', 'reality-keypair')))
    uid, sid = str(uuid.uuid4()), secrets.token_hex(8)
    inbound = {'type': 'vless', 'tag': 'reality', 'listen': '::' if ':' in server else '0.0.0.0',
               'listen_port': listen_port, 'users': [{'uuid': uid, 'flow': 'xtls-rprx-vision'}],
               'tls': {'enabled': True, 'server_name': sni, 'reality': {'enabled': True,
                       'handshake': {'server': sni, 'server_port': 443},
                       'private_key': keys['PrivateKey'], 'short_id': [sid]}}}
    host = '[' + server + ']' if ':' in server else server
    query = urlencode({'encryption': 'none', 'security': 'reality', 'flow': 'xtls-rprx-vision',
                       'sni': sni, 'fp': 'chrome', 'pbk': keys['PublicKey'], 'sid': sid, 'type': 'tcp'})
    return [inbound], [f'vless://{uid}@{host}:{listen_port}?{query}#Reality']


def attach_profiles(inbounds, links, role, previous=None):
    index, direct_links, chain_links = {}, [], []
    saved = {}
    if previous:
        for inbound in previous['inbounds']:
            by_name = {u['name']: u for u in inbound['users']}
            for user in inbound['users']:
                if user['name'].startswith('direct-'):
                    saved[(inbound['type'], credentials(inbound['type'], user))] = by_name.get(
                        user['name'].replace('direct-', 'chain-', 1))
    for i, inbound in enumerate(inbounds):
        inbound['tag'] = f'client-{i}'
        original_users = copy.deepcopy(inbound['users'])
        for j, user in enumerate(original_users):
            protocol = inbound['type']
            key = (protocol, credentials(protocol, user))
            if key in index:
                raise ConfigError('同协议的重复凭据无法唯一匹配链接；请先为入站分配独立凭据')
            inbound['users'][j]['name'] = f'direct-{i}-{j}'
            chained = copy.deepcopy(saved.get(key)) if role == 'entry' else None
            if role == 'entry' and chained is None:
                chained = new_user(protocol, user, f'chain-{i}-{j}')
            if chained:
                chained['name'] = f'chain-{i}-{j}'
                inbound['users'].append(chained)
            index[key] = (inbound['users'][j], chained)
    seen = set()
    for link in links:
        protocol, creds, _ = parse_link(link)
        key = (protocol, creds)
        if key not in index:
            raise ConfigError('节点链接与服务器入站凭据不匹配；请先刷新原订阅')
        direct, chained = index[key]
        seen.add(key)
        direct_links.append(rewrite_link(link, direct, 'A-direct' if role == 'entry' else 'B-direct'))
        if chained:
            chain_links.append(rewrite_link(link, chained, 'A-to-B'))
    if seen != set(index):
        raise ConfigError('部分入站用户没有对应节点链接，请提供完整聚合文件')
    return direct_links, chain_links


def validate_link(link):
    exact(link, 'schema_version type server server_port method password allowed_sources', 'B 对接参数')
    if type(link['schema_version']) is not int or link['schema_version'] != 1 or link['type'] != 'shadowsocks' or link['method'] != METHOD:
        raise ConfigError('仅支持 SS2022 AES-256-GCM 对接参数 v1')
    address(link['server'])
    port(link['server_port'])
    key = link['password']
    if not isinstance(key, str) or len(base64.b64decode(key, validate=True)) != 32:
        raise ConfigError('SS2022 密钥必须是 32 字节随机密钥的 Base64')
    sources = link['allowed_sources']
    if not isinstance(sources, list) or not sources or len(set(sources)) != len(sources):
        raise ConfigError('必须指定 A 的实际出站 IP 列表')
    for source in sources:
        address(source)
        if ipaddress.ip_address(source) == ipaddress.ip_address(link['server']):
            raise ConfigError('A 的出站地址不能等于 B 的接收地址')
        if ipaddress.ip_address(source).version != ipaddress.ip_address(link['server']).version:
            raise ConfigError('A 出站地址和 B 接收地址必须属于同一 IP 地址族')


def validate(spec):
    exact(spec, 'schema_version role inbounds direct_links chain_links link', '角色参数')
    if type(spec['schema_version']) is not int or spec['schema_version'] != 2 or spec['role'] not in ('entry', 'exit'):
        raise ConfigError('此版本需要独立角色参数 v2；旧双 Reality 原型请重新初始化')
    validate_link(spec['link'])
    tags, names, creds = set(), set(), set()
    if not isinstance(spec['inbounds'], list) or not spec['inbounds']:
        raise ConfigError('缺少客户端入站')
    for inbound in spec['inbounds']:
        tag, protocol = inbound.get('tag'), inbound.get('type')
        if protocol not in PROTOCOLS or not isinstance(tag, str) or not tag.startswith('client-') or tag in tags:
            raise ConfigError('客户端入站类型或标签无效')
        tags.add(tag)
        if inbound.get('detour') or inbound.get('multiplex', {}).get('enabled'):
            raise ConfigError('第一版不导入 inbound detour 或 multiplex；先关闭后重新导出')
        port(inbound['listen_port'])
        ipaddress.ip_address(inbound['listen'])
        if spec['role'] == 'exit' and inbound['listen_port'] == spec['link']['server_port']:
            raise ConfigError('B 的客户端端口和 SS2022 端口必须分开')
        if not inbound.get('users'):
            raise ConfigError('不允许无认证的客户端入站')
        for user in inbound['users']:
            name = user.get('name', '')
            prefixes = ('direct-', 'chain-') if spec['role'] == 'entry' else ('direct-',)
            if not name.startswith(prefixes) or name in names:
                raise ConfigError('认证用户名缺失、重复或角色错误')
            names.add(name)
            credential = credentials(protocol, user)
            if not all(isinstance(x, str) and x for x in credential) or (protocol, credential) in creds:
                raise ConfigError('客户端凭据缺失或重复')
            if protocol in ('vless', 'vmess', 'tuic'):
                uuid.UUID(credential[0])
            creds.add((protocol, credential))
    # Ensure exports cannot silently be stale or include the private SS2022 link.
    expected = {}
    for inbound in spec['inbounds']:
        for user in inbound['users']:
            expected[(inbound['type'], credentials(inbound['type'], user))] = 'chain_links' if user['name'].startswith('chain-') else 'direct_links'
    seen = set()
    for group in ('direct_links', 'chain_links'):
        if not isinstance(spec[group], list):
            raise ConfigError('聚合链接必须为列表')
        for text in spec[group]:
            protocol, credential, _ = parse_link(text)
            key = (protocol, credential)
            if expected.get(key) != group:
                raise ConfigError('聚合链接与用户路由不一致')
            seen.add(key)
    if seen != set(expected):
        raise ConfigError('聚合链接缺少用户')
    if spec['role'] == 'entry' and not spec['chain_links']:
        raise ConfigError('A 必须同时具有直出和链式用户')
    if not spec['direct_links']:
        raise ConfigError('缺少直出链接')


def render(spec):
    validate(spec)
    role, link = spec['role'], spec['link']
    config = {'log': {'level': 'warn', 'timestamp': True}, 'inbounds': copy.deepcopy(spec['inbounds']),
              'dns': {'servers': [{'type': 'local', 'tag': 'local-dns'}], 'final': 'local-dns'},
              'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'rules': []}}
    rules = config['route']['rules']
    if role == 'entry':
        config['outbounds'].append({'type': 'shadowsocks', 'tag': 'to-exit', 'server': link['server'],
                                    'server_port': link['server_port'], 'method': METHOD, 'password': link['password']})
        # Route before local resolution: chain destination DNS belongs to B.
        for inbound in config['inbounds']:
            names = [u['name'] for u in inbound['users'] if u['name'].startswith('chain-')]
            if names:
                rules.append({'inbound': [inbound['tag']], 'auth_user': names, 'action': 'route', 'outbound': 'to-exit'})
    else:
        config['inbounds'].append({'type': 'shadowsocks', 'tag': SS_TAG,
                                   'listen': '::' if ':' in link['server'] else '0.0.0.0',
                                   'listen_port': link['server_port'], 'method': METHOD, 'password': link['password']})
        cidrs = [str(ipaddress.ip_network(x + ('/128' if ':' in x else '/32'))) for x in link['allowed_sources']]
        rules.append({'type': 'logical', 'mode': 'and', 'rules': [
            {'inbound': [SS_TAG]}, {'source_ip_cidr': cidrs, 'invert': True}], 'action': 'reject'})
    rules += [{'action': 'resolve', 'server': 'local-dns'}, {'ip_is_private': True, 'action': 'reject'}]
    for inbound in spec['inbounds']:
        names = [u['name'] for u in inbound['users'] if u['name'].startswith('direct-')]
        if names:
            rules.append({'inbound': [inbound['tag']], 'auth_user': names, 'action': 'route', 'outbound': 'direct'})
    if role == 'exit':
        rules.append({'inbound': [SS_TAG], 'action': 'route', 'outbound': 'direct'})
    rules.append({'action': 'reject'})
    return config


def check_config(binary, config):
    with tempfile.TemporaryDirectory(prefix='chain-check-') as directory:
        candidate = Path(directory) / 'config.json'
        write_private(candidate, config)
        run_core(binary, 'check', '-c', str(candidate))


def initialize(args):
    check_version(args.binary)
    role = 'exit' if args.command == 'init-exit' else 'entry'
    if role == 'exit':
        link = {'schema_version': 1, 'type': 'shadowsocks', 'server': address(args.server),
                'server_port': port(args.link_port), 'method': METHOD,
                'password': base64.b64encode(secrets.token_bytes(32)).decode(),
                'allowed_sources': args.entry_source}
    else:
        link = read_json(args.link)
    validate_link(link)
    if args.legacy_config:
        if not args.legacy_links or args.address or args.sni:
            raise ConfigError('导入模式必须同时提供 --legacy-config 和 --legacy-links，不能混用新建参数')
        config_path = Path(args.legacy_config).resolve()
        inbounds = normalize_inbounds(read_json(config_path), config_path.parent)
        links = [line.strip() for line in Path(args.legacy_links).read_text().splitlines() if line.strip()]
    else:
        if not args.address or not args.sni or args.legacy_links:
            raise ConfigError('新建模式需要 --address 和 --sni；或使用完整的旧配置与聚合文件')
        inbounds, links = fresh_profile(args.binary, args.address, args.port, args.sni)
    direct, chained = attach_profiles(inbounds, links, role)
    spec = {'schema_version': 2, 'role': role, 'inbounds': inbounds, 'direct_links': direct,
            'chain_links': chained, 'link': link}
    check_config(args.binary, render(spec))
    with open(args.output, 'x', opener=lambda p, f: os.open(p, f, 0o600)) as stream:
        json.dump(spec, stream, indent=2, ensure_ascii=False)
        stream.write('\n')
    return spec


def build(args):
    check_version(args.binary)
    spec = read_json(args.spec)
    config = render(spec)
    check_config(args.binary, config)
    # A complete, immutable generation; no mixed old/new files on failure.
    dest = Path(args.output_dir).absolute()
    if dest.exists():
        raise ConfigError('输出目录必须不存在；使用新的版本目录，避免半更新和误覆盖')
    with tempfile.TemporaryDirectory(prefix='.chain-build-', dir=dest.parent) as directory:
        staging = Path(directory) / 'bundle'
        staging.mkdir(mode=0o700)
        write_private(staging / 'config.json', config)
        groups = {'A-direct': spec['direct_links'], 'A-to-B': spec['chain_links']} if spec['role'] == 'entry' else {'B-direct': spec['direct_links']}
        for name, links in groups.items():
            content = '\n'.join(links) + '\n'
            write_text_private(staging / (name + '.txt'), content)
            write_text_private(staging / (name + '.base64.txt'), base64.b64encode(content.encode()).decode() + '\n')
        if spec['role'] == 'exit':
            write_private(staging / 'B-link.json', spec['link'])
        write_private(staging / 'manifest.json', {'schema_version': 1, 'role': spec['role'], 'core_version': VERSION,
                      'groups': list(groups), 'listeners': [{'type': i['type'], 'port': i['listen_port']} for i in config['inbounds']]})
        os.rename(staging, dest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('init-exit', 'init-entry'):
        init = commands.add_parser(name, help='导入旧接入或新建 Reality；生成本机角色参数')
        init.add_argument('--binary', required=True)
        init.add_argument('--output', required=True)
        init.add_argument('--legacy-config')
        init.add_argument('--legacy-links')
        init.add_argument('--address')
        init.add_argument('--sni')
        init.add_argument('--port', type=int, default=8443)
        if name == 'init-exit':
            init.add_argument('--server', required=True, help='B 的服务器间连接 IP')
            init.add_argument('--link-port', type=int, default=9443)
            init.add_argument('--entry-source', action='append', required=True, help='A 的实际出站 IP，可重复')
        else:
            init.add_argument('--link', required=True, help='B 导出的 B-link.json')
    command = commands.add_parser('build', help='校验并输出配置和分组聚合链接')
    command.add_argument('--binary', required=True)
    command.add_argument('--spec', required=True)
    command.add_argument('--output-dir', required=True)
    command = commands.add_parser('update-link', help='导入新的 B 对接参数，保留 A 客户端凭据')
    command.add_argument('--binary', required=True)
    command.add_argument('--spec', required=True)
    command.add_argument('--link', required=True)
    command = commands.add_parser('refresh-profile', help='刷新原接入参数和证书，保留已有链式凭据')
    command.add_argument('--binary', required=True)
    command.add_argument('--spec', required=True)
    command.add_argument('--legacy-config', required=True)
    command.add_argument('--legacy-links', required=True)
    command = commands.add_parser('rotate-link', help='轮换 B 的 SS2022 密钥，保留客户端节点')
    command.add_argument('--binary', required=True)
    command.add_argument('--spec', required=True)
    args = parser.parse_args()
    try:
        if args.command.startswith('init-'):
            initialize(args)
        elif args.command == 'build':
            build(args)
        else:
            check_version(args.binary)
            spec = read_json(args.spec)
            validate(spec)
            previous = copy.deepcopy(spec)
            if args.command == 'update-link':
                if spec['role'] != 'entry':
                    raise ConfigError('update-link 仅用于 A')
                spec['link'] = read_json(args.link)
            elif args.command == 'rotate-link':
                if spec['role'] != 'exit':
                    raise ConfigError('rotate-link 仅用于 B')
                spec['link']['password'] = base64.b64encode(secrets.token_bytes(32)).decode()
            else:
                path = Path(args.legacy_config).resolve()
                inbounds = normalize_inbounds(read_json(path), path.parent)
                links = [line.strip() for line in Path(args.legacy_links).read_text().splitlines() if line.strip()]
                direct, chained = attach_profiles(inbounds, links, spec['role'], previous)
                spec.update(inbounds=inbounds, direct_links=direct, chain_links=chained)
            check_config(args.binary, render(spec))
            write_private(str(args.spec) + '.previous', previous)
            write_private(args.spec, spec)
        print('完成；配置和链接已保存到受限文件，未向终端输出凭据。')
    except ConfigError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        print('失败：请检查字段、文件路径和权限；未输出可能包含凭据的诊断。', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
