#!/usr/bin/env python3
"""Offline conversion of chain share-link files to a Mihomo YAML profile."""
import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import parse_qsl, unquote

from chain import ConfigError, decode64, parse_link, write_text_private
from policy import MODES, apply_mihomo, load_policy


def require(condition, message):
    if not condition:
        raise ConfigError(message)


def insecure(options):
    values = [str(options[k]).lower() for k in
              ('insecure', 'allowInsecure', 'allow_insecure') if k in options]
    require(all(v in ('0', '1', 'true', 'false') for v in values), '证书验证开关无效')
    flags = {v in ('1', 'true') for v in values}
    require(len(flags) <= 1, '证书验证开关相互冲突')
    return next(iter(flags), False)


def tls_options(node, options):
    node['skip-cert-verify'] = insecure(options)
    if options.get('sni'):
        node['servername' if node['type'] in ('vless', 'vmess') else 'sni'] = options['sni']
    if options.get('alpn'):
        node['alpn'] = options['alpn'].split(',')
    if options.get('fp'):
        node['client-fingerprint'] = options['fp']
    if options.get('pinSHA256'):
        pin = options['pinSHA256'].replace(':', '')
        require(re.fullmatch(r'[0-9a-fA-F]{64}', pin), '证书 SHA256 指纹无效')
        node['fingerprint'] = pin.lower()


def transport(node, network, path='', host=''):
    require(network in ('tcp', 'ws'), '目前仅支持 TCP / WebSocket 传输')
    node['network'] = network
    if network == 'ws':
        node['ws-opts'] = {'path': path or '/'}
        if host:
            node['ws-opts']['headers'] = {'Host': host}


def convert(link):
    protocol, creds, parsed = parse_link(link)
    require(all(creds), '节点缺少认证信息')
    node = {'type': protocol, 'udp': True}
    if protocol == 'vmess':
        require(isinstance(parsed, dict), 'VMess 格式无效')
        known = {'v', 'ps', 'add', 'port', 'id', 'aid', 'scy', 'net', 'type',
                 'host', 'path', 'tls', 'sni', 'fp', 'alpn', 'insecure',
                 'allowInsecure', 'allow_insecure'}
        require(not (set(parsed) - known), 'VMess 含尚未支持的字段')
        require(parsed.get('type', 'none') in ('', 'none'), '不支持此 VMess 伪装')
        require(parsed.get('tls', '') in ('', 'none', 'tls'), '不支持此 VMess TLS 模式')
        node.update(server=parsed['add'], port=int(parsed['port']), uuid=creds[0],
                    alterId=int(parsed.get('aid', 0)), cipher=parsed.get('scy') or 'auto',
                    tls=parsed.get('tls') == 'tls')
        transport(node, parsed.get('net') or 'tcp', parsed.get('path', ''), parsed.get('host', ''))
        tls_options(node, parsed)
        name = parsed.get('ps') or protocol
    else:
        options = {}
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            require(key not in options, '链接含重复参数')
            options[key] = value
        common = {'sni', 'alpn', 'fp', 'insecure', 'allowInsecure', 'allow_insecure', 'pinSHA256', 'security'}
        extra = {'vless': {'encryption', 'flow', 'pbk', 'sid', 'type', 'headerType', 'host', 'path'},
                 'hysteria2': {'mport', 'obfs', 'obfs-password'},
                 'tuic': {'congestion_control', 'udp_relay_mode'}, 'anytls': set()}
        require(not (set(options) - common - extra[protocol]), '链接含尚未支持的参数')
        require(not parsed.path or parsed.path == '/', '不支持节点 URL 路径')
        require(parsed.password is None or protocol == 'tuic', '密码中的冒号须进行 URL 编码')
        node.update(server=parsed.hostname, port=parsed.port)
        tls_options(node, options)
        name = unquote(parsed.fragment) or protocol
        if protocol == 'vless':
            require(options.get('encryption', 'none') == 'none', '不支持此 VLESS 加密模式')
            require(options.get('headerType', 'none') == 'none', '不支持此 TCP 伪装')
            security = options.get('security', 'none')
            require(security in ('none', 'tls', 'reality'), '不支持此 VLESS 安全模式')
            node.update(uuid=creds[0], tls=security != 'none')
            transport(node, options.get('type', 'tcp'), options.get('path', ''), options.get('host', ''))
            if options.get('flow'):
                require(options['flow'] == 'xtls-rprx-vision', '不支持此 VLESS flow')
                node['flow'] = options['flow']
            if security == 'reality':
                require(options.get('pbk'), 'Reality 缺少公钥')
                node['reality-opts'] = {'public-key': options['pbk'], 'short-id': options.get('sid', '')}
                node.setdefault('client-fingerprint', 'chrome')
        else:
            require(options.get('security', 'tls') == 'tls', '不支持此 TLS 安全模式')
            node['password'] = creds[-1]
            if protocol == 'tuic':
                node['uuid'] = creds[0]
                for source, target in [('congestion_control', 'congestion-controller'),
                                       ('udp_relay_mode', 'udp-relay-mode')]:
                    if options.get(source):
                        node[target] = options[source]
            if protocol == 'hysteria2':
                if options.get('mport'):
                    ranges = options['mport'].replace(':', '-')
                    for part in ranges.split(','):
                        require(re.fullmatch(r'\d+(?:-\d+)?', part), '端口跳跃范围无效')
                        bounds = [int(p) for p in part.split('-')]
                        require(all(1 <= p <= 65535 for p in bounds) and bounds[0] <= bounds[-1], '端口跳跃范围无效')
                    node['ports'] = ranges
                for key in ('obfs', 'obfs-password'):
                    if options.get(key):
                        node[key] = options[key]
    require(isinstance(node['server'], str) and node['server'] and 1 <= node['port'] <= 65535, '节点地址或端口无效')
    require(isinstance(name, str), '节点名称无效')
    node['name'] = name
    return node


def profile(inputs, policy=None):
    proxies, groups = [], []
    for index, path in enumerate(inputs, 1):
        content = Path(path).read_text(encoding='utf-8-sig').strip()
        if '://' not in content:
            content = decode64(''.join(content.split())).decode('utf-8')
        group_name = f'{index}: {Path(path).name.removesuffix(".txt").removesuffix(".base64")}'
        names = []
        for line_number, line in enumerate(content.splitlines(), 1):
            if not line.strip():
                continue
            try:
                node = convert(line.strip())
            except (ValueError, KeyError, TypeError, AttributeError, ConfigError) as error:
                # Never include raw URI, credentials or parser exception details.
                detail = str(error) if isinstance(error, ConfigError) else '节点格式无效'
                raise ConfigError(f'输入 {index} 第 {line_number} 行：{detail}') from None
            node['name'] = f'{index}.{len(names) + 1}: {node["name"]}'
            names.append(node['name'])
            proxies.append(node)
        require(names, f'输入 {index} 没有节点')
        groups.append({'name': group_name, 'type': 'select', 'proxies': names})
    require(groups, '至少需要一个输入文件')
    config = {'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'log-level': 'warning',
            'proxies': proxies,
            'proxy-groups': [{'name': '代理选择', 'type': 'select',
                              'proxies': [g['name'] for g in groups]}] + groups,
            'rules': ['MATCH,代理选择']}
    return apply_mihomo(config, policy if policy is not None else load_policy())


def yaml_text(config):
    # JSON flow values are valid YAML; quote every key and value safely, including names.
    return '# Mihomo profile; contains credentials. Generated offline.\n' + ''.join(
        json.dumps(key, ensure_ascii=False) + ': ' + json.dumps(value, ensure_ascii=False) + '\n'
        for key, value in config.items())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', action='append', required=True, type=Path,
                        help='逐行节点链接或 Base64 文件；可重复，每份文件对应一个选择组')
    parser.add_argument('--output', required=True, type=Path, help='输出 Mihomo YAML 文件（不可已存在）')
    parser.add_argument('--routing', choices=MODES, default='cn-direct',
                        help='默认国内和局域网直连；DIRECT 指客户端设备直连')
    parser.add_argument('--rules-dir', type=Path, help='已导入的 GeoIP + GeoSite 快照目录；规则会内嵌到客户端配置')
    for action in ('direct', 'proxy'):
        parser.add_argument('--' + action + '-domain', action='append', default=[],
                            help='强制直连/代理的域名后缀，可重复；代理例外优先')
        parser.add_argument('--' + action + '-cidr', action='append', default=[],
                            help='强制直连/代理的 IP 或网段，可重复')
    args = parser.parse_args()
    try:
        require(not args.output.exists() and not args.output.is_symlink(), '输出文件已存在，请换新文件名')
        policy = load_policy(args.routing, args.rules_dir, args.direct_domain, args.proxy_domain,
                             args.direct_cidr, args.proxy_cidr)
        data = yaml_text(profile(args.input, policy))
        # Publish a complete file without overwriting even if another writer races us.
        with tempfile.TemporaryDirectory(prefix='.clash-', dir=args.output.parent) as stage:
            candidate = Path(stage) / 'profile.yaml'
            write_text_private(candidate, data)
            os.link(candidate, args.output)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ConfigError) as error:
        print('导出失败：' + (str(error) if isinstance(error, ConfigError) else '输入/输出文件或节点格式无效'), file=sys.stderr)
        return 1
    print(f'已导出 {args.output}（包含节点凭据，文件权限 0600）')
    return 0


if __name__ == '__main__':
    sys.exit(main())
