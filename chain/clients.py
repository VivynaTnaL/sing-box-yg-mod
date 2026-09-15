"""Portable public client nodes, encoded as a standard sing-box configuration.

The exchange file carries public leaf certificates instead of SPKI pins because
sing-box rejects both fields together.  Import restores the original SPKI pin and
derives the leaf fingerprint needed by Mihomo, without reading a server file.
"""
import copy
import re
import uuid

from chain import ConfigError, PROTOCOLS, check_config, check_version, port, read_json
from profiles import certificate_pins, client, host, select_inbounds


COMMON = {'type', 'tag', 'server', 'server_port', 'tls'}
PROXY_FIELDS = {
    'vless': {'uuid', 'flow', 'transport'},
    'vmess': {'uuid', 'security', 'alter_id', 'transport'},
    'hysteria2': {'password', 'obfs'},
    'tuic': {'uuid', 'password', 'congestion_control'},
    'anytls': {'password'},
}
TLS_FIELDS = {'enabled', 'server_name', 'insecure', 'alpn', 'min_version',
              'max_version', 'cipher_suites', 'certificate',
              'certificate_public_key_sha256', 'utls', 'reality'}
SKIPPED_TYPES = {'selector', 'urltest', 'direct', 'block', 'dns'}
PEM = re.compile(r'-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----')


def label_check(label):
    if label not in ('A-direct', 'B-direct'):
        raise ConfigError('客户端节点只能导入 A-direct 或 B-direct 组')


def fields(value, allowed, description):
    if not isinstance(value, dict) or set(value) - allowed:
        raise ConfigError(description + ' 包含外部依赖、私钥或尚未支持的字段')


def public_certificate(value):
    """Accept only PEM certificate blocks, never arbitrary attached material."""
    if isinstance(value, list) and all(isinstance(line, str) for line in value):
        value = '\n'.join(value)
    if not isinstance(value, str):
        raise ConfigError('客户端公开证书格式无效')
    certificates = PEM.findall(value)
    if not certificates or PEM.sub('', value).strip():
        raise ConfigError('客户端公开证书只能包含 PEM 证书，不能包含私钥或其他内容')
    try:
        for certificate in certificates:
            certificate_pins(certificate)
    except (ValueError, TypeError, OSError) as error:
        raise ConfigError('客户端公开证书无法读取') from None
    # The peer leaf is sufficient to reproduce both original pin forms.
    return certificates[0].splitlines()


def export_clients_source(config_path, server, label, selected=()):
    """Read local server material once, returning only portable public outbounds."""
    label_check(label)
    inbounds, _ = select_inbounds(config_path, selected)
    outbounds = []
    for index, inbound in enumerate(inbounds, 1):
        for user_index, user in enumerate(inbound['users'], 1):
            item = client(inbound, user, server,
                          f'{label}-{inbound["type"]}-{index}-{user_index}')
            outbound = item['outbound']
            tls = outbound.get('tls', {})
            if item.get('certificate_fingerprint'):
                tls.pop('certificate_public_key_sha256', None)
                tls['certificate'] = public_certificate(inbound['tls']['certificate'])
            outbounds.append(outbound)
    return {'outbounds': outbounds}


def validate_tls(tls):
    fields(tls, TLS_FIELDS, '客户端 TLS')
    if type(tls.get('enabled', False)) is not bool or type(tls.get('insecure', False)) is not bool:
        raise ConfigError('客户端 TLS 开关格式无效')
    if tls.get('insecure'):
        raise ConfigError('客户端节点必须启用证书验证，不能设置 insecure')
    for field in ('server_name', 'min_version', 'max_version'):
        if field in tls and not isinstance(tls[field], str):
            raise ConfigError('客户端 TLS 参数格式无效')
    for field in ('alpn', 'cipher_suites'):
        if field in tls and (not isinstance(tls[field], list) or
                             any(not isinstance(value, str) for value in tls[field])):
            raise ConfigError('客户端 TLS 参数格式无效')
    if 'utls' in tls:
        fields(tls['utls'], {'enabled', 'fingerprint'}, '客户端 uTLS')
        if type(tls['utls'].get('enabled', False)) is not bool:
            raise ConfigError('客户端 uTLS 开关格式无效')
        if tls['utls'].get('enabled') and tls['utls'].get('fingerprint', 'chrome') != 'chrome':
            raise ConfigError('目前跨格式导入仅支持 chrome uTLS 指纹')
    if 'reality' in tls:
        reality = tls['reality']
        fields(reality, {'enabled', 'public_key', 'short_id'}, '客户端 Reality')
        if type(reality.get('enabled', False)) is not bool:
            raise ConfigError('客户端 Reality 开关格式无效')
        if reality.get('enabled') and any(field in tls for field in
                                         ('certificate', 'certificate_public_key_sha256')):
            raise ConfigError('Reality 不能同时配置证书或证书 pin')
    fingerprint = None
    if 'certificate' in tls:
        if 'certificate_public_key_sha256' in tls:
            raise ConfigError('sing-box 的 certificate 与 certificate_public_key_sha256 不能同时使用')
        certificate = public_certificate(tls.pop('certificate'))
        fingerprint, spki = certificate_pins(certificate)
        tls['certificate_public_key_sha256'] = [spki]
    elif tls.get('certificate_public_key_sha256'):
        raise ConfigError('只有 SPKI pin 无法还原 Mihomo 证书指纹；请在来源机使用 export-nodes 导出公开证书')
    return fingerprint


def validate_outbound(value):
    if not isinstance(value, dict) or value.get('type') not in PROTOCOLS:
        raise ConfigError('仅支持 VLESS、VMess、HY2、TUIC、AnyTLS 客户端节点')
    out = copy.deepcopy(value)
    protocol = out['type']
    fields(out, COMMON | PROXY_FIELDS[protocol], '客户端节点')
    try:
        out['server'] = host(out['server'])
        port(out['server_port'])
        if protocol in ('vless', 'vmess', 'tuic'):
            if not isinstance(out.get('uuid'), str):
                raise ValueError()
            uuid.UUID(out['uuid'])
        if protocol in ('hysteria2', 'tuic', 'anytls'):
            if not isinstance(out.get('password'), str) or not out['password']:
                raise ValueError()
    except (KeyError, ValueError, TypeError, AttributeError):
        raise ConfigError('客户端节点地址、端口或认证信息无效') from None
    if 'transport' in out:
        transport = out['transport']
        fields(transport, {'type', 'path', 'headers', 'max_early_data',
                           'early_data_header_name'}, '客户端传输')
        if transport.get('type') != 'ws':
            raise ConfigError('目前跨格式导入仅支持 TCP 或 WebSocket 传输')
        if 'max_early_data' in transport and (type(transport['max_early_data']) is not int or
                                            transport['max_early_data'] < 0):
            raise ConfigError('WebSocket early-data 大小无效')
        if 'headers' in transport and (not isinstance(transport['headers'], dict) or
                                       any(not isinstance(key, str) or not isinstance(value, str)
                                           for key, value in transport['headers'].items())):
            raise ConfigError('WebSocket headers 格式无效')
        for field in ('path', 'early_data_header_name'):
            if field in transport and not isinstance(transport[field], str):
                raise ConfigError('WebSocket 路径或 early-data 标头格式无效')
    if 'obfs' in out:
        fields(out['obfs'], {'type', 'password'}, 'HY2 混淆')
    fingerprint = validate_tls(out['tls']) if 'tls' in out else None
    if protocol in ('hysteria2', 'tuic', 'anytls') and not out.get('tls', {}).get('enabled'):
        raise ConfigError('HY2、TUIC 和 AnyTLS 需要 TLS 配置')
    return {'outbound': out, 'certificate_fingerprint': fingerprint}


def import_clients(config_path, label, binary):
    """Import supported proxy outbounds; ignore client routing and local listeners."""
    label_check(label)
    config = read_json(config_path)
    if not isinstance(config, dict) or not isinstance(config.get('outbounds'), list):
        raise ConfigError('客户端配置必须包含 outbounds 数组')
    items = []
    for outbound in config['outbounds']:
        if not isinstance(outbound, dict):
            raise ConfigError('客户端 outbound 必须为对象')
        if outbound.get('type') in SKIPPED_TYPES:
            continue
        item = validate_outbound(outbound)
        item['outbound']['tag'] = f'{label}-{item["outbound"]["type"]}-{len(items) + 1}'
        items.append(item)
    if not items:
        raise ConfigError('客户端配置中没有受支持的代理节点')
    check_version(binary)
    check_config(binary, {'outbounds': [item['outbound'] for item in items]})
    return items
