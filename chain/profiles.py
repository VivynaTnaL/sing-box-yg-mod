"""Import standard sing-box configurations without depending on their generator."""
import base64
import copy
import hashlib
import ipaddress
import re
import secrets
import ssl
import subprocess
from pathlib import Path
from urllib.parse import quote, urlencode

from chain import (ConfigError, METHOD, PROTOCOLS, check_config, check_version,
                   decode64, new_user, normalize_inbounds, port, read_json, run_core)


def host(value):
    if not isinstance(value, str) or not value or any(c.isspace() for c in value):
        raise ConfigError('请提供客户端可访问的 IP 或域名，不含协议和端口')
    try:
        address = ipaddress.ip_address(value)
        if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
            raise ConfigError('公网访问地址不能是通配、回环或链路本地地址')
        return str(address)
    except ValueError as error:
        if isinstance(error, ConfigError):
            raise
    if len(value) > 253 or not re.fullmatch(r'[A-Za-z0-9.-]+', value):
        raise ConfigError('访问域名格式无效')
    if any(not x or len(x) > 63 or x.startswith('-') or x.endswith('-') for x in value.split('.')):
        raise ConfigError('访问域名格式无效')
    return value.lower()


def openssl(*args, data):
    result = subprocess.run(['openssl', *args], input=data, capture_output=True, timeout=15)
    if result.returncode:
        raise ConfigError('证书或 Reality 密钥无法读取；需要可用的 openssl')
    return result.stdout


def public_key(private):
    raw = decode64(private)
    if len(raw) != 32:
        raise ConfigError('Reality 私钥长度无效')
    der = openssl('pkey', '-inform', 'DER', '-pubout', '-outform', 'DER',
                  data=bytes.fromhex('302e020100300506032b656e04220420') + raw)
    if len(der) != 44 or not der.startswith(bytes.fromhex('302a300506032b656e032100')):
        raise ConfigError('Reality 公钥推导失败')
    return base64.urlsafe_b64encode(der[-32:]).decode().rstrip('=')


def certificate_pins(certificate):
    pem = certificate if isinstance(certificate, str) else '\n'.join(certificate)
    match = re.search(r'-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----', pem)
    if not match:
        raise ConfigError('TLS 配置缺少可读取的证书')
    pem = match[0]
    der = ssl.PEM_cert_to_DER_cert(pem)
    public = openssl('x509', '-pubkey', '-noout', data=pem.encode())
    spki = openssl('pkey', '-pubin', '-outform', 'DER', data=public)
    return hashlib.sha256(der).hexdigest(), base64.b64encode(hashlib.sha256(spki).digest()).decode()


def check_dependencies(inbound):
    """Reject implicit files/providers/transports that cannot survive source removal."""
    if inbound.get('detour') or inbound.get('multiplex', {}).get('enabled'):
        raise ConfigError('请先关闭待导入入站的 detour / multiplex')
    transport = inbound.get('transport', {})
    if transport and (transport.get('type') != 'ws' or set(transport) - {'type', 'path', 'headers', 'max_early_data', 'early_data_header_name'}):
        raise ConfigError('目前仅导入 TCP 或 WebSocket 入站')
    if 'max_early_data' in transport and (type(transport['max_early_data']) is not int or transport['max_early_data'] < 0):
        raise ConfigError('WebSocket early-data 大小无效')
    tls = inbound.get('tls', {})
    if any(tls.get(k) for k in ('acme', 'certificate_provider', 'ech', 'client_authentication',
                               'client_certificate', 'client_certificate_path', 'client_certificate_public_key_sha256')):
        raise ConfigError('请把证书提供器/ACME 转为证书文件；暂不导入 ECH 或双向 TLS')
    def walk(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key.endswith('_path') or key in ('bind_interface', 'routing_mark', 'netns'):
                    raise ConfigError('入站还依赖外部文件或网络设置，无法独立导入')
                walk(value)
        elif isinstance(obj, list):
            for value in obj:
                walk(value)
    walk(inbound)


def select_inbounds(path, selected=()):
    path = Path(path).resolve()
    config = read_json(path)
    source = config.get('inbounds', [])
    if not isinstance(source, list):
        raise ConfigError('sing-box 配置的 inbounds 必须为数组')
    named = []
    tags = set()
    for index, item in enumerate(source):
        item = copy.deepcopy(item)
        name = item.get('tag') or f'{item.get("type", "inbound")}-{index + 1}'
        if name in tags:
            raise ConfigError('源配置的入站 tag 必须唯一')
        tags.add(name)
        if not selected or name in selected:
            item['tag'] = name
            named.append(item)
    if set(selected) - tags:
        raise ConfigError('指定的入站 tag 不存在')
    if not named:
        raise ConfigError('没有可导入的入站')
    result = normalize_inbounds({'inbounds': named}, path.parent)
    for item in result:
        check_dependencies(item)
        port(item['listen_port'])
    return result, {port(i['listen_port']) for i in source if 'listen_port' in i}


def client(inbound, user, server, label):
    protocol = inbound['type']
    tls = inbound.get('tls', {})
    transport = inbound.get('transport', {})
    result = {'type': protocol, 'tag': label, 'server': host(server), 'server_port': inbound['listen_port']}
    for field in ('uuid', 'password', 'flow'):
        if field in user:
            result[field] = user[field]
    if protocol == 'vmess':
        result.update(security='auto', alter_id=user.get('alterId', 0))
    if protocol == 'tuic':
        result['congestion_control'] = inbound.get('congestion_control', 'cubic')
    if protocol == 'hysteria2' and inbound.get('obfs'):
        result['obfs'] = copy.deepcopy(inbound['obfs'])
    pin = None
    if tls.get('enabled'):
        client_tls = {'enabled': True, 'server_name': tls.get('server_name', server), 'insecure': False}
        for field in ('alpn', 'min_version', 'max_version', 'cipher_suites'):
            if field in tls:
                client_tls[field] = copy.deepcopy(tls[field])
        reality = tls.get('reality', {})
        if reality.get('enabled'):
            client_tls['utls'] = {'enabled': True, 'fingerprint': 'chrome'}
            client_tls['reality'] = {'enabled': True, 'public_key': public_key(reality['private_key']),
                                     'short_id': (reality.get('short_id') or [''])[0]}
        else:
            pin, spki = certificate_pins(tls.get('certificate', []))
            client_tls['certificate_public_key_sha256'] = [spki]
        result['tls'] = client_tls
    elif protocol in ('hysteria2', 'tuic', 'anytls'):
        raise ConfigError('HY2、TUIC 和 AnyTLS 需要 TLS 配置')
    if transport:
        result['transport'] = copy.deepcopy(transport)
    return {'outbound': result, 'certificate_fingerprint': pin}


def share_link(item):
    """URI format carries public parameters only; full profiles also carry TLS pins."""
    import json
    out = item['outbound']
    protocol, tls, tr = out['type'], out.get('tls', {}), out.get('transport', {})
    name = out['tag']
    if protocol == 'vmess':
        data = {'v': '2', 'ps': name, 'add': out['server'], 'port': str(out['server_port']),
                'id': out['uuid'], 'aid': str(out.get('alter_id', 0)), 'scy': out.get('security', 'auto'),
                'net': tr.get('type', 'tcp'), 'type': 'none', 'path': tr.get('path', ''),
                'host': tr.get('headers', {}).get('Host', ''), 'tls': 'tls' if tls.get('enabled') else '',
                'sni': tls.get('server_name', ''), 'insecure': '0'}
        return 'vmess://' + base64.b64encode(json.dumps(data, separators=(',', ':')).encode()).decode()
    info = quote(out.get('uuid', out.get('password', '')), safe='')
    if protocol == 'tuic':
        info += ':' + quote(out['password'], safe='')
    query = {}
    if tls.get('enabled'):
        query.update(sni=tls.get('server_name', ''), insecure='0')
        if tls.get('alpn'):
            query['alpn'] = ','.join(tls['alpn'])
        if item.get('certificate_fingerprint'):
            query['pinSHA256'] = item['certificate_fingerprint']
    if protocol == 'vless':
        query.update(encryption='none', security='tls' if tls.get('enabled') else 'none', type=tr.get('type', 'tcp'))
        if out.get('flow'):
            query['flow'] = out['flow']
        if tls.get('reality', {}).get('enabled'):
            query.update(security='reality', fp='chrome', pbk=tls['reality']['public_key'], sid=tls['reality']['short_id'])
        if tr:
            query.update(path=tr.get('path', '/'), host=tr.get('headers', {}).get('Host', ''))
    if protocol == 'tuic':
        query['congestion_control'] = out['congestion_control']
    if protocol == 'hysteria2' and out.get('obfs'):
        query.update(obfs=out['obfs']['type'], **{'obfs-password': out['obfs']['password']})
    server = '[' + out['server'] + ']' if ':' in out['server'] else out['server']
    return f'{protocol}://{info}@{server}:{out["server_port"]}?{urlencode(query)}#{quote(name, safe="")}'


def import_entry(path, server, binary, port_start=None, selected=(), previous=None):
    check_version(binary)
    host(server)
    source, reserved = select_inbounds(path, selected)
    existing = {p['source_tag']: p for p in (previous or [])}
    profiles, used = [], set()
    next_port = port_start if port_start is not None else 21000
    port(next_port)
    for index, inbound in enumerate(source):
        tag = inbound['tag']
        old = existing.get(tag)
        if old and old['inbound']['type'] != inbound['type']:
            raise ConfigError('同一 tag 的协议发生变化，请为新协议使用新 tag')
        if old and port_start is None:
            chosen = old['inbound']['listen_port']
        else:
            if port_start is None:
                while next_port in reserved or next_port in used:
                    next_port += 1
            chosen = port(next_port)
            next_port += 1
        if chosen in reserved or chosen in used:
            raise ConfigError('附件端口与源配置或其他附件入站冲突，请选择新的起始端口')
        used.add(chosen)
        listen = '::' if ':' in inbound.get('listen', '0.0.0.0') else '0.0.0.0'
        inbound.update(tag=f'addon-{index + 1}', listen=listen, listen_port=chosen)
        old_users = old['inbound']['users'] if old else []
        inbound['users'] = [dict(new_user(inbound['type'], u, f'addon-{index + 1}-{j + 1}'),
                                 **({k: old_users[j][k] for k in ('uuid', 'password') if k in old_users[j]}
                                    if j < len(old_users) else {}))
                            for j, u in enumerate(inbound['users'])]
        reality = inbound.get('tls', {}).get('reality', {})
        if reality.get('enabled'):
            if old and old['inbound'].get('tls', {}).get('reality', {}).get('enabled'):
                previous_reality = old['inbound']['tls']['reality']
                reality.update(private_key=previous_reality['private_key'], short_id=previous_reality['short_id'])
            else:
                keys = dict(re.findall(r'(PrivateKey|PublicKey):\s*(\S+)', run_core(binary, 'generate', 'reality-keypair')))
                reality.update(private_key=keys['PrivateKey'], short_id=[secrets.token_hex(8)])
        clients = [client(inbound, u, server, f'A-to-B-{inbound["type"]}-{index + 1}-{j + 1}')
                   for j, u in enumerate(inbound['users'])]
        profiles.append({'source_tag': tag, 'inbound': inbound, 'clients': clients})
    return profiles


def import_direct(path, server, label, selected=()):
    if not label or len(label) > 64 or any(c in label for c in '\r\n'):
        raise ConfigError('直连节点组名称无效')
    inbounds, _ = select_inbounds(path, selected)
    return [client(i, user, server, f'{label}-{i["type"]}-{n + 1}-{j + 1}')
            for n, i in enumerate(inbounds) for j, user in enumerate(i['users'])]


def handoff(path):
    config = read_json(path)
    outs = config.get('outbounds', [])
    if not isinstance(outs, list) or len(outs) != 1:
        raise ConfigError('B 对接配置需要且只能包含一个 SS2022 outbound')
    out = copy.deepcopy(outs[0])
    if set(out) - {'type', 'tag', 'server', 'server_port', 'method', 'password'}:
        raise ConfigError('对接出站包含外部依赖或未知字段')
    if out.get('type') != 'shadowsocks' or out.get('method') != METHOD:
        raise ConfigError('服务器间对接需要 SS2022 AES-256-GCM')
    host(out['server'])
    port(out['server_port'])
    if len(base64.b64decode(out['password'], validate=True)) != 32:
        raise ConfigError('SS2022 密钥长度无效')
    out['tag'] = 'to-exit'
    return out


def entry_config(profiles, link):
    tags = [p['inbound']['tag'] for p in profiles]
    return {'log': {'level': 'warn'}, 'inbounds': [p['inbound'] for p in profiles],
            'dns': {'servers': [{'type': 'local', 'tag': 'local'}]},
            'outbounds': [copy.deepcopy(link)],
            'route': {'default_domain_resolver': 'local', 'rules': [
                {'inbound': tags, 'action': 'route', 'outbound': 'to-exit'}, {'action': 'reject'}]}}


def exit_config(server, listen_port, sources, password=None, reserved=()):
    # Handoff uses a precise IP, so ACL address-family selection is unambiguous.
    server = str(ipaddress.ip_address(host(server)))
    port(listen_port)
    if listen_port in reserved:
        raise ConfigError('SS2022 端口与原配置冲突')
    if not sources:
        raise ConfigError('需要至少一个中转 A 的实际出站 IP')
    cidrs = []
    for value in sources:
        address = ipaddress.ip_address(host(value))
        if address.version != ipaddress.ip_address(server).version or str(address) == server:
            raise ConfigError('A 出站 IP 与 B 地址需同地址族且不同')
        cidrs.append(str(ipaddress.ip_network(str(address) + ('/32' if address.version == 4 else '/128'))))
    password = password or base64.b64encode(secrets.token_bytes(32)).decode()
    inbound = {'type': 'shadowsocks', 'tag': 'addon-link', 'listen': '::' if ':' in server else '0.0.0.0',
               'listen_port': listen_port, 'method': METHOD, 'password': password}
    link = {'type': 'shadowsocks', 'tag': 'to-exit', 'server': server, 'server_port': listen_port,
            'method': METHOD, 'password': password}
    config = {'log': {'level': 'warn'}, 'inbounds': [inbound],
              'dns': {'servers': [{'type': 'local', 'tag': 'local'}]},
              'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'rules': [
                  {'source_ip_cidr': cidrs, 'invert': True, 'action': 'reject'},
                  {'action': 'resolve', 'server': 'local'}, {'ip_is_private': True, 'action': 'reject'},
                  {'inbound': ['addon-link'], 'action': 'route', 'outbound': 'direct'}, {'action': 'reject'}]}}
    return config, {'outbounds': [link]}
