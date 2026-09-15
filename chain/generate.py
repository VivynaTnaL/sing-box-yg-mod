#!/usr/bin/env python3
"""Generate portable sing-box server configuration without installing a service.

The input is a small, explicit parameter document, not shell code. Certificate
paths are resolved relative to that document and embedded in the output. Only
the supplied core's version, key generation and config check commands execute.
"""
import argparse
import base64
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
import uuid

from chain import ConfigError, VERSION, check_version, domain, port, read_json, run_core


DEFAULT_PORTS = dict(zip(('vless', 'vmess', 'hysteria2', 'tuic', 'anytls'), range(20001, 20006)))
EXAMPLE = {
    'schema_version': 1,
    'listen': '0.0.0.0',
    'tls': {'server_name': 'proxy.example.com',
            'certificate_path': './cert.pem', 'key_path': './key.pem'},
    'protocols': [
        {'type': 'vless', 'port': 20001, 'reality': {'server_name': 'www.example.com'}},
        {'type': 'vmess', 'port': 20002, 'path': '/vmess'},
        {'type': 'hysteria2', 'port': 20003},
        {'type': 'tuic', 'port': 20004},
        {'type': 'anytls', 'port': 20005},
    ],
}


def fields(value, required, optional, name):
    if (not isinstance(value, dict) or not set(required.split()) <= set(value)
            or set(value) - set((required + ' ' + optional).split())):
        raise ConfigError(name + ' 缺少必需字段或包含未知字段')


def nonempty_text(value, name, maximum=1024):
    if (not isinstance(value, str) or not value or len(value) > maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ConfigError(name + ' 必须是非空文本，且不能包含控制字符')
    return value


def user_uuid(value):
    if not isinstance(value, str):
        raise ConfigError('UUID 格式错误')
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise ConfigError('UUID 格式错误') from None
    if str(parsed) != value.lower():
        raise ConfigError('UUID 必须使用带连字符的标准格式')
    return str(parsed)


def tls_material(params, base):
    fields(params, 'server_name certificate_path key_path', '', 'TLS 参数')
    domain(params['server_name'])
    result = {'enabled': True, 'server_name': params['server_name']}
    for field in ('certificate', 'key'):
        path = Path(nonempty_text(params[field + '_path'], '证书或私钥路径', 4096))
        if not path.is_absolute():
            path = base / path
        # Core check verifies the PEM format and matching key before publishing.
        content = path.read_text(encoding='utf-8')
        if not content.strip() or len(content) > 1024 * 1024:
            raise ConfigError('证书或私钥文件为空或过大')
        result[field] = content.splitlines()
    return result


def reality_tls(params, binary):
    fields(params, 'server_name', 'private_key short_id handshake_server handshake_port', 'Reality 参数')
    domain(params['server_name'])
    handshake = params.get('handshake_server', params['server_name'])
    nonempty_text(handshake, 'Reality 握手地址', 253)
    try:
        ip = ipaddress.ip_address(handshake)
    except ValueError:
        domain(handshake)
    else:
        if ip.is_unspecified or ip.is_multicast or '%' in handshake:
            raise ConfigError('Reality 握手地址不能为未指定或组播地址')
    handshake_port = port(params.get('handshake_port', 443))
    private_key = params.get('private_key')
    if 'private_key' not in params:
        output = run_core(binary, 'generate', 'reality-keypair')
        match = re.search(r'^PrivateKey:\s*([A-Za-z0-9_-]{43})\s*$', output, re.M)
        if not match:
            raise ConfigError('内核未返回有效的 Reality 私钥')
        private_key = match[1]
    if (not isinstance(private_key, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', private_key)
            or len(base64.urlsafe_b64decode(private_key + '=')) != 32):
        raise ConfigError('Reality 私钥必须是 32 字节的 URL-safe Base64')
    short_id = params.get('short_id', secrets.token_hex(8))
    if (not isinstance(short_id, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,8}', short_id)):
        raise ConfigError('Reality short_id 必须是 2–16 位、偶数长度的十六进制文本')
    return {'enabled': True, 'server_name': params['server_name'], 'reality': {
        'enabled': True, 'handshake': {'server': handshake, 'server_port': handshake_port},
        'private_key': private_key, 'short_id': [short_id.lower()]}}


def render(params, base, binary):
    """Build a standard config; this does not write files or start a listener."""
    fields(params, 'schema_version protocols', 'listen tls', '生成参数')
    if type(params['schema_version']) is not int or params['schema_version'] != 1:
        raise ConfigError('生成参数仅支持 schema_version 1')
    listen = params.get('listen', '0.0.0.0')
    if not isinstance(listen, str) or '%' in listen:
        raise ConfigError('listen 必须是 IPv4 或 IPv6 地址')
    try:
        ip = ipaddress.ip_address(listen)
    except ValueError:
        raise ConfigError('listen 必须是 IPv4 或 IPv6 地址') from None
    if ip.is_multicast:
        raise ConfigError('listen 不能为组播地址')
    protocols = params['protocols']
    if not isinstance(protocols, list) or not protocols:
        raise ConfigError('protocols 必须是非空协议列表')
    common_tls = tls_material(params['tls'], Path(base)) if 'tls' in params else None
    seen_types, seen_ports, inbounds = set(), set(), []
    for protocol in protocols:
        if not isinstance(protocol, dict) or not isinstance(protocol.get('type'), str):
            raise ConfigError('每个协议必须包含 type')
        kind = protocol['type']
        if kind not in DEFAULT_PORTS:
            raise ConfigError('仅支持 VLESS、VMess、Hysteria2、TUIC、AnyTLS')
        optional = {'vless': 'uuid reality', 'vmess': 'uuid path tls',
                    'hysteria2': 'password', 'tuic': 'uuid password', 'anytls': 'password'}[kind]
        fields(protocol, 'type', 'port ' + optional, '协议参数')
        if kind in seen_types:
            raise ConfigError('每种协议只允许配置一次')
        seen_types.add(kind)
        listen_port = port(protocol.get('port', DEFAULT_PORTS[kind]))
        if listen_port in seen_ports:
            raise ConfigError('各协议端口必须不同')
        seen_ports.add(listen_port)
        user = {'name': kind + '-user'}
        if kind in ('vless', 'vmess', 'tuic'):
            user['uuid'] = user_uuid(protocol['uuid']) if 'uuid' in protocol else str(uuid.uuid4())
        if kind in ('hysteria2', 'tuic', 'anytls'):
            user['password'] = (nonempty_text(protocol['password'], '密码') if 'password' in protocol
                                else secrets.token_urlsafe(32))
        inbound = {'type': kind, 'tag': kind + '-in', 'listen': str(ip),
                   'listen_port': listen_port, 'users': [user]}
        tls_enabled = protocol.get('tls', True)
        if type(tls_enabled) is not bool:
            raise ConfigError('VMess 的 tls 必须为 true 或 false')
        if kind == 'vless':
            user['flow'] = 'xtls-rprx-vision'
            inbound['tls'] = reality_tls(protocol.get('reality'), binary)
        elif tls_enabled:
            if common_tls is None:
                raise ConfigError('除 Reality 或显式禁用 TLS 的 VMess 外，协议需要顶层 tls 证书参数')
            inbound['tls'] = copy.deepcopy(common_tls)
        if kind == 'vmess':
            path = nonempty_text(protocol.get('path', '/vmess'), 'WebSocket 路径')
            if not path.startswith('/') or any(char in path for char in ('?', '#', ' ')):
                raise ConfigError('WebSocket 路径必须以 / 开始，不能包含空格、查询或片段')
            inbound['transport'] = {'type': 'ws', 'path': path}
        elif kind in ('hysteria2', 'tuic'):
            inbound['tls']['alpn'] = ['h3']
            if kind == 'tuic':
                inbound['congestion_control'] = 'bbr'
        inbounds.append(inbound)
    return {'log': {'level': 'info', 'timestamp': True}, 'inbounds': inbounds,
            'outbounds': [{'type': 'direct', 'tag': 'direct'}],
            'route': {'final': 'direct'}}


def generate_values(params, base, output, binary):
    """Validate using the pinned core, then publish a new 0600 file atomically."""
    output = Path(output)
    if os.path.lexists(output):
        raise ConfigError('输出文件已存在；请选择新路径，已有文件不会被覆盖')
    if not output.parent.is_dir():
        raise ConfigError('输出目录不存在，请先创建目录')
    check_version(binary)
    config = render(params, base, binary)
    fd, temp_path = tempfile.mkstemp(prefix='.generate-', suffix='.json', dir=output.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(config, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        run_core(binary, 'check', '-c', temp_path)
        # link() is atomic and refuses a destination created during core check.
        # replace() would silently overwrite another writer's file.
        try:
            os.link(temp_path, output)
        except FileExistsError:
            raise ConfigError('输出文件已存在；已有文件不会被覆盖') from None
    finally:
        os.unlink(temp_path)
    return config


def generate(params_path, output, binary):
    params_path = Path(params_path)
    return generate_values(read_json(params_path), params_path.resolve().parent, output, binary)


def ask(label, default=None, validate=None):
    """Retry ordinary input mistakes without printing credentials."""
    while True:
        suffix = (' [' + str(default) + ']') if default is not None else ''
        value = input(label + suffix + '：').strip()
        value = str(default) if not value and default is not None else value
        try:
            if not value:
                raise ConfigError('此项不能为空')
            return validate(value) if validate else value
        except (ConfigError, ValueError) as exc:
            print(str(exc) if isinstance(exc, ConfigError) else '输入格式不正确，请重试。')


def selected_protocols(value):
    if value.lower() in ('all', '全部'):
        return list(DEFAULT_PORTS)
    mapping = {str(index): kind for index, kind in enumerate(DEFAULT_PORTS, 1)}
    values = [mapping.get(part.lower(), part.lower()) for part in re.split(r'[,，\s]+', value)]
    if not values or any(kind not in DEFAULT_PORTS for kind in values) or len(set(values)) != len(values):
        raise ConfigError('请输入协议编号或名称，用逗号分隔，且不要重复')
    return values


def tls_choice(value):
    if value not in ('1', '2'):
        raise ConfigError('请选择 1 或 2')
    return value


def prepare_binary(binary, output, download=False, interactive=False):
    if binary is None and interactive and not download:
        value = ask('sing-box ' + VERSION + ' 内核路径，输入 auto 自动下载校验', 'auto')
        if value.lower() == 'auto':
            download = True
        else:
            binary = Path(value).expanduser()
    if binary is not None:
        return Path(binary).expanduser().resolve()
    if not download:
        raise ConfigError('请指定 --binary，或使用 --download-core 下载已锁定版本的内核')
    directory = Path(output).resolve().parent / '.sb-generator-core'
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink():
        raise ConfigError('内核缓存目录不能为符号链接')
    path = directory / ('sing-box-' + VERSION)
    if not path.exists():
        print('下载并校验 sing-box ' + VERSION + ' 到 ' + str(path))
        result = subprocess.run([sys.executable, str(Path(__file__).with_name('fetch-core.py')),
                                 '--output', str(path)], capture_output=True, text=True, timeout=240)
        if result.returncode:
            raise ConfigError('内核下载或 SHA256 校验失败；可以使用 --binary 指定本地内核')
    check_version(path)
    return path


def self_signed_tls(directory, server_name):
    """Generate temporary PEM material; render embeds it before cleanup."""
    domain(server_name)
    certificate, key = Path(directory) / 'cert.pem', Path(directory) / 'key.pem'
    result = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                             'ec_paramgen_curve:P-256', '-nodes', '-days', '365',
                             '-subj', '/CN=' + server_name, '-addext', 'subjectAltName=DNS:' + server_name,
                             '-keyout', str(key), '-out', str(certificate)],
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ConfigError('自签证书生成失败，请检查 openssl 是否可用')
    return {'server_name': server_name, 'certificate_path': str(certificate), 'key_path': str(key)}


def wizard(output=None, binary=None, download=False):
    print('只生成服务端配置向导：生成的文件可交给链式附件，也可自行运行。')
    if output is None:
        output = Path(ask('输出配置文件', './server.json')).expanduser()
    output = Path(output).absolute()
    if os.path.lexists(output):
        raise ConfigError('输出文件已存在；请选择新路径，已有文件不会被覆盖')
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    protocols = ask('协议：1 VLESS Reality，2 VMess WS，3 Hysteria2，4 TUIC，5 AnyTLS；可多选',
                    'all', selected_protocols)
    start = ask('起始端口，所选协议依次递增', 20001, lambda value: port(int(value)))
    if start + len(protocols) - 1 > 65535:
        raise ConfigError('所选协议端口超出 65535，请使用更小的起始端口')
    listen = ask('监听地址', '0.0.0.0')
    params = {'schema_version': 1, 'listen': listen, 'protocols': []}
    for index, kind in enumerate(protocols):
        item = {'type': kind, 'port': start + index}
        if kind == 'vless':
            item['reality'] = {'server_name': ask('Reality 握手域名', 'www.apple.com')}
        elif kind == 'vmess':
            item['path'] = ask('VMess WebSocket 路径', '/vmess')
        params['protocols'].append(item)
    needs_tls = any(kind != 'vless' for kind in protocols)
    with tempfile.TemporaryDirectory(prefix='.sb-cert-', dir=output.parent) as temporary:
        if needs_tls:
            choice = ask('TLS 证书：1 自动生成自签证书，2 使用已有证书', '1',
                         tls_choice)
            name = ask('TLS 服务器域名', 'proxy.example.com')
            if choice == '1':
                params['tls'] = self_signed_tls(temporary, name)
                print('证书将嵌入配置；客户端使用时需要信任该证书，附件导出会携带证书固定信息。')
            else:
                params['tls'] = {'server_name': name,
                                 'certificate_path': str(Path(ask('证书 PEM 文件')).expanduser().absolute()),
                                 'key_path': str(Path(ask('私钥 PEM 文件')).expanduser().absolute())}
        binary = prepare_binary(binary, output, download, interactive=True)
        generate_values(params, Path.cwd(), output, binary)
    return output, binary


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='只生成 sing-box ' + VERSION + ' 服务端配置，不安装、不启动服务。',
        epilog='不传 --params 即进入中文向导。凭据自动生成，TLS 证书嵌入输出。原 sb 默认流程保持不变。')
    parser.add_argument('--example', action='store_true', help='打印无凭据的五协议参数模板后退出')
    parser.add_argument('--params', type=Path, help='参数 JSON 文件；格式参见 --example')
    parser.add_argument('--output', type=Path, help='尚不存在的目标配置文件，权限 0600')
    parser.add_argument('--binary', type=Path, help='用于校验的 sing-box ' + VERSION + ' 可执行文件')
    parser.add_argument('--download-core', action='store_true', help='自动下载并校验锁定内核，保存在输出目录的 .sb-generator-core 内')
    parser.add_argument('--interactive', '--wizard', action='store_true', help='中文交互向导（不传 --params 时默认）')
    args = parser.parse_args(argv)
    if args.example:
        if args.params is not None or args.output is not None or args.binary is not None or args.download_core or args.interactive:
            parser.error('--example 不能与生成参数同时使用')
        print(json.dumps(EXAMPLE, ensure_ascii=False, indent=2))
        return 0
    if args.params and args.interactive:
        parser.error('--params 与 --interactive 不能同时使用')
    if args.params and args.output is None:
        parser.error('使用 --params 时必须指定 --output')
    if args.binary and args.download_core:
        parser.error('--binary 与 --download-core 不能同时使用')
    try:
        if args.params is None:
            args.output, args.binary = wizard(args.output, args.binary, args.download_core)
        else:
            args.binary = prepare_binary(args.binary, args.output, args.download_core)
            generate(args.params, args.output, args.binary)
    except (EOFError, KeyboardInterrupt):
        print('\n已取消，未启动服务。', file=sys.stderr)
        return 130
    except (ConfigError, ValueError, OSError, subprocess.SubprocessError) as exc:
        print('生成失败：' + (str(exc) if isinstance(exc, ConfigError)
                         else '请检查参数文件、证书和内核路径，诊断未显示以免泄露凭据。'), file=sys.stderr)
        return 1
    print('已生成并校验配置：' + str(args.output))
    print('手动运行：' + shlex.join([str(args.binary), 'run', '-c', str(args.output)]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
