#!/usr/bin/env python3
"""Independent chain manager. Run without arguments for the Chinese menu."""
import argparse
import base64
import copy
import fcntl
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager, nullcontext

from chain import ConfigError, check_config, check_version, read_json, write_private, write_text_private
import profiles

DEFAULT_STATE = Path('/etc/sing-box-addon')


class Store:
    def __init__(self, root):
        self.root = Path(root).absolute()

    @contextmanager
    def locked(self):
        if self.root.is_symlink():
            raise ConfigError('附件状态目录不能为符号链接')
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with open(self.root / '.manager.lock', 'a', opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW, 0o600)) as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ConfigError('另一个管理操作正在执行') from None
            yield

    def read(self, name='state.json', optional=False):
        path = self.root / name
        if optional and not path.exists():
            return None
        if not path.is_file() or path.is_symlink():
            raise ConfigError('尚未初始化附件，或状态文件路径异常')
        data = read_json(path)
        if name == 'state.json' and (data.get('schema_version') != 1 or data.get('role') not in ('entry', 'exit')):
            raise ConfigError('附件状态版本无效')
        return data

    def save(self, data, name='state.json'):
        write_private(self.root / name, data)

    @contextmanager
    def transaction(self, *names):
        """Restore manager metadata if publication or a later save fails."""
        from runtime import atomic_write
        previous = {}
        for name in names:
            path = self.root / name
            if path.is_symlink():
                raise ConfigError('拒绝备份符号链接状态文件')
            previous[path] = path.read_bytes() if path.exists() else None
        try:
            yield
        except BaseException:
            for path, data in previous.items():
                if data is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic_write(path, data)
            raise


def binary_for(args, store, state=None):
    value = getattr(args, 'binary', None) or (state or {}).get('binary')
    if not value:
        installed = Path('/opt/sing-box-addon/sing-box')
        value = installed if installed.is_file() else store.root / 'core'
    path = Path(value).resolve()
    if not path.is_file():
        if getattr(args, 'binary', None):
            raise ConfigError('指定内核文件不存在')
        # A retained state can refer to an uninstalled binary. Reuse/download the
        # cache, then install again; never download into a missing /opt directory.
        path = store.root / 'core'
    if not path.is_file():
        fetcher = Path(__file__).with_name('fetch-core.py')
        print('下载并验证固定版本 sing-box 内核……')
        result = subprocess.run([sys.executable, str(fetcher), '--output', str(path)], capture_output=True)
        if result.returncode:
            raise ConfigError('内核下载失败；也可用 --binary 指定已验证的内核')
    check_version(path)
    return str(path)


def default_policy():
    from policy import load_policy
    return load_policy('cn-direct')


def initialize_exit(args, store):
    if store.read(optional=True):
        raise ConfigError('附件已经初始化；更新落地请使用 update-exit，或选择新的状态目录')
    binary = binary_for(args, store)
    reserved = set()
    if args.config:
        source = read_json(args.config)
        reserved = {i['listen_port'] for i in source.get('inbounds', []) if 'listen_port' in i}
    config, link = profiles.exit_config(args.address, args.port, args.entry_source, reserved=reserved)
    check_config(binary, config)
    state = {'schema_version': 1, 'role': 'exit', 'binary': binary, 'server_config': config,
             'handoff': link, 'public_host': args.address, 'entry_sources': args.entry_source,
             'policy': default_policy(), 'groups': {}}
    store.save(state)
    # Explicit private exchange file in standard sing-box format, never a subscription asset.
    write_private(store.root / 'handoff.json', link)
    return state


def initialize_entry(args, store, refresh=False):
    old = store.read(optional=True)
    if bool(old) != refresh or old and old['role'] != 'entry':
        raise ConfigError('新建请使用 init-entry；现有中转请使用 import-config')
    binary = binary_for(args, store, old)
    link = profiles.handoff(args.link) if getattr(args, 'link', None) else copy.deepcopy(old['server_config']['outbounds'][0])
    address = args.address or (old or {}).get('public_host')
    selected = args.inbound
    if selected is None and old:
        selected = [p['source_tag'] for p in old['profiles']]
    imported = profiles.import_entry(args.config, address, binary, args.port_start,
                                     selected or (), (old or {}).get('profiles'))
    server = profiles.entry_config(imported, link)
    # Prevent a common accidental A -> A recursion when public endpoint is shared.
    if link['server'] == address and link['server_port'] in {p['inbound']['listen_port'] for p in imported}:
        raise ConfigError('落地地址指向本机附件入口，会形成代理循环')
    check_config(binary, server)
    state = copy.deepcopy(old) if old else {'schema_version': 1, 'role': 'entry', 'policy': default_policy(), 'groups': {}}
    state.update(binary=binary, public_host=address, profiles=imported, server_config=server)
    state['groups']['A-to-B'] = [c for p in imported for c in p['clients']]
    store.save(state)
    return state


def export_clients(state, dest):
    from export_clash import convert, yaml_text
    from policy import apply_mihomo, apply_singbox
    groups = state.get('groups', {})
    if not groups:
        return False
    nodes, outbound_nodes, mh_groups, sb_groups, links = [], [], [], [], []
    names = set()
    for index, (name, clients) in enumerate(groups.items(), 1):
        members = []
        for item in clients:
            item = copy.deepcopy(item)
            # Prefix prevents collisions between independently imported groups.
            item['outbound']['tag'] = f'{index}.{len(members) + 1}-{item["outbound"]["tag"]}'
            tag = item['outbound']['tag']
            if tag in names:
                raise ConfigError('客户端节点名称重复')
            names.add(tag)
            members.append(tag)
            link = profiles.share_link(item)
            node = convert(link)
            node['name'] = tag
            if item.get('certificate_fingerprint'):
                node['fingerprint'] = item['certificate_fingerprint']
            transport = item['outbound'].get('transport', {})
            if transport.get('type') == 'ws':
                ws = {'path': transport.get('path', '/')}
                for source, target in (('headers', 'headers'), ('max_early_data', 'max-early-data'),
                                       ('early_data_header_name', 'early-data-header-name')):
                    if source in transport:
                        ws[target] = copy.deepcopy(transport[source])
                node['ws-opts'] = ws
            nodes.append(node)
            outbound_nodes.append(item['outbound'])
            links.append(link)
        if not members:
            raise ConfigError('节点组不能为空')
        mh_groups.append({'name': name, 'type': 'select', 'proxies': members})
        sb_groups.append({'type': 'selector', 'tag': f'group-{index}', 'outbounds': members})
    mh = {'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'log-level': 'warning',
          'proxies': nodes, 'proxy-groups': [{'name': '代理选择', 'type': 'select', 'proxies': list(groups)}] + mh_groups}
    apply_mihomo(mh, state['policy'])
    sb = {'log': {'level': 'warn'},
          'inbounds': [{'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1', 'listen_port': 7890}],
          'outbounds': [{'type': 'selector', 'tag': 'proxy', 'outbounds': [g['tag'] for g in sb_groups]},
                        {'type': 'direct', 'tag': 'direct'}] + sb_groups + outbound_nodes}
    apply_singbox(sb, state['policy'])
    check_config(state['binary'], sb)
    write_text_private(dest / 'mihomo.yaml', yaml_text(mh))
    write_private(dest / 'sing-box.json', sb)
    raw = '\n'.join(links) + '\n'
    write_text_private(dest / 'nodes.txt', raw)
    write_text_private(dest / 'nodes.base64.txt', base64.b64encode(raw.encode()).decode() + '\n')
    return True


def build(store, state=None):
    from updates import ensure
    persist = state is None
    original = state if state is not None else store.read()
    state = ensure(store, original)
    check_config(state['binary'], state['server_config'])
    releases = store.root / 'releases'
    releases.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.build-', dir=releases) as tmp:
        staging = Path(tmp) / 'bundle'
        staging.mkdir(mode=0o700)
        write_private(staging / 'server.json', state['server_config'])
        if state.get('handoff'):
            write_private(staging / 'handoff.json', state['handoff'])
        has_clients = export_clients(state, staging)
        write_private(staging / 'manifest.json', {'schema_version': 1, 'role': state['role'],
                      'groups': list(state['groups']), 'clients': has_clients})
        dest = releases / secrets.token_hex(12)
        os.rename(staging, dest)
    if persist and state != original:
        store.save(state)
    return dest


def deploy(store):
    from runtime import Runtime
    from publish import Publisher
    from updates import ensure
    runtime = Runtime()
    if not runtime.binary.is_file():
        raise ConfigError('请先选择安装附件运行环境，或执行 install')
    state = store.read()
    # Deployed snapshots must survive removal of any import-time core path.
    state['binary'] = str(runtime.binary)
    state = ensure(store, state)
    release = build(store, state)
    subscription = store.read('publication.json', optional=True)
    # Hold all rollback contexts through the final metadata writes.
    with store.transaction('state.json', 'active.json'), runtime.transaction():
        runtime.apply(release / 'server.json')
        publisher = Publisher(subscription['root']) if subscription else None
        with publisher.transaction() if publisher else nullcontext():
            if publisher:
                publisher.publish(release)
            store.save(state)
            store.save({'release': str(release), 'state': state}, 'active.json')
    return release


def show_status(store):
    from runtime import Runtime
    from publish import Publisher
    state = store.read(optional=True)
    if not state:
        print('尚未初始化')
        return
    print('角色：' + ('中转 A' if state['role'] == 'entry' else '落地 B'))
    print('准备配置的监听端口：' + ', '.join(str(i['listen_port']) for i in state['server_config']['inbounds']))
    print('客户端分流：' + str(state['policy'].get('mode', '已保存')))
    from updates import source
    print('规则来源：' + source(state) + '；版本：' + str(state.get('geodata', {}).get('version', '尚未获取 / 本地规则')))
    from scheduler import Scheduler
    print('规则自动更新：' + json.dumps(Scheduler().status(), ensure_ascii=False))
    print('附件服务：' + json.dumps(Runtime().status(), ensure_ascii=False))
    active = store.read('active.json', optional=True)
    print('已部署版本：' + (Path(active['release']).name if active else '无；当前仅生成配置'))
    subscription = store.read('publication.json', optional=True)
    if subscription:
        print('订阅发布：' + json.dumps(Publisher(subscription['root']).status_service(), ensure_ascii=False))


def show_urls(store):
    from publish import Publisher
    settings = store.read('publication.json', optional=True)
    if not settings:
        raise ConfigError('尚未设置订阅发布')
    publisher = Publisher(settings['root'])
    print('以下地址含访问口令，请仅保存到自己的客户端：')
    for filename in ('mihomo.yaml', 'sing-box.json', 'nodes.txt', 'nodes.base64.txt'):
        print(filename + ': ' + publisher.url(settings['base_url'], filename))


def set_publication(args, store):
    from publish import Publisher
    active = store.read('active.json', optional=True)
    if not active or not active['state'].get('groups'):
        raise ConfigError('请先部署带客户端节点的配置，再发布订阅')
    publisher = Publisher(args.root)
    # Validate base URL before starting services or changing publication state.
    from urllib.parse import urlsplit
    parsed = urlsplit(args.base_url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.query or parsed.fragment:
        raise ConfigError('订阅基地址需为 http(s) URL，不含口令、查询参数或片段')
    parsed.port
    if Path(args.root).absolute() != Path('/var/lib/sing-box-addon-sub'):
        raise ConfigError('后台订阅服务使用 /var/lib/sing-box-addon-sub；自定义目录可用 publish.py serve 前台运行')
    Publisher._server_options(args.bind, args.port, args.cert, args.key)
    with store.transaction('publication.json'), publisher.transaction(), publisher.service_transaction():
        publisher.publish(Path(active['release']))
        publisher.install_service(bind=args.bind, port=args.port, cert=args.cert, key=args.key)
        publisher.start_service()
        store.save({'root': str(Path(args.root).absolute()), 'base_url': args.base_url,
                    'bind': args.bind, 'port': args.port}, 'publication.json')
    show_urls(store)


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('--state', type=Path, default=DEFAULT_STATE, help='独立状态目录')
    sub = result.add_subparsers(dest='command')
    for name in ('init-entry', 'import-config'):
        p = sub.add_parser(name, help='导入标准 sing-box 入站配置；分配附件独立端口')
        p.add_argument('--config', required=True)
        p.add_argument('--address', required=name == 'init-entry')
        p.add_argument('--link', required=name == 'init-entry', help='B 导出的标准 sing-box 出站配置')
        p.add_argument('--port-start', type=int)
        p.add_argument('--inbound', action='append', help='只选择指定 tag，可重复')
        p.add_argument('--binary')
    for name in ('init-exit', 'update-exit'):
        p = sub.add_parser(name, help='配置独立 SS2022 落地；不接管旧服务')
        p.add_argument('--address', required=True)
        p.add_argument('--entry-source', action='append', required=True)
        p.add_argument('--port', type=int, default=22000)
        p.add_argument('--config', help='可选源配置，仅用于排除占用端口')
        p.add_argument('--binary')
    p = sub.add_parser('add-direct', help='从标准服务端配置导出原直连节点，不改变原服务')
    p.add_argument('--config', required=True)
    p.add_argument('--address', required=True)
    p.add_argument('--label', required=True, choices=['A-direct', 'B-direct'])
    p.add_argument('--inbound', action='append')
    p = sub.add_parser('update-link', help='更换 B 对接配置，保留附件客户端凭据')
    p.add_argument('--link', required=True)
    p = sub.add_parser('rules', help='设置客户端分流及例外；不改变服务器链路规则')
    p.add_argument('--mode', choices=['cn-direct', 'lan-direct', 'global'], default='cn-direct')
    p.add_argument('--rules-dir')
    for flag in ('direct-domain', 'proxy-domain', 'direct-cidr', 'proxy-cidr'):
        p.add_argument('--' + flag, action='append', default=[])
    p = sub.add_parser('geodata', help='自动从 GitHub 获取 GeoIP+GeoSite；也可导入本机数据库，更新订阅无需重启')
    p.add_argument('--geoip')
    p.add_argument('--geosite')
    p.add_argument('--binary')
    p.add_argument('--force', action='store_true', help='强制重新下载并校验')
    p = sub.add_parser('rules-auto', help='每天自动更新 GitHub 规则及订阅，不重启代理')
    p.add_argument('action', choices=['enable', 'disable', 'status'])
    p = sub.add_parser('install', help='安装附件自己的核心、工具和服务')
    p.add_argument('--binary')
    for name in ('build', 'deploy', 'refresh-clients', 'start', 'stop', 'status', 'urls', 'rotate-token', 'stop-publish', 'start-publish', 'uninstall'):
        sub.add_parser(name)
    p = sub.add_parser('restore-legacy', help='仅供旧接管版迁移：停止旧 chain 并恢复原 sing-box')
    p.add_argument('--no-enable', action='store_true', help='恢复原服务运行但不设置开机启动')
    p = sub.add_parser('publish', help='发布已经部署的客户端配置')
    p.add_argument('--base-url', required=True)
    p.add_argument('--root', default='/var/lib/sing-box-addon-sub')
    p.add_argument('--bind', default='127.0.0.1')
    p.add_argument('--port', type=int, default=18080)
    p.add_argument('--cert')
    p.add_argument('--key')
    p = sub.add_parser('export', help='从已保存参数导出到新目录；不部署、不发布')
    p.add_argument('--output-dir', required=True)
    return result


def execute(args):
    from runtime import Runtime
    from publish import Publisher
    from policy import load_policy
    store = Store(args.state)
    if args.command in ('status', 'urls'):
        return show_status(store) if args.command == 'status' else show_urls(store)
    if args.command == 'rules-auto' and args.action in ('disable', 'status'):
        from scheduler import Scheduler
        print(json.dumps(getattr(Scheduler(), args.action)(), ensure_ascii=False))
        if args.action == 'disable':
            print('已取消后续自动更新；正在进行的一次更新会正常完成')
        return
    with store.locked():
        if args.command == 'init-entry':
            initialize_entry(args, store)
        elif args.command == 'import-config':
            initialize_entry(args, store, refresh=True)
        elif args.command == 'init-exit':
            initialize_exit(args, store)
            print('将此私有对接文件通过 SSH/SFTP 交给 A：' + str(store.root / 'handoff.json'))
        elif args.command == 'update-exit':
            state = store.read()
            if state['role'] != 'exit':
                raise ConfigError('此命令仅用于落地 B')
            binary = binary_for(args, store, state)
            reserved = {i['listen_port'] for i in read_json(args.config).get('inbounds', []) if 'listen_port' in i} if args.config else ()
            config, link = profiles.exit_config(args.address, args.port, args.entry_source,
                                                state['handoff']['outbounds'][0]['password'], reserved)
            check_config(binary, config)
            state.update(binary=binary, server_config=config, handoff=link, public_host=args.address, entry_sources=args.entry_source)
            store.save(state)
            write_private(store.root / 'handoff.json', link)
        elif args.command == 'update-link':
            state = store.read()
            if state['role'] != 'entry':
                raise ConfigError('此命令仅用于中转 A')
            link = profiles.handoff(args.link)
            if link['server'] == state['public_host'] and link['server_port'] in {p['inbound']['listen_port'] for p in state['profiles']}:
                raise ConfigError('落地地址指向本机附件入口，会形成代理循环')
            state['server_config'] = profiles.entry_config(state['profiles'], link)
            check_config(state['binary'], state['server_config'])
            store.save(state)
        elif args.command == 'add-direct':
            state = store.read()
            state['groups'][args.label] = profiles.import_direct(args.config, args.address, args.label, args.inbound or ())
            store.save(state)
        elif args.command == 'rules':
            state = store.read()
            policy = load_policy(args.mode, args.rules_dir, args.direct_domain, args.proxy_domain,
                                 args.direct_cidr, args.proxy_cidr)
            if not args.rules_dir and state['policy'].get('source') == 'inline':
                policy.update(source='inline', sets=state['policy']['sets'])
            state['policy'] = policy
            if args.rules_dir:
                state['rules_source'] = 'local'
                state.pop('geodata', None)
            store.save(state)
        elif args.command == 'geodata':
            state = store.read()
            from updates import update_rules
            update_rules(store, args.geoip, args.geosite, binary_for(args, store, state), args.force)
        elif args.command == 'refresh-clients':
            from updates import refresh_clients
            refresh_clients(store)
            print('客户端分流已应用；未重启代理')
        elif args.command == 'rules-auto':
            from scheduler import Scheduler
            scheduler = Scheduler()
            if args.action == 'enable':
                from updates import update_rules
                update_rules(store)
                scheduler.enable(store.root)
                print('已启用每日 GitHub 规则与订阅自动更新')
            else:
                print(json.dumps(getattr(scheduler, args.action)(), ensure_ascii=False))
        elif args.command == 'install':
            state = store.read(optional=True)
            binary = binary_for(args, store, state)
            Runtime().install(binary, tool_dir=Path(__file__).parent)
            if state:
                state['binary'] = '/opt/sing-box-addon/sing-box'
                store.save(state)
        elif args.command == 'build':
            print('已生成：' + str(build(store)))
        elif args.command == 'export':
            target = Path(args.output_dir).absolute()
            if target.exists() or target.is_symlink():
                raise ConfigError('输出目录必须尚不存在')
            release = build(store)
            # A download/export directory contains client files only.
            with tempfile.TemporaryDirectory(prefix='.export-', dir=target.parent) as tmp:
                staged = Path(tmp) / 'clients'
                staged.mkdir(mode=0o700)
                for name in ('mihomo.yaml', 'sing-box.json', 'nodes.txt', 'nodes.base64.txt'):
                    if not (release / name).is_file():
                        raise ConfigError('此角色尚无客户端节点，可用 add-direct 导入已有节点')
                    shutil.copyfile(release / name, staged / name)
                    (staged / name).chmod(0o600)
                os.rename(staged, target)
            print('已导出客户端文件：' + str(target))
        elif args.command == 'deploy':
            print('已部署：' + str(deploy(store)))
        elif args.command in ('start', 'stop'):
            getattr(Runtime(), args.command)()
        elif args.command == 'restore-legacy':
            Runtime().restore_legacy(enable_original=not args.no_enable)
        elif args.command == 'publish':
            set_publication(args, store)
        elif args.command in ('rotate-token', 'stop-publish', 'start-publish'):
            settings = store.read('publication.json')
            publisher = Publisher(settings['root'])
            if args.command == 'rotate-token':
                publisher.rotate_token()
                show_urls(store)
            else:
                getattr(publisher, 'stop_service' if args.command == 'stop-publish' else 'start_service')()
        elif args.command == 'uninstall':
            Runtime().uninstall()
            print('附件运行环境已卸载；参数与导出文件保留供重新安装')
        else:
            raise ConfigError('未知操作')


def ask(label, default=None):
    value = input(label + (f' [{default}]' if default is not None else '') + '：').strip()
    return value or default or ''


def menu(state_root):
    # Menu is only an adapter. The exact same command functions serve automation.
    while True:
        print('\n独立链式代理（原服务可并行运行）\n'
              '1. 初始化中转 A / 落地 B\n2. 安装运行环境并部署\n3. 启动 / 停止 / 查看状态\n'
              '4. 更新配置 / 落地连接\n5. 导出客户端文件 / 添加原直连节点\n'
              '6. 发布与管理订阅 URL\n7. 客户端分流 / GitHub 自动规则更新\n'
              '8. 恢复旧接管版的原服务\n9. 卸载附件\n10. 仅生成标准 sing-box 配置\n0. 退出')
        choice = ask('请选择', '0')
        if choice == '0':
            return 0
        commands = []
        try:
            if choice == '1':
                role = ask('本机是中转 A 还是落地 B', 'B').upper()
                binary = ask('已有 sing-box 内核路径（留空自动准备）')
                if role == 'B':
                    command = ['init-exit', '--address', ask('B 接收链路的 IP'), '--port', ask('独立链路端口', '22000')]
                    for source in ask('A 的实际出站 IP（多个用空格分开）').split():
                        command += ['--entry-source', source]
                    config = ask('已有服务器配置路径（可选，用于避开原端口）')
                    if config:
                        command += ['--config', config]
                elif role == 'A':
                    command = ['init-entry', '--config', ask('sing-box 服务端配置路径'),
                               '--address', ask('客户端访问 A 的 IP 或域名'), '--link', ask('B 对接配置文件路径')]
                    selected = ask('选择入站 tag（留空全部，多个用空格分开）')
                    for tag in selected.split():
                        command += ['--inbound', tag]
                else:
                    raise ConfigError('请输入 A 或 B')
                if binary:
                    command += ['--binary', binary]
                commands.append(command)
            elif choice == '2':
                commands = [['install'], ['deploy']]
            elif choice == '3':
                action = ask('1 启动；2 停止；3 状态', '3')
                commands = [[{'1': 'start', '2': 'stop', '3': 'status'}[action]]]
            elif choice == '4':
                action = ask('1 重新导入 A 接入配置；2 更换 B 对接；3 更新 B 地址/来源；4 部署准备好的配置', '4')
                if action == '1':
                    commands = [['import-config', '--config', ask('新源配置路径')]]
                elif action == '2':
                    commands = [['update-link', '--link', ask('新 B 对接配置路径')]]
                elif action == '3':
                    cmd = ['update-exit', '--address', ask('B 的 IP'), '--port', ask('链路端口', '22000')]
                    for source in ask('A 的实际出站 IP（空格分隔）').split():
                        cmd += ['--entry-source', source]
                    commands = [cmd]
                else:
                    commands = [['deploy']]
                if action in ('1', '2', '3') and ask('生成并部署更新？y/n', 'y').lower() == 'y':
                    commands.append(['deploy'])
            elif choice == '5':
                action = ask('1 导出客户端文件；2 添加 A-direct/B-direct 节点', '1')
                if action == '1':
                    commands = [['export', '--output-dir', ask('新的客户端导出目录')]]
                else:
                    commands = [['add-direct', '--config', ask('标准 sing-box 服务端配置路径'),
                                 '--address', ask('原节点公网 IP 或域名'), '--label', ask('节点组', 'A-direct')]]
            elif choice == '6':
                action = ask('1 设置发布；2 查看 URL；3 更换访问口令；4 停止；5 启动', '2')
                if action == '1':
                    cmd = ['publish', '--base-url', ask('客户端访问的基地址（如 https://sub.example.com）'),
                           '--bind', ask('监听 IP（反向代理用127.0.0.1；直接公网用0.0.0.0）', '127.0.0.1'),
                           '--port', ask('订阅端口', '18080')]
                    cert = ask('HTTPS 证书路径（通过反向代理提供 HTTPS 时留空）')
                    if cert:
                        cmd += ['--cert', cert, '--key', ask('HTTPS 私钥路径')]
                    commands = [cmd]
                else:
                    commands = [[{'2': 'urls', '3': 'rotate-token', '4': 'stop-publish', '5': 'start-publish'}[action]]]
            elif choice == '7':
                action = ask('1 立即更新 GitHub 规则；2 设置分流；3 每日自动更新；4 导入本机规则库', '1')
                if action == '1':
                    commands = [['geodata']]
                elif action == '3':
                    value = {'1': 'enable', '2': 'disable', '3': 'status'}[ask('1 启用；2 停用；3 状态', '1')]
                    commands = [['rules-auto', value]]
                elif action == '4':
                    commands = [['geodata', '--geoip', ask('GeoIP 文件', '/root/geoip.db'),
                                 '--geosite', ask('GeoSite 文件', '/root/geosite.db')]]
                elif action == '2':
                    mode = {'1': 'cn-direct', '2': 'lan-direct', '3': 'global'}[ask('1 国内/局域网直连；2 仅局域网直连；3 全部代理', '1')]
                    cmd = ['rules', '--mode', mode]
                    for flag, prompt in (('--direct-domain', '始终直连的域名后缀'), ('--proxy-domain', '始终代理的域名后缀'),
                                         ('--direct-cidr', '始终直连的 IP/CIDR'), ('--proxy-cidr', '始终代理的 IP/CIDR')):
                        for domain in ask(prompt + '（空格分隔，可留空）').split():
                            cmd += [flag, domain]
                    commands = [cmd, ['refresh-clients']]
                else:
                    raise ConfigError('请选择 1 至 4')
                print('分流在客户端执行；规则更新直接刷新已部署节点的订阅。')
            elif choice == '8':
                print('此操作仅用于旧接管版：停止 sing-box-chain，恢复原 sing-box 并启用其开机启动。')
                if ask('输入 restore 执行') == 'restore':
                    commands = [['restore-legacy']]
            elif choice == '9':
                if ask('停止并卸载附件运行环境（保留参数）？输入 uninstall') == 'uninstall':
                    commands = [['uninstall']]
            elif choice == '10':
                import generate
                generate.main([])
            else:
                print('请选择菜单中的编号')
            for command in commands:
                execute(parser().parse_args(['--state', str(state_root), *command]))
            if commands:
                print('操作完成')
        except (ConfigError, RuntimeError) as error:
            print(str(error), file=sys.stderr)
        except SystemExit:
            print('参数格式不正确，请重新选择菜单操作。', file=sys.stderr)
        except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
            print('操作失败：请检查输入、文件权限和状态；未输出凭据。', file=sys.stderr)


def main():
    args = parser().parse_args()
    try:
        if not args.command:
            if not sys.stdin.isatty():
                parser().print_help()
                return 0
            return menu(args.state)
        execute(args)
        return 0
    except (ConfigError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        print('操作失败：请检查输入、路径、内核和权限；未输出可能含凭据的诊断。', file=sys.stderr)
    except (KeyboardInterrupt, EOFError):
        print('\n已退出')
    return 1


if __name__ == '__main__':
    sys.exit(main())
