"""Refresh portable client rules without applying pending server changes."""
import copy
from contextlib import nullcontext
from pathlib import Path
import sys
import time

from chain import ConfigError
from policy import load_policy, import_geodata


def source(state):
    return state.get('rules_source', 'local' if state['policy'].get('source') == 'inline' else 'github')


def with_snapshot(state, snapshot, origin, metadata=None):
    result = copy.deepcopy(state)
    old = result['policy']
    result['policy'] = load_policy(old['mode'], snapshot, old['direct_domains'], old['proxy_domains'],
                                  old['direct_cidrs'], old['proxy_cidrs'])
    result['rules_source'] = origin
    result['geodata'] = {**(metadata or {}), 'snapshot': str(snapshot), 'checked_at': time.time()}
    return result


def ensure(store, state):
    """First domestic export fetches GitHub rules; later exports use the last good snapshot.

    Regular refreshes are explicit or timer driven. Building a profile remains
    deterministic after this first materialization, including when offline.
    """
    if not state.get('groups') or state['policy']['mode'] != 'cn-direct':
        return state
    if source(state) != 'github' or state['policy'].get('source') == 'inline':
        return state
    import geodata
    print('从 GitHub 获取 GeoIP + GeoSite 并校验，生成国内直连规则……', file=sys.stderr)
    result = geodata.current(store.root / 'geodata') or geodata.update(state['binary'], store.root / 'geodata')
    return with_snapshot(state, result['snapshot'], 'github', result)


def refresh_clients(store, state=None):
    """Apply desired client policy to active nodes only; never deploy staged nodes/ports."""
    from addon import build
    from publish import Publisher
    desired = ensure(store, state or store.read())
    active = store.read('active.json', optional=True)
    publication = store.read('publication.json', optional=True)
    publisher = Publisher(publication['root']) if publication and active else None
    updated = None
    if active:
        updated = copy.deepcopy(active['state'])
        for key in ('policy', 'rules_source', 'geodata'):
            if key in desired:
                updated[key] = copy.deepcopy(desired[key])
            else:
                updated.pop(key, None)
        release = build(store, updated)
    with store.transaction('state.json', 'active.json'), publisher.transaction() if publisher else nullcontext():
        if publisher:
            publisher.publish(release)
        store.save(desired)
        if active:
            store.save({'release': str(release), 'state': updated}, 'active.json')
    return Path(release) if active else None


def update_rules(store, geoip=None, geosite=None, binary=None, force=False, scheduled=False):
    from addon import build
    from publish import Publisher
    state = store.read()
    active = store.read('active.json', optional=True)
    if bool(geoip) != bool(geosite):
        raise ConfigError('导入本机规则需要同时指定 --geoip 和 --geosite')
    if scheduled and (source(state) != 'github' or not state.get('groups')):
        print('当前未启用 GitHub 客户端规则；跳过定时更新')
        return None
    if geoip:
        import secrets
        snapshot = store.root / ('rules-' + secrets.token_hex(8))
        import_geodata(binary or state['binary'], geoip, geosite, snapshot)
        metadata, origin = {}, 'local'
    else:
        import geodata
        metadata = geodata.update(binary or state['binary'], store.root / 'geodata', force=force)
        snapshot, origin = metadata['snapshot'], 'github'
    desired = with_snapshot(state, snapshot, origin, metadata)
    updated = with_snapshot(active['state'], snapshot, origin, metadata) if active else None
    publication = store.read('publication.json', optional=True)
    publisher = Publisher(publication['root']) if publication and active else None
    # A pending import can contain new credentials or ports. Always build the
    # deployed snapshot here, and preserve each snapshot's own rule exceptions.
    changed = bool(updated and updated['policy'] != active['state']['policy'])
    release = build(store, updated) if changed else Path(active['release']) if active else None
    with store.transaction('state.json', 'active.json'), publisher.transaction() if publisher else nullcontext():
        if publisher and changed:
            publisher.publish(release)
        store.save(desired)
        if updated:
            store.save({'release': str(release), 'state': updated}, 'active.json')
    if origin == 'github':
        protected = [item['geodata']['snapshot'] for item in (desired, updated) if item and item.get('geodata')]
        try:
            geodata.prune(store.root / 'geodata', protected=protected)
        except (ConfigError, OSError):
            print('规则已生效，但旧数据库缓存暂未清理；下次更新会重试。', file=sys.stderr)
    print('规则已更新，固定订阅 URL 保持不变；代理进程无需重启' if publisher else '规则快照已更新')
    return metadata
