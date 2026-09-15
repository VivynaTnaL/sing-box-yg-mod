"""Download one verified MetaCubeX GeoIP/GeoSite release and extract CN rules.

The public GitHub API supplies the release/asset IDs and SHA-256 digests. These
checks detect partial, mixed-version and changed downloads; they trust GitHub
and the upstream maintainers, and are not a separate publisher signature.
Only ``cache_dir`` is written. Updates never edit existing generations; explicit
pruning can remove verified old generations after publication has committed.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from chain import ConfigError, write_private
import policy


REPOSITORY = 'MetaCubeX/meta-rules-dat'
REPOSITORY_URL = 'https://github.com/' + REPOSITORY
API_ROOT = 'https://api.github.com/repos/' + REPOSITORY
RELEASE_URL = API_ROOT + '/releases/latest'
ASSET_NAMES = ('geoip.db', 'geosite.db')
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_DATABASE_BYTES = 128 * 1024 * 1024
SOCKET_TIMEOUT = 45
DOWNLOAD_DEADLINE = 300
CACHE_FORMAT = 1
GENERATION_PATTERN = re.compile(r'r[0-9]+-[a-f0-9]{16}-[a-f0-9]{8}')


def _require(condition, message):
    if not condition:
        raise ConfigError(message)


def _https(url):
    parsed = urllib.parse.urlsplit(url)
    _require(parsed.scheme == 'https' and parsed.hostname and not parsed.username
             and not parsed.password, 'GitHub geodata 下载地址必须使用 HTTPS')


class _HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _https(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open_default():
    # The default SSL context verifies both certificate chains and hostnames.
    # No token, netrc, git credential helper or gh authentication is consulted.
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _HTTPSRedirect()).open


def _http_error(exc):
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code in (403, 429):
            return 'GitHub API 拒绝请求或已限流（HTTP %s）；请稍后重试，现有规则保持不变' % exc.code
        if exc.code == 404:
            return 'GitHub 发布或固定资产已移除（HTTP 404）；请重新更新以获取同一新版的两本数据库'
        return 'GitHub geodata 下载失败（HTTP %s）；现有规则保持不变' % exc.code
    return '无法通过 HTTPS 下载 GitHub geodata（网络、超时或证书错误）；请稍后重试'


def _download(url, opener, *, limit, destination=None, expected_size=None):
    _https(url)
    headers = {'Accept': 'application/octet-stream' if destination else 'application/vnd.github+json',
               'User-Agent': 'sing-box-chain-geodata', 'X-GitHub-Api-Version': '2022-11-28'}
    request = urllib.request.Request(url, headers=headers)
    digest, count, chunks = hashlib.sha256(), 0, []
    started = time.monotonic()
    try:
        with opener(request, timeout=SOCKET_TIMEOUT) as response:
            _https(response.geturl())
            status = getattr(response, 'status', 200)
            _require(status == 200, 'GitHub geodata 下载返回非完整响应')
            declared = response.headers.get('Content-Length')
            if declared is not None:
                _require(str(declared).isdigit(), 'GitHub 下载大小声明无效')
                declared = int(declared)
                _require(0 < declared <= limit, 'GitHub geodata 文件超过大小限制或为空')
                _require(expected_size is None or declared == expected_size,
                         'GitHub 资产大小与发布清单不一致')
            stream = destination.open('xb') if destination else None
            try:
                if stream:
                    os.chmod(destination, 0o600)
                while True:
                    _require(time.monotonic() - started <= DOWNLOAD_DEADLINE, 'GitHub geodata 下载超时')
                    block = response.read(min(1024 * 1024, limit - count + 1))
                    if not block:
                        break
                    count += len(block)
                    _require(count <= limit, 'GitHub geodata 文件超过大小限制')
                    digest.update(block)
                    if stream:
                        stream.write(block)
                    else:
                        chunks.append(block)
                _require(count > 0 and (declared is None or count == declared),
                         'GitHub geodata 下载不完整')
                _require(expected_size is None or count == expected_size,
                         'GitHub geodata 下载不完整或大小与发布清单不符')
                if stream:
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                if stream:
                    stream.close()
    except ConfigError:
        raise
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, ConnectionError, OSError) as exc:
        raise ConfigError(_http_error(exc)) from None
    return {'sha256': digest.hexdigest(), 'size': count, 'data': b''.join(chunks)}


def _release(opener):
    raw = _download(RELEASE_URL, opener, limit=MAX_METADATA_BYTES)['data']
    try:
        release = json.loads(raw)
        _require(isinstance(release, dict), 'GitHub 发布清单格式无效')
        release_id, tag = release.get('id'), release.get('tag_name')
        _require(type(release_id) is int and release_id > 0 and isinstance(tag, str) and tag
                 and len(tag) <= 200 and not any(c in tag for c in '\r\n\x00'),
                 'GitHub 发布版本信息无效')
        _require(not release.get('draft') and not release.get('prerelease'), 'GitHub 发布不是正式版本')
        published = release.get('published_at')
        _require(isinstance(published, str) and len(published) <= 50, 'GitHub 发布时间无效')
        datetime.fromisoformat(published.replace('Z', '+00:00'))
        assets = release.get('assets')
        _require(isinstance(assets, list) and all(isinstance(a, dict) for a in assets),
                 'GitHub 资产清单无效')
        selected = {}
        for name in ASSET_NAMES:
            matches = [a for a in assets if a.get('name') == name]
            _require(len(matches) == 1, '同一 GitHub 发布必须同时提供唯一的 geoip.db 和 geosite.db')
            asset = matches[0]
            asset_id, size, digest = asset.get('id'), asset.get('size'), asset.get('digest')
            _require(type(asset_id) is int and asset_id > 0, 'GitHub 资产 ID 无效')
            _require(type(size) is int and 0 < size <= MAX_DATABASE_BYTES,
                     'GitHub geodata 资产超过大小限制或为空')
            _require(isinstance(digest, str) and re.fullmatch(r'sha256:[a-fA-F0-9]{64}', digest),
                     'GitHub 资产缺少 SHA-256 digest，无法校验；请稍后重试')
            # Never follow the mutable /download/latest URLs or a URL supplied
            # by release JSON. Asset IDs pin both files to this metadata read.
            selected[name] = {'asset_id': asset_id, 'url': API_ROOT + '/releases/assets/' + str(asset_id),
                              'size': size, 'sha256': digest.split(':')[1].lower()}
        _require(len({a['asset_id'] for a in selected.values()}) == 2, 'GitHub 资产 ID 重复')
        upstream = {'repository': REPOSITORY_URL, 'release_id': release_id, 'tag': tag,
                    'published_at': published, 'sources': selected}
        identity = hashlib.sha256(json.dumps(upstream, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        return upstream, identity
    except ConfigError:
        raise
    except (ValueError, TypeError, KeyError):
        raise ConfigError('GitHub 发布清单不是有效的 geodata 版本信息') from None


def _directory(path):
    _require(not path.is_symlink(), 'geodata 缓存目录不能是符号链接')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _require(path.is_dir(), 'geodata 缓存路径不是目录')


@contextmanager
def _lock(root):
    fd = os.open(root / '.update.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ConfigError('另一个 geodata 更新正在进行，请稍后重试') from None
        yield
    finally:
        os.close(fd)


def _result(directory, metadata, changed):
    upstream = metadata['upstream']
    return {'snapshot': str(directory / 'snapshot'), 'version': '%s@%s' % (upstream['tag'], upstream['release_id']),
            'changed': changed, 'sources': upstream['sources'], 'repository': upstream['repository'],
            'release_id': upstream['release_id'], 'published_at': upstream['published_at'],
            'fetched_at': metadata['fetched_at'], 'identity': metadata['identity']}


def _read_current(root):
    pointer = root / 'current.json'
    if not pointer.exists() and not pointer.is_symlink():
        return None
    try:
        _require(not pointer.is_symlink(), 'geodata 缓存索引不能是符号链接')
        index = json.loads(pointer.read_text())
        key = index['generation']
        _require(isinstance(key, str) and GENERATION_PATTERN.fullmatch(key), 'geodata 缓存索引无效')
        directory = root / 'releases' / key
        _require(not (root / 'releases').is_symlink() and not directory.is_symlink(),
                 'geodata 缓存版本不能是符号链接')
        meta_path = directory / 'metadata.json'
        _require(not meta_path.is_symlink(), 'geodata 缓存清单不能是符号链接')
        metadata = json.loads(meta_path.read_text())
        _require(metadata['format'] == CACHE_FORMAT and metadata['identity'] == index['identity'],
                 'geodata 缓存清单不匹配')
        upstream = metadata['upstream']
        identity = hashlib.sha256(json.dumps(upstream, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        _require(identity == metadata['identity'] and upstream['repository'] == REPOSITORY_URL,
                 'geodata 缓存来源或版本校验失败')
        for name in ASSET_NAMES:
            path = directory / name
            source = upstream['sources'][name]
            _require(not path.is_symlink() and path.stat().st_size == source['size']
                     and policy._sha256(path) == source['sha256'], 'geodata 缓存数据库校验失败')
        _require(not (directory / 'snapshot').is_symlink(), 'geodata 规则快照不能是符号链接')
        manifest_path = directory / 'snapshot' / 'manifest.json'
        _require(not manifest_path.is_symlink(), 'geodata 规则快照清单不能是符号链接')
        manifest = json.loads(manifest_path.read_text())
        _require(manifest['sources'] == {name[:-3]: upstream['sources'][name]['sha256'] for name in ASSET_NAMES},
                 'geodata 规则快照与数据库来源不匹配')
        policy.load_policy(rules_dir=directory / 'snapshot')
        return directory, metadata
    except ConfigError:
        raise
    except (OSError, ValueError, KeyError, TypeError):
        raise ConfigError('geodata 缓存缺失或损坏，请重新更新') from None


def current(cache_dir):
    """Read and verify the last complete generation without network access."""
    root = Path(cache_dir).absolute()
    _require(not root.is_symlink(), 'geodata 缓存目录不能是符号链接')
    cached = _read_current(root)
    return _result(*cached, False) if cached else None


def _prunable(directory):
    """Recognize only our exact, complete generation layout; skip other files."""
    try:
        if directory.is_symlink() or not directory.is_dir() or not GENERATION_PATTERN.fullmatch(directory.name):
            return None
        if {p.name for p in directory.iterdir()} != {*ASSET_NAMES, 'metadata.json', 'snapshot'}:
            return None
        snapshot = directory / 'snapshot'
        if snapshot.is_symlink() or not snapshot.is_dir():
            return None
        if {p.name for p in snapshot.iterdir()} != {*policy.SNAPSHOT_FILES.values(), 'manifest.json'}:
            return None
        files = [directory / name for name in (*ASSET_NAMES, 'metadata.json')]
        files += [snapshot / name for name in (*policy.SNAPSHOT_FILES.values(), 'manifest.json')]
        if any(path.is_symlink() or not path.is_file() for path in files):
            return None
        metadata = json.loads((directory / 'metadata.json').read_text())
        upstream = metadata['upstream']
        identity = hashlib.sha256(json.dumps(upstream, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        if (metadata['format'] != CACHE_FORMAT or metadata['identity'] != identity
                or upstream['repository'] != REPOSITORY_URL
                or not directory.name.startswith('r%s-%s-' % (upstream['release_id'], identity[:16]))
                or set(upstream['sources']) != set(ASSET_NAMES)):
            return None
        for name in ASSET_NAMES:
            source = upstream['sources'][name]
            if (source['url'] != API_ROOT + '/releases/assets/' + str(source['asset_id'])
                    or (directory / name).stat().st_size != source['size']
                    or policy._sha256(directory / name) != source['sha256']):
                return None
        manifest = json.loads((snapshot / 'manifest.json').read_text())
        if manifest['sources'] != {name[:-3]: upstream['sources'][name]['sha256'] for name in ASSET_NAMES}:
            return None
        policy.load_policy(rules_dir=snapshot)
        if not isinstance(metadata['fetched_at'], str):
            return None
        fetched = datetime.fromisoformat(metadata['fetched_at'].replace('Z', '+00:00'))
        return fetched.timestamp() if fetched.tzinfo is not None else None
    except (ConfigError, OSError, ValueError, TypeError, KeyError):
        return None


def prune(cache_dir, keep=3, protected=()):
    """Remove old verified generations, returning their absolute directory paths.

    Keep the newest ``keep`` complete generations plus current and every supplied
    snapshot's generation. Call only after state/publication commits, passing
    snapshots referenced by active and pending state. Unknown layouts, corrupt
    generations and symlinks are left alone. Individual deletion failures are
    ignored; no pointer, metadata or retained snapshot is modified.
    """
    _require(type(keep) is int and keep >= 0, '保留的 geodata 版本数量必须为非负整数')
    root = Path(cache_dir).absolute()
    for path in (root, *root.parents):
        _require(not path.is_symlink(), 'geodata 清理路径不能包含符号链接')
    if not root.exists():
        return []
    releases = root / 'releases'
    _require(not releases.is_symlink(), 'geodata 缓存版本目录不能为符号链接')
    # rmtree's descriptor-based implementation never follows a directory swapped
    # for a symlink between inspection and deletion (available on supported Linux).
    _require(shutil.rmtree.avoids_symlink_attacks, '当前平台不支持安全清理 geodata 目录')
    protected_keys = set()
    for value in protected:
        path = Path(value).absolute()
        for part in (path, *path.parents):
            _require(not part.is_symlink(), '受保护的 geodata 路径不能包含符号链接')
            if part.parent == releases and GENERATION_PATTERN.fullmatch(part.name):
                protected_keys.add(part.name)
    try:
        with _lock(root):
            cached = _read_current(root)
            if cached is None:
                return []
            protected_keys.add(cached[0].name)
            candidates = []
            for directory in releases.iterdir():
                fetched = _prunable(directory)
                if fetched is not None:
                    candidates.append((fetched, directory.name, directory))
            candidates.sort(reverse=True)
            protected_keys.update(item[1] for item in candidates[:keep])
            removed = []
            for _, name, directory in candidates[keep:]:
                if name in protected_keys:
                    continue
                try:
                    shutil.rmtree(directory)
                except OSError:
                    continue
                removed.append(str(directory))
            return removed
    except ConfigError:
        raise
    except OSError:
        raise ConfigError('无法清理旧 geodata 缓存；当前规则和订阅保持不变') from None


def update(binary, cache_dir, force=False, opener=None):
    """Fetch one pinned release; publish a new cache pointer only after conversion.

    Returns ``snapshot`` (absolute path), ``version``, ``changed`` and source
    metadata. The caller decides when to deploy profiles made from the snapshot.
    ``force`` makes a new immutable generation even if upstream is unchanged.
    ``opener`` is an injectable ``urlopen(Request, timeout=...)`` callable.
    """
    root = Path(cache_dir).absolute()
    try:
        _directory(root)
        _directory(root / 'releases')
        with _lock(root):
            opener = opener or _open_default()
            upstream, identity = _release(opener)
            if not force:
                try:
                    cached = _read_current(root)
                except ConfigError:
                    # Recover into a new generation. Do not edit a damaged or
                    # previously deployed directory in place.
                    cached = None
                if cached and cached[1]['identity'] == identity:
                    return _result(*cached, False)
            key = 'r%s-%s-%s' % (upstream['release_id'], identity[:16], uuid.uuid4().hex[:8])
            destination = root / 'releases' / key
            with tempfile.TemporaryDirectory(prefix='.download-', dir=root) as temporary:
                stage = Path(temporary) / 'release'
                stage.mkdir(mode=0o700)
                for name in ASSET_NAMES:
                    source = upstream['sources'][name]
                    fetched = _download(source['url'], opener, limit=MAX_DATABASE_BYTES,
                                        destination=stage / name, expected_size=source['size'])
                    _require(fetched['sha256'] == source['sha256'],
                             name + ' SHA-256 校验失败；现有规则保持不变，请重新更新')
                policy.import_geodata(binary, stage / 'geoip.db', stage / 'geosite.db', stage / 'snapshot')
                metadata = {'format': CACHE_FORMAT, 'identity': identity, 'upstream': upstream,
                            'fetched_at': datetime.now(timezone.utc).isoformat(),
                            'verification': 'GitHub release asset SHA-256 digest over verified HTTPS'}
                write_private(stage / 'metadata.json', metadata)
                os.rename(stage, destination)
            write_private(root / 'current.json', {'format': CACHE_FORMAT, 'generation': key, 'identity': identity})
            return _result(destination, metadata, True)
    except ConfigError:
        raise
    except OSError:
        raise ConfigError('无法写入 geodata 缓存或获取更新锁；现有快照保持不变') from None


def main():
    parser = argparse.ArgumentParser(description='从官方 GitHub 发布更新 GeoIP/GeoSite 并生成国内直连规则')
    parser.add_argument('--binary', required=True, help='sing-box 1.14.0 内核路径')
    parser.add_argument('--cache-dir', required=True, help='附件自己的 geodata 缓存目录')
    parser.add_argument('--force', action='store_true', help='重新下载并建立全新规则快照')
    args = parser.parse_args()
    try:
        print(json.dumps(update(args.binary, args.cache_dir, args.force), ensure_ascii=False, indent=2))
    except ConfigError as exc:
        parser.exit(1, '错误：' + str(exc) + '\n')


if __name__ == '__main__':
    main()
