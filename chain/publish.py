#!/usr/bin/env python3
"""Publish a private snapshot containing only supported client subscriptions."""
import argparse
import base64
import contextlib
import fcntl
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urlsplit


FILES = ("mihomo.yaml", "sing-box.json", "nodes.txt", "nodes.base64.txt")
ROOT = Path("/var/lib/sing-box-addon-sub")
SERVICE = "sing-box-addon-sub.service"
MAX_FILE_BYTES = 32 * 1024 * 1024


def _atomic(path, payload, mode=0o600):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("拒绝写入符号链接")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".stage-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(payload.encode() if isinstance(payload, str) else payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _token(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", value):
        raise ValueError("订阅路径口令必须由 24–128 位字母、数字、下划线或连字符组成")
    return value


def _reject_symlinks(path):
    path = Path(path).absolute()
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError("订阅路径不能包含符号链接")


def _read_at(directory, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    with os.fdopen(descriptor, "rb") as stream:
        import stat
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("订阅文件必须是普通文件")
        payload = stream.read(MAX_FILE_BYTES + 1)
        if len(payload) > MAX_FILE_BYTES:
            raise ValueError("订阅文件过大")
        return payload


class Publisher:
    def __init__(self, root=ROOT):
        self.root = Path(root).absolute()
        self._mutex = threading.RLock()
        self._lock_depth = 0
        self._pinned_generations = set()
        self._service_runtime = None

    @contextlib.contextmanager
    def _lock(self):
        with self._mutex:
            if self._lock_depth:
                self._lock_depth += 1
                try:
                    yield
                finally:
                    self._lock_depth -= 1
                return
            _reject_symlinks(self.root)
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.root.chmod(0o700)
            descriptor = os.open(self.root / ".publish.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "a") as stream:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._lock_depth = 1
                try:
                    yield
                finally:
                    self._lock_depth = 0

    @contextlib.contextmanager
    def transaction(self):
        """Keep the old snapshot available until deployment metadata is saved."""
        with self._lock():
            previous = self.state() if (self.root / "state.json").exists() else None
            pinned = set(self._pinned_generations)
            if previous:
                self._pinned_generations.add(previous["generation"])
            try:
                yield self
            except BaseException:
                if previous is None:
                    (self.root / "state.json").unlink(missing_ok=True)
                else:
                    _atomic(self.root / "state.json", json.dumps(previous))
                raise
            finally:
                self._pinned_generations = pinned

    @staticmethod
    def _validate_state(value):
        if not isinstance(value, dict):
            raise ValueError("订阅状态无效")
        _token(value.get("token"))
        if not isinstance(value.get("generation"), str) or not re.fullmatch(r"[a-f0-9]{32}", value["generation"]):
            raise ValueError("订阅版本无效")
        if value.get("files") != list(FILES):
            raise ValueError("订阅文件清单无效")
        return value

    def state(self):
        _reject_symlinks(self.root)
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            return self._validate_state(json.loads(_read_at(descriptor, "state.json")))
        finally:
            os.close(descriptor)

    def publish(self, release_dir, token=None):
        """Validate and copy four client files, then atomically switch the manifest."""
        source = Path(release_dir).absolute()
        _reject_symlinks(source)
        source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            payloads = {name: _read_at(source_fd, name) for name in FILES}
        finally:
            os.close(source_fd)
        client = json.loads(payloads["sing-box.json"])
        if not isinstance(client, dict) or not isinstance(client.get("outbounds"), list) or not client["outbounds"]:
            raise ValueError("缺少客户端出站；落地服务端或空配置不能作为订阅发布")
        if not payloads["nodes.txt"].strip() or base64.b64decode(payloads["nodes.base64.txt"].strip(), validate=True) != payloads["nodes.txt"]:
            raise ValueError("节点文本与 Base64 订阅不一致")
        if not payloads["mihomo.yaml"].strip():
            raise ValueError("Mihomo 配置为空")
        if token is not None:
            _token(token)
        with self._lock():
            current = self.state() if (self.root / "state.json").exists() else None
            if current and token is not None and token != current["token"]:
                raise ValueError("更新订阅会保留现有口令；更换口令请使用 rotate_token")
            selected = current["token"] if current else token or secrets.token_urlsafe(32)
            generation = secrets.token_hex(16)
            releases = self.root / "releases"
            _reject_symlinks(releases)
            releases.mkdir(mode=0o700, exist_ok=True)
            staging = Path(tempfile.mkdtemp(prefix=".stage-", dir=releases))
            destination = releases / generation
            try:
                for name, payload in payloads.items():
                    _atomic(staging / name, payload)
                os.replace(staging, destination)
                value = {"schema_version": 1, "token": selected, "generation": generation, "files": list(FILES)}
                _atomic(self.root / "state.json", json.dumps(value))
            finally:
                if staging.exists():
                    shutil.rmtree(staging)
            # Keep the previous generation so requests reading the previous manifest
            # finish normally. Only tool-created generation names are considered.
            keep = {generation, current["generation"] if current else None} | self._pinned_generations
            for old in releases.iterdir():
                if re.fullmatch(r"[a-f0-9]{32}", old.name) and old.name not in keep and old.is_dir() and not old.is_symlink():
                    # Cleanup cannot turn an already committed publication into a
                    # reported failure; a future publication may retry it.
                    try:
                        shutil.rmtree(old)
                    except OSError:
                        pass
            return value

    def rotate_token(self):
        with self._lock():
            value = self.state()
            value["token"] = secrets.token_urlsafe(32)
            _atomic(self.root / "state.json", json.dumps(value))
            return value["token"]

    def url(self, base_url, filename="mihomo.yaml"):
        if filename not in FILES:
            raise ValueError("不支持的客户端文件")
        parsed = urlsplit(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("请提供没有凭据、查询参数和片段的 HTTP/HTTPS 基础地址")
        try:
            parsed.port
        except ValueError as error:
            raise ValueError("基础地址端口无效") from error
        return base_url.rstrip("/") + "/" + self.state()["token"] + "/" + filename

    def response(self, request_path):
        """Return a complete file snapshot, or None; no path is joined from user input."""
        try:
            parsed = urlsplit(request_path)
            if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or "%" in parsed.path:
                return None
            pieces = parsed.path.split("/")
            if len(pieces) != 3 or pieces[0] or pieces[2] not in FILES:
                return None
            _reject_symlinks(self.root)
            root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                state = self._validate_state(json.loads(_read_at(root_fd, "state.json")))
                if not hmac.compare_digest(pieces[1], state["token"]):
                    return None
                releases_fd = os.open("releases", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
                try:
                    generation_fd = os.open(state["generation"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=releases_fd)
                    try:
                        payload = _read_at(generation_fd, pieces[2])
                    finally:
                        os.close(generation_fd)
                finally:
                    os.close(releases_fd)
            finally:
                os.close(root_fd)
            mime = "application/json" if pieces[2].endswith(".json") else "text/plain; charset=utf-8"
            return payload, mime
        except (OSError, ValueError, TypeError):
            return None

    def handler(self):
        publisher = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "Subscription"
            sys_version = ""

            def setup(self):
                self.request.settimeout(20)
                super().setup()

            def do_GET(self):
                self._send(False)

            def do_HEAD(self):
                self._send(True)

            def _send(self, head):
                found = publisher.response(self.path)
                payload, content_type = found if found else (b"Not found\n", "text/plain; charset=utf-8")
                self.send_response(200 if found else 404)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                if not head:
                    self.wfile.write(payload)

            def log_message(self, format, *args):
                # Request paths contain the secret; never include them in access logs.
                pass

        return Handler

    @staticmethod
    def _server_options(bind, port, cert, key):
        if not isinstance(bind, str):
            raise ValueError("监听地址无效")
        try:
            ipaddress.ip_address(bind)
        except ValueError as error:
            raise ValueError("监听地址必须是 IPv4 或 IPv6 地址") from error
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError("订阅服务端口必须在 1024–65535 之间")
        if bool(cert) != bool(key):
            raise ValueError("TLS 证书和私钥必须同时提供")

    def serve(self, bind="127.0.0.1", port=8080, cert=None, key=None):
        self._server_options(bind, port, cert, key)
        self.state()
        server_type = ThreadingHTTPServer
        if ":" in bind:
            import socket

            class IPv6Server(ThreadingHTTPServer):
                address_family = socket.AF_INET6

            server_type = IPv6Server
        with server_type((bind, port), self.handler()) as server:
            if cert:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.load_cert_chain(cert, key)
                server.socket = context.wrap_socket(server.socket, server_side=True)
            server.serve_forever()

    def install_service(self, bind="127.0.0.1", port=8080, cert=None, key=None, system_root="/", runner=None):
        """Install the HTTP unit; publishing and starting remain separate operations."""
        from runtime import Runtime, atomic_write
        self._server_options(bind, port, cert, key)
        self.state()
        runtime = self._service_runtime or Runtime(system_root, runner=runner)
        runtime.preflight()
        if self.root != runtime.path(ROOT):
            raise ValueError("systemd 发布服务要求使用独立的标准订阅目录")
        settings = {"root": str(ROOT), "bind": bind, "port": port}
        material = {}
        if cert:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            for source, name in ((cert, "subscription.crt"), (key, "subscription.key")):
                material[name] = Path(source).read_bytes()
            settings.update(cert="/etc/sing-box-addon/subscription.crt", key="/etc/sing-box-addon/subscription.key")
        unit = """[Unit]
Description=Independent sing-box client subscriptions
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/sing-box-addon/tool/publish.py serve --settings /etc/sing-box-addon/subscription.json
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077

[Install]
WantedBy=multi-user.target
"""
        with self.service_transaction(system_root, runner):
            for name, payload in material.items():
                atomic_write(runtime.root / name, payload)
            atomic_write(runtime.root / "subscription.json", json.dumps(settings))
            atomic_write(runtime.path("/opt/sing-box-addon/tool/publish.py"), Path(__file__).read_bytes(), 0o644)
            atomic_write(runtime.path("/etc/systemd/system/" + SERVICE), unit, 0o644)
            runtime._daemon_reload()
        return settings

    @contextlib.contextmanager
    def service_transaction(self, system_root="/", runner=None):
        """Rollback settings, TLS files, unit and process state across install/start/save."""
        from runtime import Runtime
        if self._service_runtime is not None:
            if self._service_runtime.system_root != Path(system_root).resolve():
                raise ValueError("嵌套服务操作必须使用相同 system_root")
            yield self._service_runtime
            return
        runtime = Runtime(system_root, runner=runner)
        paths = [runtime.root / name for name in ("subscription.json", "subscription.crt", "subscription.key")]
        paths += [runtime.path("/opt/sing-box-addon/tool/publish.py"),
                  runtime.path("/etc/systemd/system/" + SERVICE)]
        with self._lock(), runtime.transaction(service=SERVICE, files=paths, reload=True):
            self._service_runtime = runtime
            try:
                yield runtime
            finally:
                self._service_runtime = None

    def start_service(self, system_root="/", runner=None):
        with self.service_transaction(system_root, runner) as runtime:
            unit = runtime.path("/etc/systemd/system/" + SERVICE)
            if not unit.is_file() or not (runtime.root / "subscription.json").is_file():
                raise RuntimeError("请先配置订阅发布服务")
            runtime._require("restart", service=SERVICE)
            if not runtime.healthy(SERVICE):
                raise RuntimeError("订阅发布服务健康检查失败")
            runtime._require("enable", service=SERVICE)
        return Publisher.status_service(system_root, runner)

    def stop_service(self, system_root="/", runner=None):
        from runtime import Runtime
        runtime = Runtime(system_root, runner=runner)
        with runtime._lock():
            if runtime.path("/etc/systemd/system/" + SERVICE).is_file():
                runtime._require("stop", service=SERVICE)
                runtime._require("disable", service=SERVICE)
        return Publisher.status_service(system_root, runner)

    @staticmethod
    def status_service(system_root="/", runner=None):
        from runtime import Runtime
        runtime = Runtime(system_root, runner=runner)
        return runtime.service_state(SERVICE, strict=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="前台提供客户端订阅")
    serve.add_argument("--root", type=Path, default=ROOT)
    serve.add_argument("--bind", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--cert")
    serve.add_argument("--key")
    serve.add_argument("--settings", type=Path)
    args = parser.parse_args(argv)
    try:
        options = {"root": args.root, "bind": args.bind, "port": args.port, "cert": args.cert, "key": args.key}
        if args.settings:
            stored = json.loads(args.settings.read_text())
            if not isinstance(stored, dict) or set(stored) - set(options):
                raise ValueError("订阅服务设置无效")
            options.update(stored)
        root = options.pop("root")
        Publisher(root).serve(**options)
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print("订阅服务失败；请检查发布状态、监听地址、端口和 TLS 文件。", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
