#!/usr/bin/env python3
"""Manage only the independent addon; legacy recovery is explicitly invoked."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time


SERVICE = "sing-box-addon.service"
SUB_SERVICE = "sing-box-addon-sub.service"
RULES_SERVICE = "sing-box-addon-rules.service"
RULES_TIMER = "sing-box-addon-rules.timer"
CONFIG_DIR = Path("/etc/sing-box-addon")
BINARY = Path("/opt/sing-box-addon/sing-box")
TOOL_DIR = Path("/opt/sing-box-addon/tool")
SUB_ROOT = Path("/var/lib/sing-box-addon-sub")


def atomic_write(path, data, mode=0o600):
    """Replace one file without exposing an incomplete version."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError("拒绝写入符号链接")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".stage-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data.encode() if isinstance(data, str) else data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class Runtime:
    def __init__(self, system_root="/", runner=None, health_checks=3, health_interval=1):
        self.system_root = Path(system_root).resolve()
        self.runner = runner or subprocess.run
        self.mock_system = self.system_root != Path("/")
        self.has_runner = runner is not None
        self.health_checks = max(1, health_checks)
        self.health_interval = health_interval
        self.root = self.path(CONFIG_DIR)
        self.binary = self.path(BINARY)
        self.unit = self.path("/etc/systemd/system/" + SERVICE)
        self._mutex = threading.RLock()
        self._lock_depth = 0

    def path(self, absolute):
        return self.system_root / str(absolute).lstrip("/")

    def _run(self, argv, timeout=30):
        if self.mock_system and not self.has_runner:
            raise RuntimeError("隔离 system_root 必须提供 runner，拒绝操作真实系统服务")
        return self.runner([str(item) for item in argv], capture_output=True,
                           text=True, timeout=timeout)

    def control(self, *arguments, service=SERVICE):
        try:
            return self._run(["systemctl", *arguments, service]).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _require(self, *arguments, service=SERVICE):
        if not self.control(*arguments, service=service):
            raise RuntimeError("服务操作失败：" + " ".join(arguments) + " " + service)

    def _daemon_reload(self):
        if self._run(["systemctl", "daemon-reload"]).returncode:
            raise RuntimeError("systemd daemon-reload 失败")

    def preflight(self):
        """Check the credential-capable system manager before installing files."""
        if not self.mock_system and os.geteuid() != 0:
            raise RuntimeError("后台服务安装需要 root 权限")
        try:
            version = self._run(["systemctl", "--version"])
            match = re.search(r"^systemd (\d+)", version.stdout, re.M)
            if version.returncode or not match or int(match[1]) < 247:
                raise RuntimeError("后台服务需要 systemd 247 或更新版本（LoadCredential）")
            manager = self._run(["systemctl", "show", "--property=Version", "--value"])
            if manager.returncode or not manager.stdout.strip():
                raise RuntimeError("无法连接 systemd 管理器；请在运行 systemd 的主机上安装后台服务")
        except (OSError, subprocess.SubprocessError) as error:
            raise RuntimeError("无法运行 systemctl；后台安装需要可访问的 systemd 管理器") from error
        return {"systemd": int(match[1])}

    def _query_state(self, action, service=SERVICE):
        try:
            result = self._run(["systemctl", action, service])
        except (OSError, subprocess.SubprocessError) as error:
            raise RuntimeError("无法查询服务状态：" + service) from error
        if result.returncode == 0:
            return True
        value = (result.stdout or "").strip()
        known = {"inactive", "failed", "unknown", "activating", "deactivating", "not-found"}
        codes = {3, 4}
        if action == "is-enabled":
            known = {"disabled", "masked", "masked-runtime", "not-found", "bad"}
            codes = {1, 4}
        if result.returncode in codes and (value in known or (not value and not result.stderr)):
            return False
        diagnostic = (result.stderr or "").strip()
        if (action == "is-enabled" and result.returncode in codes and
                diagnostic.startswith("Failed to get unit file state for ") and
                diagnostic.endswith("No such file or directory")):
            return False
        raise RuntimeError("无法查询服务状态：" + service + "（systemctl " + action + " 失败）")

    def service_state(self, service=SERVICE, strict=True):
        result = {"service": service}
        errors = []
        for key, action in (("active", "is-active"), ("enabled", "is-enabled")):
            try:
                result[key] = self._query_state(action, service)
            except RuntimeError as error:
                if strict or (self.mock_system and not self.has_runner):
                    raise
                result[key] = None
                errors.append(str(error))
        if errors:
            result["error"] = "；".join(errors)
        return result

    def _pid(self, service=SERVICE):
        try:
            result = self._run(["systemctl", "show", "--property=MainPID", "--value", service])
            return int(result.stdout.strip()) if not result.returncode else 0
        except (OSError, ValueError, subprocess.SubprocessError):
            return 0

    def healthy(self, service=SERVICE):
        """Check a stable process, not cross-server network reachability."""
        if service.endswith(".timer"):
            try:
                return self._query_state("is-active", service)
            except RuntimeError:
                return False
        pid = self._pid(service)
        if not pid:
            return False
        for index in range(self.health_checks):
            if index:
                time.sleep(self.health_interval)
            if not self.control("is-active", "--quiet", service=service) or self._pid(service) != pid:
                return False
        return True

    def check(self, config_path, binary=None):
        result = self._run([binary or self.binary, "check", "-c", config_path])
        if result.returncode:
            raise RuntimeError("sing-box 配置校验失败；未输出可能包含凭据的内核诊断")

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
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.root.chmod(0o700)
            lockpath = self.root / ".runtime.lock"
            descriptor = os.open(lockpath, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._lock_depth = 1
                try:
                    yield
                finally:
                    self._lock_depth = 0

    @contextlib.contextmanager
    def transaction(self, service=SERVICE, files=None, reload=False):
        """Rollback runtime files and service state if a later metadata save fails.

        Keep this context open through publication and active.json persistence.
        Nested apply/start calls must use this same Runtime instance.
        """
        paths = [self.root / "config.json", self.root / "config.previous.json"] if files is None else list(files)
        with self._lock():
            state = self.service_state(service)
            previous = {}
            for path in paths:
                path = Path(path)
                if path.is_symlink():
                    raise ValueError("拒绝备份符号链接")
                previous[path] = (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists() else None
            try:
                yield self
            except BaseException as error:
                unit = self.path("/etc/systemd/system/" + service)
                stopped = self.control("stop", service=service) if unit.exists() or state["active"] else True
                disabled = self.control("disable", service=service) if unit.exists() else True
                for path, snapshot in previous.items():
                    if snapshot is None:
                        path.unlink(missing_ok=True)
                    else:
                        atomic_write(path, *snapshot)
                if reload:
                    self._daemon_reload()
                # A service with no previous unit needs only to remain stopped.
                restored = self._restore(state["active"], state["enabled"], service) if unit.exists() else not state["active"]
                if not stopped or not disabled or not restored:
                    raise RuntimeError("操作失败，文件已回退，但服务状态未能完全恢复：" + service) from error
                raise

    def install(self, binary, tool_dir=None, state_root=None):
        source = Path(binary).resolve(strict=True)
        if not source.is_file() or not os.access(source, os.X_OK):
            raise ValueError("请提供可执行的 sing-box 内核文件")
        version = self._run([source, "version"])
        sources = Path(tool_dir) if tool_dir else Path(__file__).resolve().parent
        expected_version = json.loads((sources / "core.lock.json").read_text())["version"]
        if version.returncode or not re.search(r"^sing-box version " + re.escape(expected_version) + r"\s*$", str(version.stdout), re.M):
            raise ValueError("本附件要求 sing-box " + expected_version + "；请使用锁定版本的内核")
        self.preflight()
        source_bytes = source.read_bytes()
        with self._lock():
            changed = True
            if self.binary.exists():
                changed = hashlib.sha256(self.binary.read_bytes()).digest() != hashlib.sha256(source_bytes).digest()
                if changed and self._query_state("is-active"):
                    raise RuntimeError("附件正在运行；请先停止附件再更新内核")
            wrapper = self.path("/usr/bin/sb-chain")
            if wrapper.exists() and "# sing-box-addon managed launcher" not in wrapper.read_text():
                raise RuntimeError("/usr/bin/sb-chain 已存在且不属于本附件")
            destination = self.path(TOOL_DIR)
            payloads = {destination / item.name: item.read_bytes()
                        for item in sorted(sources.glob("*.py")) + [sources / "core.lock.json"] if item.is_file()}
            settings = self.root / "manager.json"
            remembered = (json.dumps({"schema_version": 1, "state_dir": str(Path(state_root).absolute())})
                          if state_root is not None else None)
            paths = [self.binary, wrapper, self.unit, *payloads]
            if remembered is not None:
                paths.append(settings)
            with self.transaction(files=paths, reload=True):
                self.root.chmod(0o700)
                if changed:
                    atomic_write(self.binary, source_bytes, 0o755)
                destination.mkdir(parents=True, exist_ok=True)
                for path, payload in payloads.items():
                    atomic_write(path, payload, 0o644)
                atomic_write(wrapper, '#!/bin/sh\n# sing-box-addon managed launcher\nexec python3 /opt/sing-box-addon/tool/addon.py "$@"\n', 0o755)
                atomic_write(self.unit, self._unit_text(), 0o644)
                if remembered is not None:
                    atomic_write(settings, remembered)
                self._daemon_reload()
        return {"binary": str(self.binary), "service": SERVICE, "launcher": str(wrapper)}

    @staticmethod
    def _unit_text():
        return """[Unit]
Description=Independent sing-box addon
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
DynamicUser=yes
LoadCredential=config.json:/etc/sing-box-addon/config.json
ExecStart=/opt/sing-box-addon/sing-box run -c %d/config.json
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
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
UMask=0077
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""

    def _restore(self, active, enabled, service=SERVICE):
        results = [self.control("enable" if enabled else "disable", service=service)]
        results.append(self.control("start" if active else "stop", service=service))
        if active and results[-1]:
            results.append(self.healthy(service))
        return all(results)

    def apply(self, config_path):
        if not self.unit.is_file() or not self.binary.is_file():
            raise RuntimeError("请先安装附件内核和服务")
        snapshot = Path(config_path).read_bytes()
        if not isinstance(json.loads(snapshot), dict):
            raise ValueError("服务端配置必须是 JSON 对象")
        with self._lock():
            with tempfile.TemporaryDirectory(prefix=".check-", dir=self.root) as directory:
                candidate = Path(directory) / "config.json"
                atomic_write(candidate, snapshot)
                self.check(candidate)
            target = self.root / "config.json"
            previous = target.read_bytes() if target.exists() else None
            state = self.service_state()
            active, enabled = state["active"], state["enabled"]
            if previous is not None:
                atomic_write(self.root / "config.previous.json", previous)
            atomic_write(target, snapshot)
            try:
                self._require("restart")
                if not self.healthy():
                    raise RuntimeError("附件进程健康检查失败")
                self._require("enable")
            except BaseException as error:
                stopped = self.control("stop")
                if previous is None:
                    target.unlink(missing_ok=True)
                else:
                    atomic_write(target, previous)
                recovered = self._restore(active, enabled)
                if not stopped or not recovered:
                    raise RuntimeError("配置已恢复，但附件服务恢复失败；请检查 systemctl status " + SERVICE) from error
                raise RuntimeError("部署失败，已恢复附件之前的配置和服务状态") from error
        return self.status()

    def start(self):
        with self._lock():
            config = self.root / "config.json"
            if not self.unit.is_file() or not config.is_file():
                raise RuntimeError("请先安装并部署附件配置")
            self.check(config)
            state = self.service_state()
            active, enabled = state["active"], state["enabled"]
            try:
                self._require("start")
                if not self.healthy():
                    raise RuntimeError("附件进程健康检查失败")
                self._require("enable")
            except BaseException as error:
                if not self._restore(active, enabled):
                    raise RuntimeError("启动失败，附件之前的服务状态也未能恢复") from error
                raise
        return self.status()

    def stop(self):
        with self._lock():
            if self.unit.is_file():
                self._require("stop")
                self._require("disable")
        return self.status()

    def status(self):
        return {**self.service_state(strict=False),
                "installed": self.unit.is_file() and self.binary.is_file(),
                "configured": (self.root / "config.json").is_file()}

    def uninstall(self):
        """Remove executable resources; retain parameters and subscriptions for reinstall."""
        with self._lock():
            for service in (RULES_TIMER, RULES_SERVICE, SUB_SERVICE, SERVICE):
                unit = self.path("/etc/systemd/system/" + service)
                if unit.exists():
                    self._require("stop", service=service)
                    if service != RULES_SERVICE:
                        self._require("disable", service=service)
                    unit.unlink()
            wrapper = self.path("/usr/bin/sb-chain")
            if wrapper.is_file() and "# sing-box-addon managed launcher" in wrapper.read_text():
                wrapper.unlink()
            path = self.path("/opt/sing-box-addon")
            if path.is_symlink():
                raise ValueError("拒绝删除符号链接目录")
            if path.exists():
                shutil.rmtree(path)
            self._daemon_reload()

    def restore_legacy(self, enable_original=True):
        """Explicit one-time recovery of an old takeover, never called by normal operations."""
        original = "sing-box.service"
        old = "sing-box-chain.service"
        marker = self.path("/etc/sing-box-chain/legacy-managed")
        if not marker.is_file() or marker.is_symlink():
            raise ValueError("未找到有效的旧版接管标记")
        try:
            if json.loads(marker.read_text()).get("service") != old:
                raise ValueError("接管标记与预期旧服务不符")
        except (json.JSONDecodeError, AttributeError) as error:
            raise ValueError("接管标记格式不符") from error
        config = self.path("/etc/s-box/sb.json")
        binary = self.path("/etc/s-box/sing-box")
        required = [config, binary, self.path("/etc/systemd/system/" + original),
                    self.path("/etc/systemd/system/" + old)]
        if not all(item.is_file() for item in required):
            raise ValueError("原版配置、内核或 systemd 服务不完整；拒绝恢复")
        # Verify the known installation shape before stopping anything.
        original_unit = required[2].read_text()
        old_unit = required[3].read_text()
        if "ExecStart=/etc/s-box/sing-box run -c /etc/s-box/sb.json" not in original_unit or "/opt/sing-box-chain/sing-box" not in old_unit:
            raise ValueError("系统服务内容与受支持的旧版安装不符；拒绝恢复")
        self.check(config, binary=binary)
        with self._lock():
            states = {service: self.service_state(service) for service in (original, old)}
            try:
                self._require("stop", service=old)
                self._require("disable", service=old)
                self._require("start", service=original)
                if not self.healthy(original):
                    raise RuntimeError("原版服务健康检查失败")
                self._require("enable" if enable_original else "disable", service=original)
                marker.unlink()  # sb is unlocked only once the original service is healthy.
            except BaseException as error:
                results = [self.control("stop", service=original)]
                results.append(self._restore(states[original]["active"], states[original]["enabled"], service=original))
                results.append(self._restore(states[old]["active"], states[old]["enabled"], service=old))
                if not all(results):
                    raise RuntimeError("恢复原版失败，旧服务状态未能完全恢复；接管标记已保留") from error
                raise RuntimeError("恢复原版失败，已还原之前的服务状态并保留接管标记") from error
        return {"service": original, "active": True, "enabled": bool(enable_original)}
