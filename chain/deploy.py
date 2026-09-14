#!/usr/bin/env python3
"""Apply a checked configuration to the dedicated, already installed service."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from chain import check_version, run_core, write_private

ROOT = Path("/etc/sing-box-chain")
BINARY = Path("/opt/sing-box-chain/sing-box")
SERVICE = "sing-box-chain.service"


def control(*args, service=SERVICE):
    try:
        return subprocess.run(["systemctl", *args, service], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def main_pid():
    try:
        result = subprocess.run(["systemctl", "show", "--property=MainPID", "--value", SERVICE],
                                capture_output=True, text=True, timeout=10, check=True)
        return int(result.stdout.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0


def healthy():
    # Process health only. End-to-end exit verification is a separate acceptance step.
    pid = main_pid()
    if not pid:
        return False
    for _ in range(5):
        if not control("is-active", "--quiet") or main_pid() != pid:
            return False
        time.sleep(1)
    return True


def apply(candidate, root=ROOT, binary=BINARY, take_over_legacy=False):
    check_version(binary)
    data = json.loads(Path(candidate).read_text())
    # Check exactly the snapshot we will deploy, even if the source changes later.
    with tempfile.TemporaryDirectory(prefix=".check-", dir=root) as directory:
        snapshot = Path(directory) / "config.json"
        write_private(snapshot, data)
        run_core(binary, "check", "-c", str(snapshot))
    target = root / "config.json"
    previous = json.loads(target.read_text()) if target.exists() else None
    was_active = control("is-active", "--quiet")
    legacy_active = control("is-active", "--quiet", service="sing-box.service") if take_over_legacy else False
    legacy_enabled = control("is-enabled", "--quiet", service="sing-box.service") if take_over_legacy else False
    marker = root / "legacy-managed"
    had_marker = marker.exists()
    if take_over_legacy and (was_active or had_marker):
        raise ValueError("接管选项仅用于首次迁移；现有 chain 服务更新请省略该选项")
    if previous is not None:
        write_private(root / "config.previous.json", previous)
    write_private(target, data)
    try:
        if take_over_legacy:
            write_private(marker, {"service": SERVICE})
            if not control("stop", service="sing-box.service"):
                raise RuntimeError("无法停止原服务")
        if not control("restart") or not healthy():
            raise RuntimeError("新配置服务健康检查失败")
        if take_over_legacy and not control("disable", service="sing-box.service"):
            raise RuntimeError("无法禁用原服务开机启动")
    except BaseException:
        control("stop")
        if previous is None:
            target.unlink(missing_ok=True)
        else:
            write_private(target, previous)
        if take_over_legacy:
            if not had_marker:
                marker.unlink(missing_ok=True)
            recovered = True
            if legacy_enabled:
                recovered = control("enable", service="sing-box.service") and recovered
            if legacy_active:
                recovered = control("start", service="sing-box.service") and recovered
            if not recovered:
                raise RuntimeError("配置已恢复，但原 sing-box 服务恢复失败，请检查 systemctl status sing-box")
        if was_active and previous is not None:
            if not control("start") or not healthy():
                raise RuntimeError("旧配置已恢复，但服务恢复失败；请检查 journalctl")
        raise RuntimeError("部署失败，已恢复原配置和服务启停状态")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--take-over-legacy", action="store_true",
                        help="检查成功后停止原 sing-box.service；失败恢复，成功禁用原服务开机启动")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("部署需要 root；render 不需要 root")
    if not ROOT.is_dir():
        parser.error("请先按 README 安装独立服务和配置目录")
    try:
        with open(ROOT / ".deploy.lock", "a", opener=lambda p, f: os.open(p, f, 0o600)) as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            apply(Path(args.config).resolve(), take_over_legacy=args.take_over_legacy)
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError):
        print("部署失败；请检查服务状态和受限目录内的备份。诊断未输出凭据。", file=sys.stderr)
        return 1
    print("配置已部署，进程健康检查通过；仍需执行跨机器出口验收。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
