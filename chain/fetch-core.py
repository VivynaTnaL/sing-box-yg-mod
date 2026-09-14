#!/usr/bin/env python3
"""Download only the locked official core; verify before extracting executable."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="新内核路径；拒绝覆盖已有文件")
    args = parser.parse_args()
    lock = json.loads(Path(__file__).with_name("core.lock.json").read_text())
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if arch not in lock["sha256"]:
        parser.error("仅支持 Linux amd64/arm64")
    if platform.system() != "Linux":
        parser.error("仅支持 Linux")
    name = f'sing-box-{lock["version"]}-linux-{arch}'
    url = f'https://github.com/SagerNet/sing-box/releases/download/v{lock["version"]}/{name}.tar.gz'
    with tempfile.TemporaryDirectory(prefix="chain-core-") as directory:
        archive = Path(directory) / "core.tar.gz"
        subprocess.run(["curl", "--fail", "--show-error", "--silent", "--location",
                        "--proto", "=https", "--proto-redir", "=https", "--retry", "2",
                        "--connect-timeout", "15", "--max-time", "180", "-o", str(archive), url], check=True)
        data = archive.read_bytes()
        if hashlib.sha256(data).hexdigest() != lock["sha256"][arch]:
            raise ValueError("SHA256 校验失败")
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            member = tar.getmember(name + "/sing-box")
            if not member.isfile():
                raise ValueError("内核不是普通文件")
            executable = tar.extractfile(member).read()
        # Validate the archive's binary before publishing anything.
        candidate = Path(directory) / "sing-box"
        candidate.write_bytes(executable)
        candidate.chmod(0o700)
        result = subprocess.run([str(candidate), "version"], capture_output=True, text=True, check=True)
        if result.stdout.splitlines()[0] != "sing-box version " + lock["version"]:
            raise ValueError("内核版本不匹配")
        with open(args.output, "xb", opener=lambda p, f: os.open(p, f, 0o755)) as stream:
            stream.write(executable)
            stream.flush()
            os.fsync(stream.fileno())
    print("内核已校验并写入；未安装或启动系统服务。")


if __name__ == "__main__":
    main()
