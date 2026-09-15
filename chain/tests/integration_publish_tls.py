#!/usr/bin/env python3
"""Exercise the real HTTPS publisher using /tmp files and loopback sockets only."""
import base64
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from publish import FILES, Publisher


def unused_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def main():
    with tempfile.TemporaryDirectory(prefix="addon-publish-tls-", dir="/tmp") as directory:
        root = Path(directory)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(cert), "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
                       check=True, capture_output=True, timeout=30)
        key.chmod(0o600)
        release = root / "release"
        release.mkdir(mode=0o700)
        (release / "mihomo.yaml").write_text("proxies: []\n")
        (release / "sing-box.json").write_text('{"outbounds":[{"type":"direct"}]}')
        (release / "config.json").write_text("server-only-secret")

        def nodes(value):
            payload = ("vless://" + value + "@example.com:8443\n").encode()
            (release / "nodes.txt").write_bytes(payload)
            (release / "nodes.base64.txt").write_bytes(base64.b64encode(payload) + b"\n")
            return payload

        first_payload = nodes("first")
        publisher = Publisher(root / "public")
        first = publisher.publish(release)
        port = unused_port()
        command = [sys.executable, str(Path(__file__).resolve().parents[1] / "publish.py"),
                   "serve", "--root", str(publisher.root), "--bind", "127.0.0.1",
                   "--port", str(port), "--cert", str(cert), "--key", str(key)]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        context = ssl.create_default_context(cafile=str(cert))

        def request(path, method="GET"):
            connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=2, context=context)
            try:
                connection.connect()
                assert connection.sock.version() in ("TLSv1.2", "TLSv1.3")
                connection.request(method, path)
                response = connection.getresponse()
                return response.status, response.read(), dict(response.getheaders())
            finally:
                connection.close()

        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    raise AssertionError("HTTPS publisher exited before readiness")
                try:
                    assert request("/" + first["token"] + "/nodes.txt")[1] == first_payload
                    break
                except (OSError, http.client.HTTPException):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)
            for filename in FILES:
                code, payload, headers = request("/" + first["token"] + "/" + filename)
                assert code == 200 and payload == (release / filename).read_bytes()
                assert headers["Cache-Control"] == "no-store"
            code, payload, headers = request("/" + first["token"] + "/nodes.txt", "HEAD")
            assert code == 200 and not payload and int(headers["Content-Length"]) == len(first_payload)
            assert request("/" + first["token"] + "/config.json")[0] == 404

            second_payload = nodes("second")
            publisher.publish(release)
            assert request("/" + first["token"] + "/nodes.txt")[1] == second_payload
            rotated = publisher.rotate_token()
            assert request("/" + first["token"] + "/nodes.txt")[0] == 404
            assert request("/" + rotated + "/nodes.txt")[1] == second_payload

            try:
                with publisher.transaction():
                    third_payload = nodes("third")
                    publisher.publish(release)
                    assert request("/" + rotated + "/nodes.txt")[1] == third_payload
                    raise RuntimeError("simulated metadata failure")
            except RuntimeError:
                pass
            assert request("/" + rotated + "/nodes.txt")[1] == second_payload
        finally:
            process.terminate()
            try:
                output, errors = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                output, errors = process.communicate(timeout=5)
            assert first["token"].encode() not in output + errors

        wrong_key = root / "wrong.key"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                        "-out", str(wrong_key)], check=True, capture_output=True, timeout=30)
        invalid = command[:]
        invalid[invalid.index("--port") + 1] = str(unused_port())
        invalid[-1] = str(wrong_key)
        result = subprocess.run(invalid, capture_output=True, timeout=10)
        assert result.returncode != 0, "mismatched TLS key unexpectedly started the server"
        print(json.dumps({"checks": 7, "result": "pass", "scope": "verified HTTPS, HEAD, private-file exclusion, live update, token rotation, rollback, mismatched TLS rejection"}))


if __name__ == "__main__":
    main()
