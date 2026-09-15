#!/usr/bin/env python3
"""Offline addon integration: real loopback processes, no systemd or installed state.

Run with a locked sing-box core: python3 chain/tests/integration_addon.py --binary PATH
All sockets bind to loopback and all files live in one temporary /tmp directory.
"""
import argparse
import base64
import contextlib
import copy
import errno
import http.client
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import chain
import profiles
import publish
import policy


def receive(sock, count):
    data = b""
    while len(data) < count:
        block = sock.recv(count - len(data))
        if not block:
            raise OSError("unexpected EOF")
        data += block
    return data


def socks_connection(proxy_port, target_port, command=1):
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=3)
    try:
        sock.sendall(b"\x05\x01\x00")
        if receive(sock, 2) != b"\x05\x00":
            raise OSError("SOCKS authentication failed")
        sock.sendall(bytes([5, command, 0, 1]) + socket.inet_aton("127.0.0.1") + struct.pack("!H", target_port))
        reply = receive(sock, 4)
        if reply[1] != 0:
            raise OSError("SOCKS request rejected")
        if reply[3] == 1:
            host = socket.inet_ntoa(receive(sock, 4))
        elif reply[3] == 4:
            host = socket.inet_ntop(socket.AF_INET6, receive(sock, 16))
        else:
            raise OSError("invalid SOCKS address")
        bound_port = struct.unpack("!H", receive(sock, 2))[0]
        return sock, (host, bound_port)
    except BaseException:
        sock.close()
        raise


def socks_echo(proxy_port, target_port):
    sock, _ = socks_connection(proxy_port, target_port)
    with sock:
        sock.sendall(b"addon-integration")
        return receive(sock, len(b"127.0.0.3:addon-integration"))


def socks_udp_echo(proxy_port, target_port):
    control, relay = socks_connection(proxy_port, 0, command=3)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        # Only this test's loopback SOCKS server can be the relay.
        assert relay[0] == "127.0.0.1", "UDP relay did not bind loopback"
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(3)
        header = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", target_port)
        udp.sendto(header + b"addon-udp-integration", relay)
        response, peer = udp.recvfrom(4096)
        assert peer == relay, "UDP response came from an unexpected relay"
        assert response[:10] == header, "UDP response had an invalid SOCKS5 header"
        return response[10:]


def blocked(proxy_port, target_port, udp=False):
    try:
        result = (socks_udp_echo if udp else socks_echo)(proxy_port, target_port)
    except OSError:
        return
    raise AssertionError("blocked chain unexpectedly returned " + repr(result))


def echo_server(listener):
    def handle(connection):
        try:
            with connection:
                connection.settimeout(3)
                data = connection.recv(4096)
                if data:
                    connection.sendall(connection.getpeername()[0].encode() + b":" + data)
        except OSError:
            pass

    while True:
        try:
            connection, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=handle, args=(connection,), daemon=True).start()


def udp_echo_server(listener):
    while True:
        try:
            data, peer = listener.recvfrom(4096)
            listener.sendto(peer[0].encode() + b":" + data, peer)
        except OSError:
            return


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def ready(process, port, label):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(label + " exited before listening")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(label + " did not open its loopback listener")


def client_config(outbound, listen_port):
    outbound = copy.deepcopy(outbound)
    outbound.update(server="127.0.0.1", tag="proxy")
    return {"log": {"level": "error"},
            "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": listen_port}],
            "outbounds": [outbound], "route": {"final": "proxy"}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args(argv)
    binary = str(args.binary.resolve(strict=True))
    chain.check_version(binary)
    with tempfile.TemporaryDirectory(prefix="addon-integration-", dir="/tmp") as directory, contextlib.ExitStack() as stack:
        root = Path(directory)
        reservations = {}

        def reserve(label):
            # Reserve both transports so the UDP echo or SS listener cannot
            # accidentally receive a port selected for a future TCP process.
            while True:
                tcp = stack.enter_context(socket.socket())
                udp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                tcp.bind(("127.0.0.1", 0))
                port = tcp.getsockname()[1]
                try:
                    udp.bind(("127.0.0.1", port))
                except OSError as error:
                    tcp.close()
                    udp.close()
                    if error.errno != errno.EADDRINUSE:
                        raise
                    continue
                reservations[label] = (tcp, udp)
                return port

        def release_port(label):
            for sock in reservations[label]:
                sock.close()

        ports = {name: reserve(name) for name in ("original", "entry", "exit", "original-client", "chain-client", "subscription")}
        listener = stack.enter_context(socket.socket())
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        echo_port = listener.getsockname()[1]
        threading.Thread(target=echo_server, args=(listener,), daemon=True).start()
        udp_listener = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        udp_listener.bind(("127.0.0.1", 0))
        udp_echo_port = udp_listener.getsockname()[1]
        threading.Thread(target=udp_echo_server, args=(udp_listener,), daemon=True).start()

        original_inbound = {"type": "vmess", "tag": "original-vmess", "listen": "127.0.0.1",
                            "listen_port": ports["original"], "users": [{"uuid": str(uuid.uuid4())}],
                            "transport": {"type": "ws", "path": "/addon-integration"}}
        original_config = {"log": {"level": "error"}, "inbounds": [original_inbound],
                           "outbounds": [{"type": "direct", "tag": "direct", "inet4_bind_address": "127.0.0.2"}],
                           "route": {"final": "direct"}}
        source = root / "import-source.json"
        chain.write_private(source, original_config)
        original_bytes = source.read_bytes()
        imported = profiles.import_entry(source, "192.0.2.10", binary, port_start=ports["entry"])
        assert source.read_bytes() == original_bytes, "import modified its input"
        assert imported[0]["inbound"]["listen_port"] != ports["original"], "addon reused the original port"
        assert imported[0]["inbound"]["users"][0]["uuid"] != original_inbound["users"][0]["uuid"], "addon reused original credentials"
        production_exit, handoff = profiles.exit_config("192.0.2.20", ports["exit"], ["192.0.2.10"])
        production_entry = profiles.entry_config(imported, handoff["outbounds"][0])
        assert any(rule.get("ip_is_private") and rule.get("action") == "reject"
                   for rule in production_exit["route"]["rules"]), "production private-target block is missing"
        assert [out["type"] for out in production_entry["outbounds"]] == ["shadowsocks"], "entry has an unexpected fallback outbound"

        # Only temporary test copies point at loopback; the production generator
        # still rejects loopback public endpoints and retains its private-target rule.
        configs = {"original": original_config, "entry": copy.deepcopy(production_entry),
                   "exit": copy.deepcopy(production_exit)}
        for name in ("entry", "exit"):
            for inbound in configs[name]["inbounds"]:
                inbound["listen"] = "127.0.0.1"
        configs["entry"]["outbounds"][0]["server"] = "127.0.0.1"
        configs["exit"]["route"]["rules"][0]["source_ip_cidr"] = ["127.0.0.1/32"]
        configs["exit"]["outbounds"][0]["inet4_bind_address"] = "127.0.0.3"
        original_client = profiles.client(original_inbound, original_inbound["users"][0], "192.0.2.10", "original")
        configs["original-client"] = client_config(original_client["outbound"], ports["original-client"])
        configs["chain-client"] = client_config(imported[0]["clients"][0]["outbound"], ports["chain-client"])

        def start_core(name):
            config_path = root / (name + ".json")
            chain.write_private(config_path, configs[name])
            chain.run_core(binary, "check", "-c", str(config_path))
            release_port(name)
            log = stack.enter_context((root / (name + ".log")).open("ab"))
            process = subprocess.Popen([binary, "run", "-c", str(config_path)], stdout=log, stderr=log)
            stack.callback(stop, process)
            ready(process, ports[name], name)
            return process

        original = start_core("original")
        exit_process = start_core("exit")
        entry = start_core("entry")
        start_core("original-client")
        client_process = start_core("chain-client")
        source.unlink()

        def original_works():
            assert original.poll() is None, "original process was interrupted"
            assert socks_echo(ports["original-client"], echo_port) == b"127.0.0.2:addon-integration"
            assert socks_udp_echo(ports["original-client"], udp_echo_port) == b"127.0.0.2:addon-udp-integration"

        def chain_works():
            assert socks_echo(ports["chain-client"], echo_port) == b"127.0.0.3:addon-integration"
            assert socks_udp_echo(ports["chain-client"], udp_echo_port) == b"127.0.0.3:addon-udp-integration"

        def chain_blocked():
            blocked(ports["chain-client"], echo_port)
            blocked(ports["chain-client"], udp_echo_port, udp=True)

        original_works()
        chain_blocked()
        print("PASS: imported on separate port/credentials; production chain rejects private TCP/UDP targets", flush=True)

        stop(exit_process)
        configs["exit"]["route"]["rules"] = [rule for rule in configs["exit"]["route"]["rules"] if not rule.get("ip_is_private")]
        exit_process = start_core("exit")
        chain_works()
        original_works()
        assert not source.exists(), "test source unexpectedly reappeared"
        print("PASS: concurrent TCP/UDP traffic; original exits via .2, chain via B .3", flush=True)

        # Exercise actual client routing using a local destination whose TCP
        # and UDP replies identify the selected exit. The synthetic CN-IP case
        # removes loopback from this test's LAN set so CN matching is observable.
        baseline_client = copy.deepcopy(configs['chain-client'])
        routing_cases = [
            ('LAN direct', policy.load_policy('lan-direct'), '127.0.0.1'),
            ('global proxy', policy.load_policy('global'), '127.0.0.3'),
            ('explicit proxy over LAN', policy.load_policy('lan-direct', proxy_cidrs=['127.0.0.1/32']), '127.0.0.3'),
            ('explicit direct over global', policy.load_policy('global', direct_cidrs=['127.0.0.1/32']), '127.0.0.1'),
        ]
        cn_policy = policy.load_policy('cn-direct')
        cn_policy.update(source='inline', sets={'cn-domain': [{'domain_suffix': ['example.cn']}],
                                                'cn-ip': [{'ip_cidr': ['127.0.0.1/32']}]})
        routing_cases.append(('CN IP direct', cn_policy, '127.0.0.1'))
        for label, routing, expected in routing_cases:
            stop(client_process)
            candidate = copy.deepcopy(baseline_client)
            candidate['outbounds'].append({'type': 'direct', 'tag': 'direct'})
            original_lan = policy.LAN_CIDRS
            try:
                if label == 'CN IP direct':
                    policy.LAN_CIDRS = ('10.0.0.0/8',)
                policy.apply_singbox(candidate, routing)
            finally:
                policy.LAN_CIDRS = original_lan
            configs['chain-client'] = candidate
            client_process = start_core('chain-client')
            assert socks_echo(ports['chain-client'], echo_port) == expected.encode() + b':addon-integration', label
            assert socks_udp_echo(ports['chain-client'], udp_echo_port) == expected.encode() + b':addon-udp-integration', label
        stop(client_process)
        configs['chain-client'] = baseline_client
        client_process = start_core('chain-client')
        chain_works()
        original_works()
        print('PASS: real client TCP/UDP routing selects LAN/CN/explicit DIRECT and global/explicit proxy exits', flush=True)

        stop(exit_process)
        configs["exit"]["route"]["rules"][0]["source_ip_cidr"] = ["192.0.2.99/32"]
        exit_process = start_core("exit")
        chain_blocked()
        original_works()
        print("PASS: B rejects unauthorized SS2022 source for TCP/UDP; original remains usable", flush=True)
        stop(exit_process)
        configs["exit"]["route"]["rules"][0]["source_ip_cidr"] = ["127.0.0.1/32"]
        exit_process = start_core("exit")
        chain_works()

        stop(exit_process)
        chain_blocked()
        original_works()
        print("PASS: SS2022 link failure blocks TCP/UDP without fallback; original remains usable", flush=True)

        exit_process = start_core("exit")
        chain_works()
        stop(entry)
        correct_key = configs["entry"]["outbounds"][0]["password"]
        configs["entry"]["outbounds"][0]["password"] = base64.b64encode(bytes(value ^ 1 for value in base64.b64decode(correct_key))).decode()
        entry = start_core("entry")
        chain_blocked()
        original_works()
        print("PASS: incorrect SS2022 key rejects TCP/UDP; original remains usable", flush=True)
        stop(entry)
        configs["entry"]["outbounds"][0]["password"] = correct_key
        entry = start_core("entry")
        chain_works()
        stop(entry)
        chain_blocked()
        original_works()
        assert (root / "original.json").read_bytes() == original_bytes, "original runtime configuration changed"
        print("PASS: stopping addon A leaves the original process, configuration and traffic intact", flush=True)

        release = root / "release"
        release.mkdir()

        def release_files(revision):
            item = copy.deepcopy(imported[0]["clients"][0])
            item["outbound"]["tag"] = "A-to-B-revision-" + str(revision)
            nodes = (profiles.share_link(item) + "\n").encode()
            (release / "nodes.txt").write_bytes(nodes)
            (release / "nodes.base64.txt").write_bytes(base64.b64encode(nodes) + b"\n")
            outbound = item["outbound"]
            chain.write_private(release / "sing-box.json", {"outbounds": [outbound], "route": {"final": outbound["tag"]}})
            mihomo_node = {"name": outbound["tag"], "type": "vmess", "server": outbound["server"],
                           "port": outbound["server_port"], "uuid": outbound["uuid"], "alterId": 0,
                           "cipher": "auto", "network": "ws", "ws-opts": {"path": "/addon-integration"}}
            # JSON is also a valid YAML document.
            (release / "mihomo.yaml").write_text(json.dumps({"mode": "rule", "proxies": [mihomo_node],
                                                             "rules": ["MATCH," + outbound["tag"]]}) + "\n")

        release_files(1)
        (release / "config.json").write_text("test server private key\n")
        (release / "B-link.json").write_text("test handoff password\n")
        publisher = publish.Publisher(root / "subscriptions")
        state = publisher.publish(release)
        log_path = root / "subscription.log"
        log = stack.enter_context(log_path.open("wb"))
        release_port("subscription")
        server = subprocess.Popen([sys.executable, str(Path(publish.__file__).resolve()), "serve", "--root", str(publisher.root),
                                   "--bind", "127.0.0.1", "--port", str(ports["subscription"])], stdout=log, stderr=log)
        stack.callback(stop, server)
        ready(server, ports["subscription"], "subscription")

        def request(method, path):
            connection = http.client.HTTPConnection("127.0.0.1", ports["subscription"], timeout=3)
            try:
                connection.request(method, path)
                response = connection.getresponse()
                return response.status, response.read(), dict(response.getheaders())
            finally:
                connection.close()

        prefix = "/" + state["token"] + "/"
        for name in publish.FILES:
            status, body, headers = request("GET", prefix + name)
            assert status == 200 and body == (release / name).read_bytes(), "GET subscription mismatch"
            assert headers["Cache-Control"] == "no-store"
            status, body, headers = request("HEAD", prefix + name)
            assert status == 200 and body == b"" and int(headers["Content-Length"]) == (release / name).stat().st_size, "HEAD subscription mismatch"
        for path in ("/", prefix, prefix + "config.json", prefix + "B-link.json", prefix + "../state.json", prefix + "%2e%2e/state.json"):
            assert request("GET", path)[0] == 404, "subscription exposed an unsupported path"
        release_files(2)
        updated = publisher.publish(release)
        assert updated["token"] == state["token"]
        assert request("GET", prefix + "nodes.txt")[1] == (release / "nodes.txt").read_bytes(), "running HTTP server served stale contents"
        new_token = publisher.rotate_token()
        assert request("GET", prefix + "nodes.txt")[0] == 404, "old subscription token remains valid"
        assert request("GET", "/" + new_token + "/nodes.txt")[0] == 200
        stop(server)
        log.flush()
        access_log = log_path.read_bytes()
        assert state["token"].encode() not in access_log and new_token.encode() not in access_log, "subscription token leaked to logs"
        original_works()
        print("PASS: real HTTP GET/HEAD, atomic updates, stable URL, token rotation, whitelist and private logs", flush=True)
        print("PASS: all addon integration checks completed without systemd or external network", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
