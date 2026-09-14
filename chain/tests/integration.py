#!/usr/bin/env python3
"""Offline three-group Reality + SS2022 integration test. Requires a core and openssl, no system services."""
import argparse
import base64
import uuid
import contextlib
import json
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import chain


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def receive(sock, count):
    data = b""
    while len(data) < count:
        block = sock.recv(count - len(data))
        if not block:
            raise OSError("unexpected EOF")
        data += block
    return data


def socks(proxy_port, target_port, command=1):
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=4)
    try:
        sock.sendall(b"\x05\x01\x00")
        assert receive(sock, 2) == b"\x05\x00"
        sock.sendall(bytes([5, command, 0, 1]) + socket.inet_aton("127.0.0.1") + struct.pack("!H", target_port))
        reply = receive(sock, 4)
        if reply[1] != 0:
            raise OSError("SOCKS request rejected")
        if reply[3] == 1:
            host = socket.inet_ntoa(receive(sock, 4))
        elif reply[3] == 4:
            host = socket.inet_ntop(socket.AF_INET6, receive(sock, 16))
        else:
            raise OSError("unexpected SOCKS address")
        bound_port = struct.unpack("!H", receive(sock, 2))[0]
        return sock, (host, bound_port)
    except BaseException:
        sock.close()
        raise


def echo_server(sock, udp=False, tls=None):
    while True:
        try:
            if udp:
                data, peer = sock.recvfrom(4096)
                sock.sendto(peer[0].encode() + b":" + data, peer)
                continue
            conn, _ = sock.accept()
        except OSError:
            return
        def handle(conn):
            try:
                conn.settimeout(4)
                if tls:
                    conn = tls.wrap_socket(conn, server_side=True)
                with conn:
                    data = conn.recv(4096)
                    if data:
                        conn.sendall(conn.getpeername()[0].encode() + b":" + data)
            except (OSError, ssl.SSLError):
                conn.close()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    chain.check_version(binary)
    with tempfile.TemporaryDirectory(prefix="chain-integration-") as directory, contextlib.ExitStack() as stack:
        root = Path(directory)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-addext", "subjectAltName=DNS:www.example.com",
                        "-subj", "/CN=www.example.com", "-keyout", str(root / "key"),
                        "-out", str(root / "cert")], check=True, capture_output=True)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.load_cert_chain(root / "cert", root / "key")
        ports = []
        for udp, context in ((False, tls), (False, None), (True, None)):
            sock = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM))
            sock.bind(("127.0.0.1", 0))
            if not udp:
                sock.listen()
            ports.append(sock.getsockname()[1])
            threading.Thread(target=echo_server, args=(sock, udp, context), daemon=True).start()
        handshake_port, tcp_port, udp_port = ports
        def initialize(role):
            server = "192.0.2.10" if role == "entry" else "192.0.2.20"
            inbounds, links = chain.fresh_profile(binary, server, port(), "www.example.com")
            for protocol in ("vmess", "hysteria2", "tuic", "anytls"):
                listen_port, uid, password = port(), str(uuid.uuid4()), "test-password"
                tls_options = {"enabled": True, "server_name": "www.example.com",
                               "certificate_path": str(root / "cert"), "key_path": str(root / "key")}
                inbound = {"type": protocol, "tag": protocol, "listen": "127.0.0.1", "listen_port": listen_port,
                           "tls": tls_options, "users": []}
                if protocol == "vmess":
                    inbound["users"] = [{"uuid": uid}]
                    inbound["transport"] = {"type": "ws", "path": "/ws-test"}
                    data = {"v": "2", "id": uid, "add": server, "port": str(listen_port), "net": "ws", "path": "/ws-test",
                            "tls": "tls", "sni": "www.example.com", "host": "www.example.com", "ps": "WS"}
                    link = "vmess://" + base64.b64encode(json.dumps(data).encode()).decode()
                elif protocol == "tuic":
                    inbound["users"] = [{"uuid": uid, "password": password}]
                    inbound["tls"]["alpn"] = ["h3"]
                    link = f"tuic://{uid}:{password}@{server}:{listen_port}?sni=www.example.com&insecure=1#TUIC"
                else:
                    inbound["users"] = [{"password": password}]
                    link = f"{protocol}://{password}@{server}:{listen_port}?sni=www.example.com&insecure=1#test"
                inbounds.append(inbound)
                links.append(link)
            config_path, links_path = root / (role + "-legacy.json"), root / (role + "-links.txt")
            chain.write_private(config_path, {"inbounds": inbounds})
            links_path.write_text("\n".join(links))
            options = dict(binary=binary, output=str(root / (role + "-spec.json")), legacy_config=str(config_path),
                           legacy_links=str(links_path), address=None, port=8443, sni=None, command="init-" + role)
            if role == "exit":
                options.update(server="192.0.2.20", link_port=port(), entry_source=["192.0.2.10"])
            else:
                options["link"] = str(root / "B-link.json")
            return chain.initialize(argparse.Namespace(**options))
        exit_spec = initialize("exit")
        chain.write_private(root / "B-link.json", exit_spec["link"])
        entry_spec = initialize("entry")
        specs = {"entry": entry_spec, "exit": exit_spec}
        configs = {role: chain.render(spec) for role, spec in specs.items()}
        for config in configs.values():
            for inbound in config["inbounds"]:
                inbound["listen"] = "127.0.0.1"
                if inbound["type"] == "vless":
                    inbound["tls"]["reality"]["handshake"] = {"server": "127.0.0.1", "server_port": handshake_port}
        configs["entry"]["outbounds"][1]["server"] = "127.0.0.1"
        configs["exit"]["route"]["rules"][0]["rules"][1]["source_ip_cidr"] = ["127.0.0.1/32"]
        # Distinct loopback source addresses let the echo target prove which server exited.
        configs["entry"]["outbounds"][0]["inet4_bind_address"] = "127.0.0.2"
        configs["exit"]["outbounds"][0]["inet4_bind_address"] = "127.0.0.3"
        from urllib.parse import parse_qs
        proxy_ports = {}
        for group_name, spec, group in (("A-direct", entry_spec, "direct_links"), ("A-to-B", entry_spec, "chain_links"),
                                         ("B-direct", exit_spec, "direct_links")):
            for link in spec[group]:
                protocol, creds, url = chain.parse_link(link)
                name = group_name + "-" + protocol
                client_out = {"type": protocol, "tag": "proxy", "server": "127.0.0.1",
                              "server_port": int(url["port"]) if protocol == "vmess" else url.port}
                if protocol == "vless":
                    query = parse_qs(url.query)
                    client_out.update(uuid=creds[0], flow="xtls-rprx-vision", packet_encoding="xudp",
                        tls={"enabled": True, "server_name": query["sni"][0],
                             "utls": {"enabled": True, "fingerprint": "chrome"},
                             "reality": {"enabled": True, "public_key": query["pbk"][0], "short_id": query["sid"][0]}})
                else:
                    # Trust only this test's ephemeral certificate, never insecure TLS.
                    client_out["tls"] = {"enabled": True, "server_name": "www.example.com",
                                         "certificate": (root / "cert").read_text().splitlines()}
                    if protocol == "vmess":
                        client_out.update(uuid=creds[0], security="auto", transport={"type": "ws", "path": url["path"]})
                    elif protocol == "tuic":
                        client_out.update(uuid=creds[0], password=creds[1], congestion_control="bbr")
                        client_out["tls"]["alpn"] = ["h3"]
                    else:
                        client_out["password"] = creds[0]
                proxy_ports[name] = port()
                configs[name] = {"inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": proxy_ports[name]}],
                                 "outbounds": [client_out], "route": {"final": "proxy"}, "log": {"level": "warn"}}
        processes = []
        def stop(process):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        def start(role):
            path = root / (role + ".json")
            chain.write_private(path, configs[role])
            chain.run_core(binary, "check", "-c", str(path))
            process = subprocess.Popen([binary, "run", "-c", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            stack.callback(stop, process)
            processes.append(process)
            time.sleep(0.3)
            assert process.poll() is None, role + " failed to start"
            return process
        exit_process = start("exit")
        entry_process = start("entry")
        clients = {name: start(name) for name in proxy_ports}
        def reconnect_clients():
            # QUIC clients retain connections across server restarts. Start fresh sessions
            # for routing assertions instead of depending on transport idle timeouts.
            for name, process in clients.items():
                stop(process)
                clients[name] = start(name)
        def tcp_echo(name):
            sock, _ = socks(proxy_ports[name], tcp_port)
            with sock:
                sock.sendall(b"chain-tcp")
                return sock.recv(100)
        def assert_blocked(name):
            try:
                result = tcp_echo(name)
            except OSError:
                return
            assert not result, "unexpected traffic: " + repr(result)
        for name in proxy_ports:
            assert_blocked(name)
        print("PASS: all groups reject private targets")
        stop(exit_process)
        stop(entry_process)
        # Only test configurations remove this rule to permit loopback echo targets.
        for config in configs.values():
            config["route"]["rules"] = [r for r in config["route"].get("rules", []) if not r.get("ip_is_private")]
        exit_process = start("exit")
        entry_process = start("entry")
        reconnect_clients()
        for name in proxy_ports:
            source = "127.0.0.2" if name.startswith("A-direct") else "127.0.0.3"
            assert tcp_echo(name) == source.encode() + b":chain-tcp", name
            control, relay = socks(proxy_ports[name], 0, command=3)
            with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(5)
                packet = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", udp_port) + b"chain-udp"
                udp.sendto(packet, relay)
                reply, _ = udp.recvfrom(4096)
                assert reply.endswith(source.encode() + b":chain-udp"), name
            print("PASS: " + name + " TCP/UDP verified exit " + source)
        stop(exit_process)
        configs["exit"]["route"]["rules"][0]["rules"][1]["source_ip_cidr"] = ["192.0.2.99/32"]
        exit_process = start("exit")
        reconnect_clients()
        for name in proxy_ports:
            if name.startswith("A-to-B"):
                assert_blocked(name)
            elif name.startswith("B-direct"):
                assert tcp_echo(name).startswith(b"127.0.0.3:")
        print("PASS: unauthorized SS source rejected; B-direct remains usable")
        stop(exit_process)
        for name in proxy_ports:
            if name.startswith("A-direct"):
                assert tcp_echo(name).startswith(b"127.0.0.2:")
            else:
                assert_blocked(name)
        print("PASS: B offline blocks chain; A-direct remains usable")
        configs['exit']['route']['rules'][0]['rules'][1]['source_ip_cidr'] = ['127.0.0.1/32']
        exit_process = start('exit')
        stop(entry_process)
        configs['entry']['outbounds'][1]['password'] = base64.b64encode(b'X' * 32).decode()
        entry_process = start('entry')
        reconnect_clients()
        assert_blocked('A-to-B-vless')
        assert tcp_echo('A-direct-vless').startswith(b'127.0.0.2:')
        assert tcp_echo('B-direct-vless').startswith(b'127.0.0.3:')
        print('PASS: incorrect SS2022 key rejected; both direct groups remain usable')


if __name__ == "__main__":
    main()
