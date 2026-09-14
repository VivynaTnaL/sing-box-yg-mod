import json
import argparse
import copy
import base64
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import chain
import deploy


def spec(role="entry"):
    uid = "11111111-1111-4111-8111-111111111111"
    inbound = {"type": "vless", "tag": "vless", "listen": "0.0.0.0", "listen_port": 8443,
               "users": [{"uuid": uid, "flow": "xtls-rprx-vision"}]}
    link = "vless://" + uid + "@192.0.2.10:8443?security=reality&sni=www.example.com#test"
    direct, chained = chain.attach_profiles([inbound], [link], role)
    return {"schema_version": 2, "role": role, "inbounds": [inbound], "direct_links": direct, "chain_links": chained,
            "link": {"schema_version": 1, "type": "shadowsocks", "server": "192.0.2.20", "server_port": 9443,
                     "method": chain.METHOD, "password": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                     "allowed_sources": ["192.0.2.10"]}}


class ConfigTests(unittest.TestCase):
    def test_chain_routes_before_dns_and_unknown_users_rejected(self):
        data = spec()
        config = chain.render(data)
        self.assertEqual(config["route"]["rules"][0]["outbound"], "to-exit")
        self.assertTrue(config["route"]["rules"][0]["auth_user"][0].startswith("chain-"))
        self.assertEqual(config["route"]["rules"][-1], {"action": "reject"})
        self.assertNotIn(data["link"]["password"], str(data["direct_links"] + data["chain_links"]))

    def test_exit_acl_scoped_to_ss_and_direct_clients_preserved(self):
        config = chain.render(spec("exit"))
        rule = config["route"]["rules"][0]
        self.assertEqual(rule["rules"][0]["inbound"], [chain.SS_TAG])
        self.assertTrue(rule["rules"][1]["invert"])
        self.assertEqual(config["inbounds"][-1]["type"], "shadowsocks")
        self.assertEqual(len(config["inbounds"]), 2)

    def test_reject_invalid_link_and_colliding_ports(self):
        for field, value in (("server_port", True), ("server", "127.0.0.1"), ("password", "weak"),
                             ("method", "none"), ("allowed_sources", []), ("allowed_sources", ["0.0.0.0/0"])):
            data = spec()
            data["link"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                chain.validate(data)
        data = spec("exit")
        data["link"]["server_port"] = 8443
        with self.assertRaises(ValueError):
            chain.validate(data)

    def test_reject_stale_exports_and_unknown_fields(self):
        data = spec()
        data["chain_links"] = data["direct_links"]
        with self.assertRaises(ValueError):
            chain.validate(data)
        data = spec()
        data["fallback"] = "direct"
        with self.assertRaises(ValueError):
            chain.validate(data)

    def test_ipv6_acl_and_separate_source_address(self):
        data = spec("exit")
        data["link"]["server"] = "2001:db8::2"
        data["link"]["allowed_sources"] = ["2001:db8::9"]
        config = chain.render(data)
        self.assertEqual(config["inbounds"][-1]["listen"], "::")
        self.assertEqual(config["route"]["rules"][0]["rules"][1]["source_ip_cidr"], ["2001:db8::9/128"])

    def test_links_keep_public_endpoint_and_tls_query(self):
        data = spec()
        old = chain.parse_link(data["direct_links"][0])[2]
        new = chain.parse_link(data["chain_links"][0])[2]
        self.assertEqual(old.hostname, new.hostname)
        self.assertEqual(old.port, new.port)
        self.assertEqual(old.query, new.query)
        self.assertNotEqual(old.username, new.username)

    def test_vmess_cdn_argo_fields_preserved(self):
        import base64
        original = {"id": "11111111-1111-4111-8111-111111111111", "add": "cdn.example.com", "host": "argo.example.com",
                    "port": "443", "net": "ws", "path": "/original", "tls": "tls", "sni": "argo.example.com", "ps": "Argo"}
        link = "vmess://" + base64.b64encode(json.dumps(original).encode()).decode()
        new = chain.parse_link(chain.rewrite_link(link, {"uuid": "new-uuid"}, "A-to-B"))[2]
        for key in ("add", "host", "port", "net", "path", "tls", "sni"):
            self.assertEqual(original[key], new[key])
        self.assertEqual(new["id"], "new-uuid")

    def test_json_comments_keep_urls_and_reject_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text('{"url":"https://host/path", /* comment */ "x":1 // note\n}')
            self.assertEqual(chain.read_json(path)["url"], "https://host/path")
            path.write_text('{"x":1,"x":2}')
            with self.assertRaises(ValueError):
                chain.read_json(path)

    def test_private_atomic_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text("old")
            path.chmod(0o644)
            chain.write_private(path, {"secret": "test"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text()), {"secret": "test"})

    def test_refresh_keeps_chain_credentials(self):
        previous = spec()
        inbounds = copy.deepcopy(previous['inbounds'])
        for inbound in inbounds:
            inbound['users'] = [u for u in inbound['users'] if u['name'].startswith('direct-')]
        direct, chained = chain.attach_profiles(inbounds, previous['direct_links'], 'entry', previous)
        self.assertEqual(chain.parse_link(chained[0])[1], chain.parse_link(previous['chain_links'][0])[1])
        self.assertEqual(len(inbounds[0]['users']), 2)

    @patch.object(chain, 'check_version')
    @patch.object(chain, 'check_config')
    def test_build_groups_and_private_handoff(self, *_):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for role in ('entry', 'exit'):
                data = spec(role)
                chain.write_private(root / 'spec.json', data)
                args = argparse.Namespace(binary='core', spec=root / 'spec.json', output_dir=root / role)
                chain.build(args)
                groups = ('A-direct', 'A-to-B') if role == 'entry' else ('B-direct',)
                for group in groups:
                    text = (root / role / (group + '.txt')).read_text()
                    encoded = (root / role / (group + '.base64.txt')).read_text()
                    self.assertEqual(base64.b64decode(encoded).decode(), text)
                    self.assertNotIn(data['link']['password'], text)
                self.assertEqual((root / role / 'B-link.json').exists(), role == 'exit')
                self.assertEqual((root / role).stat().st_mode & 0o777, 0o700)
                with self.assertRaises(chain.ConfigError):
                    chain.build(args)

    def test_certificate_paths_embedded_for_dynamic_user(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'cert.pem').write_text('certificate\n')
            (root / 'key.pem').write_text('private-key\n')
            config = {'inbounds': [{'type': 'anytls', 'users': [{'password': 'x'}],
                                   'tls': {'certificate_path': 'cert.pem', 'key_path': 'key.pem'}, 'sniff': True}]}
            inbound = chain.normalize_inbounds(config, root)[0]
            self.assertEqual(inbound['tls']['key'], ['private-key'])
            self.assertNotIn('key_path', inbound['tls'])
            self.assertNotIn('sniff', inbound)


class DeployTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / "config.json"
        self.candidate = self.root / "candidate.json"
        self.candidate.write_text('{"new":true}')

    @patch.object(deploy, "check_version")
    @patch.object(deploy, "run_core", side_effect=ValueError("bad config"))
    @patch.object(deploy, "control")
    def test_invalid_config_does_not_touch_service(self, control, *_):
        self.target.write_text('{"old":true}')
        with self.assertRaises(ValueError):
            deploy.apply(self.candidate, self.root)
        self.assertEqual(json.loads(self.target.read_text()), {"old": True})
        control.assert_not_called()

    @patch.object(deploy, "check_version")
    @patch.object(deploy, "run_core")
    @patch.object(deploy, "control", return_value=True)
    @patch.object(deploy, "healthy", side_effect=[False, True])
    def test_failure_restores_old_config(self, healthy, control, *_):
        self.target.write_text('{"old":true}')
        with self.assertRaises(RuntimeError):
            deploy.apply(self.candidate, self.root)
        self.assertEqual(json.loads(self.target.read_text()), {"old": True})
        self.assertEqual(json.loads((self.root / "config.previous.json").read_text()), {"old": True})
        self.assertIn(unittest.mock.call("start"), control.call_args_list)

    @patch.object(deploy, "check_version")
    @patch.object(deploy, "run_core")
    @patch.object(deploy, "control", side_effect=[False, True, True])
    @patch.object(deploy, "healthy", return_value=False)
    def test_failed_first_install_leaves_service_stopped(self, *_):
        with self.assertRaises(RuntimeError):
            deploy.apply(self.candidate, self.root)
        self.assertFalse(self.target.exists())

    @patch.object(deploy, "check_version")
    @patch.object(deploy, "run_core")
    @patch.object(deploy, "control", return_value=True)
    @patch.object(deploy, "healthy", return_value=True)
    def test_success(self, *_):
        deploy.apply(self.candidate, self.root)
        self.assertEqual(json.loads(self.target.read_text()), {"new": True})

    @patch.object(deploy, "main_pid", side_effect=[10, 11])
    @patch.object(deploy, "control", return_value=True)
    def test_crash_restart_is_unhealthy(self, *_):
        self.assertFalse(deploy.healthy())

    @patch.object(deploy, 'check_version')
    @patch.object(deploy, 'run_core')
    @patch.object(deploy, 'control')
    @patch.object(deploy, 'healthy', return_value=False)
    def test_takeover_failure_restores_legacy_and_marker(self, healthy, control, *_):
        control.side_effect = lambda *args, **kw: not (args[0] == 'is-active' and not kw)
        with self.assertRaises(RuntimeError):
            deploy.apply(self.candidate, self.root, take_over_legacy=True)
        self.assertFalse((self.root / 'legacy-managed').exists())
        self.assertFalse(self.target.exists())
        self.assertIn(unittest.mock.call('start', service='sing-box.service'), control.call_args_list)
        self.assertIn(unittest.mock.call('enable', service='sing-box.service'), control.call_args_list)

    @patch.object(deploy, 'check_version')
    @patch.object(deploy, 'run_core')
    @patch.object(deploy, 'control')
    @patch.object(deploy, 'healthy', return_value=True)
    def test_takeover_success_disables_legacy(self, healthy, control, *_):
        control.side_effect = lambda *args, **kw: not (args[0] == 'is-active' and not kw)
        deploy.apply(self.candidate, self.root, take_over_legacy=True)
        self.assertTrue((self.root / 'legacy-managed').exists())
        self.assertIn(unittest.mock.call('disable', service='sing-box.service'), control.call_args_list)


class LegacyTests(unittest.TestCase):
    def test_failed_download_preserves_existing_core_and_cleans_stage(self):
        source = (Path(__file__).resolve().parents[2] / "sb.sh").read_text()
        function = source[source.index("fetch_sbcore(){"):source.index("\ninssb(){")]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core = root / "sing-box"
            core.write_text("existing-core")
            (root / "sing-box.tar.gz").write_text("stale-archive")
            function = function.replace("/etc/s-box", directory)
            script = 'red(){ :; }\ncurl(){ return 22; }\ncpu=amd64\n' + function
            script += '\nfetch_sbcore 1.14.0\n'
            result = subprocess.run(["bash", "-c", script], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(core.read_text(), "existing-core")
            self.assertFalse(list(root.glob(".core.*")))

    def test_firewall_entry_does_not_call_system_tools(self):
        source = (Path(__file__).resolve().parents[2] / "sb.sh").read_text()
        function = source[source.index("close(){"):source.index("# Download into an isolated directory.")]
        result = subprocess.run(["/bin/bash", "-c", 'yellow(){ :; }\n' + function + '\nclose\nopenyn\n'],
                                env={"PATH": "/nonexistent"}, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main()
