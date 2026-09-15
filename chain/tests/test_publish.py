import base64
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import publish
import runtime
from test_runtime import FakeSystem


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.release = self.root / "release"
        self.release.mkdir()
        (self.release / "mihomo.yaml").write_text("proxies: []\n")
        (self.release / "sing-box.json").write_text(json.dumps({"outbounds": [{"type": "direct"}]}))
        self.nodes("vless://test@example.com:8443\n")
        (self.release / "config.json").write_text("server private key")
        (self.release / "B-link.json").write_text("handoff password")
        self.publisher = publish.Publisher(self.root / "public")

    def nodes(self, text):
        (self.release / "nodes.txt").write_text(text)
        (self.release / "nodes.base64.txt").write_bytes(base64.b64encode(text.encode()) + b"\n")

    def test_snapshot_whitelist_and_fixed_url_across_updates(self):
        first = self.publisher.publish(self.release)
        url = self.publisher.url("https://sub.example.com/sub", "mihomo.yaml")
        self.assertEqual(url, "https://sub.example.com/sub/" + first["token"] + "/mihomo.yaml")
        self.nodes("vless://new@example.com:8443\n")
        second = self.publisher.publish(self.release)
        self.assertEqual(second["token"], first["token"])
        self.assertNotEqual(second["generation"], first["generation"])
        published = self.publisher.root / "releases" / second["generation"]
        self.assertEqual(set(item.name for item in published.iterdir()), set(publish.FILES))
        self.assertEqual(self.publisher.response("/" + first["token"] + "/nodes.txt")[0], b"vless://new@example.com:8443\n")

    def test_rotation_invalidates_old_token(self):
        first = self.publisher.publish(self.release)
        token = self.publisher.rotate_token()
        self.assertNotEqual(token, first["token"])
        self.assertIsNone(self.publisher.response("/" + first["token"] + "/nodes.txt"))
        self.assertIsNotNone(self.publisher.response("/" + token + "/nodes.txt"))

    def test_traversal_secret_and_directory_paths_are_unavailable(self):
        token = self.publisher.publish(self.release)["token"]
        paths = ["/", "/" + token + "/", "/" + token + "/config.json", "/" + token + "/B-link.json",
                 "/" + token + "/../state.json", "/" + token + "/%2e%2e/state.json", "/" + token + "/nodes.txt/extra",
                 "/" + token + "/nodes.txt?download=1", "http://example.com/" + token + "/nodes.txt"]
        for path in paths:
            with self.subTest(path=path):
                self.assertIsNone(self.publisher.response(path))

    def test_publish_rejects_source_symlink_without_modifying_current(self):
        first = self.publisher.publish(self.release)
        source = self.release / "nodes.txt"
        source.unlink()
        source.symlink_to(self.release / "config.json")
        with self.assertRaises((OSError, ValueError)):
            self.publisher.publish(self.release)
        self.assertEqual(self.publisher.state(), first)

    def test_handler_rejects_published_symlink(self):
        state = self.publisher.publish(self.release)
        target = self.publisher.root / "releases" / state["generation"] / "nodes.txt"
        target.unlink()
        target.symlink_to(self.release / "config.json")
        self.assertIsNone(self.publisher.response("/" + state["token"] + "/nodes.txt"))

    def test_failure_before_manifest_switch_keeps_old_contents(self):
        state = self.publisher.publish(self.release)
        self.nodes("vless://new@example.com:8443\n")
        original = publish._atomic

        def atomic(path, payload, mode=0o600):
            if Path(path).name == "state.json":
                raise OSError("disk full")
            return original(path, payload, mode)

        with patch.object(publish, "_atomic", side_effect=atomic):
            with self.assertRaises(OSError):
                self.publisher.publish(self.release)
        self.assertEqual(self.publisher.state(), state)
        self.assertEqual(self.publisher.response("/" + state["token"] + "/nodes.txt")[0], b"vless://test@example.com:8443\n")

    def test_reject_empty_client_or_inconsistent_nodes(self):
        (self.release / "sing-box.json").write_text('{"inbounds":[]}')
        with self.assertRaisesRegex(ValueError, "客户端出站"):
            self.publisher.publish(self.release)
        (self.release / "sing-box.json").write_text('{"outbounds":[{"type":"direct"}]}')
        (self.release / "nodes.base64.txt").write_text(base64.b64encode(b"different").decode())
        with self.assertRaisesRegex(ValueError, "不一致"):
            self.publisher.publish(self.release)

    def test_updates_cannot_accidentally_change_token(self):
        self.publisher.publish(self.release)
        with self.assertRaisesRegex(ValueError, "rotate_token"):
            self.publisher.publish(self.release, token="A" * 32)

    def test_head_no_body_and_access_logs_do_not_reveal_token(self):
        state = self.publisher.publish(self.release)
        handler = object.__new__(self.publisher.handler())
        handler.path = "/" + state["token"] + "/nodes.txt"
        handler.wfile = io.BytesIO()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        with patch("sys.stderr", new_callable=io.StringIO) as stderr:
            handler.log_message("request %s", handler.path)
        self.assertEqual(stderr.getvalue(), "")
        handler.do_HEAD()
        self.assertEqual(handler.wfile.getvalue(), b"")
        handler.send_response.assert_called_once_with(200)
        handler.send_header.assert_any_call("Cache-Control", "no-store")

    def test_service_install_is_independent_loopback_and_does_not_start(self):
        publisher = publish.Publisher(self.root / "var/lib/sing-box-addon-sub")
        publisher.publish(self.release)
        system = FakeSystem()
        settings = publisher.install_service(system_root=self.root, runner=system)
        self.assertEqual(settings["bind"], "127.0.0.1")
        unit = self.root / "etc/systemd/system/sing-box-addon-sub.service"
        self.assertIn("/opt/sing-box-addon/tool/publish.py", unit.read_text())
        self.assertNotIn(str(self.release), unit.read_text())
        changes = [argv for argv in system.calls if argv[1] in ("start", "restart", "stop", "enable", "disable", "daemon-reload")]
        self.assertEqual(changes, [["systemctl", "daemon-reload"]])
        config = self.root / "etc/sing-box-addon/subscription.json"
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(config.parent.stat().st_mode & 0o777, 0o700)

    def test_transaction_restores_manifest_and_pins_original_across_updates(self):
        original = self.publisher.publish(self.release)
        with self.assertRaisesRegex(OSError, "metadata full"):
            with self.publisher.transaction():
                for number in range(3):
                    self.nodes("vless://new" + str(number) + "@example.com:8443\n")
                    self.publisher.publish(self.release)
                raise OSError("metadata full")
        self.assertEqual(self.publisher.state(), original)
        self.assertEqual(self.publisher.response("/" + original["token"] + "/nodes.txt")[0], b"vless://test@example.com:8443\n")

    def test_first_publication_transaction_rolls_back_to_unpublished(self):
        with self.assertRaises(OSError):
            with self.publisher.transaction():
                self.publisher.publish(self.release)
                raise OSError("metadata full")
        self.assertFalse((self.publisher.root / "state.json").exists())

    def service_setup(self):
        publisher = publish.Publisher(self.root / "var/lib/sing-box-addon-sub")
        publisher.publish(self.release)
        system = FakeSystem()
        publisher.install_service(system_root=self.root, runner=system)
        system.active[publish.SERVICE] = True
        system.enabled[publish.SERVICE] = True
        system.calls.clear()
        return publisher, system

    def test_failed_service_reconfiguration_restores_settings_running_and_manifest(self):
        publisher, system = self.service_setup()
        first = publisher.state()
        settings = self.root / "etc/sing-box-addon/subscription.json"
        previous = settings.read_bytes()
        self.nodes("vless://new@example.com:8443\n")
        with patch.object(runtime.Runtime, "healthy", side_effect=[False, True]):
            with self.assertRaisesRegex(RuntimeError, "健康检查失败"):
                with publisher.transaction(), publisher.service_transaction(self.root, system):
                    publisher.publish(self.release)
                    publisher.install_service(port=8888, system_root=self.root, runner=system)
                    publisher.start_service(system_root=self.root, runner=system)
        self.assertEqual(publisher.state(), first)
        self.assertEqual(settings.read_bytes(), previous)
        self.assertTrue(system.active[publish.SERVICE])
        self.assertTrue(system.enabled[publish.SERVICE])
        self.assertIn(["systemctl", "start", publish.SERVICE], system.calls)

    def test_service_transaction_restores_after_metadata_write_failure(self):
        publisher, system = self.service_setup()
        settings = self.root / "etc/sing-box-addon/subscription.json"
        previous = settings.read_bytes()
        with patch.object(runtime.Runtime, "healthy", return_value=True):
            with self.assertRaisesRegex(OSError, "metadata full"):
                with publisher.service_transaction(self.root, system):
                    publisher.install_service(port=8888, system_root=self.root, runner=system)
                    publisher.start_service(system_root=self.root, runner=system)
                    raise OSError("metadata full")
        self.assertEqual(settings.read_bytes(), previous)
        self.assertTrue(system.active[publish.SERVICE])

    def test_first_service_transaction_failure_removes_unit_and_disables_service(self):
        publisher = publish.Publisher(self.root / "var/lib/sing-box-addon-sub")
        publisher.publish(self.release)
        system = FakeSystem()
        with patch.object(runtime.Runtime, "healthy", return_value=True):
            with self.assertRaisesRegex(OSError, "metadata full"):
                with publisher.service_transaction(self.root, system):
                    publisher.install_service(system_root=self.root, runner=system)
                    publisher.start_service(system_root=self.root, runner=system)
                    raise OSError("metadata full")
        self.assertFalse((self.root / "etc/systemd/system" / publish.SERVICE).exists())
        self.assertFalse((self.root / "etc/sing-box-addon/subscription.json").exists())
        self.assertFalse(system.active[publish.SERVICE])
        self.assertFalse(system.enabled[publish.SERVICE])

    def test_standalone_start_failure_keeps_previous_service_active(self):
        publisher, system = self.service_setup()
        system.fail.add(("restart", publish.SERVICE))
        with patch.object(runtime.Runtime, "healthy", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "服务操作失败"):
                publisher.start_service(system_root=self.root, runner=system)
        self.assertTrue(system.active[publish.SERVICE])
        self.assertTrue(system.enabled[publish.SERVICE])

    def test_service_status_does_not_hide_system_bus_failure(self):
        def denied(argv, **kwargs):
            import subprocess
            return subprocess.CompletedProcess(argv, 1, "", "Operation not permitted")
        result = publish.Publisher.status_service(self.root, denied)
        self.assertIsNone(result["active"])
        self.assertIsNone(result["enabled"])
        self.assertIn("error", result)

    def test_service_options_reject_invalid_tls_and_ports(self):
        for options in [("127.0.0.1", 80, None, None), ("127.0.0.1", 8080, "cert", None),
                        ("localhost\nExecStart=bad", 8080, None, None)]:
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.publisher._server_options(*options)


if __name__ == "__main__":
    unittest.main()
