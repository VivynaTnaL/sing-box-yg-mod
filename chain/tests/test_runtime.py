import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import runtime


class FakeSystem:
    def __init__(self):
        self.calls = []
        self.active = {}
        self.enabled = {}
        self.fail = set()
        self.bad_config = False
        self.manager_available = True
        self.systemd_version = 252

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        code, output = 0, ""
        if argv[0] != "systemctl":
            if argv[1] == "version":
                output = "sing-box version 1.14.0\n"
            elif argv[1] == "check":
                code = int(self.bad_config)
        elif argv[1] == "--version":
            output = "systemd " + str(self.systemd_version) + "\n"
        elif argv[1:3] == ["show", "--property=Version"]:
            output = str(self.systemd_version) if self.manager_available else ""
            code = 0 if self.manager_available else 1
        elif argv[1] == "daemon-reload":
            pass
        else:
            action, service = argv[1], argv[-1]
            if (action, service) in self.fail:
                code = 1
            elif action == "is-active":
                code = 0 if self.active.get(service) else 3
            elif action == "is-enabled":
                code = 0 if self.enabled.get(service) else 1
            elif action == "show":
                output = "1234\n" if self.active.get(service) else "0\n"
            elif action in ("start", "restart", "stop"):
                self.active[service] = action != "stop"
            elif action in ("enable", "disable"):
                self.enabled[service] = action == "enable"
        return subprocess.CompletedProcess(argv, code, output, "")


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.system = FakeSystem()
        self.runtime = runtime.Runtime(self.root, runner=self.system, health_interval=0)
        self.source = self.root / "source-core"
        self.source.write_text("fake core")
        self.source.chmod(0o755)
        self.runtime.install(self.source)
        self.candidate = self.root / "candidate.json"
        self.candidate.write_text('{"inbounds":[],"outbounds":[{"type":"direct"}]}')
        self.system.calls.clear()

    def assert_only_addon(self):
        for argv in self.system.calls:
            if argv[0] == "systemctl" and argv[1] != "daemon-reload":
                if argv[1] == "--version" or argv[1:3] == ["show", "--property=Version"]:
                    continue
                self.assertIn(argv[-1], (runtime.SERVICE, runtime.SUB_SERVICE, runtime.RULES_TIMER, runtime.RULES_SERVICE))

    def test_install_stages_tools_and_does_not_start_service(self):
        self.runtime.install(self.source)
        self.assertTrue(self.runtime.unit.exists())
        self.assertTrue(self.runtime.path(runtime.TOOL_DIR / "publish.py").is_file())
        wrapper = self.runtime.path("/usr/bin/sb-chain")
        self.assertIn("/opt/sing-box-addon/tool/addon.py", wrapper.read_text())
        self.assertFalse(any(argv[0] == "systemctl" and argv[1] in ("start", "restart", "enable") for argv in self.system.calls))
        self.assert_only_addon()

    def test_install_rejects_replacing_running_core(self):
        self.system.active[runtime.SERVICE] = True
        self.source.write_text("different core")
        with self.assertRaisesRegex(RuntimeError, "先停止"):
            self.runtime.install(self.source)
        self.assertEqual(self.runtime.binary.read_text(), "fake core")

    def test_install_remembers_directory_without_changing_running_proxy(self):
        from locations import state_directory
        state_root = self.root / "custom state"
        state_root.mkdir()
        self.system.active[runtime.SERVICE] = True
        self.system.enabled[runtime.SERVICE] = True
        config = self.runtime.root / "config.json"
        config.write_text('{"existing":"deployed configuration"}')
        original = config.read_bytes()
        inode = self.runtime.binary.stat().st_ino

        self.runtime.install(self.source, state_root=state_root)

        settings = self.runtime.root / "manager.json"
        self.assertEqual(state_directory(settings_path=settings), state_root)
        self.assertEqual(settings.stat().st_mode & 0o777, 0o600)
        self.assertTrue(self.runtime.path(runtime.TOOL_DIR / "locations.py").is_file())
        self.assertEqual(config.read_bytes(), original)
        self.assertEqual(self.runtime.binary.stat().st_ino, inode)
        self.assertTrue(self.system.active[runtime.SERVICE])
        self.assertTrue(self.system.enabled[runtime.SERVICE])
        self.assertFalse(any(argv[0] == "systemctl" and argv[1] in
                             ("stop", "start", "restart", "enable", "disable")
                             for argv in self.system.calls))

    def test_failed_install_restores_or_removes_remembered_directory(self):
        settings = self.runtime.root / "manager.json"
        previous = b'{"schema_version":1,"state_dir":"/previous-state"}'
        for before in (None, previous):
            with self.subTest(existing=before is not None):
                if before is None:
                    settings.unlink(missing_ok=True)
                else:
                    settings.write_bytes(before)
                reload = self.runtime._daemon_reload
                calls = 0

                def fail_once():
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        raise RuntimeError("reload rejected")
                    return reload()

                with patch.object(self.runtime, "_daemon_reload", side_effect=fail_once):
                    with self.assertRaisesRegex(RuntimeError, "reload rejected"):
                        self.runtime.install(self.source, state_root=self.root / "new-state")
                if before is None:
                    self.assertFalse(settings.exists())
                else:
                    self.assertEqual(settings.read_bytes(), before)

    def test_uninstall_retains_remembered_directory_for_reinstall(self):
        from locations import state_directory
        state_root = self.root / "retained-state"
        state_root.mkdir()
        self.runtime.install(self.source, state_root=state_root)
        self.runtime.uninstall()
        settings = self.runtime.root / "manager.json"
        self.assertEqual(state_directory(settings_path=settings), state_root)
        self.runtime.install(self.source)
        self.assertEqual(state_directory(settings_path=settings), state_root)

    def test_install_rejects_unlocked_core_version(self):
        original = self.runtime._run

        def run(argv, timeout=30):
            if argv[1] == "version":
                return subprocess.CompletedProcess(argv, 0, "sing-box version 1.13.0\n", "")
            return original(argv, timeout)

        with patch.object(self.runtime, "_run", side_effect=run):
            with self.assertRaisesRegex(ValueError, "sing-box 1.14.0"):
                self.runtime.install(self.source)
        self.assertFalse(any(argv[0] == "systemctl" for argv in self.system.calls))

    def test_apply_invalid_config_does_not_change_target_or_services(self):
        target = self.runtime.root / "config.json"
        target.write_text('{"old":true}')
        self.system.bad_config = True
        with self.assertRaisesRegex(RuntimeError, "配置校验失败"):
            self.runtime.apply(self.candidate)
        self.assertEqual(json.loads(target.read_text()), {"old": True})
        self.assertFalse(any(argv[0] == "systemctl" for argv in self.system.calls))

    def test_apply_enables_own_service_and_ignores_legacy(self):
        self.system.active["sing-box.service"] = True
        result = self.runtime.apply(self.candidate)
        self.assertTrue(result["active"])
        self.assertTrue(result["enabled"])
        self.assertTrue(self.system.active["sing-box.service"])
        self.assertEqual((self.runtime.root / "config.json").stat().st_mode & 0o777, 0o600)
        self.assert_only_addon()

    def test_install_preflight_rejects_old_systemd_before_writing_files(self):
        self.system.systemd_version = 246
        self.source.write_text("different core")
        with self.assertRaisesRegex(RuntimeError, "247"):
            self.runtime.install(self.source)
        self.assertEqual(self.runtime.binary.read_text(), "fake core")

    def test_install_preflight_rejects_inaccessible_manager(self):
        self.system.manager_available = False
        with self.assertRaisesRegex(RuntimeError, "无法连接"):
            self.runtime.install(self.source)

    def test_failed_install_restores_previous_binary_tools_and_unit(self):
        before = self.runtime.unit.read_bytes()
        self.source.write_text("replacement core")
        original = self.runtime._daemon_reload
        calls = 0
        def reload_once():
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("reload rejected")
            return original()
        with patch.object(self.runtime, "_daemon_reload", side_effect=reload_once):
            with self.assertRaisesRegex(RuntimeError, "reload rejected"):
                self.runtime.install(self.source)
        self.assertEqual(self.runtime.binary.read_text(), "fake core")
        self.assertEqual(self.runtime.unit.read_bytes(), before)
        self.assertFalse(self.system.active[runtime.SERVICE])

    def test_status_reports_unavailable_systemctl_as_unknown(self):
        def denied(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, "", "Failed to connect to bus: Operation not permitted")
        self.runtime.runner = denied
        result = self.runtime.status()
        self.assertIsNone(result["active"])
        self.assertIsNone(result["enabled"])
        self.assertIn("无法查询", result["error"])

    def test_apply_cannot_treat_query_failure_as_stopped_service(self):
        target = self.runtime.root / "config.json"
        target.write_text('{"old": true}')
        original = self.runtime.runner
        def denied(argv, **kwargs):
            if argv[0] == "systemctl" and argv[1] == "is-active":
                return subprocess.CompletedProcess(argv, 1, "", "permission denied")
            return original(argv, **kwargs)
        self.runtime.runner = denied
        with self.assertRaisesRegex(RuntimeError, "无法查询"):
            self.runtime.apply(self.candidate)
        self.assertEqual(json.loads(target.read_text()), {"old": True})
        self.assertFalse(any(argv[0] == "systemctl" and argv[1] in ("restart", "stop") for argv in self.system.calls))

    def test_outer_transaction_rolls_back_after_active_metadata_failure(self):
        self.runtime.apply(self.candidate)
        before = (self.runtime.root / "config.json").read_bytes()
        self.candidate.write_text('{"outbounds":[{"type":"direct","tag":"new"}]}')
        with self.assertRaisesRegex(OSError, "metadata full"):
            with self.runtime.transaction():
                self.runtime.apply(self.candidate)
                raise OSError("metadata full")
        self.assertEqual((self.runtime.root / "config.json").read_bytes(), before)
        self.assertFalse((self.runtime.root / "config.previous.json").exists())
        self.assertTrue(self.system.active[runtime.SERVICE])
        self.assertTrue(self.system.enabled[runtime.SERVICE])

    def test_outer_transaction_restores_failed_first_deployment(self):
        with self.assertRaises(OSError):
            with self.runtime.transaction():
                self.runtime.apply(self.candidate)
                raise OSError("metadata full")
        self.assertFalse((self.runtime.root / "config.json").exists())
        self.assertFalse(self.system.active[runtime.SERVICE])
        self.assertFalse(self.system.enabled[runtime.SERVICE])

    def test_failed_apply_restores_config_running_and_enabled_states(self):
        target = self.runtime.root / "config.json"
        old = '{"old":true}'
        target.write_text(old)
        self.system.active[runtime.SERVICE] = True
        self.system.enabled[runtime.SERVICE] = False
        with patch.object(self.runtime, "healthy", side_effect=[False, True]):
            with self.assertRaisesRegex(RuntimeError, "已恢复附件"):
                self.runtime.apply(self.candidate)
        self.assertEqual(target.read_text(), old)
        self.assertEqual((self.runtime.root / "config.previous.json").read_text(), old)
        self.assertTrue(self.system.active[runtime.SERVICE])
        self.assertFalse(self.system.enabled[runtime.SERVICE])
        self.assert_only_addon()

    def test_failed_first_apply_removes_config_and_stops_service(self):
        with patch.object(self.runtime, "healthy", return_value=False):
            with self.assertRaises(RuntimeError):
                self.runtime.apply(self.candidate)
        self.assertFalse((self.runtime.root / "config.json").exists())
        self.assertFalse(self.system.active[runtime.SERVICE])
        self.assertFalse(self.system.enabled[runtime.SERVICE])

    def test_stop_and_uninstall_do_not_touch_import_or_legacy(self):
        self.runtime.apply(self.candidate)
        parameters = self.runtime.root / "state.json"
        parameters.write_text('{"role":"entry"}')
        subscription = self.runtime.path(runtime.SUB_ROOT / "state.json")
        runtime.atomic_write(subscription, '{"token":"keep-for-reinstall"}')
        self.runtime.stop()
        self.assertFalse(self.system.active[runtime.SERVICE])
        self.runtime.uninstall()
        self.assertTrue(self.candidate.exists())
        self.assertEqual(json.loads(parameters.read_text()), {"role": "entry"})
        self.assertTrue((self.runtime.root / "config.json").exists())
        self.assertEqual(json.loads(subscription.read_text()), {"token": "keep-for-reinstall"})
        self.assertFalse(self.runtime.unit.exists())
        self.assertFalse(self.runtime.binary.exists())
        self.assert_only_addon()

    def test_stop_uninstall_are_repeatable_and_remove_only_addon_timer(self):
        for service in (runtime.RULES_SERVICE, runtime.RULES_TIMER):
            runtime.atomic_write(self.runtime.path("/etc/systemd/system/" + service), "managed timer")
            self.system.active[service] = True
            self.system.enabled[service] = service == runtime.RULES_TIMER
        retained = self.runtime.root / "rules-update.json"
        retained.write_text('{}')
        self.runtime.stop()
        self.runtime.stop()
        self.runtime.uninstall()
        self.runtime.uninstall()
        self.runtime.stop()
        self.assertTrue(retained.exists())
        for service in (runtime.RULES_SERVICE, runtime.RULES_TIMER):
            self.assertFalse(self.runtime.path("/etc/systemd/system/" + service).exists())
            self.assertFalse(self.system.active[service])
            self.assertFalse(self.system.enabled[service])
        self.assert_only_addon()

    def test_active_timer_health_does_not_require_main_pid(self):
        self.system.active[runtime.RULES_TIMER] = True
        with patch.object(self.runtime, "_pid", side_effect=AssertionError("timer has no process")):
            self.assertTrue(self.runtime.healthy(runtime.RULES_TIMER))

    def test_isolated_root_without_runner_refuses_real_commands(self):
        isolated = runtime.Runtime(self.root)
        with patch.object(runtime.subprocess, "run") as execute:
            with self.assertRaisesRegex(RuntimeError, "隔离"):
                isolated.status()
            execute.assert_not_called()

    def legacy_setup(self):
        marker = self.runtime.path("/etc/sing-box-chain/legacy-managed")
        runtime.atomic_write(marker, json.dumps({"service": "sing-box-chain.service"}))
        runtime.atomic_write(self.runtime.path("/etc/s-box/sb.json"), "{}")
        runtime.atomic_write(self.runtime.path("/etc/s-box/sing-box"), "fake core", 0o755)
        runtime.atomic_write(self.runtime.path("/etc/systemd/system/sing-box.service"),
                             "ExecStart=/etc/s-box/sing-box run -c /etc/s-box/sb.json\n")
        runtime.atomic_write(self.runtime.path("/etc/systemd/system/sing-box-chain.service"),
                             "ExecStart=/opt/sing-box-chain/sing-box run -c %d/config.json\n")
        self.system.active["sing-box-chain.service"] = True
        self.system.enabled["sing-box-chain.service"] = True
        return marker

    def test_explicit_restore_legacy_removes_marker_last(self):
        marker = self.legacy_setup()
        original_health = self.runtime.healthy

        def health(service):
            self.assertTrue(marker.exists())
            return original_health(service)

        with patch.object(self.runtime, "healthy", side_effect=health):
            result = self.runtime.restore_legacy()
        self.assertFalse(marker.exists())
        self.assertTrue(result["enabled"])
        self.assertTrue(self.system.active["sing-box.service"])
        self.assertFalse(self.system.active["sing-box-chain.service"])

    def test_failed_restore_keeps_marker_and_previous_states(self):
        marker = self.legacy_setup()
        with patch.object(self.runtime, "healthy", side_effect=[False, True]):
            with self.assertRaisesRegex(RuntimeError, "保留接管标记"):
                self.runtime.restore_legacy()
        self.assertTrue(marker.exists())
        self.assertFalse(self.system.active["sing-box.service"])
        self.assertFalse(self.system.enabled["sing-box.service"])
        self.assertTrue(self.system.active["sing-box-chain.service"])
        self.assertTrue(self.system.enabled["sing-box-chain.service"])

    def test_restore_unknown_installation_rejected_before_service_calls(self):
        self.legacy_setup()
        self.runtime.path("/etc/systemd/system/sing-box.service").write_text("unrelated service")
        with self.assertRaisesRegex(ValueError, "安装不符"):
            self.runtime.restore_legacy()
        self.assertFalse(self.system.calls)


if __name__ == "__main__":
    unittest.main()
