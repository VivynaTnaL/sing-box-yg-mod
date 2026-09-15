import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scheduler
import runtime
from chain import ConfigError
from test_runtime import FakeSystem


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.system = FakeSystem()
        self.manager = runtime.Runtime(self.root, runner=self.system, health_interval=0)
        self.scheduler = scheduler.Scheduler(self.manager)
        self.state = self.root / 'state with spaces'
        self.state.mkdir()
        (self.state / 'state.json').write_text('{}')
        tool = self.manager.path('/opt/sing-box-addon/tool/scheduler.py')
        tool.parent.mkdir(parents=True)
        tool.write_text('test tool')
        self.system.active[runtime.SERVICE] = True

    def test_enable_installs_daily_timer_without_restarting_proxy(self):
        result = self.scheduler.enable(self.state)
        self.assertTrue(result['active'])
        self.assertTrue(result['enabled'])
        self.assertIn('OnCalendar=daily', self.scheduler.timer.read_text())
        self.assertEqual(json.loads(self.scheduler.settings.read_text())['state'], str(self.state))
        self.assertNotIn(str(self.state), self.scheduler.service.read_text())
        self.assertTrue(self.system.active[runtime.SERVICE])
        self.assertFalse(any(command[-1] == runtime.SERVICE for command in self.system.calls))

    def test_failed_first_enable_restores_settings_and_units(self):
        self.system.fail.add(('start', scheduler.TIMER))
        with self.assertRaises(RuntimeError):
            self.scheduler.enable(self.state)
        self.assertFalse(self.scheduler.settings.exists())
        self.assertFalse(self.scheduler.service.exists())
        self.assertFalse(self.scheduler.timer.exists())
        self.assertFalse(self.system.active.get(scheduler.TIMER, False))
        self.assertFalse(self.system.enabled.get(scheduler.TIMER, False))

    def test_failure_restores_previously_active_timer_and_its_state_path(self):
        self.scheduler.enable(self.state)
        previous = self.scheduler.settings.read_bytes()
        other = self.root / 'other-state'
        other.mkdir()
        (other / 'state.json').write_text('{}')
        original = self.manager._require
        def fail_once(*args, **kwargs):
            if args == ('start',):
                raise RuntimeError('simulated start failure')
            return original(*args, **kwargs)
        with patch.object(self.manager, '_require', side_effect=fail_once):
            with self.assertRaisesRegex(RuntimeError, 'simulated'):
                self.scheduler.enable(other)
        self.assertEqual(self.scheduler.settings.read_bytes(), previous)
        self.assertTrue(self.system.active[scheduler.TIMER])
        self.assertTrue(self.system.enabled[scheduler.TIMER])

    def test_disable_cancels_timer_and_allows_current_update_to_finish(self):
        self.scheduler.enable(self.state)
        self.system.active[scheduler.SERVICE] = True
        self.scheduler.disable()
        self.assertFalse(self.system.active[scheduler.TIMER])
        self.assertTrue(self.system.active[scheduler.SERVICE])
        self.assertFalse(self.system.enabled[scheduler.TIMER])
        self.assertTrue(self.system.active[runtime.SERVICE])

    def test_background_requires_installed_tool(self):
        self.manager.path('/opt/sing-box-addon/tool/scheduler.py').unlink()
        with self.assertRaisesRegex(ConfigError, '先安装'):
            self.scheduler.enable(self.state)
        self.assertFalse(self.scheduler.timer.exists())

    def test_timer_runner_passes_saved_directory_without_shell_evaluation(self):
        self.scheduler.enable(self.state)
        (self.state / 'state.json').write_text(json.dumps({'schema_version': 1, 'role': 'entry'}))
        with patch('updates.update_rules') as update:
            scheduler.run(self.scheduler.settings)
        self.assertEqual(update.call_args.args[0].root, self.state)
        self.assertEqual(update.call_args.kwargs, {'scheduled': True})

    def test_settings_rejects_relative_state_path(self):
        settings = self.root / 'bad.json'
        settings.write_text(json.dumps({'version': 1, 'state': '../bad'}))
        with self.assertRaisesRegex(ConfigError, '无效'):
            scheduler.run(settings)


if __name__ == '__main__':
    unittest.main()
