"""Interactive menu choices must never turn cancellation into deployment."""
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import addon


class MenuSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='addon-menu-')
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name) / 'state'

    def run_menu(self, responses):
        output, errors = io.StringIO(), io.StringIO()
        # Exercise input/ask/default handling, while keeping every actual command
        # outside the test. No state or service implementation can run here.
        with patch('builtins.input', side_effect=responses) as keyboard, \
                patch.object(addon, 'execute') as execute, \
                patch.object(addon.Store, 'read', return_value=None), \
                redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(addon.menu(self.state), 0)
        self.assertEqual(keyboard.call_count, len(responses))
        self.assertFalse(self.state.exists())
        arguments = [call.args[0] for call in execute.call_args_list]
        for args in arguments:
            self.assertEqual(Path(args.state), self.state)
        return arguments, output.getvalue(), errors.getvalue()

    def test_server_menu_zero_and_empty_input_cancel_without_deployment(self):
        for action in ('0', '', '   '):
            with self.subTest(action=action):
                args, output, errors = self.run_menu(['4', action, '0'])
                self.assertEqual(args, [])
                self.assertEqual(output.count('管理状态目录：'), 2)
                self.assertNotIn('操作完成', output)
                self.assertEqual(errors, '')

    def test_invalid_server_menu_choice_never_falls_through_to_deploy(self):
        for action in ('5', '-1', 'deploy', '退出'):
            with self.subTest(action=action):
                args, output, errors = self.run_menu(['4', action, '0'])
                self.assertEqual(args, [])
                self.assertEqual(output.count('管理状态目录：'), 2)
                self.assertNotIn('操作完成', output)
                self.assertTrue(errors.strip())

    def test_explicit_apply_runs_deploy_exactly_once_and_explains_restart(self):
        args, output, errors = self.run_menu(['4', '4', '0'])
        self.assertEqual([arg.command for arg in args], ['deploy'])
        self.assertIn('重启', output)
        self.assertEqual(errors, '')

    def test_import_server_configuration_can_be_saved_without_deployment(self):
        for confirmation in ('n', 'N', ''):
            with self.subTest(confirmation=confirmation):
                args, _, errors = self.run_menu(['4', '1', '/fixture/new-server.json', confirmation, '0'])
                self.assertEqual([arg.command for arg in args], ['import-config'])
                self.assertEqual(args[0].config, '/fixture/new-server.json')
                self.assertEqual(errors, '')

    def test_import_server_configuration_deploys_only_when_requested(self):
        for confirmation in ('y', 'Y'):
            with self.subTest(confirmation=confirmation):
                args, _, errors = self.run_menu(['4', '1', '/fixture/new-server.json', confirmation, '0'])
                self.assertEqual([arg.command for arg in args], ['import-config', 'deploy'])
                self.assertEqual(args[0].config, '/fixture/new-server.json')
                self.assertEqual(errors, '')

    def test_zero_at_apply_confirmation_discards_pending_import(self):
        args, output, errors = self.run_menu(['4', '1', '/fixture/new-server.json', '0', '0'])
        self.assertEqual(args, [])
        self.assertEqual(output.count('管理状态目录：'), 2)
        self.assertNotIn('操作完成', output)
        self.assertEqual(errors, '')

    def test_invalid_apply_confirmation_does_not_save_or_deploy(self):
        for confirmation in ('1', '-1', 'yes', 'cancel'):
            with self.subTest(confirmation=confirmation):
                args, output, errors = self.run_menu(['4', '1', '/fixture/new-server.json', confirmation, '0'])
                self.assertEqual(args, [])
                self.assertEqual(output.count('管理状态目录：'), 2)
                self.assertNotIn('操作完成', output)
                self.assertTrue(errors.strip())

    def test_zero_returns_from_each_submenu_to_main_without_commands(self):
        for menu in ('1', '3', '4', '5', '6', '7'):
            with self.subTest(menu=menu):
                args, output, errors = self.run_menu([menu, '0', '0'])
                self.assertEqual(args, [])
                self.assertEqual(output.count('管理状态目录：'), 2)
                self.assertNotIn('操作完成', output)
                self.assertEqual(errors, '')

    def test_invalid_choices_in_other_submenus_do_not_execute_commands(self):
        for menu in ('3', '5', '6', '7'):
            for action in ('-1', '99', 'cancel'):
                with self.subTest(menu=menu, action=action):
                    args, output, errors = self.run_menu([menu, action, '0'])
                    self.assertEqual(args, [])
                    self.assertEqual(output.count('管理状态目录：'), 2)
                    self.assertTrue(errors.strip())

    def test_nested_rule_menus_zero_returns_to_main_without_mutation(self):
        for action in ('2', '3'):
            with self.subTest(action=action):
                args, output, errors = self.run_menu(['7', action, '0', '0'])
                self.assertEqual(args, [])
                self.assertEqual(output.count('管理状态目录：'), 2)
                self.assertNotIn('操作完成', output)
                self.assertEqual(errors, '')

    def test_nested_rule_menus_reject_invalid_choices_without_mutation(self):
        for action in ('2', '3'):
            for value in ('4', '-1', 'cancel'):
                with self.subTest(action=action, value=value):
                    args, output, errors = self.run_menu(['7', action, value, '0'])
                    self.assertEqual(args, [])
                    self.assertEqual(output.count('管理状态目录：'), 2)
                    self.assertTrue(errors.strip())

    def test_rule_menu_empty_input_returns_without_downloading_rules(self):
        args, _, errors = self.run_menu(['7', '', '0'])
        self.assertEqual(args, [])
        self.assertEqual(errors, '')

    def test_routing_mode_empty_input_cancels_without_changing_policy(self):
        args, _, errors = self.run_menu(['7', '2', '', '0'])
        self.assertEqual(args, [])
        self.assertEqual(errors, '')

    def test_service_menu_empty_input_queries_status(self):
        args, _, errors = self.run_menu(['3', '', '0'])
        self.assertEqual([arg.command for arg in args], ['status'])
        self.assertEqual(errors, '')

    def test_client_menu_empty_input_keeps_export_default(self):
        args, _, errors = self.run_menu(['5', '', '', '/fixture/export', '0'])
        self.assertEqual([arg.command for arg in args], ['export'])
        self.assertEqual(args[0].group, 'A-to-B')
        self.assertEqual(args[0].output_dir, '/fixture/export')
        self.assertEqual(errors, '')

    def test_publication_menu_empty_input_only_shows_urls(self):
        args, _, errors = self.run_menu(['6', '', '0'])
        self.assertEqual([arg.command for arg in args], ['urls'])
        self.assertEqual(errors, '')

    def test_automatic_rule_menu_empty_input_queries_status(self):
        args, _, errors = self.run_menu(['7', '3', '', '0'])
        self.assertEqual([arg.command for arg in args], ['rules-auto'])
        self.assertEqual(args[0].action, 'status')
        self.assertEqual(errors, '')


if __name__ == '__main__':
    unittest.main()
