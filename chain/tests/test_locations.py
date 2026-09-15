"""Remembered manager locations must work without touching real services."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import addon
from chain import ConfigError
import locations


class LocationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='addon-locations-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.settings = self.root / 'manager.json'
        self.saved = self.root / 'saved-state'
        self.saved.mkdir()
        self.default = self.root / 'old-default'
        for target, value in (('locations.MANAGER_SETTINGS', self.settings),
                              ('locations.DEFAULT_STATE', self.default)):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def remember(self, directory=None):
        self.settings.write_text(json.dumps({
            'schema_version': 1,
            'state_dir': str(self.saved if directory is None else directory),
        }))

    def test_first_run_keeps_original_default_and_does_not_create_files(self):
        self.assertEqual(locations.state_directory(), self.default)
        self.assertFalse(self.default.exists())
        self.assertFalse(self.settings.exists())

    def test_saved_directory_becomes_default(self):
        self.remember()
        self.assertEqual(locations.state_directory(), self.saved)

    def test_explicit_settings_path_is_supported(self):
        other = self.root / 'other-manager.json'
        other.write_text(json.dumps({'schema_version': 1, 'state_dir': str(self.saved)}))
        self.settings.write_text('broken default settings')
        self.assertEqual(locations.state_directory(settings_path=other), self.saved)

    def test_explicit_new_directory_overrides_corrupt_settings(self):
        self.settings.write_text('broken settings')
        new_directory = self.root / 'new-state'
        self.assertEqual(locations.state_directory(new_directory), new_directory)
        self.assertFalse(new_directory.exists())

    def test_explicit_directory_overrides_missing_saved_directory(self):
        self.remember(self.root / 'deleted-state')
        self.assertEqual(locations.state_directory(self.saved), self.saved)

    def test_explicit_directory_overrides_symlinked_settings(self):
        target = self.root / 'target.json'
        target.write_text('broken settings')
        self.settings.symlink_to(target)
        self.assertEqual(locations.state_directory(self.saved), self.saved)

    def test_explicit_relative_directory_is_made_absolute(self):
        value = Path('new-relative-addon-state')
        self.assertEqual(locations.state_directory(value), value.absolute())

    def test_invalid_saved_documents_fail_instead_of_falling_back(self):
        documents = [
            '', '{broken json', 'null', '[]',
            json.dumps({}),
            json.dumps({'schema_version': 2, 'state_dir': str(self.saved)}),
            json.dumps({'schema_version': '1', 'state_dir': str(self.saved)}),
            json.dumps({'schema_version': True, 'state_dir': str(self.saved)}),
            json.dumps({'schema_version': 1}),
            json.dumps({'schema_version': 1, 'state_dir': None}),
            json.dumps({'schema_version': 1, 'state_dir': 42}),
            json.dumps({'schema_version': 1, 'state_dir': ''}),
            json.dumps({'schema_version': 1, 'state_dir': 'relative-state'}),
            json.dumps({'schema_version': 1, 'state_dir': '/tmp/invalid\x00state'}),
        ]
        for document in documents:
            with self.subTest(document=document):
                self.settings.write_text(document)
                with self.assertRaises(ConfigError):
                    locations.state_directory()
        self.assertFalse(self.default.exists())

    def test_missing_saved_directory_does_not_select_empty_default(self):
        self.remember(self.root / 'deleted-state')
        with self.assertRaises(ConfigError):
            locations.state_directory()
        self.assertFalse(self.default.exists())

    def test_saved_path_must_be_a_directory(self):
        regular_file = self.root / 'not-a-directory'
        regular_file.write_text('file')
        self.remember(regular_file)
        with self.assertRaises(ConfigError):
            locations.state_directory()

    def test_symlinked_saved_directory_is_rejected(self):
        link = self.root / 'linked-state'
        link.symlink_to(self.saved, target_is_directory=True)
        self.remember(link)
        with self.assertRaises(ConfigError):
            locations.state_directory()

    def test_symlinked_settings_are_rejected_even_when_target_is_missing(self):
        target = self.root / 'target-settings.json'
        for existing in (False, True):
            with self.subTest(existing=existing):
                if existing:
                    target.write_text(json.dumps({'schema_version': 1, 'state_dir': str(self.saved)}))
                self.settings.symlink_to(target)
                with self.assertRaises(ConfigError):
                    locations.state_directory()
                self.settings.unlink()

    def test_directory_cannot_be_used_as_settings_file(self):
        self.settings.mkdir()
        with self.assertRaises(ConfigError):
            locations.state_directory()

    def test_directory_text_is_data_and_never_shell_code(self):
        special = self.root / "space ' quote $HOME `id` $(touch marker)"
        special.mkdir()
        self.remember(special)
        with patch('subprocess.run', side_effect=AssertionError('must not launch a process')), \
                patch('os.system', side_effect=AssertionError('must not launch a shell')):
            self.assertEqual(locations.state_directory(), special)
            self.assertEqual(locations.state_directory(special), special)


class RememberedLocationCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='addon-locations-cli-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.saved = self.root / 'installed-state'
        self.default = self.root / 'unused-default'
        self.settings = self.root / 'manager.json'
        self.saved.mkdir()
        self.settings.write_text(json.dumps({'schema_version': 1, 'state_dir': str(self.saved)}))
        addon.Store(self.saved).save({
            'schema_version': 1, 'role': 'exit',
            'server_config': {'inbounds': [{'listen_port': 22000}]},
            'policy': {'mode': 'lan-direct'}, 'groups': {},
        })
        for target, value in (('locations.MANAGER_SETTINGS', self.settings),
                              ('locations.DEFAULT_STATE', self.default)):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        # A status query is exercised end to end, with only service queries mocked.
        for target in ('runtime.Runtime', 'scheduler.Scheduler'):
            patcher = patch(target)
            mocked = patcher.start()
            mocked.return_value.status.return_value = {'active': True}
            self.addCleanup(patcher.stop)

    def test_parser_does_not_turn_omitted_state_into_explicit_old_default(self):
        self.assertIsNone(addon.parser().parse_args(['status']).state)

    def test_status_uses_remembered_deployment_and_shows_directory(self):
        output = io.StringIO()
        with redirect_stdout(output):
            addon.execute(addon.parser().parse_args(['status']))
        self.assertIn('落地 B', output.getvalue())
        self.assertIn('22000', output.getvalue())
        self.assertIn(str(self.saved), output.getvalue())
        self.assertNotIn('尚未初始化', output.getvalue())
        self.assertFalse(self.default.exists())

    def test_explicit_status_still_selects_another_directory(self):
        explicit = self.root / 'explicit-state'
        output = io.StringIO()
        with redirect_stdout(output):
            addon.execute(addon.parser().parse_args(['--state', str(explicit), 'status']))
        self.assertIn('尚未初始化', output.getvalue())
        self.assertIn(str(explicit), output.getvalue())
        self.assertNotIn('落地 B', output.getvalue())
        self.assertFalse(explicit.exists())

    def test_interactive_main_passes_remembered_directory_to_menu(self):
        with patch.object(sys, 'argv', ['sb-chain']), \
                patch.object(sys.stdin, 'isatty', return_value=True), \
                patch('addon.menu', return_value=0) as menu:
            self.assertEqual(addon.main(), 0)
        menu.assert_called_once_with(self.saved)

    def test_interactive_main_explicit_state_overrides_broken_settings(self):
        self.settings.write_text('broken settings')
        explicit = self.root / 'explicit-new-state'
        with patch.object(sys, 'argv', ['sb-chain', '--state', str(explicit)]), \
                patch.object(sys.stdin, 'isatty', return_value=True), \
                patch('addon.menu', return_value=0) as menu:
            self.assertEqual(addon.main(), 0)
        menu.assert_called_once_with(explicit)

    def test_interactive_main_does_not_open_wrong_menu_after_saved_directory_disappears(self):
        (self.saved / 'state.json').unlink()
        self.saved.rmdir()
        with patch.object(sys, 'argv', ['sb-chain']), \
                patch.object(sys.stdin, 'isatty', return_value=True), \
                patch('addon.menu') as menu, redirect_stderr(io.StringIO()):
            self.assertEqual(addon.main(), 1)
        menu.assert_not_called()
        self.assertFalse(self.default.exists())

    def test_menu_shows_its_selected_state_directory(self):
        output = io.StringIO()
        with patch('addon.ask', return_value='0'), redirect_stdout(output):
            self.assertEqual(addon.menu(self.saved), 0)
        self.assertIn(str(self.saved), output.getvalue())


if __name__ == '__main__':
    unittest.main()
