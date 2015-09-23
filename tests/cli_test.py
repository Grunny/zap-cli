"""
Tests for the ZAP CLI.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

import unittest

from click.testing import CliRunner
from ddt import ddt, data, unpack
from mock import Mock, MagicMock, patch
import zapv2

from zapcli import zap_helper, cli
from zapcli.exceptions import ZAPError


@ddt
class ZAPCliTestCase(unittest.TestCase):
    """Test ZAP CLI methods."""

    def setUp(self):
        self.runner = CliRunner()
        cli.console = Mock()

    @patch('zapcli.zap_helper.ZAPHelper.start')
    def test_start_zap_daemon(self, helper_mock):
        """Test command to start ZAP daemon."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'start'])
        helper_mock.assert_called_with(options=None)
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.start')
    def test_start_zap_daemon_with_options(self, helper_mock):
        """Test command to start ZAP daemon."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'start',
                                              '--start-options', '-config api.key=12345'])
        helper_mock.assert_called_with(options='-config api.key=12345')
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.start')
    def test_start_zap_daemon_exception(self, helper_mock):
        """Test command to start ZAP daemon has an exit code of 1 when an exception is raised."""
        helper_mock.side_effect = ZAPError('error')
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'start'])
        helper_mock.assert_called_with(options=None)
        self.assertEqual(result.exit_code, 1)

    @patch('zapcli.zap_helper.ZAPHelper.shutdown')
    def test_shutdown_zap_daemon(self, helper_mock):
        """Test command to shutdown ZAP daemon."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'shutdown'])
        helper_mock.assert_called_with()
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.shutdown')
    def test_shutdown_zap_daemon_exception(self, helper_mock):
        """Test command to shutdown ZAP daemon has an exit code of 1 when an exception is raised."""
        helper_mock.side_effect = ZAPError('error')
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'shutdown'])
        helper_mock.assert_called_with()
        self.assertEqual(result.exit_code, 1)

    @patch('zapcli.zap_helper.ZAPHelper.open_url')
    def test_open_url(self, helper_mock):
        """Test open URL method."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'open-url', 'http://localhost/'])
        helper_mock.assert_called_with('http://localhost/')
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.open_url')
    def test_open_url_no_url(self, helper_mock):
        """Test open URL method isn't called and an error status raised when no URL provided."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'open-url'])
        self.assertFalse(helper_mock.called)
        self.assertEqual(result.exit_code, 2)

    @patch('zapcli.zap_helper.ZAPHelper.run_spider')
    def test_spider_url(self, helper_mock):
        """Test spider URL method."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'spider', 'http://localhost/'])
        helper_mock.assert_called_with('http://localhost/')
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.run_spider')
    def test_spider_url_no_url(self, helper_mock):
        """Test spider URL method isn't called and an error status raised when no URL provided."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'spider'])
        self.assertFalse(helper_mock.called)
        self.assertEqual(result.exit_code, 2)

    @patch.object(zap_helper.ZAPHelper, '__new__')
    def test_quick_scan(self, helper_mock):
        """Testing quick scan."""
        class_mock = Mock()
        class_mock.scanner_groups = ['xss']
        class_mock.scanner_group_map = {'xss': ['40012', '40014', '40016', '40017']}
        class_mock.alerts.return_value = []
        helper_mock.return_value = class_mock

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'quick-scan',
                                              'http://localhost/', '--self-contained', '--scanners', 'xss',
                                              '--spider', '--exclude', 'pattern'])
        self.assertEqual(result.exit_code, 0)

    @patch.object(zap_helper.ZAPHelper, '__new__')
    def test_quick_scan_start_error(self, helper_mock):
        """Testing quick scan."""
        class_mock = Mock()
        class_mock.start.side_effect = ZAPError('error')
        helper_mock.return_value = class_mock

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'quick-scan',
                                              'http://localhost/', '--self-contained'])
        self.assertEqual(result.exit_code, 1)

    @patch.object(zap_helper.ZAPHelper, '__new__')
    def test_quick_scan_shutdown_error(self, helper_mock):
        """Testing quick scan."""
        class_mock = Mock()
        class_mock.alerts.return_value = []
        class_mock.shutdown.side_effect = ZAPError('error')
        helper_mock.return_value = class_mock

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'quick-scan',
                                              'http://localhost/', '--self-contained'])
        self.assertEqual(result.exit_code, 1)

    @patch.object(zap_helper.ZAPHelper, '__new__')
    def test_quick_scan_enable_scanners_error(self, helper_mock):
        """Testing quick scan."""
        class_mock = Mock()
        class_mock.alerts.return_value = []
        class_mock.scanner_groups = ['xss']
        class_mock.scanner_group_map = {'xss': ['40012', '40014', '40016', '40017']}
        class_mock.set_enabled_scanners.side_effect = ZAPError('error')
        helper_mock.return_value = class_mock

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'quick-scan',
                                              'http://localhost/', '--scanners', 'xss'])
        self.assertEqual(result.exit_code, 1)

    @patch.object(zap_helper.ZAPHelper, '__new__')
    def test_quick_scan_exclude_from_all_error(self, helper_mock):
        """Testing quick scan."""
        class_mock = Mock()
        class_mock.alerts.return_value = []
        class_mock.exclude_from_all.side_effect = ZAPError('error')
        helper_mock.return_value = class_mock

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'quick-scan',
                                              'http://localhost/', '--exclude', 'pattern'])
        self.assertEqual(result.exit_code, 1)

    @patch.object(zapv2.ascan, '__new__')
    def test_active_scanners_enable(self, ascan_mock):
        """Test enabling active scanners."""
        class_mock = MagicMock()
        ascan_mock.return_value = class_mock

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'scanners', 'enable',
                                              '--scanners', '1,2,3'])
        class_mock.enable_scanners.assert_called_with('1,2,3', apikey='')

    @patch.object(zapv2.ascan, '__new__')
    def test_active_scanners_disable(self, ascan_mock):
        """Test enabling active scanners."""
        class_mock = MagicMock()
        ascan_mock.return_value = class_mock

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'scanners', 'disable',
                                              '--scanners', '1,2,3'])
        class_mock.disable_scanners.assert_called_with('1,2,3', apikey='')

    @patch.object(zapv2.ascan, '__new__')
    def test_active_scan_policies_enable(self, ascan_mock):
        """Test enabling active scan policies method."""
        class_mock = MagicMock()
        ascan_mock.return_value = class_mock

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'policies', 'enable',
                                              '--policy-ids', '1,2,3'])
        class_mock.set_enabled_policies.assert_called_with('1,2,3', apikey='')

    @patch('zapcli.zap_helper.ZAPHelper.exclude_from_all')
    def test_exclude_from_scanners(self, helper_mock):
        """Test exclude from scanners command."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'exclude', 'pattern'])
        helper_mock.assert_called_with('pattern')
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.exclude_from_all')
    def test_exclude_from_scanners_error(self, helper_mock):
        """Test exclude from scanners command with error raised."""
        helper_mock.side_effect = ZAPError('error')
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'exclude', '['])
        helper_mock.assert_called_with('[')
        self.assertEqual(result.exit_code, 1)

    @data(
        (
            [
                {'id': 1, 'value': 'one'},
                {'id': 5, 'value': 'five'},
                {'id': 10, 'value': 'ten'}
            ],
            [1],
            [{'id': 1, 'value': 'one'}]
        ),
        (
            [
                {'id': 1, 'value': 'one'},
                {'id': 5, 'value': 'five'},
                {'id': 10, 'value': 'ten'}
            ],
            [1, 10],
            [
                {'id': 1, 'value': 'one'},
                {'id': 10, 'value': 'ten'}
            ]
        ),
        (
            [
                {'id': 1, 'value': 'one'},
                {'id': 5, 'value': 'five'},
                {'id': 10, 'value': 'ten'}
            ],
            [4],
            []
        ),
        (
            [
                {'id': 1, 'value': 'one'},
                {'id': 5, 'value': 'five'},
                {'id': 10, 'value': 'ten'}
            ],
            [],
            [
                {'id': 1, 'value': 'one'},
                {'id': 5, 'value': 'five'},
                {'id': 10, 'value': 'ten'}
            ]
        ),
        (
            [],
            [],
            []
        )
    )
    @unpack
    def test_filter_by_ids(self, original_list, ids_to_filter, expected_result):
        """Test the function for filtering a list of dicts by IDs."""
        result = cli.filter_by_ids(original_list, ids_to_filter)

        self.assertEqual(result, expected_result)


if __name__ == '__main__':
    unittest.main()
