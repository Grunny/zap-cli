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

    @patch('zapcli.zap_helper.ZAPHelper.is_running')
    def test_check_status_running(self, helper_mock):
        """Test the status command."""
        helper_mock.return_value = True
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'status'])
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.is_running')
    def test_check_status_not_running(self, helper_mock):
        """Test the status command when ZAP is not running."""
        helper_mock.return_value = False
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'status'])
        self.assertEqual(result.exit_code, 1)

    @patch('zapcli.zap_helper.ZAPHelper.wait_for_zap')
    @patch('zapcli.zap_helper.ZAPHelper.is_running')
    def test_check_status_timeout(self, running_mock, wait_mock):
        """Test the status command with a timeout."""
        running_mock.return_value = False
        wait_mock.side_effect = ZAPError('error')
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'status', '-t', '0'])
        self.assertEqual(result.exit_code, 1)

    @patch('zapcli.zap_helper.ZAPHelper.wait_for_zap')
    @patch('zapcli.zap_helper.ZAPHelper.is_running')
    def test_check_status_timeout_success(self, running_mock, wait_mock):
        """Test the status command with a successful wait for ZAP to start."""
        running_mock.return_value = False
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'status', '-t', '0'])
        self.assertEqual(result.exit_code, 0)

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
        helper_mock.assert_called_with('http://localhost/', None, None)
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.run_spider')
    def test_spider_url_no_url(self, helper_mock):
        """Test spider URL method isn't called and an error status raised when no URL provided."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'spider'])
        self.assertFalse(helper_mock.called)
        self.assertEqual(result.exit_code, 2)

    @patch('zapcli.zap_helper.ZAPHelper.run_ajax_spider')
    def test_ajax_spider_url(self, helper_mock):
        """Test AJAX Spider URL method."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'ajax-spider', 'http://localhost/'])
        helper_mock.assert_called_with('http://localhost/')
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.run_ajax_spider')
    def test_ajax_spider_url_no_url(self, helper_mock):
        """Test AJAX Spider URL method isn't called and an error status raised when no URL provided."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'ajax-spider'])
        self.assertFalse(helper_mock.called)
        self.assertEqual(result.exit_code, 2)

    @patch('zapcli.cli.ZAPHelper')
    def test_quick_scan(self, helper_mock):
        """Testing quick scan."""
        instance = helper_mock.return_value
        instance.scanner_groups = ['xss']
        instance.scanner_group_map = {'xss': ['40012', '40014', '40016', '40017']}
        instance.alerts.return_value = []

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'quick-scan',
                                              'http://localhost/', '--self-contained', '--scanners', 'xss',
                                              '--spider', '--exclude', 'pattern'])
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.start')
    def test_quick_scan_start_error(self, helper_mock):
        """Testing quick scan."""
        helper_mock.side_effect = ZAPError('error')

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'quick-scan',
                                              'http://localhost/', '--self-contained'])
        self.assertEqual(result.exit_code, 1)

    @patch('zapcli.cli.ZAPHelper')
    def test_quick_scan_shutdown_error(self, helper_mock):
        """Testing quick scan."""
        instance = helper_mock.return_value
        instance.alerts.return_value = []
        instance.shutdown.side_effect = ZAPError('error')

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'quick-scan',
                                              'http://localhost/', '--self-contained'])
        self.assertEqual(result.exit_code, 1)

    @patch('zapcli.cli.ZAPHelper')
    def test_quick_scan_enable_scanners_error(self, helper_mock):
        """Testing quick scan."""
        instance = helper_mock.return_value
        instance.alerts.return_value = []
        instance.scanner_groups = ['xss']
        instance.scanner_group_map = {'xss': ['40012', '40014', '40016', '40017']}
        instance.set_enabled_scanners.side_effect = ZAPError('error')

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'quick-scan',
                                              'http://localhost/', '--scanners', 'xss'])
        self.assertEqual(result.exit_code, 1)

    @patch('zapcli.cli.ZAPHelper')
    def test_quick_scan_exclude_from_all_error(self, helper_mock):
        """Testing quick scan."""
        instance = helper_mock.return_value
        instance.alerts.return_value = []
        instance.exclude_from_all.side_effect = ZAPError('error')

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'quick-scan',
                                              'http://localhost/', '--exclude', 'pattern'])
        self.assertEqual(result.exit_code, 1)

    @patch('zapv2.ascan')
    def test_active_scanners_enable(self, ascan_mock):
        """Test enabling active scanners."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'scanners', 'enable',
                                              '--scanners', '1,2,3'])
        ascan_mock.return_value.enable_scanners.assert_called_with('1,2,3', apikey='')

    @patch('zapv2.ascan')
    def test_active_scanners_disable(self, ascan_mock):
        """Test enabling active scanners."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'scanners', 'disable',
                                              '--scanners', '1,2,3'])
        ascan_mock.return_value.disable_scanners.assert_called_with('1,2,3', apikey='')

    @patch('zapv2.ascan')
    def test_active_scan_policies_enable(self, ascan_mock):
        """Test enabling active scan policies method."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'policies', 'enable',
                                              '--policy-ids', '1,2,3'])
        ascan_mock.return_value.set_enabled_policies.assert_called_with('1,2,3', apikey='')

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

    @patch('zapcli.zap_helper.ZAPHelper.enable_script')
    def test_enable_script(self, helper_mock):
        """Test command to enable a script."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'enable', 'Foo.js'])
        helper_mock.assert_called_with('Foo.js')
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.enable_script')
    def test_enable_script_error(self, helper_mock):
        """Test command to enable a script with error raised."""
        helper_mock.side_effect = ZAPError('error')
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'enable', 'Foo.js'])
        helper_mock.assert_called_with('Foo.js')
        self.assertEqual(result.exit_code, 1)

    @patch('zapcli.zap_helper.ZAPHelper.disable_script')
    def test_disable_script(self, helper_mock):
        """Test command to disable a script."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'disable', 'Foo.js'])
        helper_mock.assert_called_with('Foo.js')
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.disable_script')
    def test_disable_script_error(self, helper_mock):
        """Test command to disable a script with error raised."""
        helper_mock.side_effect = ZAPError('error')
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'disable', 'Foo.js'])
        helper_mock.assert_called_with('Foo.js')
        self.assertEqual(result.exit_code, 1)

    @patch('zapcli.zap_helper.ZAPHelper.remove_script')
    def test_remove_script(self, helper_mock):
        """Test command to remove a script."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'remove', 'Foo.js'])
        helper_mock.assert_called_with('Foo.js')
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.remove_script')
    def test_remove_script_error(self, helper_mock):
        """Test command to remove a script with error raised."""
        helper_mock.side_effect = ZAPError('error')
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'remove', 'Foo.js'])
        helper_mock.assert_called_with('Foo.js')
        self.assertEqual(result.exit_code, 1)

    @patch('zapcli.zap_helper.ZAPHelper.load_script')
    def test_load_script(self, helper_mock):
        """Test command to load a script."""
        script_name = 'Foo.js'
        script_type = 'proxy'
        engine = 'Oracle Nashorn'

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'load',
                                              '--name', script_name, '--script-type', script_type,
                                              '--engine', engine, '--file-path', script_name])
        helper_mock.assert_called_with(name=script_name, script_type=script_type, engine=engine,
                                       file_path=script_name, description='')
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.load_script')
    def test_load_script_error(self, helper_mock):
        """Test command to load a script with error raised."""
        helper_mock.side_effect = ZAPError('error')
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'load',
                                              '--name', 'Foo.js', '--script-type', 'proxy',
                                              '--engine', 'Oracle Nashorn', '--file-path', 'Foo.js'])
        self.assertEqual(result.exit_code, 1)

    @patch('zapcli.zap_helper.ZAPHelper.xml_report')
    def test_xml_report(self, report_mock):
        """Testing XML report."""
        result = self.runner.invoke(cli.cli,
                                    ['report', '-o', 'foo.xml', '-f', 'xml'])
        report_mock.assert_called_with('foo.xml')
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.html_report')
    def test_html_report(self, report_mock):
        """Testing HTML report."""
        result = self.runner.invoke(cli.cli,
                                    ['report', '-o', 'foo.html', '-f', 'html'])
        report_mock.assert_called_with('foo.html')
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.include_in_context')
    def test_context_include(self, helper_mock):
        """Testing including a regex in a given context."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'context',
                                              'include', '--name', 'Test', '--pattern', 'zap-cli'])
        self.assertEqual(result.exit_code, 0)

    def test_context_include_error(self):
        """Testing that an error is reported when providing an invalid regex."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'context',
                                              'include', '--name', 'Test', '--pattern', '['])
        self.assertEqual(result.exit_code, 1)

    @patch('zapcli.zap_helper.ZAPHelper.exclude_from_context')
    def test_context_exclude(self, helper_mock):
        """Testing excluding a regex from a given context."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'context',
                                              'exclude', '--name', 'Test', '--pattern', 'zap-cli'])
        self.assertEqual(result.exit_code, 0)

    def test_context_exclude_error(self):
        """Testing that an error is reported when providing an invalid regex."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'context',
                                              'exclude', '--name', 'Test', '--pattern', '['])
        self.assertEqual(result.exit_code, 1)


if __name__ == '__main__':
    unittest.main()
