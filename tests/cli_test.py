"""
Tests for the ZAP CLI.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

import unittest

from click.testing import CliRunner
from ddt import ddt
from mock import PropertyMock, Mock, MagicMock, patch
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
        self.assertEqual(result.exit_code, 2)

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
        self.assertEqual(result.exit_code, 2)

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
        self.assertEqual(result.exit_code, 2)

    @patch('zapcli.zap_helper.ZAPHelper.wait_for_zap')
    @patch('zapcli.zap_helper.ZAPHelper.is_running')
    def test_check_status_timeout(self, running_mock, wait_mock):
        """Test the status command with a timeout."""
        running_mock.return_value = False
        wait_mock.side_effect = ZAPError('error')
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'status', '-t', '0'])
        self.assertEqual(result.exit_code, 2)

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

    @patch('zapcli.cli.ZAPHelper')
    def test_quick_scan_issues_found(self, helper_mock):
        """Testing quick scan."""
        instance = helper_mock.return_value
        instance.scanner_groups = ['xss']
        instance.scanner_group_map = {'xss': ['40012', '40014', '40016', '40017']}
        instance.alerts.return_value = [{
            'url': 'http://localhost/?test=%3C%2Fspan%3E%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E%3Cspan%3E',
            'alert': 'Cross Site Scripting (Reflected)',
            'cweid': '79',
            'risk': 'High',
        }]

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'quick-scan',
                                              'http://localhost/', '--self-contained', '--scanners', 'xss',
                                              '--spider', '--exclude', 'pattern'])
        self.assertEqual(result.exit_code, 1)

    @patch('zapcli.zap_helper.ZAPHelper.start')
    def test_quick_scan_start_error(self, helper_mock):
        """Testing quick scan."""
        helper_mock.side_effect = ZAPError('error')

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'quick-scan',
                                              'http://localhost/', '--self-contained'])
        self.assertEqual(result.exit_code, 2)

    @patch('zapcli.cli.ZAPHelper')
    def test_quick_scan_shutdown_error(self, helper_mock):
        """Testing quick scan."""
        instance = helper_mock.return_value
        instance.alerts.return_value = []
        instance.shutdown.side_effect = ZAPError('error')

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'quick-scan',
                                              'http://localhost/', '--self-contained'])
        self.assertEqual(result.exit_code, 2)

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
        self.assertEqual(result.exit_code, 2)

    @patch('zapcli.cli.ZAPHelper')
    def test_quick_scan_exclude_from_all_error(self, helper_mock):
        """Testing quick scan."""
        instance = helper_mock.return_value
        instance.alerts.return_value = []
        instance.exclude_from_all.side_effect = ZAPError('error')

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'quick-scan',
                                              'http://localhost/', '--exclude', 'pattern'])
        self.assertEqual(result.exit_code, 2)

    @patch('zapv2.ascan')
    def test_active_scanners_enable(self, ascan_mock):
        """Test enabling active scanners."""
        self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'scanners', 'enable',
                                     '--scanners', '1,2,3'])
        ascan_mock.return_value.enable_scanners.assert_called_with('1,2,3')

    @patch('zapv2.ascan')
    def test_active_scanners_disable(self, ascan_mock):
        """Test enabling active scanners."""
        self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'scanners', 'disable',
                                     '--scanners', '1,2,3'])
        ascan_mock.return_value.disable_scanners.assert_called_with('1,2,3')

    @patch('zapv2.ascan')
    def test_active_scan_policies_enable(self, ascan_mock):
        """Test enabling active scan policies method."""
        self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'policies', 'enable',
                                     '--policy-ids', '1,2,3'])
        ascan_mock.return_value.set_enabled_policies.assert_called_with('1,2,3')

    @patch('zapcli.zap_helper.ZAPHelper.exclude_from_all')
    def test_exclude_from_scanners(self, helper_mock):
        """Test exclude from scanners command."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'exclude', 'pattern'])
        helper_mock.assert_called_with('pattern')
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.exclude_from_all')
    def test_exclude_from_scanners_error(self, helper_mock):
        """Test exclude from scanners command with error raised."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'exclude', '['])
        self.assertFalse(helper_mock.called)
        self.assertEqual(result.exit_code, 2)

    @patch('zapv2.script.enable')
    def test_enable_script(self, enable_mock):
        """Test command to enable a script."""
        enable_mock.return_value = 'OK'
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'enable', 'Foo.js'])
        enable_mock.assert_called_with('Foo.js')
        self.assertEqual(result.exit_code, 0)

    @patch('zapv2.script.enable')
    def test_enable_script_error(self, enable_mock):
        """Test command to enable a script with error raised."""
        enable_mock.return_value = 'Does Not Exist'
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'enable', 'Foo.js'])
        enable_mock.assert_called_with('Foo.js')
        self.assertEqual(result.exit_code, 2)

    @patch('zapv2.script.disable')
    def test_disable_script(self, disable_mock):
        """Test command to disable a script."""
        disable_mock.return_value = 'OK'
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'disable', 'Foo.js'])
        disable_mock.assert_called_with('Foo.js')
        self.assertEqual(result.exit_code, 0)

    @patch('zapv2.script.disable')
    def test_disable_script_error(self, disable_mock):
        """Test command to disable a script with error raised."""
        disable_mock.return_value = 'Does Not Exist'
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'disable', 'Foo.js'])
        disable_mock.assert_called_with('Foo.js')
        self.assertEqual(result.exit_code, 2)

    @patch('zapv2.script.remove')
    def test_remove_script(self, remove_mock):
        """Test command to remove a script."""
        remove_mock.return_value = 'OK'
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'remove', 'Foo.js'])
        remove_mock.assert_called_with('Foo.js')
        self.assertEqual(result.exit_code, 0)

    @patch('zapv2.script.remove')
    def test_remove_script_error(self, remove_mock):
        """Test command to remove a script with error raised."""
        remove_mock.return_value = 'Does Not Exist'
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'remove', 'Foo.js'])
        remove_mock.assert_called_with('Foo.js')
        self.assertEqual(result.exit_code, 2)

    @patch('zapv2.script')
    @patch('os.path.isfile')
    def test_load_script(self, isfile_mock, script_mock):
        """Test command to load a script."""
        script_name = 'Foo.js'
        script_type = 'proxy'
        engine = 'Oracle Nashorn'
        valid_engines = ['ECMAScript : Oracle Nashorn']

        isfile_mock.return_value = True

        class_mock = MagicMock()
        class_mock.load.return_value = 'OK'
        engines = PropertyMock(return_value=valid_engines)
        type(class_mock).list_engines = engines
        script_mock.return_value = class_mock

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'load',
                                              '--name', script_name, '--script-type', script_type,
                                              '--engine', engine, '--file-path', script_name])
        class_mock.load.assert_called_with(script_name, script_type, engine, script_name, scriptdescription='')
        self.assertEqual(result.exit_code, 0)

    @patch('zapv2.script')
    @patch('os.path.isfile')
    def test_load_script_file_error(self, isfile_mock, script_mock):
        """Testing that an error is raised when an invalid file is provided."""
        isfile_mock.return_value = False
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'load',
                                              '--name', 'Foo.js', '--script-type', 'proxy',
                                              '--engine', 'Oracle Nashorn', '--file-path', 'Foo.js'])
        self.assertEqual(result.exit_code, 2)
        self.assertFalse(script_mock.return_value.load.called)

    @patch('zapv2.script')
    @patch('os.path.isfile')
    def test_load_script_engine_error(self, isfile_mock, script_mock):
        """Testing that an error is raised when an invalid engine is provided."""
        isfile_mock.return_value = True

        valid_engines = ['ECMAScript : Oracle Nashorn']
        class_mock = MagicMock()
        class_mock.load.return_value = 'OK'
        engines = PropertyMock(return_value=valid_engines)
        type(class_mock).list_engines = engines
        script_mock.return_value = class_mock

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'load',
                                              '--name', 'Foo.js', '--script-type', 'proxy',
                                              '--engine', 'Invalid Engine', '--file-path', 'Foo.js'])
        self.assertEqual(result.exit_code, 2)
        self.assertFalse(class_mock.load.called)

    @patch('zapv2.script')
    @patch('os.path.isfile')
    def test_load_script_unknown_error(self, isfile_mock, script_mock):
        """Testing that an error is raised when an erro response is received from the API."""
        script_name = 'Foo.js'
        script_type = 'proxy'
        engine = 'Oracle Nashorn'
        valid_engines = ['ECMAScript : Oracle Nashorn']

        isfile_mock.return_value = True

        class_mock = MagicMock()
        class_mock.load.return_value = 'Internal Error'
        engines = PropertyMock(return_value=valid_engines)
        type(class_mock).list_engines = engines
        script_mock.return_value = class_mock

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', 'scripts', 'load',
                                              '--name', script_name, '--script-type', script_type,
                                              '--engine', engine, '--file-path', script_name])
        self.assertEqual(result.exit_code, 2)
        class_mock.load.assert_called_with(script_name, script_type, engine, script_name, scriptdescription='')

    @patch('zapcli.zap_helper.ZAPHelper.xml_report')
    def test_xml_report(self, report_mock):
        """Testing XML report."""
        result = self.runner.invoke(cli.cli,
                                    ['report', '-o', 'foo.xml', '-f', 'xml'])
        report_mock.assert_called_with('foo.xml')
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.md_report')
    def test_md_report(self, report_mock):
        """Testing MD report."""
        result = self.runner.invoke(cli.cli,
                                    ['report', '-o', 'foo.md', '-f', 'md'])
        report_mock.assert_called_with('foo.md')
        self.assertEqual(result.exit_code, 0)

    @patch('zapcli.zap_helper.ZAPHelper.html_report')
    def test_html_report(self, report_mock):
        """Testing HTML report."""
        result = self.runner.invoke(cli.cli,
                                    ['report', '-o', 'foo.html', '-f', 'html'])
        report_mock.assert_called_with('foo.html')
        self.assertEqual(result.exit_code, 0)

    @patch('zapv2.context.include_in_context')
    def test_context_include(self, context_mock):
        """Testing including a regex in a given context."""
        context_mock.return_value = 'OK'
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'context',
                                              'include', '--name', 'Test', '--pattern', 'zap-cli'])
        context_mock.assert_called_with(contextname='Test', regex='zap-cli')
        self.assertEqual(result.exit_code, 0)

    @patch('zapv2.context.include_in_context')
    def test_context_include_error(self, context_mock):
        """Testing that an error is reported when an invalid response is received from the API."""
        context_mock.return_value = 'Error'
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'context',
                                              'include', '--name', 'Test', '--pattern', 'zap-cli'])
        context_mock.assert_called_with(contextname='Test', regex='zap-cli')
        self.assertEqual(result.exit_code, 2)

    def test_context_include_regex_error(self):
        """Testing that an error is reported when providing an invalid regex."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'context',
                                              'include', '--name', 'Test', '--pattern', '['])
        self.assertEqual(result.exit_code, 2)

    @patch('zapv2.context.exclude_from_context')
    def test_context_exclude(self, context_mock):
        """Testing excluding a regex from a given context."""
        context_mock.return_value = 'OK'
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'context',
                                              'exclude', '--name', 'Test', '--pattern', 'zap-cli'])
        context_mock.assert_called_with(contextname='Test', regex='zap-cli')
        self.assertEqual(result.exit_code, 0)

    @patch('zapv2.context.exclude_from_context')
    def test_context_exclude_error(self, context_mock):
        """Testing that an error is reported when an invalid response is received from the API."""
        context_mock.return_value = 'Error'
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'context',
                                              'exclude', '--name', 'Test', '--pattern', 'zap-cli'])
        context_mock.assert_called_with(contextname='Test', regex='zap-cli')
        self.assertEqual(result.exit_code, 2)

    def test_context_exclude_regex_error(self):
        """Testing that an error is reported when providing an invalid regex."""
        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'context',
                                              'exclude', '--name', 'Test', '--pattern', '['])
        self.assertEqual(result.exit_code, 2)

    @patch('zapv2.core.load_session')
    @patch('os.path.isfile')
    def test_load_session(self, isfile_mock, session_mock):
        """Test loading a session from a file."""
        isfile_mock.return_value = True
        file_path = '/path/to/zap'

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'session',
                                              'load', file_path])
        self.assertEqual(result.exit_code, 0)
        session_mock.assert_called_with(file_path)

    @patch('zapv2.core.load_session')
    @patch('os.path.isfile')
    def test_load_session_error(self, isfile_mock, session_mock):
        """Testing that an error is reported when providing an invalid file path."""
        isfile_mock.return_value = False
        file_path = 'invalid'

        result = self.runner.invoke(cli.cli, ['--boring', '--api-key', '', '--verbose', 'session',
                                              'load', file_path])
        self.assertEqual(result.exit_code, 2)
        self.assertFalse(session_mock.called)


if __name__ == '__main__':
    unittest.main()
