"""
Tests for the ZAP CLI helper.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

import shlex
import subprocess
import unittest

from ddt import ddt, data, unpack
from mock import PropertyMock, Mock, MagicMock, mock_open, patch
from requests.exceptions import ConnectionError
import responses
from six import binary_type

from zapcli import zap_helper
from zapcli.exceptions import ZAPError


@ddt
class ZAPHelperTestCase(unittest.TestCase):
    """Test ZAP Helper methods."""

    def setUp(self):
        self.zap_helper = zap_helper.ZAPHelper()
        self.zap_helper._status_check_sleep = 0

    @data(
        (
            'Linux',
            'zap.sh'
        ),
        (
            'Darwin',
            'zap.sh'
        ),
        (
            'Windows',
            'zap.bat'
        ),
        (
            'CYGWIN_NT-6.1-WOW64',
            'zap.bat'
        )
    )
    @unpack
    @patch('platform.system')
    @patch('subprocess.Popen')
    @patch('os.path.isfile')
    def test_start_successful(self, platform_string, executable, isfile_mock, popen_mock, platform_mock):
        """Test starting the ZAP daemon."""
        def is_running_result():
            """Used to mock the result of ZAPHelper.is_running."""
            if self.zap_helper.is_running.call_count > 1:
                return True

            return False

        self.zap_helper.is_running = Mock(side_effect=is_running_result)
        platform_mock.return_value = platform_string
        isfile_mock.return_value = True

        file_open_mock = mock_open()
        with patch('zapcli.zap_helper.open', file_open_mock, create=True):
            self.zap_helper.start()

        expected_command = shlex.split('{} -daemon -port 8090'.format(executable))
        popen_mock.assert_called_with(expected_command, cwd='', stderr=subprocess.STDOUT, stdout=file_open_mock())

    @patch('platform.system')
    @patch('subprocess.Popen')
    @patch('os.path.isfile')
    def test_start_extra_options(self, isfile_mock, popen_mock, platform_mock):
        """Test starting the ZAP daemon with extra commandline options."""
        def is_running_result():
            """Used to mock the result of ZAPHelper.is_running."""
            if self.zap_helper.is_running.call_count > 1:
                return True

            return False

        self.zap_helper.is_running = Mock(side_effect=is_running_result)
        platform_mock.return_value = 'Linux'
        isfile_mock.return_value = True

        extra_options = '-config api.key=12345 -config connection.timeoutInSecs=60'

        file_open_mock = mock_open()
        with patch('zapcli.zap_helper.open', file_open_mock, create=True):
            self.zap_helper.start(options=extra_options)

        expected_command = shlex.split('zap.sh -daemon -port 8090 {0}'.format(extra_options))
        popen_mock.assert_called_with(expected_command, cwd='', stderr=subprocess.STDOUT, stdout=file_open_mock())

    @patch('platform.system')
    @patch('subprocess.Popen')
    def test_start_timeout(self, popen_mock, platform_mock):
        """Test trying to start ZAP when the daemon is already running."""
        self.zap_helper.is_running = Mock(return_value=False)
        self.zap_helper.timeout = 0
        platform_mock.return_value = 'Linux'

        file_open_mock = mock_open()
        with patch('zapcli.zap_helper.open', file_open_mock, create=True):
            with self.assertRaises(ZAPError):
                self.zap_helper.start()

    @patch('subprocess.Popen')
    def test_start_running(self, popen_mock):
        """Test trying to start ZAP when the daemon is already running."""
        self.zap_helper.is_running = Mock(return_value=True)

        self.zap_helper.start()

        self.assertFalse(popen_mock.called)

    @patch('platform.system')
    @patch('subprocess.Popen')
    @patch('os.path.isfile')
    def test_start_not_found(self, isfile_mock, popen_mock, platform_mock):
        """Test trying to start ZAP when the ZAP executable is not found."""
        self.zap_helper.is_running = Mock(return_value=False)
        isfile_mock.return_value = False
        platform_mock.return_value = 'Linux'

        with self.assertRaises(ZAPError):
            self.zap_helper.start()

    @patch('zapv2.core.shutdown')
    def test_shutdown_successful(self, shutdown_mock):
        """Test shutting down the ZAP daemon."""
        def is_running_result():
            """Used to mock the result of ZAPHelper.is_running."""
            if self.zap_helper.is_running.call_count > 1:
                return False

            return True

        self.zap_helper.is_running = Mock(side_effect=is_running_result)

        self.zap_helper.shutdown()

        self.assertTrue(shutdown_mock.called)

    @patch('zapv2.core.shutdown')
    def test_shutdown_timeout(self, shutdown_mock):
        """Test shutting down the ZAP daemon."""
        self.zap_helper.is_running = Mock(return_value=True)
        self.zap_helper.timeout = 0

        with self.assertRaises(ZAPError):
            self.zap_helper.shutdown()

        self.assertTrue(shutdown_mock.called)

    @patch('zapv2.core.shutdown')
    def test_shutdown_not_running(self, shutdown_mock):
        """Test trying to shut down the ZAP daemon when ZAP daemon isn't running."""
        self.zap_helper.is_running = Mock(return_value=False)

        self.zap_helper.shutdown()

        self.assertFalse(shutdown_mock.called)

    @responses.activate
    def test_is_running(self):
        """Test the check if ZAP is running."""
        responses.add(responses.GET, 'http://127.0.0.1:8090',
                      adding_headers={'Access-Control-Allow-Headers': 'ZAP-Header'})

        result = self.zap_helper.is_running()

        self.assertTrue(result)

    @responses.activate
    def test_is_not_running(self):
        """Test the check if ZAP is running when it isn't."""
        responses.add(responses.GET, 'http://127.0.0.1:8090',
                      body=ConnectionError('[Errno 111] Connection refused'))

        result = self.zap_helper.is_running()

        self.assertFalse(result)

    @responses.activate
    def test_is_not_running_error(self):
        """Test that an exception is raised when something else is listening on the port set for ZAP."""
        responses.add(responses.GET, 'http://127.0.0.1:8090')

        with self.assertRaises(ZAPError):
            self.zap_helper.is_running()

    @patch('zapv2.ZAPv2.urlopen')
    def test_open_url(self, urlopen_mock):
        """Test opening a URL through ZAP."""
        url = 'http://localhost/'

        urlopen_mock.return_value = None

        self.zap_helper.open_url(url, 0)

        urlopen_mock.assert_called_with(url)

    def test_run_spider(self):
        """Test running the spider."""
        def status_result():
            """Return value of the status property."""
            if status.call_count > 2:
                return '100'
            return '50'

        class_mock = MagicMock()
        class_mock.scan.return_value = '1'
        status = Mock(side_effect=status_result)
        class_mock.status = status
        self.zap_helper.zap.spider = class_mock

        self.zap_helper.run_spider('http://localhost')

    def test_run_spider_error(self):
        """Test running the spider when an error occurs."""
        class_mock = MagicMock()
        class_mock.scan.return_value = 'Provided parameter has illegal or unrecognized value'
        self.zap_helper.zap.spider = class_mock

        with self.assertRaises(ZAPError):
            self.zap_helper.run_spider('http://localhost')

    def test_run_spider_as_user(self):
        """Test running the spider as a given user."""
        def status_result():
            """Return value of the status property."""
            if status.call_count > 2:
                return '100'
            return '50'

        class_mock = MagicMock()
        class_mock.scan_as_user.return_value = '1'
        status = Mock(side_effect=status_result)
        class_mock.status = status
        self.zap_helper.zap.spider = class_mock
        self.zap_helper.zap.context.context = Mock(return_value={'id': '1'})
        self.zap_helper.zap.users.users_list = Mock(return_value=[{'name': 'Test', 'id': '1'}])

        self.zap_helper.run_spider('http://localhost', 'Test', 'Test')

    def test_run_spider_as_user_error(self):
        """Test running the spider as a given user when an error occurs."""
        def status_result():
            """Return value of the status property."""
            if status.call_count > 2:
                return '100'
            return '50'

        class_mock = MagicMock()
        class_mock.scan_as_user.return_value = '1'
        status = Mock(side_effect=status_result)
        class_mock.status = status
        self.zap_helper.zap.spider = class_mock
        self.zap_helper.zap.context.context = Mock(return_value={'id': '1'})
        self.zap_helper.zap.users.users_list = Mock(return_value=[])

        with self.assertRaises(ZAPError):
            self.zap_helper.run_spider('http://localhost', 'Test', 'Test')

    def test_run_active_scan(self):
        """Test running an active scan."""
        def status_result():
            """Return value of the status property."""
            if status.call_count > 2:
                return '100'
            return '50'

        class_mock = MagicMock()
        class_mock.scan.return_value = '1'
        status = Mock(side_effect=status_result)
        class_mock.status = status
        self.zap_helper.zap.ascan = class_mock

        self.zap_helper.run_active_scan('http://localhost')

    def test_run_active_scan_as_user(self):
        """Test running an active scan as a given user."""
        def status_result():
            """Return value of the status property."""
            if status.call_count > 2:
                return '100'
            return '50'

        class_mock = MagicMock()
        class_mock.scan_as_user.return_value = '1'
        status = Mock(side_effect=status_result)
        class_mock.status = status
        self.zap_helper.zap.ascan = class_mock
        self.zap_helper.zap.context.context = Mock(return_value={'id': '1'})
        self.zap_helper.zap.users.users_list = Mock(return_value=[{'name': 'Test', 'id': '1'}])

        self.zap_helper.run_active_scan('http://localhost', False, 'Test', 'Test')

    def test_run_active_scan_error(self):
        """Test running an active scan."""
        class_mock = MagicMock()
        class_mock.scan.return_value = ''
        self.zap_helper.zap.ascan = class_mock

        with self.assertRaises(ZAPError):
            self.zap_helper.run_active_scan('http://localhost')

    def test_run_active_scan_url_not_found(self):
        """Test running an active scan when the URL is not in the site tree."""
        class_mock = MagicMock()
        class_mock.scan.return_value = 'URL Not Found in the Scan Tree'
        self.zap_helper.zap.ascan = class_mock

        with self.assertRaises(ZAPError):
            self.zap_helper.run_active_scan('http://localhost')

    def test_run_ajax_spider(self):
        """Test running the AJAX Spider."""
        def status_result():
            """Return value of the status property."""
            if status.call_count > 2:
                return 'stopped'
            return 'running'

        class_mock = MagicMock()
        status = PropertyMock(side_effect=status_result)
        type(class_mock).status = status
        self.zap_helper.zap.ajaxSpider = class_mock

        self.zap_helper.run_ajax_spider('http://localhost')

    @data(
        (
            [
                {'alert': 'Cross Site Scripting (Reflected)', 'risk': 'High'},
                {'alert': 'X-Content-Type-Options header missing', 'risk': 'Low'},
                {'alert': 'X-Frame-Options header not set', 'risk': 'Informational'}
            ],
            'High',
            [{'alert': 'Cross Site Scripting (Reflected)', 'risk': 'High'}]
        ),
        (
            [
                {'alert': 'X-Content-Type-Options header missing', 'risk': 'Low'},
                {'alert': 'X-Frame-Options header not set', 'risk': 'Informational'}
            ],
            'High',
            []
        ),
        (
            [],
            'High',
            []
        ),
        (
            [
                {'alert': 'X-Content-Type-Options header missing', 'risk': 'Low'},
                {'alert': 'Cross Site Scripting (Reflected)', 'risk': 'High'},
                {'alert': 'X-Frame-Options header not set', 'risk': 'Informational'}
            ],
            'Low',
            [
                {'alert': 'Cross Site Scripting (Reflected)', 'risk': 'High'},
                {'alert': 'X-Content-Type-Options header missing', 'risk': 'Low'}
            ]
        ),
        (
            [
                {'alert': 'Cross Site Scripting (Reflected)', 'risk': 'High'},
                {'alert': 'X-Content-Type-Options header missing', 'risk': 'Low'},
                {'alert': 'X-Frame-Options header not set', 'risk': 'Informational'}
            ],
            'Informational',
            [
                {'alert': 'Cross Site Scripting (Reflected)', 'risk': 'High'},
                {'alert': 'X-Content-Type-Options header missing', 'risk': 'Low'},
                {'alert': 'X-Frame-Options header not set', 'risk': 'Informational'}
            ]
        ),
    )
    @unpack
    @patch('zapv2.core.alerts')
    def test_alerts(self, alerts, alert_level, expected_result, alerts_mock):
        """Test getting alerts at a given alert threshold."""
        alerts_mock.return_value = alerts

        result = self.zap_helper.alerts(alert_level)

        self.assertEqual(result, expected_result)

    @data(
        (
            [
                {'id': '6', 'enabled': 'true'},
                {'id': '40012', 'enabled': 'true'},
                {'id': '40014', 'enabled': 'false'}
            ],
            ['6', '40012']
        ),
        (
            [],
            []
        )
    )
    @unpack
    @patch('zapv2.ascan.scanners')
    def test_enabled_scanner_ids(self, scanners, expected_result, scanners_mock):
        """Test getting enabled scanner IDs."""
        scanners_mock.return_value = scanners

        result = self.zap_helper.enabled_scanner_ids()

        self.assertEqual(result, expected_result)

    @patch('zapv2.ascan.enable_scanners')
    def test_enable_scanners_by_group(self, ascan_mock):
        """Test enabling a scanners by group name."""
        self.zap_helper.enable_scanners_by_group('xss')
        ascan_mock.assert_called_with(','.join(self.zap_helper.scanner_group_map['xss']))

    @patch('zapv2.ascan.enable_all_scanners')
    def test_enable_scanners_by_group_all(self, ascan_mock):
        """Test enabling a scanners by group name."""
        self.zap_helper.enable_scanners_by_group('all')
        self.assertTrue(ascan_mock.called)

    @patch('zapv2.ascan.enable_scanners')
    def test_enable_scanners_by_group_invalid_group(self, ascan_mock):
        """Test enabling a scanners by group name."""
        with self.assertRaises(ZAPError):
            self.zap_helper.enable_scanners_by_group('invalid-group')

        self.assertFalse(ascan_mock.called)

    @patch('zapv2.ascan.disable_scanners')
    def test_disable_scanners_by_group(self, ascan_mock):
        """Test disabling a scanners by group name."""
        self.zap_helper.disable_scanners_by_group('xss')
        ascan_mock.assert_called_with(','.join(self.zap_helper.scanner_group_map['xss']))

    @patch('zapv2.ascan.disable_all_scanners')
    def test_disable_scanners_by_group_all(self, ascan_mock):
        """Test disabling a scanners by group name."""
        self.zap_helper.disable_scanners_by_group('all')
        self.assertTrue(ascan_mock.called)

    @patch('zapv2.ascan.disable_scanners')
    def test_disable_scanners_by_group_invalid_group(self, ascan_mock):
        """Test disabling a scanners by group name."""
        with self.assertRaises(ZAPError):
            self.zap_helper.disable_scanners_by_group('invalid-group')

        self.assertFalse(ascan_mock.called)

    @patch('zapv2.ascan.enable_all_scanners')
    @patch('zapv2.ascan.enable_scanners')
    def test_enable_scanners(self, enable_mock, enable_all_mock):
        """Test enabling scanners by group(s) and/or ID(s)."""
        self.zap_helper.enable_scanners(['xss', '0', '50000'])

        self.assertFalse(enable_all_mock.called)
        self.assertEqual(enable_mock.call_count, 2)
        enable_mock.assert_any_call(','.join(self.zap_helper.scanner_group_map['xss']))
        enable_mock.assert_any_call('0,50000')

    @patch('zapv2.ascan.enable_all_scanners')
    @patch('zapv2.ascan.enable_scanners')
    def test_enable_scanners_error(self, enable_mock, enable_all_mock):
        """Test enabling scanners by group(s) and/or ID(s)."""
        with self.assertRaises(ZAPError):
            self.zap_helper.enable_scanners('invalid-group')

    @patch('zapv2.ascan.disable_all_scanners')
    @patch('zapv2.ascan.disable_scanners')
    def test_disable_scanners(self, disable_mock, disable_all_mock):
        """Test disabling scanners by group(s) and/or ID(s)."""
        self.zap_helper.disable_scanners(['xss', '0', '50000'])

        self.assertFalse(disable_all_mock.called)
        self.assertEqual(disable_mock.call_count, 2)
        disable_mock.assert_any_call(','.join(self.zap_helper.scanner_group_map['xss']))
        disable_mock.assert_any_call('0,50000')

    @patch('zapv2.ascan.disable_all_scanners')
    @patch('zapv2.ascan.disable_scanners')
    def test_disable_scanners_error(self, disable_mock, disable_all_mock):
        """Test disabling scanners by group(s) and/or ID(s)."""
        with self.assertRaises(ZAPError):
            self.zap_helper.disable_scanners('invalid-group')

    @patch('zapv2.ascan.disable_all_scanners')
    @patch('zapv2.ascan.enable_all_scanners')
    @patch('zapv2.ascan.enable_scanners')
    def test_set_enabled_scanners(self, enable_mock, enable_all_mock, disable_mock):
        """Test enabling scanners by group(s) and/or ID(s)."""
        self.zap_helper.set_enabled_scanners(['xss', '0', '50000'])

        self.assertTrue(disable_mock.called)
        self.assertFalse(enable_all_mock.called)
        self.assertEqual(enable_mock.call_count, 2)
        enable_mock.assert_any_call(','.join(self.zap_helper.scanner_group_map['xss']))
        enable_mock.assert_any_call('0,50000')

    @patch('zapv2.ascan.disable_all_scanners')
    @patch('zapv2.ascan.enable_all_scanners')
    @patch('zapv2.ascan.enable_scanners')
    def test_set_enabled_scanners_error(self, enable_mock, enable_all_mock, disable_mock):
        """Test enabling scanners by group(s) and/or ID(s)."""
        with self.assertRaises(ZAPError):
            self.zap_helper.set_enabled_scanners('invalid-group')

    @patch('zapv2.ascan.set_scanner_attack_strength')
    def test_set_scanner_attack_strength(self, set_strength_mock):
        """Test successfully setting attack strength for scanners."""
        set_strength_mock.return_value = 'OK'

        self.zap_helper.set_scanner_attack_strength([0, 50000], 'High')
        self.assertEqual(set_strength_mock.call_count, 2)

    @patch('zapv2.ascan.set_scanner_attack_strength')
    def test_set_scanner_attack_strength_error(self, set_strength_mock):
        """Test that an error is raised when the API returns an unexpected response."""
        set_strength_mock.return_value = 'Error'

        with self.assertRaises(ZAPError):
            self.zap_helper.set_scanner_attack_strength([0, 50000], 'Invalid')

    @patch('zapv2.ascan.set_scanner_alert_threshold')
    def test_set_scanner_alert_threshold(self, set_threshold_mock):
        """Test successfully setting the alert threshold for scanners."""
        set_threshold_mock.return_value = 'OK'

        self.zap_helper.set_scanner_alert_threshold([0, 50000], 'High')
        self.assertEqual(set_threshold_mock.call_count, 2)

    @patch('zapv2.ascan.set_scanner_alert_threshold')
    def test_set_scanner_alert_threshold_error(self, set_threshold_mock):
        """Test that an error is raised when the API returns an unexpected response."""
        set_threshold_mock.return_value = 'Error'

        with self.assertRaises(ZAPError):
            self.zap_helper.set_scanner_alert_threshold([0, 50000], 'Invalid')

    @patch('zapv2.ascan.set_enabled_policies')
    def test_enable_policies_by_ids(self, policies_mock):
        """Test enabling scanners by a list of IDs."""
        self.zap_helper.enable_policies_by_ids(['1', '5', '6'])
        policies_mock.assert_called_with('1,5,6')

    @patch('zapv2.ascan.set_policy_attack_strength')
    def test_set_policy_attack_strength(self, set_strength_mock):
        """Test successfully setting attack strength for policies."""
        set_strength_mock.return_value = 'OK'

        self.zap_helper.set_policy_attack_strength([0, 4], 'High')
        self.assertEqual(set_strength_mock.call_count, 2)

    @patch('zapv2.ascan.set_policy_attack_strength')
    def test_set_policy_attack_strength_error(self, set_strength_mock):
        """Test that an error is raised when the API returns an unexpected response."""
        set_strength_mock.return_value = 'Error'

        with self.assertRaises(ZAPError):
            self.zap_helper.set_policy_attack_strength([0, 4], 'Invalid')

    @patch('zapv2.ascan.set_policy_alert_threshold')
    def test_set_policy_alert_threshold(self, set_threshold_mock):
        """Test successfully setting the alert threshold for scanners."""
        set_threshold_mock.return_value = 'OK'

        self.zap_helper.set_policy_alert_threshold([0, 4], 'High')
        self.assertEqual(set_threshold_mock.call_count, 2)

    @patch('zapv2.ascan.set_policy_alert_threshold')
    def test_set_policy_alert_threshold_error(self, set_threshold_mock):
        """Test that an error is raised when the API returns an unexpected response."""
        set_threshold_mock.return_value = 'Error'

        with self.assertRaises(ZAPError):
            self.zap_helper.set_policy_alert_threshold([0, 4], 'Invalid')

    @patch('zapv2.core.exclude_from_proxy')
    @patch('zapv2.spider.exclude_from_scan')
    @patch('zapv2.ascan.exclude_from_scan')
    def test_exclude_from_all(self, ascan_mock, spider_mock, core_mock):
        """Test excluding a valid regex pattern from all aspects of a scan."""
        exclude_pattern = r"\/zapcli.+"

        self.zap_helper.exclude_from_all(exclude_pattern)

        core_mock.assert_called_with(exclude_pattern)
        spider_mock.assert_called_with(exclude_pattern)
        ascan_mock.assert_called_with(exclude_pattern)

    def test_exclude_from_all_raises_eror(self):
        """
        Test excluding a pattern from all aspects of a scan raises an error
        when given an invalid regex.
        """
        exclude_pattern = '['
        with self.assertRaises(ZAPError):
            self.zap_helper.exclude_from_all(exclude_pattern)

    @patch('zapv2.core.xmlreport')
    def test_xml_report(self, xmlreport_mock):
        """Test XML report."""
        report_str = 'test_xml_report'
        xmlreport_mock.return_value = report_str
        file_path = 'foo.xml'
        file_open_mock = mock_open()

        with patch('zapcli.zap_helper.open', file_open_mock, create=True):
            self.zap_helper.xml_report(file_path)

        xmlreport_mock.assert_called_with()
        file_open_mock.assert_called_with(file_path, mode='wb')
        if not isinstance(report_str, binary_type):
            report_str = report_str.encode('utf-8')
        file_open_mock().write.assert_called_with(report_str)

    @patch('zapv2.core.mdreport')
    def test_md_report(self, mdreport_mock):
        """Test MD report."""
        report_str = 'test_md_report'
        mdreport_mock.return_value = report_str
        file_path = 'foo.md'
        file_open_mock = mock_open()

        with patch('zapcli.zap_helper.open', file_open_mock, create=True):
            self.zap_helper.md_report(file_path)

        mdreport_mock.assert_called_with()
        file_open_mock.assert_called_with(file_path, mode='wb')
        if not isinstance(report_str, binary_type):
            report_str = report_str.encode('utf-8')
        file_open_mock().write.assert_called_with(report_str)

    @patch('zapv2.core.htmlreport')
    def test_html_report(self, htmlreport_mock):
        """Test HTML report."""
        report_str = 'test_html_report'
        htmlreport_mock.return_value = report_str
        file_path = 'foo.html'
        file_open_mock = mock_open()

        with patch('zapcli.zap_helper.open', file_open_mock, create=True):
            self.zap_helper.html_report(file_path)

        htmlreport_mock.assert_called_with()
        file_open_mock.assert_called_with(file_path, mode='wb')
        if not isinstance(report_str, binary_type):
            report_str = report_str.encode('utf-8')
        file_open_mock().write.assert_called_with(report_str)


if __name__ == '__main__':
    unittest.main()
