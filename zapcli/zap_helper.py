"""
Helper methods to extend and wrap the ZAP API client.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

import os
import platform
import re
import shlex
import subprocess
import time
import urllib2

from zapv2 import ZAPv2

from zapcli.exceptions import ZAPError
from zapcli.log import console


class ZAPHelper(object):
    """ZAPHelper class for wrapping the ZAP API client."""

    alert_levels = {
        'Informational': 1,
        'Low': 2,
        'Medium': 3,
        'High': 4,
    }

    scanner_group_map = {
        'sqli': ['40018'],
        'xss': ['40012', '40014', '40016', '40017'],
        'xss_reflected': ['40012'],
        'xss_persistent': ['40014', '40016', '40017'],
    }

    timeout = 60

    def __init__(self, zap_path='', port=8090, url='http://127.0.0.1', api_key='', logger=None):
        if os.path.isfile(zap_path):
            zap_path = os.path.dirname(zap_path)
        self.zap_path = zap_path
        self.port = port
        self.proxy_url = '{0}:{1}'.format(url, self.port)
        self.zap = ZAPv2(proxies={'http': self.proxy_url, 'https': self.proxy_url})
        self.api_key = api_key
        self.logger = logger or console

    @property
    def scanner_groups(self):
        """Available scanner groups."""
        return ['all'] + self.scanner_group_map.keys()

    def start(self, options=None):
        """Start the ZAP Daemon."""
        if self.is_running():
            self.logger.warn('ZAP is already running on port {0}'.format(self.port))
            return

        if platform.system() == 'Windows' or platform.system().startswith('CYGWIN'):
            executable = 'zap.bat'
        else:
            executable = 'zap.sh'

        executable_path = os.path.join(self.zap_path, executable)

        zap_command = [executable_path, '-daemon', '-port', str(self.port)]
        if options:
            extra_options = shlex.split(options)
            zap_command += extra_options

        log_path = os.path.join(self.zap_path, 'zap.log')

        self.logger.debug('Starting ZAP process with command: {0}.'.format(' '.join(zap_command)))
        self.logger.debug('Logging to {0}'.format(log_path))
        with open(log_path, 'w+') as log_file:
            subprocess.Popen(
                zap_command, cwd=self.zap_path, stdout=log_file,
                stderr=subprocess.STDOUT)

        timeout_time = time.time() + self.timeout
        while not self.is_running():
            if time.time() > timeout_time:
                raise ZAPError('Timed out waiting for ZAP to start.')
            time.sleep(2)

        self.logger.debug('ZAP started successfully.')

    def shutdown(self):
        """Shutdown ZAP."""
        if not self.is_running():
            self.logger.warn('ZAP is not running.')
            return

        self.logger.debug('Shutting down ZAP.')
        self.zap.core.shutdown(apikey=self.api_key)

        timeout_time = time.time() + self.timeout
        while self.is_running():
            if time.time() > timeout_time:
                raise ZAPError('Timed out waiting for ZAP to shutdown.')
            time.sleep(2)

        self.logger.debug('ZAP shutdown successfully.')

    def is_running(self):
        """Check if ZAP is running."""
        try:
            result = urllib2.urlopen(self.proxy_url)
        except urllib2.URLError:
            return False

        if 'ZAP-Header' in result.info().get('Access-Control-Allow-Headers', []):
            return True

        raise ZAPError('Another process is listening on {0}'.format(self.proxy_url))

    def open_url(self, url, sleep_after_open=2):
        """Access a URL through ZAP."""
        self.zap.urlopen(url)
        # Give the sites tree a chance to get updated
        time.sleep(sleep_after_open)

    def run_spider(self, target_url, status_check_sleep=10):
        """Run spider against a URL."""
        self.logger.debug('Spidering target {0}...'.format(target_url))

        scan_id = self.zap.spider.scan(target_url, apikey=self.api_key)

        if not scan_id:
            raise ZAPError('Error running spider.')
        elif not scan_id.isdigit():
            raise ZAPError('Error running spider: "{0}"'.format(scan_id))

        self.logger.debug('Started spider with ID {0}...'.format(scan_id))

        while int(self.zap.spider.status()) < 100:
            self.logger.debug('Spider progress %: {0}'.format(self.zap.spider.status()))
            time.sleep(status_check_sleep)

        self.logger.debug('Spider #{0} completed'.format(scan_id))

    def run_active_scan(self, target_url, recursive=False, status_check_sleep=10):
        """Run an active scan against a URL."""
        self.logger.debug('Scanning target {0}...'.format(target_url))

        scan_id = self.zap.ascan.scan(target_url, recurse=recursive, apikey=self.api_key)

        if not scan_id:
            raise ZAPError('Error running active scan.')
        elif not scan_id.isdigit():
            raise ZAPError(('Error running active scan: "{0}". Make sure the URL is in the site ' +
                            'tree by using the open-url or scanner commands before running an active ' +
                            'scan.').format(scan_id))

        self.logger.debug('Started scan with ID {0}...'.format(scan_id))

        while int(self.zap.ascan.status()) < 100:
            self.logger.debug('Scan progress %: {0}'.format(self.zap.ascan.status()))
            time.sleep(status_check_sleep)

        self.logger.debug('Scan #{0} completed'.format(scan_id))

    def run_ajax_spider(self, target_url, status_check_sleep=10):
        """Run AJAX Spider against a URL."""
        self.logger.debug('AJAX Spidering target {0}...'.format(target_url))

        self.zap.ajaxSpider.scan(target_url, apikey=self.api_key)

        while self.zap.ajaxSpider.status == 'running':
            self.logger.debug('AJAX Spider: {0}'.format(self.zap.ajaxSpider.status))
            time.sleep(status_check_sleep)

        self.logger.debug('AJAX Spider completed')

    def alerts(self, alert_level='High'):
        """Get a filtered list of alerts at the given alert level, and sorted by alert level."""
        alerts = self.zap.core.alerts()
        alert_level_value = self.alert_levels[alert_level]

        alerts = sorted((a for a in alerts if self.alert_levels[a['risk']] >= alert_level_value),
                        key=lambda k: self.alert_levels[k['risk']], reverse=True)

        return alerts

    def enabled_scanner_ids(self):
        """Retrieves a list of currently enabled scanners."""
        enabled_scanners = []
        scanners = self.zap.ascan.scanners()

        for scanner in scanners:
            if scanner['enabled'] == 'true':
                enabled_scanners.append(scanner['id'])

        return enabled_scanners

    def enable_scanners_by_ids(self, scanner_ids):
        """Enable a list of scanner IDs."""
        scanner_ids = ','.join(scanner_ids)
        self.logger.debug('Enabling scanners with IDs {0}'.format(scanner_ids))
        return self.zap.ascan.enable_scanners(scanner_ids, apikey=self.api_key)

    def disable_scanners_by_ids(self, scanner_ids):
        """Disable a list of scanner IDs."""
        scanner_ids = ','.join(scanner_ids)
        self.logger.debug('Disabling scanners with IDs {0}'.format(scanner_ids))
        return self.zap.ascan.disable_scanners(scanner_ids, apikey=self.api_key)

    def enable_scanners_by_group(self, group):
        """
        Enables the scanners in the group if it matches one in the scanner_group_map.
        """
        if group == 'all':
            self.logger.debug('Enabling all scanners')
            return self.zap.ascan.enable_all_scanners(apikey=self.api_key)

        try:
            scanner_list = self.scanner_group_map[group]
        except KeyError:
            raise ZAPError(
                'Invalid group "{0}" provided. Valid groups are: {1}'.format(
                    group, ', '.join(self.scanner_groups)
                )
            )

        self.logger.debug('Enabling scanner group {0}'.format(group))
        return self.enable_scanners_by_ids(scanner_list)

    def disable_scanners_by_group(self, group):
        """
        Disables the scanners in the group if it matches one in the scanner_group_map.
        """
        if group == 'all':
            self.logger.debug('Disabling all scanners')
            return self.zap.ascan.disable_all_scanners(apikey=self.api_key)

        try:
            scanner_list = self.scanner_group_map[group]
        except KeyError:
            raise ZAPError(
                'Invalid group "{0}" provided. Valid groups are: {1}'.format(
                    group, ', '.join(self.scanner_groups)
                )
            )

        self.logger.debug('Disabling scanner group {0}'.format(group))
        return self.disable_scanners_by_ids(scanner_list)

    def enable_scanners(self, scanners):
        """
        Enable the provided scanners by group and/or IDs.
        """
        scanner_ids = []
        for scanner in scanners:
            if scanner in self.scanner_groups:
                self.enable_scanners_by_group(scanner)
            elif scanner.isdigit():
                scanner_ids.append(scanner)
            else:
                raise ZAPError('Invalid scanner "{0}" provided. Must be a valid group or numeric ID.'.format(scanner))

        if scanner_ids:
            self.enable_scanners_by_ids(scanner_ids)

    def disable_scanners(self, scanners):
        """
        Enable the provided scanners by group and/or IDs.
        """
        scanner_ids = []
        for scanner in scanners:
            if scanner in self.scanner_groups:
                self.disable_scanners_by_group(scanner)
            elif scanner.isdigit():
                scanner_ids.append(scanner)
            else:
                raise ZAPError('Invalid scanner "{0}" provided. Must be a valid group or numeric ID.'.format(scanner))

        if scanner_ids:
            self.disable_scanners_by_ids(scanner_ids)

    def set_enabled_scanners(self, scanners):
        """
        Set only the provided scanners by group and/or IDs and disable all others.
        """
        self.logger.debug('Disabling all current scanners')
        self.zap.ascan.disable_all_scanners(apikey=self.api_key)
        self.enable_scanners(scanners)

    def enable_policies_by_ids(self, policy_ids):
        """Set enabled policy from a list of IDs."""
        policy_ids = ','.join(policy_ids)
        self.logger.debug('Setting enabled policies to IDs {0}'.format(policy_ids))
        self.zap.ascan.set_enabled_policies(policy_ids, apikey=self.api_key)

    def exclude_from_all(self, exclude_regex):
        """Exclude a pattern from proxy, spider and active scanner."""
        try:
            re.compile(exclude_regex)
        except re.error:
            raise ZAPError('Invalid regex "{0}" provided'.format(exclude_regex))

        self.logger.debug('Excluding {0} from proxy, spider and active scanner.'.format(exclude_regex))

        self.zap.core.exclude_from_proxy(exclude_regex, apikey=self.api_key)
        self.zap.spider.exclude_from_scan(exclude_regex, apikey=self.api_key)
        self.zap.ascan.exclude_from_scan(exclude_regex, apikey=self.api_key)

    def new_session(self):
        """Start a new session."""
        self.logger.debug('Starting a new session')
        self.zap.core.new_session(apikey=self.api_key)

    def save_session(self, file_path):
        """Save the current session."""
        self.logger.debug('Saving the session to "{0}"'.format(file_path))
        self.zap.core.save_session(file_path, overwrite='true', apikey=self.api_key)

    def load_session(self, file_path):
        """Load a given session."""
        if not os.path.isfile(file_path):
            raise ZAPError('No file found at "{0}", cannot load session.'.format(file_path))
        self.logger.debug('Loading session from "{0}"'.format(file_path))
        self.zap.core.load_session(file_path, apikey=self.api_key)
