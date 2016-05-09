"""
ZAP CLI.
"""

from contextlib import contextmanager
import json
import sys

import click
from tabulate import tabulate

from zapcli import __version__
from zapcli.exceptions import ZAPError
from zapcli.log import console
from zapcli.zap_helper import ZAPHelper


def validate_ids(ctx, param, value):
    """Validate a list of IDs and convert them to a list."""
    if not value:
        return None

    ids = [x.strip() for x in value.split(',')]
    for id_item in ids:
        if not id_item.isdigit():
            raise click.BadParameter('Non-numeric value "{0}" provided for an ID.'.format(id_item))

    return ids


def validate_scanner_list(ctx, param, value):
    """
    Validate a comma-separated list of scanners and extract it into a list of groups and IDs.
    """
    if not value:
        return None

    valid_groups = ctx.obj.scanner_groups
    scanners = [x.strip() for x in value.split(',')]

    if 'all' in scanners:
        return ['all']

    scanner_ids = []
    for scanner in scanners:
        if scanner.isdigit():
            scanner_ids.append(scanner)
        elif scanner in valid_groups:
            scanner_ids += ctx.obj.scanner_group_map[scanner]
        else:
            raise click.BadParameter('Invalid scanner "{0}" provided. Must be a valid group or numeric ID.'
                                     .format(scanner))

    return scanner_ids


@contextmanager
def zap_error_handler():
    """Context manager to handle ZAPError exceptions in a standard way."""
    try:
        yield
    except ZAPError as ex:
        console.error(str(ex))
        sys.exit(1)


@click.group(help='ZAP CLI v{0} - A simple commandline tool for OWASP ZAP.'.format(__version__))
@click.option('--boring', is_flag=True, default=False, help='Remove color from console output.')
@click.option('--verbose', '-v', is_flag=True, default=False, type=bool,
              help='Add more verbose debugging output.')
@click.option('--zap-path', default='/zap', envvar='ZAP_PATH', type=str,
              help='Path to the ZAP daemon. Defaults to /zap or the value of the environment variable ZAP_PATH.')
@click.option('--port', '-p', default=8090, envvar='ZAP_PORT', type=int,
              help='Port of the ZAP proxy. Defaults to 8090 or the value of the environment variable ZAP_PORT.')
@click.option('--zap-url', default='http://127.0.0.1', envvar='ZAP_URL', type=str,
              help='The URL of the ZAP proxy. Defaults to http://127.0.0.1 or the value of the environment ' +
              'variable ZAP_URL.')
@click.option('--api-key', default='', envvar='ZAP_API_KEY', type=str,
              help='The API key for using the ZAP API if required. Defaults to the value of the environment ' +
              'variable ZAP_API_KEY.')
@click.pass_context
def cli(ctx, boring, verbose, zap_path, port, zap_url, api_key):
    """Main command line entry point."""
    console.colorize = not boring

    if verbose:
        console.setLevel('DEBUG')
    else:
        console.setLevel('INFO')

    ctx.obj = ZAPHelper(zap_path=zap_path, port=port, url=zap_url, api_key=api_key)


@cli.command('start', short_help='Start the ZAP daemon.')
@click.option('--start-options', '-o', type=str,
              help='Extra options to pass to the ZAP start command, e.g. "-config api.key=12345"')
@click.pass_obj
def start_zap_daemon(zap_helper, start_options):
    """Helper to start the daemon using the current config."""
    console.info('Starting ZAP daemon')
    with zap_error_handler():
        zap_helper.start(options=start_options)


@cli.command('shutdown')
@click.pass_obj
def shutdown_zap_daemon(zap_helper):
    """Shutdown the ZAP daemon."""
    console.info('Shutting down ZAP daemon')
    with zap_error_handler():
        zap_helper.shutdown()


@cli.group(name='session', short_help='Manage sessions.')
@click.pass_context
def session_group(ctx):
    """Manage sessions."""
    pass


@session_group.command('new')
@click.pass_obj
def new_session(zap_helper):
    """Start a new session."""
    zap_helper.new_session()


@session_group.command('save')
@click.argument('file-path')
@click.pass_obj
def save_session(zap_helper, file_path):
    """Save the session."""
    zap_helper.save_session(file_path)


@session_group.command('load')
@click.argument('file-path')
@click.pass_obj
def load_session(zap_helper, file_path):
    """Load a given session."""
    with zap_error_handler():
        zap_helper.load_session(file_path)


@cli.command('open-url')
@click.argument('url')
@click.pass_obj
def open_url(zap_helper, url):
    """Open a URL using the ZAP proxy."""
    console.info('Accessing URL {0}'.format(url))
    zap_helper.open_url(url)


@cli.command('spider')
@click.argument('url')
@click.pass_obj
def spider_url(zap_helper, url):
    """Run the spider against a URL."""
    console.info('Running spider...')
    with zap_error_handler():
        zap_helper.run_spider(url)


@cli.command('ajax-spider')
@click.argument('url')
@click.pass_obj
def ajax_spider_url(zap_helper, url):
    """Run the AJAX Spider against a URL."""
    console.info('Running AJAX Spider...')
    zap_helper.run_ajax_spider(url)


@cli.command('active-scan', short_help='Run an Active Scan.')
@click.argument('url')
@click.option('--scanners', '-s', type=str, callback=validate_scanner_list,
              help='Comma separated list of scanner IDs and/or groups to use in the scan. Use the scanners ' +
              'subcommand to get a list of IDs. Available groups are: {0}.'.format(
                  ', '.join(['all'] + ZAPHelper.scanner_group_map.keys())))
@click.option('--recursive', '-r', is_flag=True, default=False, help='Make scan recursive.')
@click.pass_obj
def active_scan(zap_helper, url, scanners, recursive):
    """
    Run an Active Scan against a URL.

    The URL to be scanned must be in ZAP's site tree, i.e. it should have already
    been opened using the open-url command or found by running the spider command.
    """
    console.info('Running an active scan...')

    with zap_error_handler():
        if scanners:
            zap_helper.set_enabled_scanners(scanners)

        zap_helper.run_active_scan(url, recursive=recursive)


@cli.command('alerts')
@click.option('--alert-level', '-l', default='High', type=click.Choice(ZAPHelper.alert_levels.keys()),
              help='Minimum alert level to include in report (default: High).')
@click.option('--output-format', '-f', default='table', type=click.Choice(['table', 'json']),
              help='Output format to print the alerts.')
@click.option('--exit-code', default=True, type=bool,
              help='Whether to set the exit code to the number of alerts (default: True).')
@click.pass_obj
def show_alerts(zap_helper, alert_level, output_format, exit_code):
    """Show alerts at the given alert level."""
    alerts = zap_helper.alerts(alert_level)

    report_alerts(alerts, output_format)

    if exit_code:
        num_alerts = len(alerts)
        sys.exit(num_alerts)


@cli.command('quick-scan', short_help='Run a quick scan.')
@click.argument('url')
@click.option('--self-contained', '-sc', is_flag=True, default=False,
              help='Make the scan self-contained, i.e. start the daemon, open the URL, scan it, ' +
              'and shutdown the daemon when done.')
@click.option('--scanners', '-s', type=str, callback=validate_scanner_list,
              help='Comma separated list of scanner IDs and/or groups to use in the scan. Use the scanners ' +
              'subcommand to get a list of IDs. Available groups are: {0}.'.format(
                  ', '.join(['all'] + ZAPHelper.scanner_group_map.keys())))
@click.option('--spider', is_flag=True, default=False, help='If set, run the spider before running the scan.')
@click.option('--ajax-spider', is_flag=True, default=False, help='If set, run the AJAX Spider before running the scan.')
@click.option('--recursive', '-r', is_flag=True, default=False, help='Make scan recursive.')
@click.option('--alert-level', '-l', default='High', type=click.Choice(ZAPHelper.alert_levels.keys()),
              help='Minimum alert level to include in report.')
@click.option('--exclude', '-e', type=str, help='Regex to exclude from all aspects of the scan')
@click.option('--start-options', '-o', type=str,
              help='Extra options to pass to the ZAP start command when the --self-contained option is used, ' +
              ' e.g. "-config api.key=12345"')
@click.pass_obj
def quick_scan(zap_helper, url, **options):
    """
    Run a quick scan of a site by opening a URL, optionally spidering the URL,
    running an Active Scan, and reporting any issues found.

    This command contains most scan options as parameters, so you can do
    everything in one go.
    """
    if options['self_contained']:
        console.info('Starting ZAP daemon')
        with zap_error_handler():
            zap_helper.start(options['start_options'])

    console.info('Running a quick scan for {0}'.format(url))

    with zap_error_handler():
        if options['scanners']:
            zap_helper.set_enabled_scanners(options['scanners'])

        if options['exclude']:
            zap_helper.exclude_from_all(options['exclude'])

        zap_helper.open_url(url)

        if options['spider']:
            zap_helper.run_spider(url)

        if options['ajax_spider']:
            zap_helper.run_ajax_spider(url)

        zap_helper.run_active_scan(url, recursive=options['recursive'])

    alerts = zap_helper.alerts(options['alert_level'])

    num_alerts = len(alerts)

    report_alerts(alerts)

    if options['self_contained']:
        console.info('Shutting down ZAP daemon')
        with zap_error_handler():
            zap_helper.shutdown()

    sys.exit(num_alerts)


@cli.group(name='scanners', short_help='Enable, disable, or list a set of scanners.')
@click.pass_context
def scanner_group(ctx):
    """
    Get a list of scanners and whether or not they are enabled,
    or disable/enable scanners to use in the scan.
    """
    pass


@scanner_group.command('list')
@click.option('--scanners', '-s', type=str, callback=validate_scanner_list,
              help='Comma separated list of scanner IDs and/or groups to use in the scan. Use the scanners ' +
              'subcommand to get a list of IDs. Available groups are: {0}.'.format(
                  ', '.join(['all'] + ZAPHelper.scanner_group_map.keys())))
@click.pass_obj
def list_scanners(zap_helper, scanners):
    """Get a list of scanners and whether or not they are enabled."""
    scanner_list = zap_helper.zap.ascan.scanners()

    if scanners is not None and 'all' not in scanners:
        scanner_list = filter_by_ids(scanner_list, scanners)

    click.echo(tabulate([[s['id'], s['name'], s['policyId'], s['enabled'], s['attackStrength']]
                         for s in scanner_list],
                        headers=['ID', 'Name', 'Policy ID', 'Enabled', 'Strength'],
                        tablefmt='grid'))


@scanner_group.command('enable')
@click.option('--scanners', '-s', type=str, callback=validate_scanner_list,
              help='Comma separated list of scanner IDs and/or groups to use in the scan. Use the scanners ' +
              'subcommand to get a list of IDs. Available groups are: {0}.'.format(
                  ', '.join(['all'] + ZAPHelper.scanner_group_map.keys())))
@click.pass_obj
def enable_scanners(zap_helper, scanners):
    """Enable scanners to use in a scan."""
    scanners = scanners or ['all']
    zap_helper.enable_scanners(scanners)


@scanner_group.command('disable')
@click.option('--scanners', '-s', type=str, callback=validate_scanner_list,
              help='Comma separated list of scanner IDs and/or groups to use in the scan. Use the scanners ' +
              'subcommand to get a list of IDs. Available groups are: {0}.'.format(
                  ', '.join(['all'] + ZAPHelper.scanner_group_map.keys())))
@click.pass_obj
def disable_scanners(zap_helper, scanners):
    """Disable scanners so they are not used in a scan."""
    scanners = scanners or ['all']
    zap_helper.disable_scanners(scanners)


@cli.group(name='policies', short_help='Enable or list a set of policies.')
@click.pass_context
def policies_group(ctx):
    """
    Get a list of policies and whether or not they are enabled,
    or set the enabled policies to use in the scan.
    """
    pass


@policies_group.command('list')
@click.option('--policy-ids', '-p', type=str, callback=validate_ids,
              help='Comma separated list of policy IDs to list or enable ' +
              '(use policies without any to get a list of IDs).')
@click.pass_obj
def list_policies(zap_helper, policy_ids):
    """
    Get a list of policies and whether or not they are enabled.
    """
    policies = filter_by_ids(zap_helper.zap.ascan.policies(), policy_ids)

    click.echo(tabulate([[p['id'], p['name'], p['enabled'], p['attackStrength']]
                         for p in policies],
                        headers=['ID', 'Name', 'Enabled', 'Strength'],
                        tablefmt='grid'))


@policies_group.command('enable')
@click.option('--policy-ids', '-p', type=str, callback=validate_ids,
              help='Comma separated list of policy IDs to list or enable ' +
              '(use policies without any to get a list of IDs).')
@click.pass_obj
def enable_policies(zap_helper, policy_ids):
    """
    Set the enabled policies to use in a scan.

    When you enable a selection of policies, all other policies are
    disabled.
    """
    if not policy_ids:
        policies = zap_helper.zap.ascan.policies()
        policy_ids = [p['id'] for p in policies]

    zap_helper.enable_policies_by_ids(policy_ids)


@cli.command('exclude', short_help='Exclude a pattern from all scanners.')
@click.argument('pattern')
@click.pass_obj
def exclude_from_scanners(zap_helper, pattern):
    """Exclude a pattern from proxy, spider and active scanner."""
    with zap_error_handler():
        zap_helper.exclude_from_all(pattern)


def report_alerts(alerts, output_format='table'):
    """
    Print our alerts in the given format.
    """
    num_alerts = len(alerts)

    if output_format == 'json':
        click.echo(json.dumps(alerts, indent=4))
    else:
        console.info('Issues found: {0}'.format(num_alerts))
        if num_alerts > 0:
            click.echo(tabulate([[a['alert'], a['risk'], a['cweid'], a['url']] for a in alerts],
                                headers=['Alert', 'Risk', 'CWE ID', 'URL'], tablefmt='grid'))


def filter_by_ids(original_list, ids_to_filter):
    """Filter a list of dicts by IDs using an id key on each dict."""
    if not ids_to_filter:
        return original_list

    return [i for i in original_list if i['id'] in ids_to_filter]
