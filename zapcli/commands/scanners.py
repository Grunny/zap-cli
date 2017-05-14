"""
Group of commands to manage active scanners.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

import click
from tabulate import tabulate

from zapcli.helpers import filter_by_ids, validate_scanner_list
from zapcli.zap_helper import ZAPHelper


@click.group(name='scanners', short_help='Enable, disable, or list a set of scanners.')
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
                  ', '.join(['all'] + list(ZAPHelper.scanner_group_map.keys()))))
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
                  ', '.join(['all'] + list(ZAPHelper.scanner_group_map.keys()))))
@click.pass_obj
def enable_scanners(zap_helper, scanners):
    """Enable scanners to use in a scan."""
    scanners = scanners or ['all']
    zap_helper.enable_scanners(scanners)


@scanner_group.command('disable')
@click.option('--scanners', '-s', type=str, callback=validate_scanner_list,
              help='Comma separated list of scanner IDs and/or groups to use in the scan. Use the scanners ' +
              'subcommand to get a list of IDs. Available groups are: {0}.'.format(
                  ', '.join(['all'] + list(ZAPHelper.scanner_group_map.keys()))))
@click.pass_obj
def disable_scanners(zap_helper, scanners):
    """Disable scanners so they are not used in a scan."""
    scanners = scanners or ['all']
    zap_helper.disable_scanners(scanners)
