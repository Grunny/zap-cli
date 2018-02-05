"""
Group of commands to manage active scanners.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

import click
from tabulate import tabulate

from zapcli.helpers import filter_by_ids, validate_scanner_list, zap_error_handler
from zapcli.zap_helper import ZAPHelper
from zapcli.log import console


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
              help='Comma separated list of scanner IDs and/or groups to list (by default the list ' +
              'command will output all scanners). Available groups are: {0}.'.format(
                  ', '.join(['all'] + list(ZAPHelper.scanner_group_map.keys()))))
@click.pass_obj
def list_scanners(zap_helper, scanners):
    """Get a list of scanners and whether or not they are enabled."""
    scanner_list = zap_helper.zap.ascan.scanners()

    if scanners is not None and 'all' not in scanners:
        scanner_list = filter_by_ids(scanner_list, scanners)

    click.echo(tabulate([[s['id'], s['name'], s['policyId'], s['enabled'], s['attackStrength'], s['alertThreshold']]
                         for s in scanner_list],
                        headers=['ID', 'Name', 'Policy ID', 'Enabled', 'Strength', 'Threshold'],
                        tablefmt='grid'))


@scanner_group.command('enable')
@click.option('--scanners', '-s', type=str, callback=validate_scanner_list,
              help='Comma separated list of scanner IDs and/or groups to enable. Available groups are: {0}.'.format(
                  ', '.join(['all'] + list(ZAPHelper.scanner_group_map.keys()))))
@click.pass_obj
def enable_scanners(zap_helper, scanners):
    """Enable scanners to use in a scan."""
    scanners = scanners or ['all']
    zap_helper.enable_scanners(scanners)


@scanner_group.command('disable')
@click.option('--scanners', '-s', type=str, callback=validate_scanner_list,
              help='Comma separated list of scanner IDs and/or groups to disable. Available groups are: {0}.'.format(
                  ', '.join(['all'] + list(ZAPHelper.scanner_group_map.keys()))))
@click.pass_obj
def disable_scanners(zap_helper, scanners):
    """Disable scanners so they are not used in a scan."""
    scanners = scanners or ['all']
    zap_helper.disable_scanners(scanners)


@scanner_group.command('set-strength')
@click.option('--scanners', type=str, callback=validate_scanner_list,
              help='Comma separated list of scanner IDs and/or groups for which to set the strength. Available ' +
              'groups are: {0}.'.format(', '.join(['all'] + list(ZAPHelper.scanner_group_map.keys()))))
@click.option('--strength', default='Default',
              type=click.Choice(['Default', 'Low', 'Medium', 'High', 'Insane']),
              help='Attack strength to apply to the given policies.')
@click.pass_obj
def set_scanner_strength(zap_helper, scanners, strength):
    """Set the attack strength for scanners."""
    if not scanners or 'all' in scanners:
        scanners = _get_all_scanner_ids(zap_helper)

    with zap_error_handler():
        zap_helper.set_scanner_attack_strength(scanners, strength)

    console.info('Set attack strength to {0}.'.format(strength))


@scanner_group.command('set-threshold')
@click.option('--scanners', '-s', type=str, callback=validate_scanner_list,
              help='Comma separated list of scanner IDs and/or groups for which to set the threshold. Available ' +
              'groups are: {0}.'.format(', '.join(['all'] + list(ZAPHelper.scanner_group_map.keys()))))
@click.option('--threshold', '-t', default='Default',
              type=click.Choice(['Default', 'Off', 'Low', 'Medium', 'High']),
              help='Alert threshold to apply to the given policies.')
@click.pass_obj
def set_scanner_threshold(zap_helper, scanners, threshold):
    """Set the alert threshold for scanners."""
    if not scanners or 'all' in scanners:
        scanners = _get_all_scanner_ids(zap_helper)

    with zap_error_handler():
        zap_helper.set_scanner_alert_threshold(scanners, threshold)

    console.info('Set alert threshold to {0}.'.format(threshold))


def _get_all_scanner_ids(zap_helper):
    """Get all scanner IDs."""
    scanners = zap_helper.zap.ascan.scanners()
    return [s['id'] for s in scanners]
