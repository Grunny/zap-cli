"""
Group of commands to manage active scan policies.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

import click
from tabulate import tabulate

from zapcli.helpers import filter_by_ids, validate_ids, zap_error_handler
from zapcli.log import console


@click.group(name='policies', short_help='Enable or list a set of policies.')
@click.pass_context
def policies_group(ctx):
    """
    Get a list of policies and whether or not they are enabled,
    or set the enabled policies to use in the scan.
    """
    pass


@policies_group.command('list')
@click.option('--policy-ids', '-p', type=str, callback=validate_ids,
              help='Comma separated list of policy IDs to list ' +
              '(by default the list command will output all policies).')
@click.pass_obj
def list_policies(zap_helper, policy_ids):
    """
    Get a list of policies and whether or not they are enabled.
    """
    policies = filter_by_ids(zap_helper.zap.ascan.policies(), policy_ids)

    click.echo(tabulate([[p['id'], p['name'], p['enabled'], p['attackStrength'], p['alertThreshold']]
                         for p in policies],
                        headers=['ID', 'Name', 'Enabled', 'Strength', 'Threshold'],
                        tablefmt='grid'))


@policies_group.command('enable')
@click.option('--policy-ids', '-p', type=str, callback=validate_ids,
              help='Comma separated list of policy IDs to enable ' +
              '(by default the enable command will enable all policies).')
@click.pass_obj
def enable_policies(zap_helper, policy_ids):
    """
    Set the enabled policies to use in a scan.

    When you enable a selection of policies, all other policies are
    disabled.
    """
    if not policy_ids:
        policy_ids = _get_all_policy_ids(zap_helper)

    with zap_error_handler():
        zap_helper.enable_policies_by_ids(policy_ids)


@policies_group.command('set-strength')
@click.option('--policy-ids', '-p', type=str, callback=validate_ids,
              help='Comma separated list of policy IDs for which to set the strength.')
@click.option('--strength', '-s', default='Default',
              type=click.Choice(['Default', 'Low', 'Medium', 'High', 'Insane']),
              help='Attack strength to apply to the given policies.')
@click.pass_obj
def set_policy_strength(zap_helper, policy_ids, strength):
    """Set the attack strength for policies."""
    if not policy_ids:
        policy_ids = _get_all_policy_ids(zap_helper)

    with zap_error_handler():
        zap_helper.set_policy_attack_strength(policy_ids, strength)

    console.info('Set attack strength to {0}.'.format(strength))


@policies_group.command('set-threshold')
@click.option('--policy-ids', '-p', type=str, callback=validate_ids,
              help='Comma separated list of policy IDs for which to set the threshold.')
@click.option('--threshold', '-t', default='Default',
              type=click.Choice(['Default', 'Off', 'Low', 'Medium', 'High']),
              help='Alert threshold to apply to the given policies.')
@click.pass_obj
def set_policy_threshold(zap_helper, policy_ids, threshold):
    """Set the alert threshold for policies."""
    if not policy_ids:
        policy_ids = _get_all_policy_ids(zap_helper)

    with zap_error_handler():
        zap_helper.set_policy_alert_threshold(policy_ids, threshold)

    console.info('Set alert threshold to {0}.'.format(threshold))


def _get_all_policy_ids(zap_helper):
    """Get all policy IDs."""
    policies = zap_helper.zap.ascan.policies()
    return [p['id'] for p in policies]
