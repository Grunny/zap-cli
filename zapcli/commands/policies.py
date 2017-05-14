"""
Group of commands to manage active scan policies.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

import click
from tabulate import tabulate

from zapcli.helpers import filter_by_ids, validate_ids


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
