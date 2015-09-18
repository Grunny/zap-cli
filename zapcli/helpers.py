"""
Helper methods for use by the CLI.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

from contextlib import contextmanager
import json
import sys

import click
from tabulate import tabulate

from zapcli.exceptions import ZAPError
from zapcli.log import console


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
