"""
Group of commands to manage scripts.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

import click
from tabulate import tabulate

from zapcli.helpers import zap_error_handler
from zapcli.log import console


@click.group(name='scripts', short_help='Manage scripts.')
@click.pass_context
def scripts_group(ctx):
    """
    Get a list of scripts and whether or not they are enabled,
    load and remove scripts, or disable/enable scripts to use.
    """
    pass


@scripts_group.command('list')
@click.pass_obj
def list_scripts(zap_helper):
    """List scripts currently loaded into ZAP."""
    scripts = zap_helper.zap.script.list_scripts
    output = []
    for s in scripts:
        if 'enabled' not in s:
            s['enabled'] = 'N/A'

        output.append([s['name'], s['type'], s['engine'], s['enabled']])

    click.echo(tabulate(output, headers=['Name', 'Type', 'Engine', 'Enabled'], tablefmt='grid'))


@scripts_group.command('list-engines')
@click.pass_obj
def list_engines(zap_helper):
    """List engines that can be used to run scripts."""
    engines = zap_helper.zap.script.list_engines
    console.info('Available engines: {}'.format(', '.join(engines)))


@scripts_group.command('enable')
@click.argument('script-name', metavar='"SCRIPT NAME"')
@click.pass_obj
def enable_script(zap_helper, script_name):
    """Enable a script."""
    with zap_error_handler():
        zap_helper.enable_script(script_name)

    console.info('Script "{0}" enabled'.format(script_name))


@scripts_group.command('disable')
@click.argument('script-name', metavar='"SCRIPT NAME"')
@click.pass_obj
def disable_script(zap_helper, script_name):
    """Disable a script."""
    with zap_error_handler():
        zap_helper.disable_script(script_name)

    console.info('Script "{0}" disabled'.format(script_name))


@scripts_group.command('remove')
@click.argument('script-name', metavar='"SCRIPT NAME"')
@click.pass_obj
def remove_script(zap_helper, script_name):
    """Remove a script."""
    with zap_error_handler():
        zap_helper.remove_script(script_name)

    console.info('Script "{0}" removed'.format(script_name))


@scripts_group.command('load')
@click.option('--name', '-n', prompt=True, help='Name of the script')
@click.option('--script-type', '-t', prompt=True, help='Type of script')
@click.option('--engine', '-e', prompt=True, help='Engine the script should use')
@click.option('--file-path', '-f', prompt=True, help='Path to the script file (i.e. /home/user/script.js)')
@click.option('--description', '-d', default='', help='Optional description for the script')
@click.pass_obj
def load_script(zap_helper, **options):
    """Load a script from a file."""
    with zap_error_handler():
        zap_helper.load_script(**options)

    console.info('Script "{0}" loaded'.format(options['name']))
