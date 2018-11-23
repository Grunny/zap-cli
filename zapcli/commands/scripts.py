"""
Group of commands to manage scripts.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

import os

import click
from tabulate import tabulate

from zapcli.exceptions import ZAPError
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
        console.debug('Enabling script "{0}"'.format(script_name))
        result = zap_helper.zap.script.enable(script_name)

        if result != 'OK':
            raise ZAPError('Error enabling script: {0}'.format(result))

    console.info('Script "{0}" enabled'.format(script_name))


@scripts_group.command('disable')
@click.argument('script-name', metavar='"SCRIPT NAME"')
@click.pass_obj
def disable_script(zap_helper, script_name):
    """Disable a script."""
    with zap_error_handler():
        console.debug('Disabling script "{0}"'.format(script_name))
        result = zap_helper.zap.script.disable(script_name)

        if result != 'OK':
            raise ZAPError('Error disabling script: {0}'.format(result))

    console.info('Script "{0}" disabled'.format(script_name))


@scripts_group.command('remove')
@click.argument('script-name', metavar='"SCRIPT NAME"')
@click.pass_obj
def remove_script(zap_helper, script_name):
    """Remove a script."""
    with zap_error_handler():
        console.debug('Removing script "{0}"'.format(script_name))
        result = zap_helper.zap.script.remove(script_name)

        if result != 'OK':
            raise ZAPError('Error removing script: {0}'.format(result))

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
        if not os.path.isfile(options['file_path']):
            raise ZAPError('No file found at "{0}", cannot load script.'.format(options['file_path']))

        if not _is_valid_script_engine(zap_helper.zap, options['engine']):
            engines = zap_helper.zap.script.list_engines
            raise ZAPError('Invalid script engine provided. Valid engines are: {0}'.format(', '.join(engines)))

        console.debug('Loading script "{0}" from "{1}"'.format(options['name'], options['file_path']))
        result = zap_helper.zap.script.load(options['name'], options['script_type'], options['engine'],
                                            options['file_path'], scriptdescription=options['description'])

        if result != 'OK':
            raise ZAPError('Error loading script: {0}'.format(result))

    console.info('Script "{0}" loaded'.format(options['name']))


def _is_valid_script_engine(zap, engine):
    """Check if given script engine is valid."""
    engine_names = zap.script.list_engines
    short_names = [e.split(' : ')[1] for e in engine_names]

    return engine in engine_names or engine in short_names
