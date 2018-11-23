"""
Group of commands to manage the contexts for the current session.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

import click

from zapcli.exceptions import ZAPError
from zapcli.helpers import validate_regex, zap_error_handler
from zapcli.log import console


@click.group(name='context', short_help='Manage contexts for the current session.')
@click.pass_context
def context_group(ctx):
    """Group of commands to manage the contexts for the current session."""
    pass


@context_group.command('list')
@click.pass_obj
def context_list(zap_helper):
    """List the available contexts."""
    contexts = zap_helper.zap.context.context_list
    if len(contexts):
        console.info('Available contexts: {0}'.format(contexts[1:-1]))
    else:
        console.info('No contexts available in the current session')


@context_group.command('new')
@click.argument('name')
@click.pass_obj
def context_new(zap_helper, name):
    """Create a new context."""
    console.info('Creating context with name: {0}'.format(name))
    res = zap_helper.zap.context.new_context(contextname=name)
    console.info('Context "{0}" created with ID: {1}'.format(name, res))


@context_group.command('include')
@click.option('--name', '-n', type=str, required=True,
              help='Name of the context.')
@click.option('--pattern', '-p', type=str, callback=validate_regex,
              help='Regex to include.')
@click.pass_obj
def context_include(zap_helper, name, pattern):
    """Include a pattern in a given context."""
    console.info('Including regex {0} in context with name: {1}'.format(pattern, name))
    with zap_error_handler():
        result = zap_helper.zap.context.include_in_context(contextname=name, regex=pattern)

        if result != 'OK':
            raise ZAPError('Including regex from context failed: {}'.format(result))


@context_group.command('exclude')
@click.option('--name', '-n', type=str, required=True,
              help='Name of the context.')
@click.option('--pattern', '-p', type=str, callback=validate_regex,
              help='Regex to exclude.')
@click.pass_obj
def context_exclude(zap_helper, name, pattern):
    """Exclude a pattern from a given context."""
    console.info('Excluding regex {0} from context with name: {1}'.format(pattern, name))
    with zap_error_handler():
        result = zap_helper.zap.context.exclude_from_context(contextname=name, regex=pattern)

        if result != 'OK':
            raise ZAPError('Excluding regex from context failed: {}'.format(result))


@context_group.command('info')
@click.argument('context-name')
@click.pass_obj
def context_info(zap_helper, context_name):
    """Get info about the given context."""
    with zap_error_handler():
        info = zap_helper.get_context_info(context_name)

    console.info('ID: {}'.format(info['id']))
    console.info('Name: {}'.format(info['name']))
    console.info('Authentication type: {}'.format(info['authType']))
    console.info('Included regexes: {}'.format(info['includeRegexs']))
    console.info('Excluded regexes: {}'.format(info['excludeRegexs']))


@context_group.command('users')
@click.argument('context-name')
@click.pass_obj
def context_list_users(zap_helper, context_name):
    """List the users available for a given context."""
    with zap_error_handler():
        info = zap_helper.get_context_info(context_name)

    users = zap_helper.zap.users.users_list(info['id'])
    if len(users):
        user_list = ', '.join([user['name'] for user in users])
        console.info('Available users for the context {0}: {1}'.format(context_name, user_list))
    else:
        console.info('No users configured for the context {}'.format(context_name))


@context_group.command('import')
@click.argument('file-path')
@click.pass_obj
def context_import(zap_helper, file_path):
    """Import a saved context file."""
    with zap_error_handler():
        result = zap_helper.zap.context.import_context(file_path)

        if not result.isdigit():
            raise ZAPError('Importing context from file failed: {}'.format(result))

    console.info('Imported context from {}'.format(file_path))


@context_group.command('export')
@click.option('--name', '-n', type=str, required=True,
              help='Name of the context.')
@click.option('--file-path', '-f', type=str,
              help='Output file to export the context.')
@click.pass_obj
def context_export(zap_helper, name, file_path):
    """Export a given context to a file."""
    with zap_error_handler():
        result = zap_helper.zap.context.export_context(name, file_path)

        if result != 'OK':
            raise ZAPError('Exporting context to file failed: {}'.format(result))

    console.info('Exported context {0} to {1}'.format(name, file_path))
