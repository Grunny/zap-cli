"""
Group of commands to manage the sessions.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

import click

from zapcli.helpers import zap_error_handler


@click.group(name='session', short_help='Manage sessions.')
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
