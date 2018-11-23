"""
Group of commands to manage the sessions.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

import os

import click

from zapcli.exceptions import ZAPError
from zapcli.helpers import zap_error_handler
from zapcli.log import console


@click.group(name='session', short_help='Manage sessions.')
@click.pass_context
def session_group(ctx):
    """Manage sessions."""
    pass


@session_group.command('new')
@click.pass_obj
def new_session(zap_helper):
    """Start a new session."""
    console.debug('Starting a new session')
    zap_helper.zap.core.new_session()


@session_group.command('save')
@click.argument('file-path')
@click.pass_obj
def save_session(zap_helper, file_path):
    """Save the session."""
    console.debug('Saving the session to "{0}"'.format(file_path))
    zap_helper.zap.core.save_session(file_path, overwrite='true')


@session_group.command('load')
@click.argument('file-path')
@click.pass_obj
def load_session(zap_helper, file_path):
    """Load a given session."""
    with zap_error_handler():
        if not os.path.isfile(file_path):
            raise ZAPError('No file found at "{0}", cannot load session.'.format(file_path))
        console.debug('Loading session from "{0}"'.format(file_path))
        zap_helper.zap.core.load_session(file_path)
