"""
Logger classes for the ZAP CLI.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

import logging
import sys

from termcolor import colored


class ColorStreamHandler(logging.StreamHandler):
    """
    StreamHandler that prints color. This is used by the console client.
    """

    level_map = {
        logging.DEBUG: ('magenta', ['bold']),
        logging.INFO: ('cyan', ['bold']),
        logging.WARNING: ('yellow', ['bold']),
        logging.ERROR: ('red', ['bold']),
        logging.CRITICAL: ('red', ['bold', 'reverse'])
    }

    @property
    def is_tty(self):
        """is the stream a tty?"""
        isatty = getattr(self.stream, 'isatty', None)
        return isatty and isatty()

    def emit(self, record):
        colorize = 'console' in globals() and getattr(console, 'colorize', False)

        if self.is_tty and colorize:
            color, attr = self.level_map[record.levelno]
            prefix = colored(str('[' + record.levelname + ']').ljust(18), color, attrs=attr)
            if hasattr(record, 'highlight') and record.highlight:
                record.msg = colored(record.msg, color, attrs=['bold', 'reverse'])
        else:
            prefix = str('[' + record.levelname + ']').ljust(18)

        record.msg = prefix + record.msg

        logging.StreamHandler.emit(self, record)


class ConsoleLogger(logging.Logger):
    """Log to the console with some color decorations."""
    def __init__(self, name):
        super(ConsoleLogger, self).__init__(name)
        self.setLevel(logging.DEBUG)
        self.addHandler(ColorStreamHandler(sys.stdout))

# Save the current logger
default_logger_class = logging.getLoggerClass()

# Console logging for CLI
logging.setLoggerClass(ConsoleLogger)
console = logging.getLogger('zap')

# Restore the previous logger
logging.setLoggerClass(default_logger_class)
