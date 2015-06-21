"""
Custom exception classes for the ZAP CLI.

.. moduleauthor:: Daniel Grunwell (grunny)
"""


class ZAPError(Exception):
    """
    Generic exception for ZAP CLI.
    """

    def __init__(self, message, extra=None):
        super(ZAPError, self).__init__(message)
        self.extra = extra
