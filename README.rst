ZAP CLI
=======

.. image:: https://travis-ci.org/Grunny/zap-cli.svg?branch=master
    :target: https://travis-ci.org/Grunny/zap-cli

A commandline tool that wraps the OWASP ZAP API for controlling ZAP and
executing quick, targeted attacks.

Installation
============

To install the latest release from PyPI, you can run the following command:

::

    pip install --upgrade zapcli

To install the latest development version of ZAP CLI, you can run the
following:

::

    pip install --upgrade git+https://github.com/Grunny/zap-cli.git

To install ZAP CLI for development, including the dependencies needed
in order to run unit tests, clone this repository and use
``pip install -e .[dev]``.

Usage
=====

To use ZAP CLI, you need to set the port ZAP runs on (defaults to 8090) and
the path to the folder in which ZAP is installed. These can be set either as
commandline parameters or with the environment variables ``ZAP_PORT`` and
``ZAP_PATH``. If you have an API key set for ZAP, this can likewise be set
either as a commandline parameter or with the ``ZAP_API_KEY`` environment
variable.

ZAP CLI can then be used with the following commands:

::

    Usage: zap-cli [OPTIONS] COMMAND [ARGS]...

      ZAP CLI - A simple commandline tool for OWASP ZAP.

    Options:
      --boring            Remove color from console output.
      -v, --verbose       Add more verbose debugging output.
      --zap-path TEXT     Path to the ZAP daemon. Defaults to /zap or the value of
                          the environment variable ZAP_PATH.
      -p, --port INTEGER  Port of the ZAP proxy. Defaults to 8090 or the value of
                          the environment variable ZAP_PORT.
      --zap-url TEXT      The URL of the ZAP proxy. Defaults to http://127.0.0.1
                          or the value of the environment variable ZAP_URL.
      --api-key TEXT      The API key for using the ZAP API if required. Defaults
                          to the value of the environment variable ZAP_API_KEY.
      --help              Show this message and exit.

    Commands:
      active-scan  Run an Active Scan.
      ajax-spider  Run the AJAX Spider against a URL.
      alerts       Show alerts at the given alert level.
      exclude      Exclude a pattern from all scanners.
      open-url     Open a URL using the ZAP proxy.
      policies     Enable or list a set of policies.
      quick-scan   Run a quick scan.
      scanners     Enable, disable, or list a set of scanners.
      session      Manage sessions.
      shutdown     Shutdown the ZAP daemon.
      spider       Run the spider against a URL.
      start        Start the ZAP daemon.

You can use ``--help`` with any of the subcommands to get information on how to use
them.

Getting started running a scan
------------------------------
In order to run a scan, you can use either the ``active-scan`` or the ``quick-scan``
command. The ``active-scan`` only runs an active scan against a URL that is already
in ZAP's site tree (i.e. has already been opened using the ``open-url`` command or
found by running the ``spider``). The ``quick-scan`` command is intended to be a way
to run quick scans of a site with most options contained within a single command
(including being able to start and shutdown ZAP before and after), so you can do
everything in one go. Without any other options passed to the command, ``quick-scan``
will open the URL to make sure it's in the site tree, run an active scan, and will
output any found alerts.

As an example, to run a quick scan of a URL that will open and spider the URL, scan
recursively, exclude URLs matching a given regex, and only use XSS and SQLi scanners,
you could run:

::

    $ zap-cli quick-scan -s xss,sqli --spider -r -e "some_regex_pattern" http://127.0.0.1/
    [INFO]            Running a quick scan for http://127.0.0.1/
    [INFO]            Issues found: 1
    +----------------------------------+--------+----------+---------------------------------------------------------------------------------+
    | Alert                            | Risk   |   CWE ID | URL                                                                             |
    +==================================+========+==========+=================================================================================+
    | Cross Site Scripting (Reflected) | High   |       79 | http://127.0.0.1/index.php?foo=%22%3E%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E |
    +----------------------------------+--------+----------+---------------------------------------------------------------------------------+

The above example is equivalent to running the following commands in order:

::

    $ zap-cli open-url http://127.0.0.1/
    [INFO]            Accessing URL http://127.0.0.1/
    $ zap-cli exclude "some_regex_pattern"
    $ zap-cli spider http://127.0.0.1/
    [INFO]            Running spider...
    $ zap-cli active-scan --scanners xss,sqli --recursive http://127.0.0.1/
    [INFO]            Running an active scan...
    $ zap-cli alerts
    [INFO]            Issues found: 1
    +----------------------------------+--------+----------+---------------------------------------------------------------------------------+
    | Alert                            | Risk   |   CWE ID | URL                                                                             |
    +==================================+========+==========+=================================================================================+
    | Cross Site Scripting (Reflected) | High   |       79 | http://127.0.0.1/index.php?foo=%22%3E%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E |
    +----------------------------------+--------+----------+---------------------------------------------------------------------------------+

The ``quick-scan`` command also has a ``--self-contained`` option (or ``-sc`` for short)
which will first try to start ZAP if it isn't running already and shutdown ZAP once the
scan is finished. For example:

::

    $ zap-cli quick-scan --self-contained --spider -r -s xss http://127.0.0.1/
    [INFO]            Starting ZAP daemon
    [INFO]            Running a quick scan for http://127.0.0.1/
    [INFO]            Issues found: 1
    +----------------------------------+--------+----------+---------------------------------------------------------------------------------+
    | Alert                            | Risk   |   CWE ID | URL                                                                             |
    +==================================+========+==========+=================================================================================+
    | Cross Site Scripting (Reflected) | High   |       79 | http://127.0.0.1/index.php?foo=%22%3E%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E |
    +----------------------------------+--------+----------+---------------------------------------------------------------------------------+
    [INFO]            Shutting down ZAP daemon

Extra start options
-------------------
You can also pass extra options to the start command of ZAP using ``--start-options`` or ``-o``
with commands that allow it. For example, to start ZAP with a custom API key you could use:

::

    $ zap-cli start --start-options '-config api.key=12345'

Or to run a self-contained quick scan (that will start ZAP and shut it down after the scan
is complete) with a custom API key, you could use:

::

    $ zap-cli --api-key 12345 quick-scan --self-contained -o '-config api.key=12345' -s xss http://127.0.0.1/

Or to run the same scan with the API key disabled:

::

    $ zap-cli quick-scan -sc -o '-config api.disablekey=true' -s xss http://127.0.0.1/
