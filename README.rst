ZAP CLI
=======

A commandline tool that wraps the OWASP ZAP API for controlling ZAP and
executing quick, targeted attacks.

Installation
============

To install ZAP CLI while it's under development, clone this repository
and then run ``pip install -e .``. To include the development
dependencies in order to run unit tests, use ``pip install -e .[dev]``.

Usage
=====

To use ZAP CLI, you need to set the port ZAP runs on (defaults to 8090) and
the path to the folder in which ZAP is installed. These can be set either as
commandline parameters or with the environment variables ``ZAP_PORT`` and
``ZAP_PATH``.

ZAP CLI can then be used with the following commands:

::

    Usage: zap-cli [OPTIONS] COMMAND [ARGS]...

      ZAP CLI.

    Options:
      --boring            Remove color from console output.
      -v, --verbose       Add more verbose debugging output.
      --zap-path TEXT     Path to the ZAP daemon. Defaults to the value of the
                          environment variable ZAP_PATH.
      -p, --port INTEGER  Port of the ZAP proxy. Defaults to 8090 or the value of
                          the environment variable ZAP_PORT.
      --zap-url TEXT      The URL of the ZAP proxy. Defaults to http://127.0.0.1
                          or the value of the environment variable ZAP_URL.
      --api-key TEXT      The API key for using the ZAP API if required. Defaults
                          to the value of the environment variable ZAP_API_KEY.
      --help              Show this message and exit.

    Commands:
      active-scan   Run an Active Scan.
      alerts        Show alerts at the given alert level.
      exclude       Exclude a pattern from all scanners.
      load-session  Load a given session.
      new-session   Start a new session.
      open-url      Open a URL using the ZAP proxy.
      policies      Get a list of policies and whether or not...
      quick-scan    Run a quick scan.
      save-session  Save the session.
      scanners      Get a list of scanners and whether or not...
      shutdown      Shutdown the ZAP daemon.
      spider        Run the spider against a URL.
      start         Start the ZAP daemon.

You can use ``--help`` with any of the subcommands to get information on how to use
them.

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
