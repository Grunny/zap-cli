Release History
===============

v0.10.0 (2018-12-31)
--------------------
* Change exit codes for alerts and quick-scan commands (#29)
* Add ability to change the directory used for the log file (#62)
* Add support for outputting markdown reports
* Add ability to set the strength and threshold for policies and scanners
* Upgrade python-owasp-zap-v2.4 dependency to 0.0.14

v0.9.0 (2017-11-01)
-------------------
* Add commands to manage contexts as well as options to run the spider,
  active scan, and quick scan while authenticated as a user. (#7)

v0.8.1 (2017-07-20)
-------------------
* Upgrade python-owasp-zap-v2.4 dependency to 0.0.11

v0.8.0 (2017-07-11)
-------------------
* Fix support for unicode characters in reports
* Add JSON output format to quick-scan

v0.7.0 (2017-05-14)
-------------------
* Update zap-cli to support Python 3.5

v0.6.0 (2017-03-29)
-------------------
* Update zap-cli to support ZAP 2.6.0

v0.5.0 (2017-03-27)
-------------------
* Add commands for managing scripts

v0.4.0 (2016-10-09)
-------------------
* Add a report command to save a HTML or XML report

v0.3.0 (2016-08-28)
-------------------
* Add a status command to check if ZAP is running (#14)
* Raise an error when the ZAP executable is not found (#11)
* Upgrade python-owasp-zap-v2.4 dependency to 0.0.8

v0.2.1 (2016-05-09)
-------------------
* Handle errors when running the Spider (#9)
* Make ZAP path default to /zap if neither the environment variable nor the
  parameter are set

v0.2.0 (2016-02-21)
-------------------
* Add support for running AJAX Spider both on its own and as part of a
  quick scan.
* Add documentation to clarify the difference between active-scan and
  quick-scan, and add a few more examples of how they can work.
* Better active-scan error handling when a URL is not found in the site tree.
* Upgrade python-owasp-zap-v2.4 dependency to 0.0.7

v0.1.1 (2015-10-14)
-------------------
* Upgrade python-owasp-zap-v2.4 dependency to 0.0.5

v0.1.0 (2015-10-14)
-------------------
* Initial release of zap-cli for PyPI
