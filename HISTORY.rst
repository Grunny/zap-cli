Release History
===============

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
