.PHONY: test coverage ci

SHELL=/bin/bash

test:
	py.test -x tests

coverage:
	rm -f .coverage*
	coverage run --source=zapcli -m pytest -x tests
	coverage report

ci:
	pep8 zapcli
	pylint -f text zapcli || [[ $$(($$? & 1)) == 0 && $$(($$? & 2)) == 0 ]]
	pylint -f text -r y zapcli | perl -ne 'if (/rated at ([0-9\.]+)\/10/ && $$1 < 9.8) { print $$_; exit 1; }'
	py.test -x --color=no tests
