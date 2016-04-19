"""
ZAP CLI tool for targeted tests from the command line.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

import ast
import os
import re

from setuptools import setup


here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'zapcli', '__init__.py'), 'rb') as f:
    version = str(ast.literal_eval(re.search(
        r'__version__\s*=\s*(.*)', f.read().decode('utf-8')).group(1)))

with open('README.rst', 'r') as f:
    long_description = f.read()

setup(
    name='zapcli',
    version=version,
    description='A ZAP CLI tool for targeted tests from the command line.',
    long_description=long_description,
    url='https://github.com/Grunny/zap-cli',
    author='Daniel Grunwell (grunny)',
    author_email='mwgrunny@gmail.com',
    license='MIT',
    packages=[
        'zapcli',
    ],
    install_requires=[
        'click==4.0',
        'python-owasp-zap-v2.4==0.0.7',
        'tabulate==0.7.5',
        'termcolor==1.1.0',
    ],
    extras_require={
        'dev': [
            'coverage==3.7.1',
            'ddt==1.0.1',
            'mock==2.0.0',
            'pep8==1.6.2',
            'pylint==1.5.5',
            'pytest==2.9.1',
        ],
    },
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'zap-cli=zapcli.cli:cli',
        ],
    },
    test_suite='tests',
    classifiers=[
        'Topic :: Security',
        'Topic :: Software Development :: Quality Assurance',
        'Topic :: Software Development :: Testing',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
    ],
)
