#!/usr/bin/env python

from setuptools import setup, find_packages
from os.path import abspath, dirname, join

version_file = join(dirname(abspath(__file__)), 'src', 'NcclientLibrary', 'version.py')

with open(version_file) as file:
    code = compile(file.read(), version_file, 'exec')
    exec(code)

DESCRIPTION = """
Robot Framework keyword library wrapper NETCONF client.
"""[1:-1]


CLASSIFIERS = """
Development Status :: 5 - Production/Stable
License :: Public Domain
Operating System :: OS Independent
Programming Language :: Python
Topic :: Software Development :: Testing
"""[1:-1]

setup(
    name         = 'robotframework-ncclient2',
    version      = VERSION,
    description  = 'High quality, well-documented successor to unmaintained robotframework-ncclient',
    long_description = DESCRIPTION,
    author       = 'Scott Carrion',
    author_email = 'scott.carrion@icloud.com',
    url          = 'https://github.com/scott-carrion/robotframework-ncclient2',
    license      = 'Public Domain',
    keywords     = 'robotframework test automation NETCONF client',
    platforms    = 'any',
    classifiers  = CLASSIFIERS.splitlines(),
    package_dir  = {'' : 'src'},
    packages     = ['NcclientLibrary'],
    package_data = {'NcclientLibrary': ['tests/*.robot']},
    install_requires=[
      'robotframework',
      'ncclient'
    ],
)
