#!/usr/bin/env python
import sys

from pkg_resources import VersionConflict, require
from setuptools import setup

SETUPTOOLS_VER = "30.5.0"  # Minimum version that supports pyproject.toml

try:
    require("setuptools>=" + SETUPTOOLS_VER)
except VersionConflict:
    sys.exit(f"Error: version of setuptools is too old (<{SETUPTOOLS_VER})!")

__author__ = 'Parag Baxi <parag.baxi@gmail.com>'
__copyright__ = 'Copyright 2011-2018, Parag Baxi'
__license__ = 'BSD-new'
# Make pyflakes happy.
__pkgname__ = None
__version__ = None

exec(compile(open('qualysapi/version.py').read(), 'qualysapi/version.py', 'exec'))

REQUIREMENTS = [
    "requests",
    "lxml",
    "future-fstrings",
]

setup(name=__pkgname__,
      version=__version__,
      author='Parag Baxi',
      author_email='parag.baxi@gmail.com',
      description='Qualys API Package',
      license='BSD-new',
      keywords='Qualys API helper network security',
      url='https://github.com/paragbaxi/qualysapi',
      package_dir={'': '.'},
      packages=['qualysapi', ],
      # package_data={'qualysapi':['LICENSE']},
      # scripts=['src/scripts/qhostinfo.py', 'src/scripts/qscanhist.py', 'src/scripts/qreports.py'],
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Topic :: Utilities',
          'License :: OSI Approved :: Apache Software License',
          'Intended Audience :: Developers',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
    ],
    install_requires=REQUIREMENTS,
)
