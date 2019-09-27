# -*- coding: future_fstrings -*-
#!/usr/bin/env python
from __future__ import absolute_import
import os
import setuptools

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from setuptools import setup

# read the contents of your README file
from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

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
    "pathlib2 ; python_version == '2.7'",
]


# A utility function to read the README file into the long_description field.
def read(fname):
    """ Takes a filename and returns the contents of said file relative to
    the current directory.
    """
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


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
      long_description=long_description,
      long_description_content_type='text/markdown',
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Topic :: Utilities',
          'License :: OSI Approved :: Apache Software License',
          'Intended Audience :: Developers',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
    ],
    install_requires=REQUIREMENTS,
)
