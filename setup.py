#!/usr/bin/env python

import os
import sys
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

__author__ = 'Parag Baxi <parag.baxi@gmail.com>'
__copyright__ = 'Copyright 2011-2013, Parag Baxi'
__license__ = 'BSD-new'
# Make pyflakes happy.
__pkgname__ = None
__version__ = None
execfile('qualysapi/version.py')

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
      description='QualysGuard(R) Qualys API Package',
      license="Apache License (2.0)",
      keywords ='Qualys QualysGuard API helper network security',
      url='https://github.com/paragbaxi/qualysapi',
      package_dir={'': '.'},
      packages=['qualysapi',],
      # package_data={'qualysapi':['LICENSE']},
      # scripts=['src/scripts/qhostinfo.py', 'src/scripts/qscanhist.py', 'src/scripts/qreports.py'],
      long_description=read('README.md'),
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Topic :: Utilities',
          'License :: OSI Approved :: Apache Software License',
          'Intended Audience :: Developers',
      ],
      install_requires=[
          'requests',
      ],
     )
