#!/usr/bin/env python

import os
import sys
try:
      from setuptools import setup
except ImportError:
      from distutils.core import setup

__author__ = "Parag Baxi <parag.baxi@gmail.com>"
__copyright__ = "Copyright 2011-2013, Parag Baxi"
__license__ = "BSD-new"

# A utility function to read the README file into the long_description field.
def read(fname):
    """ Takes a filename and returns the contents of said file relative to
    the current directory.
    """
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

# A utility function that to get version number from package source tree.
def get_package_version():
    """ Adds current directory and src/ to sys.path.  imports qualysconnect
    to get __version__ and returns it.
    """
    save_path = list(sys.path)
    sys.path.insert(0, os.path.join(os.path.dirname(__file__),"src"))
    # Get the version string from the module itself.
    from qualysapi import __version__ as VERSION
    # Reset the path to pre-import.
    sys.path = save_path
    return VERSION

setup(name='QualysAPI',
      version=get_package_version(),
      author='Parag Baxi',
      author_email='parag.baxi@gmail.com',
      description='QualysGuard(R) QualysAPI Package',
      license = "BSD-new",
      keywords = "Qualys QualysGuard API helper network security",
      url='https://github.com/paragbaxi/qualysapi',
      package_dir={'': '.'},
      packages=['qualysapi',],
      package_data={'qualysapi':['LICENSE']},
      # scripts=['src/scripts/qhostinfo.py', 'src/scripts/qscanhist.py', 'src/scripts/qreports.py'],
      long_description=read('README.md'),
      classifiers=[
          "Development Status :: 4 - Beta",
          "Topic :: Utilities",
          "License :: OSI Approved :: BSD License"
      ],
      install_requires=[
          'lxml',
          'requests'
      ],
     )
