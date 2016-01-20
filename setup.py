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
exec(compile(open('qualysapi/version.py').read(), 'qualysapi/version.py', 'exec'))

# A utility function to read the README file into the long_description field.
def read(fname):
    """ Takes a filename and returns the contents of said file relative to
    the current directory.
    """
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


class Sphinx(Command):
    user_options = []
    description = 'sphinx'

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        # metadata contains information supplied in setup()
        metadata = self.distribution.metadata
        # package_dir may be None, in that case use the current directory.
        src_dir = (self.distribution.package_dir or {'': ''})['']
        src_dir = os.path.join(os.getcwd(),  src_dir)
        # Run sphinx by calling the main method, '--full' also adds a conf.py
        sphinx.apidoc.main(
            ['', '--full', '-H', metadata.name, '-A', metadata.author,
             '-V', metadata.version, '-R', metadata.version,
             '-o', os.path.join('doc', 'source'), src_dir])
        # build the doc sources
        sphinx.main(['', os.path.join('doc', 'source'),
                     os.path.join('doc', 'build')])


setup(name=__pkgname__,
    version=__version__,
    author='Parag Baxi',
    author_email='parag.baxi@gmail.com',
    description='QualysGuard(R) Qualys API Package',
    license ='BSD-new',
    keywords ='Qualys QualysGuard API helper network security',
    url='https://github.com/paragbaxi/qualysapi',
    package_dir={'': '.'},
    packages=['qualysapi', 'qualysapi.qcache'],
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
      'redis',
    ],
    test_suite='nose2.collector.collector',
#    setup_requires = ['sphinx'],
#    entry_points = {
#        'distutils.commands': [
#            'sphinx = example_module:Sphinx'
#        ]
#    }
)
