#!/usr/bin/env python
import sys
from pathlib import Path

from pkg_resources import VersionConflict, require
from setuptools import setup


SETUPTOOLS_VER = "30.5.0"  # Minimum version that supports pyproject.toml

try:
    require(f"setuptools>={SETUPTOOLS_VER}")
except VersionConflict:
    sys.exit(f"Error: version of setuptools is too old (<{SETUPTOOLS_VER})!")

__author__ = "Parag Baxi <parag.baxi@gmail.com>"
__copyright__ = "Copyright 2011-2018, Parag Baxi"
__license__ = "BSD-new"
# Make pyflakes happy.
__pkgname__ = None
__version__ = None

exec(Path("qualysapi/version.py").read_text())

setup(
    name=__pkgname__, version=__version__, license=__license__,
)
