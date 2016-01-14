''' Module to hold global settings reused throughout qualysapi. '''

__author__ = "Colin Bell <colin.bell@uwaterloo.ca>"
__copyright__ = "Copyright 2011-2013, University of Waterloo"
__license__ = "BSD-new"

global defaults
global default_filename

import os

if os.name == 'nt':
    default_filename = "config.ini"
else:
    default_filename = ".qcrc"

defaults =  {
    'hostname'           : 'qualysapi.qualys.com',
    'max_retries'        : '3',
    'filename'           : default_filename,
    'cfg_file'           : default_filename,
    'remember_me'        : False,
    'remember_me_always' : False,
    'use_ini'            : False,
    'map_template'       : 'Unknown Device Report',
}
