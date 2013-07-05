""" Module providing a single class (QualysConnectConfig) that parses a config
file and provides the information required to build QualysGuard sessions.
"""
import os
import stat
import sys
import getpass
import logging

from ConfigParser import *

import qualysapi.settings as qcs

__author__ = "Parag Baxi <parag.baxi@gmail.com> & Colin Bell <colin.bell@uwaterloo.ca>"
__copyright__ = "Copyright 2011-2013, Parag Baxi & University of Waterloo"
__license__ = "BSD-new"

class QualysConnectConfig:
    """ Class to create a ConfigParser and read user/password details
    from an ini file.
    """
    def __init__(self, filename=qcs.default_filename, remember_me=False, remember_me_always=False):

        self._cfgfile = None

        # Set home path for file.
        home_filename = os.path.join(os.getenv("HOME"),filename)
        # Check for file existence.
        if os.path.exists(filename):
            self._cfgfile = filename
        elif os.path.exists(home_filename):
            self._cfgfile = home_filename
        
        # create ConfigParser to combine defaults and input from config file.
        self._cfgparse = ConfigParser(qcs.defaults)

        if self._cfgfile:
            self._cfgfile = os.path.realpath(self._cfgfile)
            
            mode = stat.S_IMODE(os.stat(self._cfgfile)[stat.ST_MODE])
            
            # apply bitmask to current mode to check ONLY user access permissions.
            if (mode & ( stat.S_IRWXG | stat.S_IRWXO )) != 0:
                logging.warning("%s permissions allows more than user access."%(filename,))

            self._cfgparse.read(self._cfgfile)

        # if 'info' doesn't exist, create the section.
        if not self._cfgparse.has_section("info"):
            self._cfgparse.add_section("info")

        # use default hostname (if one isn't provided)
        if not self._cfgparse.has_option("info","hostname"):
            if self._cfgparse.has_option("DEFAULT","hostname"):
                hostname = self._cfgparse.get("DEFAULT","hostname")
                self._cfgparse.set('info', 'hostname', hostname)
            else:
                raise Exception("No 'hostname' set. QualysConnect does not know who to connect to.")
        
        # ask username (if one doesn't exist)
        if not self._cfgparse.has_option("info","username"):
            username = raw_input('QualysGuard Username: ')
            self._cfgparse.set('info', 'username', username)
        
        # ask password (if one doesn't exist)
        if not self._cfgparse.has_option("info", "password"):
            password = getpass.getpass('QualysGuard Password: ')
            self._cfgparse.set('info', 'password', password)
        
        logging.debug(self._cfgparse.items('info'))

        if remember_me or remember_me_always:
            # Let's create that config file for next time...
            # Where to store this?
            if remember_me:
                # Store in current working directory.
                config_path = filename
            if remember_me_always:
                # Store in home directory.
                config_path = home_filename
            if not os.path.exists(config_path):
                # Write file only if it doesn't already exists.
                # http://stackoverflow.com/questions/5624359/write-file-with-specific-permissions-in-python
                mode = stat.S_IRUSR | stat.S_IWUSR  # This is 0o600 in octal and 384 in decimal.
                umask_original = os.umask(0)
                try:
                    config_file = os.fdopen(os.open(config_path, os.O_WRONLY | os.O_CREAT, mode), 'w')
                finally:
                    os.umask(umask_original)
                # Add the settings to the structure of the file, and lets write it out...
                self._cfgparse.write(config_file)
                config_file.close()

            
    def get_config_filename(self):
        return self._cfgfile
    
    def get_config(self):
        return self._cfgparse
        
    def get_username(self):
        ''' Returns username from the configfile. '''
        return self._cfgparse.get("info", "username")
        
    def get_password(self):
        ''' Returns password from the configfile OR as provided. '''
        return self._cfgparse.get("info", "password")

    def get_hostname(self):
        ''' Returns username from the hostname. '''
        return self._cfgparse.get("info", "hostname")
