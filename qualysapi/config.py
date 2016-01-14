""" Module providing a single class (QualysConnectConfig) that parses a config
file and provides the information required to build QualysGuard sessions.
"""
import os
import stat
import getpass
import logging
import pprint

logging.basicConfig()

# Setup module level logging.
logger = logging.getLogger(__name__)

from configparser import *
# try:
#    from requests_ntlm import HttpNtlmAuth
#except ImportError, e:
#    logger.warning('Warning: Cannot support NTML authentication.')

import qualysapi.settings as qcs

__author__ = "Parag Baxi <parag.baxi@gmail.com> & Colin Bell <colin.bell@uwaterloo.ca>"
__copyright__ = "Copyright 2011-2013, Parag Baxi & University of Waterloo"
__license__ = "BSD-new"


class QualysConnectConfig:
    """ Class to create a ConfigParser and read user/password details
    from an ini file.
    """

    def __init__(self, *args, **kwargs):

        #handle kwarg defaults (don't think I can zip because of overwrite)
        settings = qcs.defaults
        settings.update(kwargs)
        logging.debug(pprint.pformat(kwargs))
        self._cfgfile = None

        #this needs to only be done in ***SOME*** cases.  UGH yuck no no no
        if(settings['use_ini']):
            # Prioritize local directory filename.
            # Check for file existence.
            if os.path.exists(settings['filename']):
                self._cfgfile = settings['filename']
            elif os.path.exists(os.path.join(os.path.expanduser("~"),
                settings['filename'])):
                # Set home path for file.
                self._cfgfile = os.path.join(os.path.expanduser("~"),
                        settings['filename'])
        else:
            self._cfgfile = None #better... but not happy...

        # create ConfigParser to combine defaults and input from config file.
        self._cfgparse = ConfigParser(qcs.defaults)
        logging.debug(pprint.pformat(self._cfgparse.sections()))

        if self._cfgfile:
            self._cfgfile = os.path.realpath(self._cfgfile)

            mode = stat.S_IMODE(os.stat(self._cfgfile)[stat.ST_MODE])

            # apply bitmask to current mode to check ONLY user access permissions.
            if (mode & ( stat.S_IRWXG | stat.S_IRWXO )) != 0:
                logging.warning('%s permissions allows more than user access.'
                        % (self._cfgfile,))

            self._cfgparse.read(self._cfgfile)

        # if 'info' doesn't exist, create the section.
        if not self._cfgparse.has_section('info'):
            self._cfgparse.add_section('info')

        # Use default hostname (if one isn't provided).
        if not self._cfgparse.has_option('info', 'hostname'):
            if self._cfgparse.has_option('DEFAULT', 'hostname'):
                hostname = self._cfgparse.get('DEFAULT', 'hostname')
                self._cfgparse.set('info', 'hostname', hostname)
            else:
                raise Exception("No 'hostname' set. QualysConnect does not know who to connect to.")

        # Use default max_retries (if one isn't provided).
        if not self._cfgparse.has_option('info', 'max_retries'):
            self.max_retries = qcs.defaults['max_retries']
        else:
            self.max_retries = self._cfgparse.get('info', 'max_retries')
            try:
                self.max_retries = int(self.max_retries)
            except Exception:
                logger.error('Value max_retries must be an integer.')
                print('Value max_retries must be an integer.')
                exit(1)
            self._cfgparse.set('info', 'max_retries', str(self.max_retries))
        self.max_retries = int(self.max_retries)

        # Proxy support
        proxy_config = proxy_url = proxy_protocol = proxy_port = proxy_username = proxy_password = None
        # User requires proxy?
        if self._cfgparse.has_option('proxy', 'proxy_url'):
            proxy_url = self._cfgparse.get('proxy', 'proxy_url')
            # Remove protocol prefix from url if included.
            for prefix in ('http://', 'https://'):
                if proxy_url.startswith(prefix):
                    proxy_protocol = prefix
                    proxy_url = proxy_url[len(prefix):]
            # Default proxy protocol is http.
            if not proxy_protocol:
                proxy_protocol = 'https://'
            # Check for proxy port request.
            if ':' in proxy_url:
                # Proxy port already specified in url.
                # Set proxy port.
                proxy_port = proxy_url[proxy_url.index(':') + 1:]
                # Remove proxy port from proxy url.
                proxy_url = proxy_url[:proxy_url.index(':')]
            if self._cfgparse.has_option('proxy', 'proxy_port'):
                # Proxy requires specific port.
                if proxy_port:
                    # Warn that a proxy port was already specified in the url.
                    proxy_port_url = proxy_port
                    proxy_port = self._cfgparse.get('proxy', 'proxy_port')
                    logger.warning('Proxy port from url overwritten by specified proxy_port from config:')
                    logger.warning('%s --> %s' % (proxy_port_url, proxy_port))
                else:
                    proxy_port = self._cfgparse.get('proxy', 'proxy_port')
            if not proxy_port:
                # No proxy port specified.
                if proxy_protocol == 'http://':
                    # Use default HTTP Proxy port.
                    proxy_port = '8080'
                else:
                    # Use default HTTPS Proxy port.
                    proxy_port = '443'

            # Check for proxy authentication request.
            if self._cfgparse.has_option('proxy', 'proxy_username'):
                # Proxy requires username & password.
                proxy_username = self._cfgparse.get('proxy', 'proxy_username')
                proxy_password = self._cfgparse.get('proxy', 'proxy_password')
                # Not sure if this use case below is valid.
                # # Support proxy with username and empty password.
                # try:
                #     proxy_password = self._cfgparse.get('proxy','proxy_password')
                # except NoOptionError, e:
                #     # Set empty password.
                #     proxy_password = ''
        # Sample proxy config:f
        # 'http://user:pass@10.10.1.10:3128'
        if proxy_url:
            # Proxy requested.
            proxy_config = proxy_url
            if proxy_port:
                # Proxy port requested.
                proxy_config += ':' + proxy_port
            if proxy_username:
                # Proxy authentication requested.
                proxy_config = proxy_username + ':' + proxy_password + '@' + proxy_config
            # Prefix by proxy protocol.
            proxy_config = proxy_protocol + proxy_config
        # Set up proxy if applicable.
        if proxy_config:
            self.proxies = {'https': proxy_config}
        else:
            self.proxies = None

        #uh... ok..., let's go ahead and handle kwarg overrides
        for key in settings:
            if settings[key] is not None:
                self._cfgparse.set('info', key, str(settings[key]))

        # ask username (if one doesn't exist)
        logging.debug('checking config file for username')
        if not self._cfgparse.has_option('info', 'username'):
            username = input('QualysGuard Username: ')
            self._cfgparse.set('info', 'username', username)
        else:
            logging.debug('username \'' + \
                    self._cfgparse.get('info', 'username') + \
                    '\' found in config file')


        # ask password (if one doesn't exist)
        if not self._cfgparse.has_option('info', 'password'):
            password = getpass.getpass('QualysGuard Password: ')
            self._cfgparse.set('info', 'password', password)

        logging.debug(self._cfgparse.items('info'))

        if settings['remember_me'] or settings['remember_me_always']:
            # Let's create that config file for next time...
            # Where to store this?
            config_path = os.path.expanduser('~') if settings['remember_me_always'] else settings['filename']
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

        # Use default map_template (if one isn't provided).
        if not self._cfgparse.has_option('report_templates', 'map_template'):
            if self._cfgparse.has_option('DEFAULT', 'map_template'):
                map_template = self._cfgparse.get('DEFAULT', 'map_template')
                self._cfgparse.set('report_templates', 'map_template', map_template)
            else:
                raise Exception("No 'map_template' set. QualysConnect does not know who to connect to.")

    def get_config(self):
        return self._cfgparse

    def get_auth(self):
        ''' Returns username from the configfile. '''
        return (self._cfgparse.get('info', 'username'), self._cfgparse.get('info', 'password'))

    def get_hostname(self):
        ''' Returns hostname. '''
        return self._cfgparse.get('info', 'hostname')

    def get_redis_options(self):
        ''' Returns the redis client configuration options. '''
        redis_opts = [ 'host', 'port', 'db', 'rpass', 'ruser' ]
        result = {}
        for opt in redis_opts:
            if self._cfgparse.has_option('redis', opt):
                result[opt] = self._cfgparse.get('redis', opt)
            else:
                result[opt] = None
        return result

    def getMapTemplate(self):
        return self._cfgfile.get('report_templates', 'map_template')

    def getReportTemplate(self):
        return self._cfgfile.get('report_templates', 'report_template')
