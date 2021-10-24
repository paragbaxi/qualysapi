""" Module providing a single class (QualysConnectConfig) that parses a config
file and provides the information required to build QualysGuard sessions.
"""
import getpass
import logging
import os
import stat
from configparser import RawConfigParser

import qualysapi.settings as qcs


# Setup module level logging.
logger = logging.getLogger(__name__)

# try:
#    from requests_ntlm import HttpNtlmAuth
# except ImportError, e:
#    logger.warning('Warning: Cannot support NTML authentication.')


__author__ = "Parag Baxi <parag.baxi@gmail.com> & Colin Bell <colin.bell@uwaterloo.ca>"
__copyright__ = "Copyright 2011-2013, Parag Baxi & University of Waterloo"
__license__ = "BSD-new"


class QualysConnectConfig:
    """ Class to create a RawConfigParser and read user/password details
    from an ini file.
    """

    def __init__(
        self,
        filename=qcs.default_filename,
        section="info",
        remember_me=False,
        remember_me_always=False,
        username=None,
        password=None,
        hostname=None,
    ):

        self._cfgfile = None
        self._section = section
        # Prioritize local directory filename.
        # Check for file existence.
        if os.path.exists(filename):
            self._cfgfile = filename
        elif os.path.exists(os.path.join(os.path.expanduser("~"), filename)):
            # Set home path for file.
            self._cfgfile = os.path.join(os.path.expanduser("~"), filename)

        # create RawConfigParser to combine defaults and input from config file.
        self._cfgparse = RawConfigParser(qcs.defaults)

        if self._cfgfile:
            self._cfgfile = os.path.realpath(self._cfgfile)

            mode = stat.S_IMODE(os.stat(self._cfgfile)[stat.ST_MODE])

            # apply bitmask to current mode to check ONLY user access permissions.
            if (mode & (stat.S_IRWXG | stat.S_IRWXO)) != 0:
                logger.warning("%s permissions allows more than user access.", filename)

            self._cfgparse.read(self._cfgfile)

        # if 'info'/ specified section doesn't exist, create the section.
        if not self._cfgparse.has_section(self._section):
            self._cfgparse.add_section(self._section)

        # Use default hostname (if one isn't provided).
        if not self._cfgparse.has_option(self._section, "hostname"):
            if not hostname:
                if self._cfgparse.has_option("DEFAULT", "hostname"):
                    hostname = self._cfgparse.get("DEFAULT", "hostname")
                else:
                    raise Exception(
                        "No 'hostname' set. QualysConnect does not know who to connect to."
                    )
            self._cfgparse.set(self._section, "hostname", hostname)

        # Use default max_retries (if one isn't provided).
        if not self._cfgparse.has_option(self._section, "max_retries"):
            self.max_retries = qcs.defaults["max_retries"]
        else:
            self.max_retries = self._cfgparse.get(self._section, "max_retries")
            try:
                self.max_retries = int(self.max_retries)
            except Exception:
                logger.error("Value max_retries must be an integer.")
                exit(1)
            self._cfgparse.set(self._section, "max_retries", str(self.max_retries))
        self.max_retries = int(self.max_retries)

        # Get template ID... user will need to set this to pull back CSV reports
        if not self._cfgparse.has_option(self._section, "template_id"):
            self.report_template_id = qcs.defaults["template_id"]
        else:
            self.report_template_id = self._cfgparse.get(self._section, "template_id")
            try:
                self.report_template_id = int(self.report_template_id)
            except Exception:
                logger.error("Report Template ID Must be set and be an integer")
                exit(1)
            self._cfgparse.set(self._section, "template_id", str(self.report_template_id))
        self.report_template_id = int(self.report_template_id)

        # Proxy support
        proxy_config = (
            proxy_url
        ) = proxy_protocol = proxy_port = proxy_username = proxy_password = None
        # User requires proxy?
        if self._cfgparse.has_option("proxy", "proxy_url"):
            proxy_url = self._cfgparse.get("proxy", "proxy_url")
            # Remove protocol prefix from url if included.
            for prefix in ("http://", "https://"):
                if proxy_url.startswith(prefix):
                    proxy_protocol = prefix
                    proxy_url = proxy_url[len(prefix) :]
            # Default proxy protocol is http.
            if not proxy_protocol:
                proxy_protocol = "https://"
            # Check for proxy port request.
            if ":" in proxy_url:
                # Proxy port already specified in url.
                # Set proxy port.
                proxy_port = proxy_url[proxy_url.index(":") + 1 :]
                # Remove proxy port from proxy url.
                proxy_url = proxy_url[: proxy_url.index(":")]
            if self._cfgparse.has_option("proxy", "proxy_port"):
                # Proxy requires specific port.
                if proxy_port:
                    # Warn that a proxy port was already specified in the url.
                    proxy_port_url = proxy_port
                    proxy_port = self._cfgparse.get("proxy", "proxy_port")
                    logger.warning(
                        "Proxy port from url overwritten by specified proxy_port from config: %s --> %s",
                        proxy_port_url,
                        proxy_port,
                    )
                else:
                    proxy_port = self._cfgparse.get("proxy", "proxy_port")
            if not proxy_port:
                # No proxy port specified.
                if proxy_protocol == "http://":
                    # Use default HTTP Proxy port.
                    proxy_port = "8080"
                else:
                    # Use default HTTPS Proxy port.
                    proxy_port = "443"

            # Check for proxy authentication request.
            if self._cfgparse.has_option("proxy", "proxy_username"):
                # Proxy requires username & password.
                proxy_username = self._cfgparse.get("proxy", "proxy_username")
                proxy_password = self._cfgparse.get("proxy", "proxy_password")
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
                proxy_config += f":{proxy_port}"
            if proxy_username:
                # Proxy authentication requested.
                proxy_config = f"{proxy_username}:{proxy_password}@{proxy_config}"
            # Prefix by proxy protocol.
            proxy_config = proxy_protocol + proxy_config
        # Set up proxy if applicable.
        if proxy_config:
            self.proxies = {"https": proxy_config}
        else:
            self.proxies = None

        # ask username (if one doesn't exist)
        if not self._cfgparse.has_option(self._section, "username"):
            if not username:
                # The next line will pass Bandit, which is required for issue B322:blacklist. QualysAPI no longer works with Python2, so this doesn't apply.
                username = input("QualysGuard Username: ")  # nosec
            self._cfgparse.set(self._section, "username", username)

        # ask password (if one doesn't exist)
        if not self._cfgparse.has_option(self._section, "password"):
            if not password:
                password = getpass.getpass("QualysGuard Password: ")
            self._cfgparse.set(self._section, "password", password)

        logger.debug(self._cfgparse.items(self._section))

        if remember_me or remember_me_always:
            # Let's create that config file for next time...
            # Where to store this?
            if remember_me:
                # Store in current working directory.
                config_path = filename
            if remember_me_always:
                # Store in home directory.
                config_path = os.path.expanduser("~")
            if not os.path.exists(config_path):
                # Write file only if it doesn't already exists.
                # http://stackoverflow.com/questions/5624359/write-file-with-specific-permissions-in-python
                mode = stat.S_IRUSR | stat.S_IWUSR  # This is 0o600 in octal and 384 in decimal.
                umask_original = os.umask(0)
                try:
                    config_file = os.fdopen(
                        os.open(config_path, os.O_WRONLY | os.O_CREAT, mode), "w"
                    )
                finally:
                    os.umask(umask_original)
                # Add the settings to the structure of the file, and lets write it out...
                self._cfgparse.write(config_file)
                config_file.close()

    def get_config_filename(self):
        return self._cfgfile

    def get_config(self):
        return self._cfgparse

    def get_auth(self):
        """ Returns username from the configfile. """
        return (
            self._cfgparse.get(self._section, "username"),
            self._cfgparse.get(self._section, "password"),
        )

    def get_hostname(self):
        """ Returns hostname. """
        return self._cfgparse.get(self._section, "hostname")

    def get_template_id(self):
        return self._cfgparse.get(self._section, "template_id")
