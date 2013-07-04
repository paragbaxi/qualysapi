""" Module that contains classes for setting up connections to QualysGuard API
and requesting data from it.
"""
import requests, urlparse
import logging
from collections import defaultdict
import qualysapi.version

__author__ = 'Parag Baxi <parag.baxi@gmail.com>'
__copyright__ = 'Copyright 2013, Parag Baxi'
__license__ = 'Apache License 2.0'

class QGConnector:
    """ Base class that provides common connection functionality for QualysGuard API.
    """
    # Define get methods for automatic http request methodology.
    # Only some commands in API v1 are POST methods. API v2 & v3 are all POST methods.
    api_v1_post_methods = set(['scan.php',
                               'scan_report.php',
                               'scan_target_history.php',
                               'knowledgebase_download.php',
                               'map-2.php',
                               'map.php',
                               'scheduled_scans.php',
                               'ignore_vuln.php',
                               'ticket_list.php',
                               'ticket_edit.php',
                               'ticket_delete.php',
                               'ticket_list_deleted.php',
                               'user.php',
                               'user_list.php',
                               'action_log_report.php',
                               'password_change.php'])

    def __init__(self, username, password, server='qualysapi.qualys.com'):
        self.logger = logging.getLogger(__name__)
        self.logger.level = logging.WARNING
        # Read username & password from file, if possible.
        self.auth = (username, password,)
        # Remember QualysGuard API server.
        self.server = server
        # Remember rate limits per call.
        self.rate_limit_remaining = defaultdict(int)

    def __call__(self):
        return self

    def url_api_version(self, api_version):
        """ Return base API url string for the QualysGuard api_version and server.

        """
        # Set base url depending on API version.
        if api_version == 1:
            # QualysGuard API v1 url.
            url = "https://%s/msp/" % (self.server,)
        elif api_version == 2:
            # QualysGuard API v2 url.
            url = "https://%s/api/2.0/fo/" % (self.server,)
        elif api_version == 3:
            # QualysGuard API v3 url.
            url = "https://%s/qps/rest/3.0/" % (self.server,)
        else:
            raise Exception("Unknown QualysGuard API Version Number (%s)" % (api_version,))
        self.logger.info("Base url = %s" % (url))
        return url


    def request(self, api_version, call, data=None, http_method=None):
        """ Return QualysGuard API response.

        """
        # Set up base url.
        url = self.url_api_version(api_version)
        # Set up headers.
        headers = {"X-Requested-With": "Parag Baxi QualysAPI (python) v%s"%(qualysapi.version.__version__,)}
        self.logger.info('headers =')
        self.logger.info(str(headers))
        # Set up http request method.
        if not http_method:
            # Automatically set method, with POST preferred.
            if api_version == 1:
                if call in self.api_v1_post_methods:
                    http_method = 'post'
                else:
                    http_method = 'get'
            else:
                http_method = 'post'
        # Remove possible starting slashes or trailing question marks in call.
        call = call.lstrip('/')
        call = call.rstrip('?')
        # Append call to url.
        url += call
        self.logger.info('url =')
        self.logger.info(url)
        # Make request.
        if http_method == 'get':
            # GET
            self.logger.info('GET request.')
            request = requests.get(url, params=data, auth=self.auth, headers=headers)
        else:
            # POST
            self.logger.info('POST request.')
            # Check if payload is a string for API v1 & v2.
            if type(data) == str and (api_version in (1, 2)):
                # Convert to dictionary.
                self.logger.info('Converting %s to dict.' % data)
                # Remove possible starting question mark & ending ampersands.
                data = data.lstrip('?')
                data = data.rstrip('&')
                # Convert to dictionary.
                data = urlparse.parse_qs(data)
            # Make POST request.
            self.logger.info('data =')
            self.logger.info(str(data))
            request = requests.post(url, data=data, auth=self.auth, headers=headers)
        self.logger.info('response headers =')
        self.logger.info(request.headers)
        # Remember how many times left user can make against call.
        try:
            self.rate_limit_remaining[call] = int(request.headers['x-ratelimit-remaining'])
            self.logger.info('rate limit for call, %s = %d' % (call, self.rate_limit_remaining[call]))
        except KeyError, e:
            # Likely a bad call.
            pass
        self.logger.info('response text =')
        self.logger.info(request.text)
        # Check to see if there was an error.
        request.raise_for_status()
        return request.text

class QGAPIConnect(QGConnector):
    """ Qualys Connection class which allows requests to the QualysGuard API
    using HTTP-Basic Authentication (over SSL).
    
    Notes:
    ======
    - Remote certificate verification is not supported.
    - This only currently functions with API v1 (not sure why).
    """
    def __init__(self, pUser, pPassword, pHost=None):

        QGConnector.__init__(self, pUser, pPassword, pHost)
