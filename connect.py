
""" Module that contains classes for setting up connections to QualysGuard API
and requesting data from it.
"""
import urllib2, requests, urlparse
import cookielib
import logging
import base64

from qualysconnect import __version__ as VERSION

__author__ = "Parag Baxi <parag.baxi@gmail.com>"
__copyright__ = "Copyright 2013, Parag Baxi"
__license__ = "GPL v3"

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
        headers = {"X-Requested-With": "Parag Baxi QualysAPI (python) v%s"%(VERSION,)}
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
        # Remove possible starting & ending slashes or trailing question marks in call.
        call = call.strip('/')
        call = call.rstrip('?')
        # Append call to url.
        url += call
        # Make request.
        if http_method == 'get':
            # GET
            request = requests.get(url, auth=self.auth, headers=headers)
        else:
            # POST
            # Check if payload is a string.
            if type(data) == str:
                # Convert to dictionary.
                # Remove possible starting & ending question marks.
                data = data.strip('?')
                # Convert to dictionary.
                data = urlparse.parse_qs(data)
            # Make POST request.
            request = requests.post(url, auth=self.auth, data=data, headers=headers)
        self.logger.info(request.headers)
        return request.text

class QGAPIConnect(QGConnector):
    """ Qualys Connection class which allows requests to the QualysGuard API
    using HTTP-Basic Authentication (over SSL).
    
    Notes:
    ======
    - Remote certificate verification is not supported.
    - This only currently functions with API v1 (not sure why).
    """
    def __init__(self, pUser, pPassword, pHost=None, pApiVer=1):

        QGConnector.__init__(self, pUser, pPassword, pHost)
