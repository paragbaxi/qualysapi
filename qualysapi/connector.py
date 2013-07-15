""" Module that contains classes for setting up connections to QualysGuard API
and requesting data from it.
"""
import requests, urlparse
import logging
from collections import defaultdict
import qualysapi.version
import qualysapi.util

__author__ = 'Parag Baxi <parag.baxi@gmail.com>'
__copyright__ = 'Copyright 2013, Parag Baxi'
__license__ = 'Apache License 2.0'

# Setup module level logging.
logger = logging.getLogger(__name__)

class QGConnector:
    """ Qualys Connection class which allows requests to the QualysGuard API using HTTP-Basic Authentication (over SSL).

    """

    def __init__(self, username, password, server='qualysapi.qualys.com'):
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
        # Convert to int.
        if type(api_version) == str:
            api_version = api_version.lower()
            if api_version[0] == 'v' and api_version[1].isdigit():
                # Remove first 'v' in case the user typed 'v1' or 'v2', etc.
                api_version = api_version[1:]
            # Check for Qualys modules.
            if api_version in ('am', 'was', 'tag'):
                # Convert portal API to API number 3.
                api_version = 3
            elif api_version in ('pol', 'pc'):
                # Convert PC module to API number 2.
                api_version = 2
            else:
                api_version = int(api_version)
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
        logger.info("Base url = %s" % (url))
        return url

    def format_http_method(self, api_version, call):
        """ Return QualysGuard API http method, with POST preferred..

        """
        # Define get methods for automatic http request methodology.
        # Only some commands in API v1 are POST methods.
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
        # Some calls in API v1 don't support POST.
        if api_version == 1:
            if call in api_v1_post_methods:
                http_method = 'post'
            else:
                http_method = 'get'
        else:
            # API v2 & v3 are all POST methods.
            http_method = 'post'
        return http_method

    def format_call(self, api_version, call):
        """ Return appropriate QualysGuard API call.

        """
        # Remove possible starting slashes or trailing question marks in call.
        call = call.lstrip('/')
        call = call.rstrip('?')
        logger.debug('call post strip = %s' % call)
        # Make sure call ends in slash for API v2 calls.
        if (api_version == 2 and call[-1] != '/'):
            call += '/'
        return call

    def format_payload(self, api_version, data):
        """ Return appropriate QualysGuard API call.

        """
        # Check if payload is for API v1 or API v2.
        if (api_version in (1, 2)):
            # Check if string type.
            if type(data) == str:
                # Convert to dictionary.
                logger.debug('Converting string to dict: %s' % data)
                # Remove possible starting question mark & ending ampersands.
                data = data.lstrip('?')
                data = data.rstrip('&')
                # Convert to dictionary.
                data = urlparse.parse_qs(data)
                logger.debug('Converted: %s' % str(data))
            # Convert spaces to plus sign.
            for item in data:
                if type(data[item]) == list:
                    # Might be a dict of lists from urlparse.parse_qs.
                    data[item][0] = data[item][0].replace(' ', '+')
                else:
                    data[item] = data[item].replace(' ', '+')
        return data


    def request(self, api_version, call, data=None, http_method=None):
        """ Return QualysGuard API response.

        """
        # Set up base url.
        url = self.url_api_version(api_version)
        # Set up headers.
        headers = {"X-Requested-With": "Parag Baxi QualysAPI (python) v%s"%(qualysapi.version.__version__,)}
        logger.debug('api_version = %d' % api_version)
        logger.debug('call = %s' % call)
        logger.debug('headers =')
        logger.debug(str(headers))
        logger.debug('data %s =' % (type(data)))
        logger.debug(str(data))
        logger.debug('http_method = %s' % http_method)
        # Set up http request method, if not specified.
        if not http_method:
            http_method = self.format_http_method(api_version, call)
        logger.debug('http_method = %s' % http_method)
        # Format API call.
        call = self.format_call(api_version, call)
        logger.debug('call =')
        logger.debug(call)
        # Append call to url.
        url += call
        # Format data, if applicable.
        if data:
            data = self.format_payload(api_version, data)
        # Make request.
        logger.info('url =')
        logger.info(str(url))
        logger.info('data =')
        logger.info(str(data))
        logger.debug('headers =')
        logger.debug(str(headers))
        if http_method == 'get':
            # GET
            logger.info('GET request.')
            request = requests.get(url, params=data, auth=self.auth, headers=headers)
        else:
            # POST
            logger.info('POST request.')
            # Make POST request.
            request = requests.post(url, data=data, auth=self.auth, headers=headers)
        logger.info('response headers =')
        logger.info(request.headers)
        # Remember how many times left user can make against call.
        try:
            self.rate_limit_remaining[call] = int(request.headers['x-ratelimit-remaining'])
            logger.info('rate limit for call, %s = %d' % (call, self.rate_limit_remaining[call]))
        except KeyError, e:
            # Likely a bad call.
            pass
        logger.info('response text =')
        logger.info(request.text)
        # Check to see if there was an error.
        request.raise_for_status()
        return request.text