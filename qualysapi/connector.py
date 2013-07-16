""" Module that contains classes for setting up connections to QualysGuard API
and requesting data from it.
"""
import requests, urlparse
import logging
import lxml.etree
import qualysapi.version

from collections import defaultdict

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
        # Define method algorithm.
        api_methods = defaultdict(set)
        # Naming convention: api_methods[api_version blah] due to api_methods_with_trailing_slash testing.
        # API v1 POST methods.
        api_methods['1 post'] = set(['scan.php',
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
        # WAS GET methods when no POST data.
        api_methods['was no data get'] = set(['count/was/webapp',
                                             'count/was/wasscan',
                                             'count/was/wasscanschedule',
                                             'count/was/report'])
        # WAS GET methods.
        api_methods['was get'] = set(['get/was/webapp/',
                                      'get/was/wasscan/',
                                      'status/was/wasscan/',
                                      'download/was/wasscan',
                                      'get/was/wasscanschedule/',
                                      'get/was/report/',
                                      'status/was/report/',
                                      'download/was/report/'])
        # Asset Management GET methods.
        api_methods['am get'] = set(['get/am/tag/',
                                     'count/am/tag',
                                     'get/am/hostasset/',
                                     'count/am/hostasset',
                                     'get/am/asset/',
                                     'count/am/asset'])
        # Keep track of methods with ending slashes to autocorrect user when they forgot slash.
        api_methods_with_trailing_slash = defaultdict(set)
        for method_group in api_methods:
            for method in api_methods[method_group]:
                if method[-1] == '/':
                    # Add applicable method with api_version preceding it.
                    # Example:
                    # WAS API has 'get/was/webapp/'.
                    # method_group = 'was get'
                    # method_group.split()[0] = 'was'
                    # Take off slash to match user provided method.
                    # api_methods_with_trailing_slash['was'] contains 'get/was/webapp'
                    api_methods_with_trailing_slash[method_group.split()[0]].add(method[:-1])


    def __call__(self):
        return self


    def format_api_version(self, api_version):
        """ Return base API url string for the QualysGuard api_version and server.

        """
        # Convert to int.
        if type(api_version) == str:
            api_version = api_version.lower()
            if api_version[0] == 'v' and api_version[1].isdigit():
                # Remove first 'v' in case the user typed 'v1' or 'v2', etc.
                api_version = api_version[1:]
            # Check for input matching Qualys modules.
            if api_version in ('asset management', 'assets', 'tag',  'tagging', 'tags'):
                # Convert to Asset Management API.
                api_version = 'am'
            elif api_version in ('webapp', 'web application scanning', 'webapp scanning'):
                # Convert to WAS API.
                api_version = 'was'
            elif api_version in ('pol', 'pc'):
                # Convert PC module to API number 2.
                api_version = 2
            else:
                api_version = int(api_version)
        return api_version


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
        elif api_version == 'was':
            # QualysGuard REST v3 API url.
            url = "https://%s/qps/rest/3.0/" % (self.server,)
        elif api_version == 'am':
            # QualysGuard REST v1 API url.
            url = "https://%s/qps/rest/1.0/" % (self.server,)
        else:
            raise Exception("Unknown QualysGuard API Version Number (%s)" % (api_version,))
        logger.info("Base url = %s" % (url))
        return url


    def format_http_method(self, api_version, call, data):
        """ Return QualysGuard API http method, with POST preferred..

        """
        # Define get methods for automatic http request methodology.
        #
        # All API v2 requests are POST methods.
        if api_version == 2:
            return 'post'
        elif api_version == 1:
            if call in self.api_methods['1 post']:
                return 'post'
            else:
                return 'get'
        elif api_version == 'was':
            # WAS API call.
            if call in self.api_methods['was get']:
                return 'get'
            # Post calls with no payload will result in HTTPError: 415 Client Error: Unsupported Media Type.
            if data == None:
                # No post data. Some calls change to GET with no post data.
                if call in self.api_methods['was no data get']:
                    return 'get'
                else:
                    return 'post'
            else:
                # Call with post data.
                return 'post'
        else:
            # Asset Management API call.
            if call in self.api_methods['am get']:
                return 'get'
            else:
                return 'post'


    def format_call(self, api_version, call):
        """ Return appropriate QualysGuard API call.

        """
        # Remove possible starting slashes or trailing question marks in call.
        call = call.lstrip('/')
        call = call.rstrip('?')
        logger.debug('call post strip = %s' % call)
        # Make sure call always ends in slash for API v2 calls.
        if (api_version == 2 and call[-1] != '/'):
            # Add slash.
            logger.info('Added "/" to call.')
            call += '/'
        if call in self.api_methods_with_trailing_slash[api_version]:
            # Add slash.
            logger.info('Added "/" to call.')
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
        elif api_version == 3:
            if type(payload) == lxml.etree._Element:
                data = lxml.etree.tostring(data)
        return data


    def request(self, api_version, call, data=None, http_method=None):
        """ Return QualysGuard API response.

        """
        logger.debug('api_version = %d' % api_version)
        logger.debug('call = %s' % call)
        logger.debug('data %s =' % (type(data)))
        logger.debug(str(data))
        logger.debug('http_method = %s' % http_method)
        # Format api version inputted.
        api_version = self.format_api_version(api_version)
        # Set up base url.
        url = self.url_api_version(api_version)
        # Set up headers.
        headers = {"X-Requested-With": "Parag Baxi QualysAPI (python) v%s"%(qualysapi.version.__version__,)}
        logger.debug('headers =')
        logger.debug(str(headers))
        if api_version == 3:
            # API v3 takes in XML text.
            headers['Content-type'] = 'text/xml'
        # Set up http request method, if not specified.
        if not http_method:
            http_method = self.format_http_method(api_version, call, data)
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