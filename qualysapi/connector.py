__author__ = 'Parag Baxi <parag.baxi@gmail.com>'
__copyright__ = 'Copyright 2013, Parag Baxi'
__license__ = 'Apache License 2.0'

""" Module that contains classes for setting up connections to QualysGuard API
and requesting data from it.
"""
import logging
import pprint
import time
import urllib.parse
from collections import defaultdict

import requests

import qualysapi.version
from qualysapi.api_methods import api_methods
from qualysapi.api_methods import api_methods_with_trailing_slash
import qualysapi.api_methods
from qualysapi import util

from qualysapi.exceptions import QualysAuthenticationException
from qualysapi.api_methods import api_methods

# Setup module level logging.
logging.basicConfig()
logger = logging.getLogger(__name__)

try:
    from lxml import etree
except ImportError as e:
    logger.warning(
        'Warning: Cannot consume lxml.builder E objects without lxml. \
                Send XML strings for AM & WAS API calls.')


class QGConnector:
    """ Qualys Connection class which allows requests to the QualysGuard API using HTTP-Basic Authentication (over SSL).

    """
    __auth                 = None
    __server               = 'qualysapi.qualys.com'
    __rate_limit_remaining = defaultdict(int)
    __proxies              = None
    __session              = None
    def __init__(self,
            auth,
            **kwargs):
        # Read username & password from file, if possible.
        self.auth = auth
        # Remember QualysGuard API server.
        if 'server' in kwargs:
            self.__server = kwargs['server']
        # Remember rate limits per call.
        if 'rate_limit_remaining' in kwargs:
            self.__rate_limit_remaining = kwargs['rate_limit_remaining']
        self.proxies = kwargs.get('proxies', None)
        logger.debug('proxies = \n%s' % self.proxies)
        # Set up requests max_retries.
        max_retries = kwargs.get('max_retries', 3)
        logger.debug('max_retries = \n%s' % max_retries)
        self.session = requests.Session()
        http_max_retries = requests.adapters.HTTPAdapter(max_retries=max_retries)
        https_max_retries = requests.adapters.HTTPAdapter(max_retries=max_retries)
        self.session.mount('http://', http_max_retries)
        self.session.mount('https://', https_max_retries)

        # new kwargs handling/options
        if 'config' in kwargs:
            self.config = kwargs.get('config')


    def __call__(self):
        return self


    def format_api_version(self, api_version):
        """ Return QualysGuard API version for api_version specified.

        """
        # Convert to int.
        if type(api_version) == str:
            api_version = api_version.lower()
            if api_version[0] == 'v' and api_version[1].isdigit():
                # Remove first 'v' in case the user typed 'v1' or 'v2', etc.
                api_version = api_version[1:]
            # Check for input matching Qualys modules.
            if api_version in ('asset management', 'assets', 'tag', 'tagging', 'tags'):
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


    def which_api_version(self, api_call):
        """ Return QualysGuard API version for api_call specified.

        """
        # Leverage patterns of calls to API methods.
        if api_call.endswith('.php'):
            # API v1.
            return 1
        elif api_call.startswith('api/2.0/'):
            # API v2.
            return 2
        elif '/am/' in api_call:
            # Asset Management API.
            return 'am'
        elif '/was/' in api_call:
            # WAS API.
            return 'was'
        return False


    def url_api_version(self, api_version):
        """ Return base API url string for the QualysGuard api_version and server.

        """
        # Set base url depending on API version.
        if api_version == 1:
            # QualysGuard API v1 url.
            url = "https://%s/msp/" % (self.__server,)
        elif api_version == 2:
            # QualysGuard API v2 url.
            url = "https://%s/" % (self.__server,)
        elif api_version == 'was':
            # QualysGuard REST v3 API url (Portal API).
            url = "https://%s/qps/rest/3.0/" % (self.__server,)
        elif api_version == 'am':
            # QualysGuard REST v1 API url (Portal API).
            url = "https://%s/qps/rest/1.0/" % (self.__server,)
        else:
            raise Exception("Unknown QualysGuard API Version Number (%s)" % (api_version,))
        logger.debug("Base url =\n%s" % (url))
        return url


    def format_http_method(self, api_version, api_call, data):
        """ Return QualysGuard API http method, with POST preferred..

        """
        # Define get methods for automatic http request methodology.
        #
        # All API v2 requests are POST methods.
        if api_version == 2:
            return 'post'
        elif api_version == 1:
            if api_call in api_methods['1 post']:
                return 'post'
            else:
                return 'get'
        elif api_version == 'was':
            # WAS API call.
            # Because WAS API enables user to GET API resources in URI, let's chop off the resource.
            # '/download/was/report/18823' --> '/download/was/report/'
            api_call_endpoint = api_call[:api_call.rfind('/') + 1]
            if api_call_endpoint in api_methods['was get']:
                return 'get'
            # Post calls with no payload will result in HTTPError: 415 Client Error: Unsupported Media Type.
            if not data:
                # No post data. Some calls change to GET with no post data.
                if api_call_endpoint in api_methods['was no data get']:
                    return 'get'
                else:
                    return 'post'
            else:
                # Call with post data.
                return 'post'
        else:
            # Asset Management API call.
            if api_call in api_methods['am get']:
                return 'get'
            else:
                return 'post'


    def format_call(self, api_version, api_call):
        """ Return properly formatted QualysGuard API call according to api_version etiquette.

        """
        # Remove possible starting slashes or trailing question marks in call.
        api_call = api_call.lstrip('/')
        api_call = api_call.rstrip('?')
        logger.debug('api_call post strip =\n%s' % api_call)
        # Make sure call always ends in slash for API v2 calls.
        if (api_version == 2 and api_call[-1] != '/'):
            # Add slash.
            logger.debug('Adding "/" to api_call.')
            api_call += '/'
        if api_call in api_methods_with_trailing_slash[api_version]:
            # Add slash.
            logger.debug('Adding "/" to api_call.')
            api_call += '/'
        return api_call


    def format_payload(self, api_version, data):
        """ Return appropriate QualysGuard API call.

        """
        # Check if payload is for API v1 or API v2.
        if (api_version in (1, 2)):
            # Check if string type.
            if type(data) == str:
                # Convert to dictionary.
                logger.debug('Converting string to dict:\n%s' % data)
                # Remove possible starting question mark & ending ampersands.
                data = data.lstrip('?')
                data = data.rstrip('&')
                # Convert to dictionary.
                data = urllib.parse.parse_qs(data)
                logger.debug('Converted:\n%s' % str(data))
        elif api_version in ('am', 'was'):
            if type(data) == etree._Element:
                logger.debug('Converting lxml.builder.E to string')
                data = etree.tostring(data)
                logger.debug('Converted:\n%s' % data)
        return data


    def request(self, api_call, data=None, api_version=None, http_method=None, concurrent_scans_retries=0,
                concurrent_scans_retry_delay=0):
        """ Return QualysGuard API response.

        """
        logger.debug('api_call =\n%s' % api_call)
        logger.debug('api_version =\n%s' % api_version)
        logger.debug('data %s =\n %s' % (type(data), str(data)))
        logger.debug('http_method =\n%s' % http_method)
        logger.debug('concurrent_scans_retries =\n%s' % str(concurrent_scans_retries))
        logger.debug('concurrent_scans_retry_delay =\n%s' % str(concurrent_scans_retry_delay))
        concurrent_scans_retries = int(concurrent_scans_retries)
        concurrent_scans_retry_delay = int(concurrent_scans_retry_delay)
        #
        # Determine API version.
        # Preformat call.
        api_call = util.preformat_call(api_call)
        if api_version:
            # API version specified, format API version inputted.
            api_version = self.format_api_version(api_version)
        else:
            # API version not specified, determine automatically.
            api_version = self.which_api_version(api_call)
        #
        # Set up base url.
        url = self.url_api_version(api_version)
        #
        # Set up headers.
        headers = {"X-Requested-With": "Parag Baxi QualysAPI (python) v%s" % (qualysapi.version.__version__,)}
        logger.debug('headers =\n%s' % (str(headers)))
        # Portal API takes in XML text, requiring custom header.
        if api_version in ('am', 'was'):
            headers['Content-type'] = 'text/xml'
        #
        # Set up http request method, if not specified.
        if not http_method:
            http_method = self.format_http_method(api_version, api_call, data)
        logger.debug('http_method =\n%s' % http_method)
        #
        # Format API call.
        api_call = self.format_call(api_version, api_call)
        logger.debug('api_call =\n%s' % (api_call))
        # Append api_call to url.
        url += api_call
        #
        # Format data, if applicable.
        if data is not None:
            data = self.format_payload(api_version, data)
        # Make request at least once (more if concurrent_retry is enabled).
        retries = 0
        while retries <= concurrent_scans_retries:
            # Make request.
            logger.debug('url =\n%s' % (str(url)))
            logger.debug('data =\n%s' % (str(data)))
            logger.debug('headers =\n%s' % (str(headers)))
            if http_method == 'get':
                # GET
                logger.debug('GET request.')
                request = self.session.get(url,
                    params=data,
                    auth=self.auth,
                    headers=headers,
                    proxies=self.proxies,
                    timeout=180)
            else:
                # POST
                logger.debug('POST request.')
                # Make POST request.
                request = self.session.post(url,
                    data=data,
                    auth=self.auth,
                    headers=headers,
                    proxies=self.proxies,
                    timeout=180)
            logger.debug('response headers =\n%s' % (str(request.headers)))
            #
            # Remember how many times left user can make against api_call.
            try:
                self.__rate_limit_remaining[api_call] = int(request.headers['x-ratelimit-remaining'])
                logger.debug('rate limit for api_call, %s = %s' % (api_call, self.__rate_limit_remaining[api_call]))
            except KeyError as e:
                # Likely a bad api_call.
                logger.debug(e)
                pass
            except TypeError as e:
                # Likely an asset search api_call.
                logger.debug(e)
                pass
            # handle authentication exception special and early
            if request.status_code == 401:
                request.close()
                raise QualysAuthenticationException('Bad Qualys username or \
                    password.')
            # Response received
            for buffblock in request.iter_content(chunk_size=8192,
                    decode_unicode=True):
                logger.debug(pprint.pformat(buffblock))
            response = b"".join([buffblock for buffblock in
                request.iter_content(chunk_size=8192, decode_unicode=False)])
            #logging.debug(pprint.pformat(response))
            # for buffblock in request.iter_content(chunk_size=8192, decode_unicode=True):
            #    response_str += unicode(buffblock)
            # response = str(request.content)
            #logger.debug('response text =\n%s' % (response))
            # Keep track of how many retries.
            retries += 1
            # Check for concurrent scans limit.
            if not (b'<responseCode>INVALID_REQUEST</responseCode>' in response and \
                                b'<errorMessage>You have reached the maximum number of concurrent running scans' in response and \
                                b'<errorResolution>Please wait until your previous scans have completed</errorResolution>' in response):
                # Did not hit concurrent scan limit.
                break
            else:
                # Hit concurrent scan limit.
                logger.critical(response)
                # If trying again, delay next try by concurrent_scans_retry_delay.
                if retries <= concurrent_scans_retries:
                    logger.warning('Waiting %d seconds until next try.' % \
                            concurrent_scans_retry_delay)
                    time.sleep(concurrent_scans_retry_delay)
                    # Inform user of how many retries.
                    logger.critical('Retry #%d' % retries)
                else:
                    # Ran out of retries. Let user know.
                    print('Alert! Ran out of concurrent_scans_retries!')
                    logger.critical('Alert! Ran out of concurrent_scans_retries!')
                    return False
        # QualysAPI lies.  400 errors aren't supposed to be thrown for API
        # errors (like missing arguments).
        if not (b'<SIMPLE_RETURN>' in response):
            # Check to see if there was a REAL error.
            try:
                request.raise_for_status()
            except requests.exceptions.HTTPError as e:
                # only do this logging if we don't know the reason for the
                # exception (have already handled it IOTW)
                logger.exception('Error! Received a 4XX client error or 5XX server error response.')
                logger.error('    Content = \n%s' % response)
                logger.error('    Headers = \n%s' % str(request.headers))
                request.raise_for_status()
            if b'<RETURN status="FAILED" number="2007">' in response:
                logger.error('Error! Your IP address is not in the list of secure IPs. Manager must include this IP (QualysGuard VM > Users > Security).')
                logger.error('    Content = \n%s' % response)
                logger.error('    Headers = \n%s' % str(request.headers))
            request.close()
        return response

    def stream_request(self,
            api_call,
            data=None,
            api_version=None,
            http_method=None,
            concurrent_scans_retries=0,
            concurrent_scans_retry_delay=0,
            **kwargs):
        """ Return QualysGuard API response as a raw input stream.  This is a
        single request and does not handle concurrent requests.  It is a
        redesigned version of the original request method and is intended for
        use with the framework.  It is not cacheable directly and this is
        intentional since most of the instances where this would be used would
        be used should cache individual result objects and not the massive xml
        response.
        """

        #
        # Determine API version.
        # Preformat call.
        api_call = util.preformat_call(api_call)
        if api_version:
            # API version specified, format API version inputted.
            api_version = self.format_api_version(api_version)
        else:
            # API version not specified, determine automatically.
            api_version = self.which_api_version(api_call)
        #
        # Set up base url.
        url = self.url_api_version(api_version)
        #
        # Set up headers.
        headers = {"X-Requested-With": "Parag Baxi QualysAPI (python) v%s" % (qualysapi.version.__version__,)}
        logger.debug('headers =\n%s' % (str(headers)))
        # Portal API takes in XML text, requiring custom header.
        if api_version in ('am', 'was'):
            headers['Content-type'] = 'text/xml'
        #
        # Set up http request method, if not specified.
        if not http_method:
            http_method = self.format_http_method(api_version, api_call, data)
        logger.debug('http_method =\n%s' % http_method)
        #
        # Format API call.
        api_call = self.format_call(api_version, api_call)
        logger.debug('api_call =\n%s' % (api_call))
        # Append api_call to url.
        url += api_call
        #
        # Format data, if applicable.
        if data is not None:
            data = self.format_payload(api_version, data)
        # this call should be results/maps oriented for large domains and/or maps and/or asset groups so
        # there really is no need or benefit to using concurrent scans here...
        # use a stream-based non-blocking request
        response = None
        if http_method == 'get':
            # GET
            logger.debug('GET request.')
            response = self.session.get(url,
                    params=data,
                    auth=self.auth,
                    headers=headers,
                    proxies=self.proxies,
                    stream=True,
                    timeout=180, # add a 3 minute timeout.. q b slow
                )
        else:
            # POST
            logger.debug('POST request.')
            # Make POST request.
            response = self.session.post(
                    url,
                    data=data,
                    auth=self.auth,
                    headers=headers,
                    proxies=self.proxies,
                    stream=True,
                    timeout=180, # add a 3 minute timeout.. q b slow
                )
        if response is not None and response.status_code == 401:
            response.close()
            raise QualysAuthenticationException('Bad Qualys username or \
                password.')
        response.raise_for_status()
        response.raw.decode_content = True
        return response.raw

    def getConfig(self):
        return self.config
