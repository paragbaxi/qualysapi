""" A set of utility functions for QualysConnect module. """
import logging
from dateutil import parser as iso8601parser
import strict_rfc3339
#import dateparser

__author__ = "Parag Baxi <parag.baxi@gmail.com> & Colin Bell <colin.bell@uwaterloo.ca>"
__copyright__ = "Copyright 2011-2013, Parag Baxi & University of Waterloo"
__license__ = 'Apache License 2.0'

# Set module level logger.
logger = logging.getLogger(__name__)


def preformat_call(api_call):
    """ Return properly formatted QualysGuard API call.

    """
    # Remove possible starting slashes or trailing question marks in call.
    api_call_formatted = api_call.lstrip('/')
    api_call_formatted = api_call_formatted.rstrip('?')
    if api_call != api_call_formatted:
        # Show difference
        logger.debug('api_call post strip =\n%s' % api_call_formatted)
    return api_call_formatted

def date_param_format(date):
    """date_param_format

    Converts python datetime to qualys date/time

    :param date: A python datetime object
    """
    return strict_rfc3339.timestamp_to_rfc3339_utcoffset(date.timestamp())

def qualys_datetime_to_python(qdatestr):
    try:
        return iso8601parser.parse(str(qdatestr))
    except:
        return None
    # return datetime.date(int(qdatestr.split('-')[0]),
    #     int(qdatestr.split('-')[1]), int(qdatestr.split('-')[2]))
