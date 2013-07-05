""" A set of utility functions for QualysConnect module. """
import logging

import qualysapi.config as qcconf
import qualysapi.connector as qcconn
import qualysapi.version

__author__ = "Parag Baxi <parag.baxi@gmail.com> & Colin Bell <colin.bell@uwaterloo.ca>"
__copyright__ = "Copyright 2011-2013, Parag Baxi & University of Waterloo"
__license__ = "BSD-new"

# define global values used by community code. will standardize debugging later.
module = 'util.py'

# Define a Handler which writes WARNING messages or higher to the sys.stderr
logger_console = logging.StreamHandler()
logger_console.setLevel(logging.ERROR)
# Set a format which is simpler for console use.
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
# Tell the handler to use this format.
logger_console.setFormatter(formatter)
# Add the handler to the root logger
logging.getLogger(__name__).addHandler(logger_console)
# Set module level logger.
logger = logging.getLogger(__name__)

def connect(remember_me=False, remember_me_always=False):
    """ Return a QGAPIConnect object for v1 API pulling settings from config
    file.
    """
    # Retrieve login credentials.
    conf = qcconf.QualysConnectConfig(remember_me=remember_me, remember_me_always=remember_me_always)
    connect = qcconn.QGAPIConnect(conf.get_username(),
                                  conf.get_password(),
                                  conf.get_hostname())
    logger.info("Finished building connector.")
    return connect