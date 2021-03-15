""" A set of utility functions for QualysConnect module. """
import logging

import qualysapi.config as qcconf
import qualysapi.connector as qcconn
import qualysapi.settings as qcs


__author__ = "Parag Baxi <parag.baxi@gmail.com> & Colin Bell <colin.bell@uwaterloo.ca>"
__copyright__ = "Copyright 2011-2013, Parag Baxi & University of Waterloo"
__license__ = "Apache License 2.0"

# Set module level logger.
logger = logging.getLogger(__name__)


# NOTE: Possibly switch to multimethod for clarity
def connect(
    config_file=qcs.default_filename,
    section="info",
    remember_me=False,
    remember_me_always=False,
    username=None,
    password=None,
    hostname="qualysapi.qualys.com",
    max_retries="3",
    proxies=None,
):
    """ Return a QGAPIConnect object for v1 API pulling settings from config
    file.
    """
    # Use function parameter login credentials.
    if username and password:
        connect = qcconn.QGConnector(
            auth=(username, password), server=hostname, max_retries=max_retries, proxies=proxies
        )

    # Retrieve login credentials from config file.
    else:
        conf = qcconf.QualysConnectConfig(
            filename=config_file,
            section=section,
            remember_me=remember_me,
            remember_me_always=remember_me_always,
        )
        connect = qcconn.QGConnector(
            conf.get_auth(), conf.get_hostname(), conf.proxies, conf.max_retries
        )

    logger.info("Finished building connector.")
    return connect
