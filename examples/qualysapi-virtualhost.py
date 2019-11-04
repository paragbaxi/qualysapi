#!/usr/bin/env python
import logging

import qualysapi

if __name__ == '__main__':
    # Basic command line processing.
    # Set the MAXIMUM level of log messages displayed @ runtime.
    logging.basicConfig(level=logging.DEBUG)

    # Call helper that creates a connection w/ HTTP-Basic to QualysGuard v1 API
    qgs = qualysapi.connect('qualys.ini')

    # Logging must be set after instanciation of connector class.
    logger = logging.getLogger('qualysapi.connector')
    logger.setLevel(logging.DEBUG)

    # Log to sys.out.
    logger_console = logging.StreamHandler()
    logger_console.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
    logging.getLogger(__name__).addHandler(logger)

    # Formulate a request to the QualysGuard V1 API
    #  docs @
    #  https://community.qualys.com/docs/DOC-1324
    #  http://www.qualys.com/docs/QualysGuard_API_User_Guide.pdf
    #
    # ret = qgs.request('/api/2.0/fo/asset/vhost/', {'action':'list'})
    ret = qgs.listVirtualHosts()
    for vhost in ret:
        print(vhost)
    print(" --- create new entry")
    qgs.createVirtualHost('dns.google.com', '8.8.8.8', 443)
    print(" --- delete entry")
    qgs.deleteVirtualHost('8.8.8.8', 443)
    ret = qgs.listVirtualHosts()
    for vhost in ret:
        print(vhost)
