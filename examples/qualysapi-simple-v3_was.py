#!/usr/bin/env python
import sys
import logging

from qualysconnect.util import build_v2_session

# Questions?  See:
#  https://bitbucket.org/uWaterloo_IST_ISS/python-qualysconnect

if __name__ == '__main__':
    # Basic command line processing.
    if len(sys.argv) != 2:
        print 'A single IPv4 address is expected as the only argument'
        sys.exit(2)
    
    # Set the MAXIMUM level of log messages displayed @ runtime. 
    logging.basicConfig(level=logging.INFO)
    
    # Call helper that creates a helper  w/ Cookie Sessions to QualysGuard v2 API
    qgs=build_v2_session()

    # Get said Session Cookie.
    qgs.connect()

    # Formulate a request to the QualysGuard V2 API 
    #  docs @
    #  https://community.qualys.com/docs/DOC-1325
    #  http://www.qualys.com/docs/QualysGuard_API_v2_User_Guide.pdf
    ret = qgs.request("asset/host/?action=list&ips=%s&"%(sys.argv[1]))

    print ret

    # Invalidate Session Cookie.
    qgs.disconnect()
