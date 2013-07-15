__author__ = 'pbaxi'

import qualysapi

# Setup connection to QualysGuard API.
qgc = qualys.connect()
#
# API v1 call: Scan the New York & Las Vegas asset groups
# The API version is our request's first parameter.
api_version = 1
# The call is our request's second parameter.
call = 'scan'
# The parameters to append to the url is our request's third parameter.
parameters = {'scan_title': 'Go big or go home', 'asset_groups': 'New York&Las Vegas', 'option': 'Initial+Options'}
# Note qualysapi will automatically convert spaces into plus signs for API v1 & v2.
# Let's call the API and store the result in xml_output.
xml_output = qgc.request(1, call, parameters)
# The request returns a unicode string, let's convert it to a string.
xml_output = xml_output.encode('utf-8')
# Let's objectify the xml_output string.
root = lxml.objectify.fromstring(xml_output)
# API v1 call: Combine all Ubuntu asset groups' IPs.
api_version = 1
call = 'asset_group_list.php'
# We can still use strings for the third parameter (not recommended).
parameters = 'title=Ubuntu'
xml_output = qgc.request(1, call, parameters).encode('utf-8')

# API v2 call:

# API v3 WAS call:

# API v3 Asset Management call: