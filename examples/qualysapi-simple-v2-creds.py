#!/usr/bin/python3

# Use the defusedxml package for all xml parsing. See bandit docs: 
# https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html#b405-import-xml-etree
from defusedxml.ElementTree import fromstring
from qualysapi import connect

# API url to pull data from. See qualys docs for a list of APIs
api_url = "/api/2.0/fo/asset/host/"

# Options for API request. See qualys docs for a list of all options
params = {
    'action': 'list',
    'truncation_limit': '10',
}

# Create a connection object used to pull data from Qualys
conn = connect(
    username="<username>", # Qualys Username
    password="<password>", # Qualys Password
    hostname="<hostname>", # Optional api host url
    max_retries="<#>",     # Optional # of retries
)

# Perform API request
resp = conn.request(api_url, params)
print(resp) # Raw text response from Qualys

# Parse the response string and convert to an xml object
xml = fromstring(resp.encode('utf-8'))
for host in xml.iter(tag='HOST'):
    id = host.find('./ID').text
    ip = host.find('./DNS').text
    print(id + ": " + ip)