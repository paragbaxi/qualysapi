qualysapi
=========

Python QualysGuard API connector.

Usage
=====

Check out the example scripts in the /scripts directory.

Example
-------
```python
>>> import qualysapi
>>> a = qualysapi.connect()
QualysGuard Username: my_username
QualysGuard Password: 
>>> print a.request('about.php')
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE ABOUT SYSTEM "https://qualysapi.qualys.com/about.dtd">
<ABOUT>
  <API-VERSION MAJOR="1" MINOR="4" />
  <WEB-VERSION>7.10.61-1</WEB-VERSION>
  <SCANNER-VERSION>7.1.10-1</SCANNER-VERSION>
  <VULNSIGS-VERSION>2.2.475-2</VULNSIGS-VERSION>
</ABOUT>
<!-- Generated for username="my_username" date="2013-07-03T10:31:57Z" -->
<!-- CONFIDENTIAL AND PROPRIETARY INFORMATION. Qualys provides the QualysGuard Service "As Is," without any warranty of any kind. Qualys makes no warranty that the information contained in this report is complete or error-free. Copyright 2013, Qualys, Inc. //--> 
```

Installation
============

Use pip to install:
```Shell
pip install qualysapi
```

NOTE: If you would like to experiment without installing globally, look into 'virtualenv'.

Requirements
------------

* requests (http://docs.python-requests.org)
* lxml (http://lxml.de/)

Tested successfully on Python 2.7.

Configuration
=============

By default, the package will ask at the command prompt for username and password. By default, the package connects to the Qualys documented host (qualysapi.qualys.com).

You can override these settings and prevent yourself from typing credentials by doing any of the following:

1. By running the following Python, `qualysapi.connect(remember_me=True)`. This automatically generates a .qcrc file in your current working directory, scoping the configuration to that directory.
2. By running the following Python, `qualysapi.connect(remember_me_always=True)`. This automatically generates a .qcrc file in your home directory, scoping the configuratoin to all calls to qualysapi, regardless of the directory.
3. By creating a file called '.qcrc' in your home directory or directory of the Python script.

Example .qcrc
-------------
```INI
; Note, it should be possible to omit any of these entries.

[info]
hostname = qualysapi.serviceprovider.com
username = jerry
password = I<3Elaine

[proxy]

; proxy_protocol set to https, if not specified.
proxy_url = proxy.mycorp.com

; proxy_port will override any port specified in proxy_url
proxy_port = 8080

; proxy authentication
proxy_username = kramer
proxy_password = giddy up!

```


License
=======
Apache License, Version 2.0
http://www.apache.org/licenses/LICENSE-2.0.html

Acknowledgements
================

Special thank you to Colin Bell for qualysconnect.
