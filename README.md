qualysapi
=========

QualysGuard API connector. Initially a fork of qualysconnect.

Usage
=====

Example
-------
```python
>>> import qualysapi
>>> a = qualysapi.connect()
QualysGuard Username: my_username
QualysGuard Password: 
>>> print a.request(1,'about.php')
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

Example .qcrc
-------------
```INI
; Note, it should be possible to omit any of these entries.

[info]
hostname = qualysapi.serviceprovider.com
username = corp_tt
password = passw0rd
```

Installation
============

You can download the source and install locally.
```Shell
python setup.py install
```

NOTE: If you would like to experiment without installing globally, look into 'virtualenv'.

Alternatively, use pip to install:
```Shell
pip install qualysapi
```

Requirements
------------

* requests (http://docs.python-requests.org)
* lxml (http://lxml.de/)

Tested successfully on Python 2.7.

Configuration
-------------

By default, the package will ask at the command prompt for username and password.  By default, the package connects to the Qualys documented host (qualysapi.qualys.com).

You can override these settings and prevent yourself from typing credentials by creating a file called '.qcrc' in your home directory or directory of the Python script.

License
=======
Apache License, Version 2.0
http://www.apache.org/licenses/LICENSE-2.0.html
