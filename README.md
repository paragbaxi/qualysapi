qualysapi
=========

Fork of qualysconnect.

Example:
```python
>>> from qualysconnect.util import build_v2_connector
>>> a = build_v2_connector()
QualysGuard Username: quays_pb27
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
<!-- Generated for username="quays_pb27" date="2013-07-03T10:31:57Z" -->
<!-- CONFIDENTIAL AND PROPRIETARY INFORMATION. Qualys provides the QualysGuard Service "As Is," without any warranty of any kind. Qualys makes no warranty that the information contained in this report is complete or error-free. Copyright 2013, Qualys, Inc. //--> 
