# 4.1.1
* Nose 2 added as a required module (unit testing)
added nose2 as a project requirement so that we could include API
authenticated testing but not as the standard unit tests.  This allows for
developer and interested party testing of their personal connections to Qualys
by extending and/or using the integration testing options of nose2.
* All lxml tests will be skipped unless lxml is available.Warnings will now
be issued by the test framework and not by qualysapi itself (less spam for
people who know they aren't using lxml)
