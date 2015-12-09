### 4.1.1
* Added Redis as an optional requirement for API call caching.  This is
  configurable specifically to allow the end-user to tweak expiration and/or
specifically expire cache entries according to development requirements.  It's
really just a simple wrapper, but makes using the remote API with a cache
braindead simple.  Documentation will be provided as soon as possible.
* Nose 2 added as a required module (unit testing)
This is so that we could include API authenticated testing but not as the
standard unit tests.  This allows for developer and interested party testing
of their personal connections to Qualys by extending and/or using the
integration testing options of nose2.
* All lxml tests will be skipped unless lxml is available.Warnings will now
be issued by the test framework and not by qualysapi itself (less spam for
people who know they aren't using lxml)
