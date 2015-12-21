#!/usr/bin/env python3
#global
import tempfile
import os
import unittest
import logging

# logging.basicConfig(level=logging.DEBUG)
# Setup module level logging.

import pudb
pu.db
from qualysapi import qcache, config, exceptions


class TestAPICache(unittest.TestCase):
    '''
    APICache unittest class

    @Params
    tf = tempfile
    test_username -- stored if there is a need to use a temporary config during
    the testing process.
    test_password -- also stored if there is a need to use a temporary config
    during testing.
    tfDestroy -- set IFF the config file is a temp file that should be cleaned
    up during tearDown.
    '''

    # set up configuration arguments for later use by config
    tf = None
    test_username = None
    test_password = None
    tfDestroy = False
    def setUp(self):
        '''
        Sets up a unittest api config file if one doesn't exist already
        '''
        #test from relative...

        #check if we have the required test data for unit tests
        self.tcfilename = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'test_data')
        self.tcfilename = os.path.join( self.tcfilename, 'unittests.cfg')

        # logger.debug('Test Case Config File is ' + self.tcfilename)
        # logger.debug(os.path.isfile(self.tcfilename))

        # if we don't have a unittest configuration file make a temporary
        # file for our unit tests
        if not os.path.isfile(self.tcfilename):
            import getpass

            # right so go ahead up-front for the test and collect a
            # username and password
            self.test_username = input('QualysGuard Username: ')
            self.test_password = getpass.getpass('QualysGuard Password: ')

            # now create a temporary file and save the user/pass for the tests...
            self.tf = tempfile.NamedTemporaryFile(delete=False)
            self.tcfilename = tf.name
            self.tf.close()
            self.tfDestroy = True

        qconf = config.QualysConnectConfig(
                use_ini=True,
                filename=self.tcfilename,
                username=self.test_username,
                password=self.test_password,
                remember_me=True)
        self.cache_instance = qcache.APICacheInstance(qconf)


    def tearDown(self):
        '''Remove the temporary file'''
        if self.tfDestroy: os.remove(os.path.abspath(self.tcfilename))


    def test_key(self):
        ''' prints out a redis key from a qualysapi style request '''
        endpoint = 'api/2.0/fo/report'
        args = {
            'action' : 'list',
            'state' : 'Finished',
        }
        self.assertEqual(
            'api/2.0/fo/report|action=list|state=Finished',
            self.cache_instance.build_redis_key(endpoint, **args)
            )

    def test_api_serialization(self):
        '''
        Tests the api object serialize/deserialize functions.
        '''
        from qualysapi import api_objects
        mymap = api_objects.Map(
            name = 'Bogus Test Map',
            ref = 'map/12345.bogus',
            date = '2015-11-19T06:00:39Z',
            status = 'Finished',
            report_id = None,
        )
        self.cache_instance.cache_api_object(obj=mymap, expiration=5)
        fromcache = self.cache_instance.load_api_object(
            objkey = mymap.getKey(),
            objtype = api_objects.Map
        )
        self.assertEqual(mymap, fromcache)


    def test_cache(self):
        ''' pulls a map_report_list and stores it in redis. '''
        result = None
        try:
            endpoint = 'map_report_list.php'
            with self.assertRaises(exceptions.QualysAuthenticationException):
                result = self.cache_instance.cache_request(endpoint)
        except Exception as e:
            logging.exception('Cache call failed!')

        if result:
            # Because we expect an exception if result actually gets set the
            # test has failed, somehow we didn't get an auth exception.
            self.assertTrue(False)


    def test_cache_clear(self):
        self.assertTrue(self.cache_instance.cache_flush(all=True))


    def test_cache_expiration(self):
        from qualysapi import api_objects
        mymap = api_objects.Map(
            name = 'Bogus Test Map',
            ref = 'map/12345.bogus',
            date = '2015-11-19T06:00:39Z',
            status = 'Finished',
            report_id = None,
        )
        self.cache_instance.cache_api_object(obj=mymap, expiration=1)
        # sleep for 2 seconds, letting the cache expire the key after 1
        import time
        time.sleep(2)
        fromcache = self.cache_instance.load_api_object(
            objkey = mymap.getKey(),
            objtype = api_objects.Map
        )
        self.assertIsNone(fromcache)


    def test_speed(self):
        self.assertTrue(False)


#stand-alone test execution
if __name__ == '__main__':
    import nose2
    nose2.main(argv=['fake', '--log-capture'])

