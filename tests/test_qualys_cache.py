#!/usr/bin/env python3
#global
import tempfile
import os
import unittest
import logging

logging.basicConfig()
# Setup module level logging.
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

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

    def test_cache_expiration(self):
        self.assertTrue(False)

    def test_speed(self):
        self.assertTrue(False)

#stand-alone test execution
if __name__ == '__main__':
    unittest.main()

