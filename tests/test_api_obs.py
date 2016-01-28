#!/usr/bin/env python3
#global
import os
import unittest
import logging
import pprint
import lxml

# Setup module level logging. -- workaround nose
# logging.basicConfig(level=logging.DEBUG)

from qualysapi import api_objects

#pudb nice debugger
import pudb

class TestAPIObjects(unittest.TestCase):
    '''
    Object unittest class

    Params
    '''

    # set up configuration arguments for later use by config
    tf = None
    def setUp(self):
        '''
        Sets up a unittest for api objects
        '''
        # open the object test xml
        self.tcfilename = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'test_data')
        self.tcfilename = os.path.join( self.tcfilename, 'obj_test.xml')
        self.tf = open(self.tcfilename, 'rb')

    def tearDown(self):
        '''Close the test file'''
        self.tf.close()

    def test_report_obj(self):
        self.tf.seek(0)
        context = lxml.etree.iterparse(self.tf, events=('end',))
        reports = []
        for event, elem in context:
            report = api_objects.Report(elem=elem) if elem.tag == 'REPORT' else None
            if report is not None:
                reports.append(report)
        self.assertGreaterEqual(len(reports), 1)
        # now try filtering the reports...
        logging.info(pprint.pformat(reports))
        pu.db
        logging.info(pprint.pformat(api_objects.filterObjects({'output_format'
            : 'XML'}, reports)))

#stand-alone test execution
if __name__ == '__main__':
    import nose2
    nose2.main(argv=['fake', '--log-capture'])

