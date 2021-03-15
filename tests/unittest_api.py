import unittest
import sys
import os
import qualysapi
import requests


class UserTest(unittest.TestCase):
    token = None

    def setUp(self):
        self.user = os.environ["qualys_user"]
        self.password = os.environ["qualys_password"]
        self.qualys_host = "qualysapi.qualys.eu"
        self.qualys_api_gw = "gateway.qg1.apps.qualys.eu"
        self.qualys_proxy = None
        self.connector = qualysapi.connector.QGConnector(
            auth=(self.user, self.password),
            server=self.qualys_host,
            api_gw=self.qualys_api_gw,
            proxies=self.qualys_proxy,
            max_retries="3",
        )
        self.token = self.connector.gitai_auth.token

    def test_connect(self):
        self.assertIsInstance(self.connector, qualysapi.connector.QGConnector)
        self.assertIsInstance(self.connector.session, requests.Session)
        self.assertIsNotNone(self.connector.gitai_auth)

    def test_gitai_filter(self):

        ret = self.connector.qualys_gitai_filter_list_assets(
            pagesize=1,
            query="agent.activations.status:ACTIVE",
            includeFields=[
                "cloudProvider",
                "operatingSystem",
                "software",
                "volume",
                "hardware",
                "agent",
                "inventory",
                "sensor",
                "activity",
            ],
        )
        self.assertIn("responseMessage", ret.keys())
        self.assertEqual(ret["responseMessage"], "Valid API Access")
        self.assertEqual(ret["count"], 1)

    def test_gitai_list_assets(self):

        ret = self.connector.qualys_gitai_list_assets(pagesize=10)
        self.assertIn("responseMessage", ret.keys())
        self.assertEqual(ret["responseMessage"], "Valid API Access")
        self.assertEqual(ret["count"], 10)

    def test_reconnect(self):
        self.assertNotEqual(self.token, None)
        temp_token = self.token
        self.connector.gitai_auth.reauth()
        self.token = self.connector.gitai_auth.token
        self.assertNotEqual(self.token, temp_token)

    def test_connect_with_token(self):
        self.assertNotEqual(self.token, None)
        temp_token = self.token
        self.connector = qualysapi.connector.QGConnector(
            auth=(self.user, self.password),
            server=self.qualys_host,
            api_gw=self.qualys_api_gw,
            proxies=self.qualys_proxy,
            max_retries="3",
            token=temp_token,
        )
        self.assertEqual(self.connector.gitai_auth.token, temp_token)


def suite():
    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(UserTest("test_connect"))
    suite.addTest(UserTest("test_gitai_filter"))
    suite.addTest(UserTest("test_gitai_list_assets"))
    suite.addTest(UserTest("test_reconnect"))
    suite.addTest(UserTest("test_connect_with_token"))

    return suite


if __name__ == "__main__":
    # ============= Test Stuff
    runner = unittest.TextTestRunner(descriptions=True, failfast=True)
    ret = not runner.run(suite()).wasSuccessful()
    sys.exit(ret)
