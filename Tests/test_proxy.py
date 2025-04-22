import unittest
from proxy_base import BaseProxyHandler

class TestProxy(unittest.TestCase):
    def test_proxy_init(self):
        config = {
            'service_name': 'office365',
            'target_domain': 'login.microsoftonline.com',
            'phishing_domain': 'o365-login.com',
            'capture_rules': {'credentials': [], 'cookies': []},
            'lure': {}
        }
        store = None
        analytics = None
        handler = BaseProxyHandler(config, store, analytics, None, None)
        self.assertEqual(handler.config['service_name'], 'office365')

if __name__ == '__main__':
    unittest.main()
