# PhishLink

A production-ready, open-source phishing tool for ethical red teaming. Supports Office 365, Gmail, and Yahoo Mail with service-specific proxies and seamless email prefill.

## Features
- Service-specific proxies for Office 365, Gmail, and Yahoo Mail
- Phishing links with email fragment: `https://<phishing_domain>#{EMAIL}`
- Auto-prefills email and advances to password page
- JSON-driven configs with schema validation
- Encrypted SQLite storage with TTL cleanup
- Campaign analytics (clicks, captures)
- JavaScript injection for dynamic capture
- Let’s Encrypt SSL support
- Cross-device compatible links
- CLI for link generation, cookie export, and stats

## Installation
```bash
git clone https://github.com/yourusername/phishlink.git
cd phishlink
pip install -r requirements.txt
