import sqlite3
import json
from cryptography.fernet import Fernet
import os
import logging
from datetime import datetime, timedelta

class DataStore:
    def __init__(self, storage_config):
        self.database = storage_config['database']
        self.encrypt = storage_config['encrypt']
        self.ttl_hours = storage_config.get('ttl_hours', 24)
        self.key = Fernet.generate_key() if self.encrypt else None
        self.cipher = Fernet(self.key) if self.encrypt else None
        self.conn = None
        self.init_db()

    def init_db(self):
        try:
            self.conn = sqlite3.connect(self.database)
            cursor = self.conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS captures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    data TEXT,
                    session_id TEXT,
                    service_name TEXT
                )
            ''')
            self.conn.commit()
        except Exception as e:
            logging.error(f"Database init error: {e}")
            raise

    def save(self, entry, session_id, service_name):
        entry['timestamp'] = datetime.utcnow().isoformat()
        data = json.dumps(entry)
        if self.encrypt:
            data = self.cipher.encrypt(data.encode()).decode()
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                'INSERT INTO captures (timestamp, data, session_id, service_name) VALUES (?, ?, ?, ?)',
                (entry['timestamp'], data, session_id, service_name)
            )
            self.conn.commit()
            self.cleanup()
        except Exception as e:
            logging.error(f"Save error: {e}")

    def cleanup(self):
        if self.ttl_hours == 0:
            return
        try:
            cursor = self.conn.cursor()
            cutoff = (datetime.utcnow() - timedelta(hours=self.ttl_hours)).isoformat()
            cursor.execute('DELETE FROM captures WHERE timestamp < ?', (cutoff,))
            self.conn.commit()
        except Exception as e:
            logging.error(f"Cleanup error: {e}")

    def export_cookies(self, session_id=None, service_name=None):
        cookies = []
        try:
            cursor = self.conn.cursor()
            query = 'SELECT data, service_name FROM captures'
            params = []
            if session_id:
                query += ' WHERE session_id = ?'
                params.append(session_id)
            if service_name:
                query += ' AND' if session_id else ' WHERE'
                query += ' service_name = ?'
                params.append(service_name)
            cursor.execute(query, params)
            for row in cursor.fetchall():
                data = row[0]
                if self.encrypt:
                    data = self.cipher.decrypt(data.encode()).decode()
                entry = json.loads(data)
                if 'cookies' in entry:
                    cookies.extend([
                        {"name": k, "value": v, "domain": config['target_domain']}
                        for k, v in entry['cookies'].items()
                    ])
        except Exception as e:
            logging.error(f"Export error: {e}")
        return cookies

    def close(self):
        if self.conn:
            self.conn.close()
