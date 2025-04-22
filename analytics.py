import sqlite3
import logging
from datetime import datetime

class Analytics:
    def __init__(self, analytics_config):
        self.enabled = analytics_config['enabled']
        self.database = analytics_config.get('database', 'analytics.db')
        self.conn = None
        if self.enabled:
            self.init_db()

    def init_db(self):
        try:
            self.conn = sqlite3.connect(self.database)
            cursor = self.conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    event_type TEXT,
                    session_id TEXT,
                    service_name TEXT,
                    details TEXT
                )
            ''')
            self.conn.commit()
        except Exception as e:
            logging.error(f"Analytics init error: {e}")
            raise

    def log_event(self, event_type, session_id, service_name, details=None):
        if not self.enabled:
            return
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                'INSERT INTO events (timestamp, event_type, session_id, service_name, details) VALUES (?, ?, ?, ?, ?)',
                (datetime.utcnow().isoformat(), event_type, session_id, service_name, json.dumps(details) if details else None)
            )
            self.conn.commit()
        except Exception as e:
            logging.error(f"Event log error: {e}")

    def get_stats(self, service_name=None):
        if not self.enabled:
            return {}
        try:
            cursor = self.conn.cursor()
            query = 'SELECT event_type, COUNT(*) FROM events'
            params = []
            if service_name:
                query += ' WHERE service_name = ?'
                params.append(service_name)
            query += ' GROUP BY event_type'
            cursor.execute(query, params)
            stats = dict(cursor.fetchall())
            query = 'SELECT COUNT(DISTINCT session_id) FROM events'
            if service_name:
                query += ' WHERE service_name = ?'
            cursor.execute(query, params)
            stats['unique_sessions'] = cursor.fetchone()[0]
            return stats
        except Exception as e:
            logging.error(f"Stats error: {e}")
            return {}

    def close(self):
        if self.conn:
            self.conn.close()
