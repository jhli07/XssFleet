"""
Ngrok Manager
Manage ngrok tunnels, expose local server to public internet
"""

import subprocess
import time
import re
import json
import requests
from typing import Optional, Dict


class NgrokManager:
    def __init__(self):
        self.process = None
        self.public_url = None
        self.api_url = "http://127.0.0.1:4040/api/tunnels"

    def start(self, port: int = 8080) -> Optional[str]:
        """Start ngrok tunnel"""
        try:
            # Check if already running
            if self.is_running():
                self.stop()
                time.sleep(1)

            # Start ngrok
            self.process = subprocess.Popen(
                ['ngrok', 'http', str(port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )

            # Wait for tunnel to establish
            time.sleep(3)

            # Get public URL
            self.public_url = self._get_public_url()
            return self.public_url

        except Exception as e:
            print(f"[-] Failed to start ngrok: {e}")
            return None

    def stop(self):
        """Stop ngrok tunnel"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait()
            except:
                pass
            self.process = None
            self.public_url = None

    def is_running(self) -> bool:
        """Check if ngrok is running"""
        try:
            response = requests.get(self.api_url, timeout=2)
            return response.status_code == 200
        except:
            return False

    def _get_public_url(self) -> Optional[str]:
        """Get public URL from ngrok API"""
        try:
            response = requests.get(self.api_url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                for tunnel in data.get('tunnels', []):
                    if tunnel.get('proto') == 'https':
                        return tunnel.get('public_url')
                    elif tunnel.get('proto') == 'http':
                        return tunnel.get('public_url')
            return None
        except Exception as e:
            return None

    def get_status(self) -> Dict:
        """Get ngrok status info"""
        try:
            response = requests.get(self.api_url, timeout=2)
            if response.status_code == 200:
                return response.json()
            return {}
        except:
            return {}

    def get_public_url(self) -> Optional[str]:
        """Get current public URL"""
        if not self.public_url:
            self.public_url = self._get_public_url()
        return self.public_url

    def __del__(self):
        """Destructor, ensure ngrok is stopped"""
        self.stop()
