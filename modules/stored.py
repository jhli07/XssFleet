"""
Stored XSS Detection Module
"""

import time
from typing import Dict, List, Optional
from ..utils.http import HTTPHandler
from ..payloads.repository import PAYLOADS


class StoredDetector:
    def __init__(self, http_handler: HTTPHandler, verbose: bool = False):
        self.http = http_handler
        self.verbose = verbose

    def detect(self, submit_url: str, form_data: Dict, check_url: str = None) -> List[Dict]:
        results = []

        if not check_url:
            check_url = submit_url

        basic_payloads = PAYLOADS.get('basic', [])[:5]

        for payload in basic_payloads:
            test_data = form_data.copy()
            for key in test_data:
                if not test_data[key] or 'test' in test_data[key].lower():
                    test_data[key] = payload

            try:
                response = self.http.post(submit_url, data=test_data)
                time.sleep(1)

                check_response = self.http.get(check_url)

                if payload in check_response.text:
                    results.append({
                        'type': 'stored',
                        'parameter': list(form_data.keys())[0] if form_data else 'unknown',
                        'payload': payload,
                        'storage_url': check_url,
                        'submit_url': submit_url
                    })
            except:
                continue

        return results
