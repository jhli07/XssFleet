"""
Reflected XSS Detection Module
"""

from typing import Dict, List, Tuple
from ..utils.http import HTTPHandler
from ..payloads.repository import PAYLOADS


class ReflectedDetector:
    def __init__(self, http_handler: HTTPHandler, verbose: bool = False):
        self.http = http_handler
        self.verbose = verbose

    def detect(self, url: str, params: Dict = None, method: str = 'GET') -> List[Dict]:
        results = []
        test_params = params.copy() if params else {}

        if not test_params:
            parsed = self.http.parse_url(url)
            test_params = parsed['params_dict']

        basic_payloads = PAYLOADS.get('basic', [])

        for param_name in test_params.keys():
            for payload in basic_payloads:
                is_vuln, evidence = self._test_parameter(url, param_name, payload, method, test_params)
                if is_vuln:
                    results.append({
                        'type': 'reflected',
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': evidence
                    })
                    break

        return results

    def _test_parameter(self, url: str, param: str, payload: str, method: str, base_params: Dict) -> Tuple[bool, Dict]:
        evidence = {'response': '', 'original': ''}

        try:
            if method.upper() == 'GET':
                test_url, _ = self.http.inject_payload_in_url(url, param, payload)
                response = self.http.get(test_url)
            else:
                test_data = self.http.inject_payload_in_post(base_params, param, payload)
                response = self.http.post(url, data=test_data)

            evidence['response'] = response.text
            return payload in response.text, evidence
        except:
            return False, evidence
