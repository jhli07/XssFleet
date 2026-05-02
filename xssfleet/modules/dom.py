"""
DOM XSS Detection Module
"""

from typing import Dict, List, Optional
from bs4 import BeautifulSoup
from ..utils.http import HTTPHandler
from ..payloads.repository import PAYLOADS


class DOMDetector:
    def __init__(self, http_handler: HTTPHandler, verbose: bool = False):
        self.http = http_handler
        self.verbose = verbose

    def detect(self, url: str) -> List[Dict]:
        results = []

        dom_sinks = [
            'innerHTML', 'outerHTML', 'insertAdjacentHTML',
            'document.write', 'document.writeln',
            'location.href', 'location.hash', 'location.search',
            'eval', 'setTimeout', 'setInterval', 'Function',
            'execScript', 'msWriteProfilerMark'
        ]

        try:
            response = self.http.get(url)
            soup = BeautifulSoup(response.text, 'lxml')

            scripts = soup.find_all('script')
            for script in scripts:
                script_content = ''
                if script.string:
                    script_content = script.string
                elif script.get('src'):
                    try:
                        src_response = self.http.get(script['src'])
                        script_content = src_response.text
                    except:
                        continue

                for sink in dom_sinks:
                    if sink in script_content:
                        for payload in PAYLOADS.get('dom_based', [])[:5]:
                            if any(keyword in payload.lower() for keyword in ['location', 'hash', 'href']):
                                results.append({
                                    'type': 'dom',
                                    'parameter': 'location.hash',
                                    'payload': payload,
                                    'sink': sink,
                                    'evidence': f"Sink '{sink}' found in script"
                                })
                                break

            forms = soup.find_all('form')
            for form in forms:
                form_html = str(form)
                for sink in ['innerHTML', 'document.write']:
                    if sink in form_html:
                        results.append({
                            'type': 'dom',
                            'parameter': 'form',
                            'payload': '<img src=x onerror=alert(1)>',
                            'sink': sink,
                            'evidence': f"Sink '{sink}' found in form"
                        })

        except Exception as e:
            if self.verbose:
                print(f"DOM detection error: {str(e)}")

        return results
