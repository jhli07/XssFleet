"""
HTTP Request Handler Module
"""

import requests
import urllib.parse
import re
from typing import Dict, Optional, List, Tuple, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class HTTPHandler:
    def __init__(self, timeout: int = 30, user_agent: str = None, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        default_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        self.session.headers.update({
            'User-Agent': user_agent or default_ua
        })
        self.last_response = None

    def parse_url(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for key in params:
            params[key] = params[key][0] if len(params[key]) == 1 else params[key]
        return {
            'scheme': parsed.scheme,
            'netloc': parsed.netloc,
            'path': parsed.path,
            'params': parsed.params,
            'query': parsed.query,
            'fragment': parsed.fragment,
            'params_dict': params
        }

    def build_url(self, parsed_url: Dict, params: Dict = None) -> str:
        query = urlencode(params) if params else parsed_url['query']
        return urlunparse((
            parsed_url['scheme'],
            parsed_url['netloc'],
            parsed_url['path'],
            parsed_url['params'],
            query,
            parsed_url['fragment']
        ))

    def get(self, url: str, params: Dict = None, headers: Dict = None, **kwargs) -> requests.Response:
        response = self.session.get(
            url,
            params=params,
            headers=headers,
            timeout=kwargs.get('timeout', self.timeout),
            verify=False,
            allow_redirects=kwargs.get('allow_redirects', True)
        )
        self.last_response = response
        return response

    def post(self, url: str, data: Dict = None, json: Dict = None, headers: Dict = None, **kwargs) -> requests.Response:
        response = self.session.post(
            url,
            data=data,
            json=json,
            headers=headers,
            timeout=kwargs.get('timeout', self.timeout),
            verify=False,
            allow_redirects=kwargs.get('allow_redirects', True)
        )
        self.last_response = response
        return response

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        response = self.session.request(
            method,
            url,
            timeout=kwargs.get('timeout', self.timeout),
            verify=False,
            allow_redirects=kwargs.get('allow_redirects', True),
            **kwargs
        )
        self.last_response = response
        return response

    def inject_payload_in_url(self, url: str, param: str, payload: str) -> Tuple[str, Dict]:
        parsed = self.parse_url(url)
        original_params = parsed['params_dict'].copy()
        if param in original_params:
            if isinstance(original_params[param], list):
                original_params[param] = [payload]
            else:
                original_params[param] = payload
        else:
            original_params[param] = payload
        new_url = self.build_url(parsed, original_params)
        return new_url, original_params

    def inject_payload_in_post(self, data: Dict, param: str, payload: str) -> Dict:
        new_data = data.copy()
        if param in new_data:
            new_data[param] = payload
        else:
            new_data[param] = payload
        return new_data

    def extract_params_from_form(self, html_content: str, base_url: str) -> Optional[Dict]:
        form_info = {'action': None, 'method': 'get', 'inputs': {}}
        action_match = re.search(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', html_content, re.I)
        if action_match:
            action = action_match.group(1)
            if action.startswith('/'):
                parsed = urlparse(base_url)
                form_info['action'] = f"{parsed.scheme}://{parsed.netloc}{action}"
            elif not action.startswith('http'):
                parsed = urlparse(base_url)
                form_info['action'] = f"{parsed.scheme}://{parsed.netloc}/{action}"
            else:
                form_info['action'] = action
        else:
            form_info['action'] = base_url
        method_match = re.search(r'<form[^>]*method=["\']([^"\']*)["\'][^>]*>', html_content, re.I)
        if method_match:
            form_info['method'] = method_match.group(1).lower()
        input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', re.I)
        for match in input_pattern.finditer(html_content):
            name = match.group(1)
            value_match = re.search(r'value=["\']([^"\']*)["\']', match.group(0), re.I)
            value = value_match.group(1) if value_match else ''
            form_info['inputs'][name] = value
        textarea_pattern = re.compile(r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>', re.I)
        for match in textarea_pattern.finditer(html_content):
            name = match.group(1)
            form_info['inputs'][name] = ''
        select_pattern = re.compile(r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>', re.I)
        for match in select_pattern.finditer(html_content):
            name = match.group(1)
            form_info['inputs'][name] = ''
        return form_info if form_info['inputs'] else None

    def detect_reflection(self, content: str, payload: str) -> bool:
        return payload in content

    def detect_context(self, content: str, payload: str) -> str:
        payload_lower = payload.lower()
        content_lower = content.lower()
        
        if '<script>' in payload_lower and '<script>' in content_lower:
            return 'html'
        if 'onerror' in payload_lower or 'onload' in payload_lower:
            if '=' in content_lower:
                return 'attribute'
            return 'html'
        if '<img' in payload_lower or '<svg' in payload_lower:
            return 'html'
        if 'javascript:' in payload_lower or 'location.' in payload_lower:
            return 'javascript'
        if 'href=' in content_lower or 'src=' in content_lower:
            return 'url'
        if payload_lower in content_lower:
            return 'html'
        return 'html'

    def set_cookie(self, cookie: str):
        self.session.headers.update({'Cookie': cookie})

    def set_header(self, key: str, value: str):
        self.session.headers.update({key: value})

    def get_cookies(self) -> Dict:
        return self.session.cookies.get_dict()

    def close(self):
        self.session.close()
