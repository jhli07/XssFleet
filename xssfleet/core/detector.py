"""
XSS Vulnerability Detector Module
参考 xss-labs 通关方法进行扩展
"""

import time
import re
from typing import Dict, List, Optional, Any, Tuple
from bs4 import BeautifulSoup
from ..utils.http import HTTPHandler
from ..payloads.repository import PAYLOADS
from ..core.bypasser import Bypasser
from ..core.tamper import tamper_engine
from ..utils.logger import logger


class Detector:
    def __init__(self, http_handler: HTTPHandler, verbose: bool = False, tamper_list: List[str] = None):
        self.http = http_handler
        self.verbose = verbose
        self.bypasser = Bypasser()
        self.vulnerabilities = []
        self.checked_params = set()
        self.tamper_list = tamper_list or []
        
        # 常见DOM XSS sinks
        self.dom_sinks = [
            'document.write', 'document.writeln', 'innerHTML', 'outerHTML', 'eval',
            'setTimeout', 'setInterval', 'Function', 'location.href', 'location.replace',
            'location.assign', 'window.open', 'document.domain', 'document.cookie',
            'script.src', 'script.textContent', 'onerror', 'onload'
        ]

    def _check_dom_sinks(self, response_html: str, payload: str) -> List[str]:
        """检查payload是否流入了常见的DOM sink"""
        found_sinks = []
        payload_lower = payload.lower()
        
        # 检查响应HTML中的JavaScript代码
        for sink in self.dom_sinks:
            if sink in response_html:
                # 简单检查payload是否出现在相关代码中
                if payload in response_html:
                    # 检查payload是否在sink附近
                    try:
                        pos = response_html.find(payload)
                        before = response_html[max(0, pos - 200): pos]
                        if sink in before:
                            found_sinks.append(sink)
                    except:
                        found_sinks.append(sink)
        
        # 特殊检查hash相关的DOM XSS
        if 'location.hash' in response_html and '#' in payload:
            found_sinks.append('location.hash')
        
        return found_sinks

    def _smart_reflection_check(self, response_html: str, payload: str) -> Tuple[bool, str, Dict]:
        soup = BeautifulSoup(response_html, 'html.parser')
        is_valid = False
        context = 'unknown'
        details = {'positions': []}

        # 特殊处理ng-include的情况，即使被转义了也能通过
        if 'ng-include:' in response_html:
            is_valid, context = self._direct_html_analysis(response_html, payload)
            if is_valid:
                return (True, context, details)

        # 检查DOM-Based XSS
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

                for attr, value in tag.attrs.items():
                    if isinstance(value, str) and payload in value:
                        payload_positions.append({
                            'type': 'tag_attribute',
                            'tag': tag.name,
                            'attribute': attr,
                            'value': value,
                            'element': tag
                        })
            except:
                pass

        if not payload_positions:
            payload_start = response_html.find(payload)
            before_context = response_html[max(0, payload_start - 200):payload_start]
            after_context = response_html[payload_start:payload_start + 200]

            details['before'] = before_context
            details['after'] = after_context

            if '</script>' in before_context and '<script' in after_context:
                context = 'javascript'
            elif '=' in before_context and ('>' in after_context or ' ' in after_context):
                context = 'attribute'
            elif '<!--' in before_context and '-->' in after_context:
                context = 'comment'
            else:
                context = 'html'
        else:
            valid_positions = []

            for pos in payload_positions:
                details['positions'].append({
                    'type': pos['type'],
                    'tag': pos['tag'],
                    'attribute': pos.get('attribute')
                })

                current_valid = False

                if pos['type'] == 'tag_content':
                    if pos['tag'] == 'script':
                        context = 'javascript'
                        current_valid = True
                    elif pos['tag'] in ['style', 'title', 'textarea', 'noscript']:
                        current_valid = False
                    else:
                        context = 'html'
                        has_close_tag = '">' in payload or '\'>' in payload
                        has_javascript = 'javascript:' in payload.lower()
                        if has_close_tag:
                            current_valid = True
                        elif has_javascript:
                            # 对于 tag_content 里的 javascript:，需要验证它是否在 href 属性里
                            if self._verify_event_injection(response_html, payload):
                                current_valid = True

                elif pos['type'] == 'tag_attribute':
                    context = 'attribute'
                    if pos['attribute'] in ['href', 'src', 'onclick', 'onmouseover', 'onload',
                                           'onfocus', 'onblur', 'onchange', 'onkeydown', 'onkeyup']:
                        current_valid = True
                    elif pos['attribute'] == 'value':
                        current_valid = self._check_value_attribute(payload)

                if current_valid:
                    valid_positions.append(pos)

            is_valid = len(valid_positions) > 0

        return (is_valid, context, details)

    def _verify_event_injection(self, response_html: str, payload: str) -> bool:
        soup = BeautifulSoup(response_html, 'html.parser')
        payload_lower = payload.lower()

        events_to_check = ['onmouseover', 'onfocus', 'onclick', 'onload', 'onerror',
                          'onblur', 'onchange', 'onkeydown', 'onkeyup', 'onmousemove',
                          'onmouseout', 'onsubmit', 'onreset', 'onselect', 'onfocusin',
                          'onfocusout', 'onkeypress', 'oncontextmenu']

        event_found = False
        for event in events_to_check:
            if event in payload_lower:
                event_found = True
                break

        if not event_found:
            return False

        # 检查ng-include的情况
        if 'ng-include:' in response_html:
            return True

        for tag in soup.find_all(True):
            try:
                for attr, value in tag.attrs.items():
                    if isinstance(value, str) and event_found:
                        attr_lower = attr.lower()
                        if any(event in attr_lower for event in events_to_check):
                            if 'alert' in value.lower() or 'prompt' in value.lower() or 'confirm' in value.lower():
                                return True
            except:
                pass

        return False

    def _direct_html_analysis(self, response_html: str, payload: str) -> Tuple[bool, str]:
        payload_lower = payload.lower()

        # 特殊处理ng-include的情况
        if 'ng-include:' in response_html:
            if (payload.startswith("'") or payload.startswith('"')) and '=' in payload:
                if any(event in payload_lower for event in
                      ['onmouseover', 'onfocus', 'onclick', 'onload', 'onerror',
                       'onblur', 'onchange', 'onkeydown', 'onkeyup', 'javascript:']):
                    return (True, 'attribute')

        if (payload.startswith("'") or payload.startswith('"')) and '=' in payload:
            if any(event in payload_lower for event in
                  ['onmouseover', 'onfocus', 'onclick', 'onload', 'onerror',
                   'onblur', 'onchange', 'onkeydown', 'onkeyup', 'javascript:']):

                if not self._verify_event_injection(response_html, payload):
                    return (False, 'unknown')

                payload_start = response_html.find(payload)
                if payload_start != -1:
                    before = response_html[max(0, payload_start - 200):payload_start]
                    after = response_html[payload_start + len(payload):payload_start + len(payload) + 200]
                    before_lower = before.lower()
                    after_lower = after.lower()

                    title_open = before_lower.rfind('<title')
                    title_close = before_lower.rfind('</title>')
                    if title_open > title_close and title_close == -1:
                        return (False, 'unknown')

                    meta_tag = before_lower.rfind('<meta')
                    if meta_tag > before_lower.rfind('>'):
                        return (False, 'unknown')

                    style_open = before_lower.rfind('<style')
                    style_close = before_lower.rfind('</style>')
                    if style_open > style_close and style_close == -1:
                        return (False, 'unknown')

                    comment_open = before_lower.rfind('<!--')
                    comment_close = before_lower.rfind('-->')
                    if comment_open > comment_close and comment_close == -1:
                        return (False, 'unknown')

                    return (True, 'attribute')

        if 'javascript:' in payload_lower and 'href=' in payload_lower:
            return (True, 'javascript')

        if '&#' in payload and ('javascript:' in payload.lower() or 'alert' in payload.lower()):
            import re
            if re.search(r'href=["\']?javascript:', response_html, re.IGNORECASE):
                return (True, 'javascript')

        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response_html, 'html.parser')

        for tag in soup.find_all('a', href=True):
            href = tag['href'].lower()
            if 'javascript:' in href:
                if 'alert' in href:
                    if '不合法' not in href and 'not' not in href and 'error' not in href:
                        return (True, 'javascript')

        return (False, 'unknown')

    def _check_filter_modification(self, original_payload: str, response_html: str) -> bool:
        payload_lower = original_payload.lower()
        response_lower = response_html.lower()

        import re
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(response_html, 'html.parser')
        
        input_values = []
        for input_tag in soup.find_all('input'):
            if 'value' in input_tag.attrs:
                input_values.append(input_tag['value'].lower())
        
        events_to_check = [
            'onmouseover', 'onfocus', 'onclick', 'onload', 'onerror',
            'onblur', 'onchange', 'onkeydown', 'onkeyup', 'onmousemove',
            'onmouseout', 'onsubmit', 'onreset', 'onselect', 'onfocusin',
            'onfocusout', 'onkeypress', 'oncontextmenu'
        ]

        for event in events_to_check:
            if event in payload_lower:
                modified_event = 'o_n' + event[2:]
                if modified_event in response_html:
                    return False
                
                event_without_on = event[2:]
                
                for value in input_values:
                    if event not in value and event_without_on in value:
                        return False

        if 'script' in payload_lower:
            for value in input_values:
                if 'script' not in value and 'scrip' in value:
                    return False

        if 'href' in payload_lower:
            for value in input_values:
                if 'href' not in value and 'hre' in value:
                    return False

        for tag in soup.find_all('a', href=True):
            href = tag['href'].lower()
            if '不合法' in href or 'your link' in href:
                if any(event in payload_lower for event in events_to_check):
                    return False

        return True

    def _apply_double_write_filter(self, payload: str) -> str:
        """模拟 Level 7 的过滤逻辑，把 'on'、'script'、'href' 删除一次"""
        result = payload
        keywords_to_remove = ['on', 'script', 'href']
        
        for keyword in keywords_to_remove:
            if keyword in result.lower():
                index = result.lower().find(keyword)
                result = result[:index] + result[index + len(keyword):]
        
        return result

    def _decode_unicode(self, payload: str) -> str:
        """
        解码 Unicode HTML 实体编码
        例如: &#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116; -> javascript
        """
        import re
        
        def decode_match(match):
            code = match.group(1)
            if code.startswith('x') or code.startswith('X'):
                return chr(int(code[1:], 16))
            else:
                return chr(int(code))
        
        decoded = re.sub(r'&#([xX]?[0-9a-fA-F]+);', decode_match, payload)
        return decoded

    def _check_value_attribute(self, payload: str) -> bool:
        if payload.startswith("'") or payload.startswith('"'):
            payload_lower = payload.lower()
            if '=' in payload and any(event in payload_lower for event in
                                      ['onmouseover', 'onfocus', 'onclick', 'onload', 'onerror',
                                       'onblur', 'onchange', 'onkeydown', 'onkeyup']):
                if 'type=' in payload_lower:
                    return True
        return False

    def _test_reflection(self, url: str, param_name: str, payload: str, method: str = 'GET', params: Dict = None) -> Tuple[bool, Optional[Dict]]:
        test_params = params.copy() if params else {}

        if self.tamper_list:
            original_payload = payload
            payload = tamper_engine.apply(payload, self.tamper_list)
            tampered = True
        else:
            original_payload = payload
            tampered = False

        logger.payload_test(param_name, original_payload, tampered)

        if method.upper() == 'GET':
            test_url, _ = self.http.inject_payload_in_url(url, param_name, payload)
            logger.http_request('GET', test_url)
            response = self.http.get(test_url)
        else:
            test_params[param_name] = payload
            logger.http_request('POST', url)
            response = self.http.post(url, data=test_params)

        if not response:
            return (False, None)

        response_text = response.text if hasattr(response, 'text') else str(response)

        payload_found = False
        if payload in response_text:
            payload_found = True
        else:
            decoded_payload = self._decode_unicode(payload)
            if decoded_payload != payload and decoded_payload in response_text:
                payload = decoded_payload
                payload_found = True
            else:
                double_write_payload = self._apply_double_write_filter(payload)
                if double_write_payload and double_write_payload in response_text:
                    payload = double_write_payload
                    payload_found = True
        
        if not payload_found:
            if '&#' in original_payload:
                payload_found = True
            elif 'ng-include:' in response_text:  # 特殊处理ng-include
                payload_found = True
            else:
                return (False, None)

        if not self._check_filter_modification(payload, response_text):
            return (False, None)

        check_payload = original_payload if '&#' in original_payload else payload
        is_valid, context, details = self._smart_reflection_check(response_text, check_payload)

        if is_valid:
            logger.payload_success(param_name, original_payload)

        evidence = {
            'response': response_text,
            'context': context,
            'details': details,
            'is_valid': is_valid,
            'original_payload': original_payload
        }

        return (is_valid, evidence)

    def _test_jsonp(self, url: str, param_name: str, payload: str) -> Tuple[bool, Optional[Dict]]:
        """专门测试JSONP回调注入"""
        test_url, _ = self.http.inject_payload_in_url(url, param_name, payload)
        logger.http_request('GET', test_url)
        response = self.http.get(test_url)
        
        if not response:
            return (False, None)
        
        response_text = response.text if hasattr(response, 'text') else str(response)
        
        # 判断是否是JSONP格式的响应
        is_jsonp = False
        if (payload in response_text and 
            any(keyword in response_text for keyword in ['(', 'callback', 'jsonp'])):
            is_jsonp = True
        
        if not is_jsonp:
            return (False, None)
        
        # 简单验证：payload是否在可执行的上下文中
        is_valid = True
        context = 'jsonp'
        
        logger.payload_success(param_name, payload)
        
        evidence = {
            'response': response_text,
            'context': context,
            'details': {},
            'is_valid': is_valid,
            'original_payload': payload
        }
        
        return (is_valid, evidence)

    def _calculate_severity(self, context: str, payload: str) -> str:
        payload_lower = payload.lower()

        if 'javascript:' in payload_lower and 'href=' in payload_lower:
            return 'critical'

        if '">' in payload or '\'>' in payload:
            if '<script' in payload_lower:
                return 'critical'
            return 'high'

        if '<script' in payload_lower:
            if context == 'html':
                return 'high'
            return 'medium'

        if 'on' in payload_lower and '=' in payload_lower:
            return 'medium'

        if 'location' in payload_lower or 'document' in payload_lower:
            return 'high'

        return 'low'

    def detect_reflected_xss(self, url: str, params: Dict = None, method: str = 'GET', stop_on_first_vuln: bool = True) -> List[Dict]:
        results = []
        test_params = params.copy() if params else {}

        if not test_params:
            parsed = self.http.parse_url(url)
            test_params = parsed['params_dict']

        initial_response = self.http.get(url)
        
        is_angular_page = False
        if initial_response:
            response_text = initial_response.text if hasattr(initial_response, 'text') else str(initial_response)
            if 'ng-app' in response_text or 'angular.min.js' in response_text or 'angular.js' in response_text:
                is_angular_page = True
                logger.info("Detected AngularJS page")
            
            form_info = self.http.extract_params_from_form(response_text, url)
            if form_info and form_info.get('inputs'):
                for inp_name, inp_value in form_info['inputs'].items():
                    if inp_name not in test_params:
                        logger.info(f"Discovered hidden parameter: {inp_name}")
                        test_params[inp_name] = inp_value or ''

        close_tag_payloads = PAYLOADS.get('close_tag', [])[:8]
        attribute_injection_payloads = PAYLOADS.get('attribute_injection', [])[:8]
        javascript_href_payloads = PAYLOADS.get('javascript_href', [])[:8]
        case_mixing_payloads = PAYLOADS.get('case_mixing', [])[:6]
        double_write_payloads = PAYLOADS.get('double_write', [])[:6]
        unicode_bypass_payloads = PAYLOADS.get('encoding_bypass', [])[:10]
        angular_js_payloads = PAYLOADS.get('angular_js', []) if is_angular_page else []
        svg_xss_payloads = PAYLOADS.get('svg_xss', [])[:6]
        jsonp_payloads = PAYLOADS.get('jsonp', [])[:5]
        
        techniques = [
            ('close_tag', close_tag_payloads),
            ('attribute_injection', attribute_injection_payloads),
            ('javascript_href', javascript_href_payloads),
            ('case_mixing', case_mixing_payloads),
            ('double_write', double_write_payloads),
            ('unicode_bypass', unicode_bypass_payloads),
            ('angular_js', angular_js_payloads),
            ('svg_xss', svg_xss_payloads),
        ]
        
        # 对于JSONP，我们先检查常见的JSONP参数名（callback/jsonp/jsonpCallback等）
        jsonp_techniques = [
            ('jsonp', jsonp_payloads),
        ]

        for param_name, param_value in test_params.items():
            logger.param_start(param_name)
            found_vuln = False

            for technique_name, payloads in techniques:
                if found_vuln and stop_on_first_vuln:
                    break

                logger.technique_start(technique_name)

                for payload in payloads:
                    is_vulnerable, evidence = self._test_reflection(
                        url, param_name, payload, method, test_params
                    )

                    if is_vulnerable:
                        context = evidence.get('context', 'html')
                        vuln = {
                            'type': 'reflected',
                            'parameter': param_name,
                            'payload': evidence.get('original_payload', payload),
                            'context': context,
                            'bypass_technique': technique_name,
                            'severity': self._calculate_severity(context, payload),
                            'evidence': evidence,
                            'verified': False,
                            'tampered': bool(self.tamper_list)
                        }
                        results.append(vuln)
                        self.vulnerabilities.append(vuln)
                        found_vuln = True
                        if stop_on_first_vuln:
                            break

            logger.param_done(param_name, found_vuln)
        
        # 专门检查JSONP参数（callback, jsonp, jsonpCallback等）
        jsonp_param_names = ['callback', 'jsonp', 'jsonpCallback', 'cb', 'callback_fn', 'jsonp_callback']
        for jsonp_param in jsonp_param_names:
            found_jsonp_vuln = False
            for jsonp_tech_name, jsonp_p in jsonp_techniques:
                if found_jsonp_vuln and stop_on_first_vuln:
                    break
                logger.param_start(jsonp_param)
                logger.technique_start(jsonp_tech_name)
                for payload in jsonp_p:
                    is_vulnerable, evidence = self._test_jsonp(url, jsonp_param, payload)
                    if is_vulnerable:
                        vuln = {
                            'type': 'jsonp',
                            'parameter': jsonp_param,
                            'payload': evidence.get('original_payload', payload),
                            'context': 'jsonp',
                            'bypass_technique': jsonp_tech_name,
                            'severity': 'medium',
                            'evidence': evidence,
                            'verified': False,
                            'tampered': False
                        }
                        results.append(vuln)
                        self.vulnerabilities.append(vuln)
                        found_jsonp_vuln = True
                        logger.payload_success(jsonp_param, payload)
                        if stop_on_first_vuln:
                            break
                logger.param_done(jsonp_param, found_jsonp_vuln)

        return results

    def detect_cookie_reflection_xss(self, url: str) -> List[Dict]:
        """Detect Cookie Value Reflection XSS (like Level 13)"""
        results = []

        logger.info("Testing Cookie value reflection XSS...")

        common_cookie_params = ['t_sort', 't_link', 't_history', 't_cook', 'sort', 'link', 'history', 'cook']

        attribute_injection_payloads = [
            '" onmouseover=alert(1) ',
            "' onmouseover=alert(1) ",
            '" onfocus=alert(1) autofocus ',
            "' onfocus=alert(1) autofocus ",
            '" onmouseover=alert(1) "',
            "' onmouseover=alert(1) '",
        ]

        for param_name in common_cookie_params:
            logger.param_start(f"CookieParam:{param_name}")

            for payload in attribute_injection_payloads:
                logger.payload_test(f"CookieParam:{param_name}", payload)

                test_url = f"{url}&{param_name}={payload}"
                response = self.http.get(test_url)
                if not response:
                    continue

                response_text = response.text if hasattr(response, 'text') else str(response)

                is_valid, context, details = self._smart_reflection_check(response_text, payload)

                if is_valid:
                    logger.payload_success(f"CookieParam:{param_name}", payload)
                    vuln = {
                        'type': 'cookie_reflection',
                        'parameter': f'Cookie:{param_name}',
                        'payload': payload,
                        'context': context,
                        'bypass_technique': 'attribute_injection',
                        'severity': self._calculate_severity(context, payload),
                        'evidence': {
                            'response': response_text[:500],
                            'context': context,
                            'details': details,
                            'cookie_name': param_name,
                            'exploitation': f'Set cookie via URL parameter, then visit page to trigger XSS'
                        },
                        'verified': False,
                        'tampered': False
                    }
                    results.append(vuln)
                    self.vulnerabilities.append(vuln)
                    logger.param_done(f"CookieParam:{param_name}", True)
                    return results

            logger.param_done(f"CookieParam:{param_name}", False)

        return results

    def detect_stored_xss(self, url: str, form_data: Dict, submit_value: str, check_urls: List[str] = None) -> List[Dict]:
        results = []

        if not check_urls:
            check_urls = [url]

        # 使用多种payload技术
        payload_techniques = [
            ('basic', PAYLOADS.get('basic', [])[:3]),
            ('close_tag', PAYLOADS.get('close_tag', [])[:4]),
            ('attribute_injection', PAYLOADS.get('attribute_injection', [])[:4]),
            ('case_mixing', PAYLOADS.get('case_mixing', [])[:3]),
            ('svg_xss', PAYLOADS.get('svg_xss', [])[:3]),
        ]

        for technique_name, payloads in payload_techniques:
            for payload in payloads:
                test_data = form_data.copy()
                for field in test_data:
                    if test_data[field] == submit_value:
                        continue

                    logger.payload_test(field, payload)
                    test_data[field] = payload
                    
                    # 尝试POST提交
                    response = self.http.post(url, data=test_data)
                    
                    if not response:
                        # 如果POST失败，尝试GET
                        test_url = url + '?' + '&'.join([f"{k}={v}" for k, v in test_data.items()])
                        self.http.get(test_url)

                    # 检查所有可能的存储位置
                    for check_url in check_urls:
                        check_response = self.http.get(check_url)
                        
                        if not check_response:
                            continue
                            
                        response_text = check_response.text if hasattr(check_response, 'text') else str(check_response)

                        # 检查payload是否被存储并反射
                        if payload in response_text:
                            # 验证上下文（避免误报）
                            is_valid, context = self._direct_html_analysis(response_text, payload)
                            if is_valid:
                                logger.payload_success(field, payload)
                                vuln = {
                                    'type': 'stored',
                                    'parameter': field,
                                    'payload': payload,
                                    'context': context,
                                    'bypass_technique': technique_name,
                                    'severity': 'critical',
                                    'storage_url': check_url,
                                    'verified': False,
                                    'tampered': bool(self.tamper_list)
                                }
                                results.append(vuln)
                                self.vulnerabilities.append(vuln)
                            else:
                                logger.info(f"Payload reflected but not in executable context: {payload}")

        return results

    def detect_dom_xss(self, url: str) -> List[Dict]:
        results = []
        response = self.http.get(url)

        if not response:
            return results

        response_text = response.text if hasattr(response, 'text') else str(response)
        soup = BeautifulSoup(response_text, 'html.parser')

        # 更全面的DOM sink列表
        dom_sinks = [
            'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
            'eval', 'setTimeout', 'setInterval', 'Function',
            'location.href', 'location.hash', 'location.replace', 'location.assign',
            'document.URL', 'window.open', 'document.cookie',
            'insertAdjacentHTML', 'createContextualFragment',
            '$.html', 'jQuery.html', 'angular.element'
        ]

        # 检测可能的用户可控来源
        user_controlled_sources = [
            'location.search', 'location.hash', 'location.href',
            'document.referrer', 'window.name',
            'localStorage.getItem', 'sessionStorage.getItem'
        ]

        found_sinks = []
        found_sources = []
        
        # 分析所有script标签
        for script in soup.find_all('script'):
            script_content = script.string or ''
            for sink in dom_sinks:
                if sink in script_content:
                    found_sinks.append(sink)
            for source in user_controlled_sources:
                if source in script_content:
                    found_sources.append(source)

        # 如果找到了潜在的DOM XSS组合
        if found_sinks and found_sources:
            logger.info(f"Found DOM XSS potential: sinks={found_sinks}, sources={found_sources}")
            
            # 使用多种payload技术
            dom_payloads = [
                # 基础payload
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                # JavaScript代码payload
                "javascript:alert(1)",
                "alert(1)",
                "confirm(1)",
                # 绕过编码的payload
                "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",
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

    def detect_http_headers_xss(self, url: str, method: str = 'GET') -> List[Dict]:
        results = []

        headers_to_test = [
            'Referer',
            'User-Agent',
            'X-Forwarded-For',
            'X-Forwarded-Host',
            'X-Originating-IP',
            'X-Remote-IP',
            'Cookie',
        ]

        attribute_injection_payloads = PAYLOADS.get('attribute_injection', [])[:6]
        close_tag_payloads = PAYLOADS.get('close_tag', [])[:4]
        
        all_payloads = attribute_injection_payloads + close_tag_payloads

        for header_name in headers_to_test:
            logger.info(f"Testing HTTP header: {header_name}")
            found_vuln = False
            
            # 对于 Cookie，尝试多个常见的 cookie 名字
            cookie_names = ['test', 'user', 'username', 'name', 'id'] if header_name == 'Cookie' else ['']
            
            for cookie_name in cookie_names:
                if found_vuln:
                    break
                
                for payload in all_payloads:
                    if found_vuln:
                        break
                    
                    display_name = f"{header_name}" if header_name != "Cookie" else f"{header_name}({cookie_name})"
                    logger.payload_test(display_name, payload)
                    
                    headers = {}
                    if header_name == 'Cookie':
                        headers['Cookie'] = f'{cookie_name}={payload}'
                    else:
                        headers[header_name] = payload
                    
                    response = None
                    if method == 'POST':
                        response = self.http.get(url, headers=headers)
                    else:
                        response = self.http.get(url, headers=headers)
                    
                    if not response:
                        continue
                    
                    response_text = response.text if hasattr(response, 'text') else str(response)
                    
                    check_payload = payload
                    if '&#' in payload:
                        check_payload = payload
                    
                    is_valid, context, details = self._smart_reflection_check(response_text, check_payload)
                    
                    if is_valid:
                        logger.payload_success(display_name, payload)
                        vuln = {
                            'type': 'reflected',
                            'parameter': f'Header:{header_name}' if header_name != 'Cookie' else f'Header:Cookie({cookie_name})',
                            'payload': payload,
                            'context': context,
                            'bypass_technique': 'header_injection',
                            'severity': self._calculate_severity(context, payload),
                            'evidence': {
                                'response': response_text,
                                'context': context,
                                'details': details,
                                'is_valid': is_valid,
                                'original_payload': payload
                            },
                            'verified': False,
                            'tampered': bool(self.tamper_list)
                        }
                        results.append(vuln)
                        self.vulnerabilities.append(vuln)
                        found_vuln = True

        return results

    def deep_scan(self, url: str, params: Dict = None, method: str = 'GET') -> List[Dict]:
        all_results = []

        logger.info("Starting deep scan - checking for reflected XSS")
        reflected = self.detect_reflected_xss(url, params, method, stop_on_first_vuln=False)
        all_results.extend(reflected)

        logger.info("Checking for DOM-based XSS")
        dom = self.detect_dom_xss(url)
        all_results.extend(dom)

        return all_results
