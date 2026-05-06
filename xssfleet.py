#!/usr/bin/env python3
"""
XssFleet - XSS Vulnerability Automatic Penetration Testing Tool

Usage:
    python xssfleet.py -u "http://target.com/search?q=test"
    python xssfleet.py -u "http://target.com/page" --method POST --data "username=test&email=test@test.com"
    python xssfleet.py -m urls.txt --deep
    python xssfleet.py -u "http://target.com" -p q --tamper=space2comment,base64encode
"""

import sys
import os
os.environ['PYTHONWARNINGS'] = 'ignore'
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import argparse
from typing import Dict, List, Optional

_script_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_script_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from colorama import Fore, Style, init

init(autoreset=True)

from xssfleet.utils.http import HTTPHandler
from xssfleet.core.detector import Detector
from xssfleet.core.verifier import Verifier
from xssfleet.core.browser import BrowserEnvironment
from xssfleet.core.tamper import tamper_engine
from xssfleet.utils.report import ReportGenerator
from xssfleet.payloads.repository import PAYLOAD_CATEGORIES
from xssfleet.utils.logger import logger, set_log_level
from xssfleet.core.exploiter import XSSExploiter


class XssFleet:
    def __init__(self, args):
        self.args = args
        self.http_handler = None
        self.detector = None
        self.verifier = None
        self.report = ReportGenerator()
        self.results = []
        self.tamper_list = []
        
        if hasattr(args, 'tamper') and args.tamper:
            self.tamper_list = [t.strip() for t in args.tamper.split(',')]
        
        log_level = min(4 + args.verbose, 6)
        set_log_level(log_level)

    def _print_banner(self):
        print()
        print(f"{Fore.CYAN}     _   _   _____   _____   ______   _        ______   ______   ______      _______ {Style.RESET_ALL}")
        print(f"{Fore.CYAN}    | \\ / | / ____| / ____| |  ____| | |      |  ____| |  ____| |  ____|   |__   __|{Style.RESET_ALL}")
        print(f"{Fore.CYAN}    |  \\/  | | (___   \\___ \\  | |___   | |      | |___   | |___   | |___     | |   {Style.RESET_ALL}")
        print(f"{Fore.CYAN}    |  /\\  |  \\___ \\   ___) | |  ___|  | |      |  ___|  |  ___|  |  ___|    | |   {Style.RESET_ALL}")
        print(f"{Fore.CYAN}    | / \\ |  ____) | |____/  | |      | |____  | |____  | |____  | |____      | |   {Style.RESET_ALL}")
        print(f"{Fore.CYAN}    |_/  \\_| |_____/ |_____|  |_|      |______| |______| |______| |______|    |_|   {Style.RESET_ALL}")
        print()
        print(f"{Fore.GREEN}    [+]{Style.RESET_ALL} {Fore.WHITE}Version: v2.0.0{Style.RESET_ALL}")
        print()
        print(f"{Fore.WHITE}    XSS Vulnerability Automatic Scanner{Style.RESET_ALL}")
        print()

    def _parse_data_string(self, data_str: str) -> Dict:
        data = {}
        if data_str:
            pairs = data_str.split('&')
            for pair in pairs:
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    data[key] = value
        return data

    def _load_urls_from_file(self, filepath: str) -> List[str]:
        urls = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        urls.append(line)
        except FileNotFoundError:
            print(f"{Fore.RED}[-] Error: File not found: {filepath}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error reading file: {str(e)}{Style.RESET_ALL}")
        return urls

    def _parse_headers(self, headers_str: str) -> Dict:
        headers = {}
        if headers_str:
            pairs = headers_str.split(';')
            for pair in pairs:
                if ':' in pair:
                    key, value = pair.split(':', 1)
                    headers[key.strip()] = value.strip()
        return headers

    def run_single_target(self, url: str):
        print(f"\n{Fore.YELLOW}[*] Starting scan for: {url}{Style.RESET_ALL}")

        method = self.args.method.upper() if self.args.method else 'GET'
        data = None

        if method == 'POST' and self.args.data:
            data = self._parse_data_string(self.args.data)

        headers = self._parse_headers(self.args.headers) if self.args.headers else {}

        self.http_handler = HTTPHandler(timeout=self.args.timeout or 30)

        for key, value in headers.items():
            self.http_handler.set_header(key, value)

        if self.args.cookie:
            self.http_handler.set_cookie(self.args.cookie)

        parsed = self.http_handler.parse_url(url)
        params = parsed['params_dict']

        if self.args.parameter:
            param_to_test = self.args.parameter
            if param_to_test not in params:
                print(f"{Fore.RED}[-] Parameter '{param_to_test}' not found in URL{Style.RESET_ALL}")
                return
            params = {param_to_test: params[param_to_test]}
            print(f"{Fore.CYAN}[*] Testing specific parameter: {param_to_test}{Style.RESET_ALL}")
        elif params:
            print(f"{Fore.CYAN}[*] Auto-detected parameters: {', '.join(params.keys())}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] No parameters detected in URL. Please provide a URL with query parameters.{Style.RESET_ALL}")
            print(f"    Example: http://target.com/page?param1=value&param2=test")
            return

        if self.tamper_list:
            print(f"{Fore.CYAN}[*] Using tamper scripts: {', '.join(self.tamper_list)}{Style.RESET_ALL}")

        self.detector = Detector(self.http_handler, verbose=self.args.verbose, tamper_list=self.tamper_list)

        print(f"{Fore.CYAN}[*] Running XSS detection...{Style.RESET_ALL}")

        vulnerabilities = []
        
        if self.args.headers_scan:
            print(f"{Fore.YELLOW}[*] HTTP header scan mode enabled{Style.RESET_ALL}")
            header_vulns = self.detector.detect_http_headers_xss(url, method)
            vulnerabilities.extend(header_vulns)
            print(f"{Fore.YELLOW}[*] Cookie reflection scan enabled{Style.RESET_ALL}")
            cookie_vulns = self.detector.detect_cookie_reflection_xss(url)
            vulnerabilities.extend(cookie_vulns)
        
        if self.args.deep:
            print(f"{Fore.YELLOW}[*] Deep scan mode enabled{Style.RESET_ALL}")
            reflected_vulns = self.detector.detect_reflected_xss(url, params, method)
            vulnerabilities.extend(reflected_vulns)
            dom_vulns = self.detector.detect_dom_xss(url)
            vulnerabilities.extend(dom_vulns)
        else:
            reflected_vulns = self.detector.detect_reflected_xss(url, params, method)
            vulnerabilities.extend(reflected_vulns)

        if vulnerabilities:
            print(f"\n{Fore.GREEN}[+] Found {len(vulnerabilities)} potential vulnerabilities!{Style.RESET_ALL}")

            if self.args.verify or self.args.show_browser:
                print(f"\n{Fore.CYAN}[*] Verifying vulnerabilities with browser...{Style.RESET_ALL}")
                self.verifier = Verifier(browser='chrome', headless=not self.args.show_browser)
                for vuln in vulnerabilities:
                    result = self.verifier.verify_vulnerability(vuln, url)
                    if result.get('verified'):
                        print(f"{Fore.GREEN}[+] Verified: {vuln['type']} XSS in parameter '{vuln['parameter']}'{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}[!] Could not verify: {vuln['type']} XSS in parameter '{vuln['parameter']}'{Style.RESET_ALL}")
                self.verifier.cleanup()

            for vuln in vulnerabilities:
                self.report.add_vulnerability(vuln)
        else:
            print(f"\n{Fore.YELLOW}[!] No XSS vulnerabilities found{Style.RESET_ALL}")

        self.http_handler.close()
        return vulnerabilities

    def run_batch(self):
        urls = self._load_urls_from_file(self.args.batch)
        if not urls:
            print(f"{Fore.RED}[-] No URLs loaded from file{Style.RESET_ALL}")
            return

        print(f"{Fore.CYAN}[*] Loaded {len(urls)} URLs from file{Style.RESET_ALL}")

        all_vulnerabilities = []
        for url in urls:
            try:
                vulns = self.run_single_target(url)
                if vulns:
                    all_vulnerabilities.extend(vulns)
            except Exception as e:
                print(f"{Fore.RED}[-] Error scanning {url}: {str(e)}{Style.RESET_ALL}")
                continue

        print(f"\n{Fore.GREEN}[+] Batch scan complete. Total vulnerabilities found: {len(all_vulnerabilities)}{Style.RESET_ALL}")

    def save_report(self, vulnerabilities: List[Dict]):
        if not vulnerabilities:
            return
        output_dir = self.args.output or '.'
        os.makedirs(output_dir, exist_ok=True)
        target_name = "scan"
        if self.args.url:
            from urllib.parse import urlparse
            parsed = urlparse(self.args.url)
            target_name = parsed.netloc.replace(':', '_').replace('.', '_')
        if self.args.report_format in ['json', 'all']:
            json_path = os.path.join(output_dir, f"{target_name}_report.json")
            if self.report.export_json(json_path):
                print(f"{Fore.GREEN}[+] JSON report saved: {json_path}{Style.RESET_ALL}")
        if self.args.report_format in ['html', 'all']:
            html_path = os.path.join(output_dir, f"{target_name}_report.html")
            if self.report.export_html(html_path):
                print(f"{Fore.GREEN}[+] HTML report saved: {html_path}{Style.RESET_ALL}")

    def run(self):
        self._print_banner()

        if self.args.list_categories:
            print(f"\n{Fore.CYAN}Available Payload Categories:{Style.RESET_ALL}\n")
            for cat, desc in PAYLOAD_CATEGORIES.items():
                print(f"  {Fore.YELLOW}{cat:20s}{Style.RESET_ALL} - {desc}")
            print()
            return

        if self.args.list_techniques:
            from xssfleet.core.bypasser import Bypasser
            bypasser = Bypasser()
            print(f"\n{Fore.CYAN}Available Bypass Techniques:{Style.RESET_ALL}\n")
            for tech in bypasser.get_available_techniques():
                print(f"  {Fore.YELLOW}- {tech}{Style.RESET_ALL}")
            print()
            return

        if self.args.list_tampers:
            print(f"\n{Fore.CYAN}Available Tamper Scripts:{Style.RESET_ALL}\n")
            for name, desc in tamper_engine.list_scripts().items():
                print(f"  {Fore.YELLOW}{name:25s}{Style.RESET_ALL} - {desc}")
            print()
            return

        if self.args.exploit:
            self.run_exploit_mode()
            return

        if self.args.list_exploit_payloads:
            self.list_exploit_payloads()
            return

        if not self.args.url and not self.args.batch:
            print(f"{Fore.RED}[-] Error: Please specify target URL (-u) or URL file (-m){Style.RESET_ALL}\n")
            self._print_help()
            return

        self.report.generate_scan_info(
            self.args.url or self.args.batch or 'unknown',
            'deep' if self.args.deep else 'basic'
        )

        if self.args.batch:
            self.run_batch()
        else:
            vulnerabilities = self.run_single_target(self.args.url)
            if vulnerabilities and self.args.output:
                self.save_report(vulnerabilities)

        self.report.print_console_report()

    def run_exploit_mode(self):
        """Run XSS exploitation mode"""
        exploiter = XSSExploiter()

        exploiter.show_disclaimer()

        try:
            choice = input("\nHave you obtained explicit authorization from the target website owner? (y/N): ").strip().lower()
            if choice != 'y':
                print(f"{Fore.RED}[-] No authorization, exiting exploitation mode{Style.RESET_ALL}")
                return
        except:
            print(f"{Fore.RED}[-] No authorization, exiting exploitation mode{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}[*] Loading available payloads...{Style.RESET_ALL}")
        payloads = exploiter.get_payloads()
        contexts = exploiter.get_contexts()

        print(f"\n{Fore.CYAN}Available payload types:{Style.RESET_ALL}")
        for key, info in payloads.items():
            print(f"  {Fore.YELLOW}{key:15s}{Style.RESET_ALL} - {info['name']}")
            print(f"          {info['description']}")

        payload_type = input(f"\n{Fore.CYAN}Select payload type: {Style.RESET_ALL}").strip()

        if payload_type not in payloads:
            print(f"{Fore.RED}[-] Invalid payload type{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}Vulnerability context types:{Style.RESET_ALL}")
        context_descriptions = {
            'html': 'HTML tag context - Payload injected directly into HTML tags',
            'attribute': 'HTML attribute context - Payload injected into HTML attributes (needs tag closure)',
            'javascript': 'JavaScript context - Payload injected into JavaScript code',
            'dom_based': 'DOM-based XSS - Payload executed via DOM manipulation',
            'url_param': 'URL parameter context - Payload as URL parameter value'
        }
        for ctx in contexts:
            desc = context_descriptions.get(ctx, ctx)
            print(f"  {Fore.YELLOW}{ctx:15s}{Style.RESET_ALL} - {desc}")

        print(f"\n{Fore.YELLOW}Tip: If you don't know the context, use 'auto' to generate multiple alternative payloads{Style.RESET_ALL}")
        context = input(f"{Fore.CYAN}Select vulnerability context: {Style.RESET_ALL}").strip()

        if context == 'auto':
            context = 'attribute'
            auto_mode = True
        else:
            auto_mode = False
            if context not in contexts:
                print(f"{Fore.YELLOW}[!] Invalid context, using default: attribute{Style.RESET_ALL}")
                context = 'attribute'

        port = self.args.port if self.args.port else 8080

        print(f"\n{Fore.CYAN}[*] Starting XSS exploitation environment...{Style.RESET_ALL}")
        result = exploiter.start_exploitation(payload_type, context, port)

        if not result['success']:
            print(f"{Fore.RED}[-] Startup failed: {result.get('error')}{Style.RESET_ALL}")
            return

        print(f"\n{Fore.GREEN}[+] XSS exploitation environment ready!{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}ngrok URL:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{result['ngrok_url']}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}Generated attack payloads (context: {context}):{Style.RESET_ALL}")
        for i, payload in enumerate(result['payloads'], 1):
            print(f"\n  {Fore.YELLOW}[{i}] {payload[:100]}...{Style.RESET_ALL}" if len(payload) > 100 else f"\n  {Fore.YELLOW}[{i}] {payload}{Style.RESET_ALL}")

        if auto_mode:
            print(f"\n{Fore.CYAN}Additional alternative payloads (other contexts):{Style.RESET_ALL}")
            suggestions = exploiter.suggest_payloads(context, payload_type)
            for i, sug in enumerate(suggestions[3:6], 4):
                print(f"\n  {Fore.YELLOW}[{i}] [{sug['context']}] {sug['payload'][:80]}...{Style.RESET_ALL}" if len(sug['payload']) > 80 else f"\n  {Fore.YELLOW}[{i}] [{sug['context']}] {sug['payload']}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}Complete payload list:{Style.RESET_ALL}")
        all_payloads = result['payloads']
        if auto_mode:
            all_payloads = result['payloads'] + [s['payload'] for s in suggestions[3:6]]
        for i, payload in enumerate(all_payloads, 1):
            print(f"\n{Fore.YELLOW}[{i}]{Style.RESET_ALL}")
            print(f"  {payload}")

        try:
            while True:
                print(f"\n{Fore.CYAN}Select action:{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}1{Style.RESET_ALL} - Show captured data")
                print(f"  {Fore.YELLOW}2{Style.RESET_ALL} - Generate new payloads")
                print(f"  {Fore.YELLOW}3{Style.RESET_ALL} - Stop exploitation")

                choice = input(f"\n{Fore.CYAN}Enter your choice: {Style.RESET_ALL}").strip()

                if choice == '1':
                    exploiter.show_captured_data()
                elif choice == '2':
                    new_context = input(f"{Fore.CYAN}Select context (or press Enter to use current '{context}'): {Style.RESET_ALL}").strip() or context
                    new_payloads = exploiter.payload_manager.generate_all_payloads(payload_type, new_context, result['ngrok_url'])
                    if new_payloads:
                        print(f"\n{Fore.CYAN}New payloads (context: {new_context}):{Style.RESET_ALL}")
                        for i, p in enumerate(new_payloads, 1):
                            print(f"  [{i}] {p}")
                    else:
                        print(f"{Fore.RED}[-] Generation failed{Style.RESET_ALL}")
                elif choice == '3':
                    exploiter.stop_exploitation()
                    print(f"{Fore.GREEN}[+] Exploitation stopped{Style.RESET_ALL}")
                    break
                else:
                    print(f"{Fore.YELLOW}[!] Invalid choice{Style.RESET_ALL}")

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] User interrupted, cleaning up...{Style.RESET_ALL}")
            exploiter.stop_exploitation()

    def list_exploit_payloads(self):
        """List all available exploit payloads"""
        exploiter = XSSExploiter()
        payloads = exploiter.get_payloads()
        
        print(f"\n{Fore.CYAN}XSS exploit payload list:{Style.RESET_ALL}\n")
        for key, info in payloads.items():
            print(f"  {Fore.YELLOW}{key}{Style.RESET_ALL}")
            print(f"    Name: {info['name']}")
            print(f"    Description: {info['description']}")
            print(f"    Supported XSS types: {', '.join(info['types'])}")
            print()

    def _print_help(self):
        help_text = """
Usage Examples:
    python xssfleet.py -u "http://target.com/search?q=test"
    python xssfleet.py -u "http://target.com/page" --method POST --data "name=test"
    python xssfleet.py -u "http://target.com" -p id --tamper=space2comment,base64encode
    python xssfleet.py -m urls.txt --deep
    python xssfleet.py -u "http://target.com" --verify

Options:
    -u, --url              Target URL
    -m, --batch           Load URLs from file (one per line)
    -p, --parameter        Test specific parameter only
    --method               HTTP method (GET or POST, default: GET)
    --data                 POST data (e.g., "username=test&email=foo")
    --headers              Custom headers (e.g., "Content-Type:application/json")
    --cookie               Cookie string
    -d, --deep             Enable deep scan (more payloads, DOM XSS)
    -b, --bypass           Enable WAF bypass techniques
    --tamper               Tamper scripts to use (comma-separated)
    --verify               Verify vulnerabilities with browser
    --browser              Show browser during verification
    -o, --output           Output directory for reports
    --report-format        Report format: json, html, or all (default: all)
    -v, --verbose          Verbose output
    --timeout              Request timeout in seconds (default: 30)
    --list-categories      List all payload categories
    --list-techniques      List all bypass techniques
    --list-tampers         List all tamper scripts
    --exploit              Enable XSS exploitation mode
    --list-exploit-payloads List all exploit payloads
    --port                 Listener port (default: 8080)
    -h, --help             Show this help message
        """
        print(help_text)


def main():
    parser = argparse.ArgumentParser(
        description='XssFleet - XSS Vulnerability Automatic Penetration Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xssfleet.py -u "http://target.com/search?q=test"
  python xssfleet.py -u "http://target.com/page" --method POST --data "name=test"
  python xssfleet.py -u "http://target.com" -p id --tamper=space2comment,base64encode
  python xssfleet.py -m urls.txt --verify

For more information, visit: https://github.com/xssfleet/xssfleet
        """
    )

    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-m', '--batch', help='Load URLs from file')
    parser.add_argument('-p', '--parameter', help='Test specific parameter')
    parser.add_argument('--method', default='GET', help='HTTP method (GET or POST)')
    parser.add_argument('--data', help='POST data string')
    parser.add_argument('--headers', help='Custom HTTP headers')
    parser.add_argument('--cookie', help='Cookie string')
    parser.add_argument('--headers-scan', action='store_true', help='Scan HTTP headers for XSS (Referer, User-Agent, etc.)')
    parser.add_argument('-d', '--deep', action='store_true', help='Enable deep scan mode')
    parser.add_argument('-b', '--bypass', action='store_true', help='Enable WAF bypass')
    parser.add_argument('--tamper', help='Tamper scripts to use (comma-separated)')
    parser.add_argument('--verify', action='store_true', help='Verify with browser automation')
    parser.add_argument('--browser', action='store_true', dest='show_browser', help='Show browser during verification')
    parser.add_argument('-o', '--output', help='Output directory for reports')
    parser.add_argument('--report-format', choices=['json', 'html', 'all'], default='all', help='Report format')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbose output (use -vv, -vvv for more)')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout')
    parser.add_argument('--list-categories', action='store_true', help='List payload categories')
    parser.add_argument('--list-techniques', action='store_true', help='List bypass techniques')
    parser.add_argument('--list-tampers', action='store_true', help='List tamper scripts')
    parser.add_argument('--exploit', action='store_true', help='Enable XSS exploitation mode')
    parser.add_argument('--list-exploit-payloads', action='store_true', help='List all exploit payloads')
    parser.add_argument('--port', type=int, default=8080, help='Listener port for exploitation')

    args = parser.parse_args()

    try:
        scanner = XssFleet(args)
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[-] Fatal error: {str(e)}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()