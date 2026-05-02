"""Report generation utilities for XssFleet."""

import json
import time
from typing import Dict, List, Any, Optional
from urllib.parse import quote
from colorama import Fore, Style


class ReportGenerator:
    def __init__(self, vulnerabilities: Optional[List[Dict[str, Any]]] = None, target_url: str = ''):
        self.vulnerabilities = vulnerabilities or []
        self.target_url = target_url
        self.report_data = self._build_report_data()

    def _build_report_data(self) -> Dict[str, Any]:
        vuln_id = 1
        processed_vulns = []
        for vuln in self.vulnerabilities:
            vuln_copy = vuln.copy()
            vuln_copy['id'] = vuln_id
            processed_vulns.append(vuln_copy)
            vuln_id += 1

        return {
            'scan_info': {
                'tool': 'XssFleet',
                'version': '1.0.0',
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            },
            'target': {
                'url': self.target_url
            },
            'vulnerabilities': processed_vulns,
            'summary': {}
        }

    def generate_scan_info(self, url: str, scan_mode: str):
        """Backward compatible method"""
        self.target_url = url
        self.report_data['target']['url'] = url
        if scan_mode:
            self.report_data['scan_info']['mode'] = scan_mode

    def add_vulnerability(self, vulnerability: Dict[str, Any]):
        """Add a vulnerability to report (backward compatible)"""
        self.vulnerabilities.append(vulnerability)
        self.report_data = self._build_report_data()

    def generate_summary(self):
        total_vulns = len(self.vulnerabilities)
        verified_count = sum(1 for v in self.vulnerabilities if v.get('verified', False))
        severities = {}
        for vuln in self.vulnerabilities:
            sev = vuln.get('severity', 'unknown').lower()
            severities[sev] = severities.get(sev, 0) + 1

        risk_level = self._calculate_risk_level(severities)
        self.report_data['summary'] = {
            'total_vulnerabilities': total_vulns,
            'verified_count': verified_count,
            'severity_distribution': severities,
            'risk_level': risk_level
        }

    def _calculate_risk_level(self, severity_counts: Dict) -> str:
        if severity_counts.get('critical', 0) > 0 or severity_counts.get('high', 0) > 2:
            return 'CRITICAL'
        elif severity_counts.get('high', 0) > 0 or severity_counts.get('medium', 0) > 2:
            return 'HIGH'
        elif severity_counts.get('medium', 0) > 0 or severity_counts.get('low', 0) > 2:
            return 'MEDIUM'
        else:
            return 'LOW'

    def print_console_report(self):
        self.generate_summary()
        print("\n" + "=" * 70)
        print(f"{Fore.CYAN}XssFleet Scan Report{Style.RESET_ALL}")
        print("=" * 70)

        print(f"\n{Fore.WHITE}Scan Info:{Style.RESET_ALL}")
        print(f"  Tool: {self.report_data['scan_info'].get('tool', 'N/A')}")
        print(f"  Version: {self.report_data['scan_info'].get('version', 'N/A')}")
        print(f"  Timestamp: {self.report_data['scan_info'].get('timestamp', 'N/A')}")
        print(f"  Target: {self.report_data['target'].get('url', 'N/A')}")

        if self.report_data['vulnerabilities']:
            print(f"\n{Fore.YELLOW}Summary:{Style.RESET_ALL}")
            summary = self.report_data.get('summary', {})
            print(f"  Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
            print(f"  Verified: {summary.get('verified_count', 0)}")
            print(f"  Risk Level: {self._get_risk_color(summary.get('risk_level', 'UNKNOWN'))}")

            print(f"\n{Fore.YELLOW}Available Payloads (Sorted by Priority):{Style.RESET_ALL}")
            param_groups = {}
            for vuln in self.report_data['vulnerabilities']:
                param = vuln.get('parameter', 'unknown')
                if param not in param_groups:
                    param_groups[param] = []
                param_groups[param].append(vuln)

            for param, vulns in param_groups.items():
                sorted_vulns = sorted(vulns, key=lambda v: (
                    0 if v.get('verified') else 1,
                    -{'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(v.get('severity', 'low'), 0),
                    0 if v.get('bypass_technique') in ['javascript_href', 'close_tag'] else 1,
                    0 if '">' in v.get('payload', '') or '\'>' in v.get('payload', '') else 1
                ))

                print(f"\n  {Fore.GREEN}Parameter: {param}{Style.RESET_ALL}")
                print("  " + "-" * 68)
                for i, vuln in enumerate(sorted_vulns, 1):
                    severity = vuln.get('severity', 'UNKNOWN')
                    severity_color = self._get_severity_color(severity)
                    status = f"{Fore.GREEN}[VERIFIED]" if vuln.get('verified') else f"{Fore.WHITE}[POTENTIAL]"

                    extra_tag = ""
                    payload = vuln.get('payload', '')
                    if 'javascript:' in payload.lower() and 'href=' in payload.lower():
                        extra_tag = f" {Fore.CYAN}[HIGH PROBABILITY]{Style.RESET_ALL}"
                    elif '">' in payload or '\'>' in payload:
                        extra_tag = f" {Fore.GREEN}[CLOSE TAG]{Style.RESET_ALL}"

                    safe_payload = payload.replace('"', '\\"')
                    encoded_payload = quote(payload)

                    print(f"\n  [{i}] {severity_color}{severity.upper()}{Style.RESET_ALL} {status}{extra_tag}")
                    print(f"      Type: {vuln['type'].upper()} XSS")
                    print(f"      Context: {vuln.get('context', 'N/A')}")
                    if vuln.get('bypass_technique') and vuln['bypass_technique'] != 'none':
                        print(f"      Bypass: {vuln['bypass_technique']}")
                    print(f"      Payload: \"{safe_payload}\"")
                    print(f"      Example URL: ?{param}={encoded_payload}")
        else:
            print(f"\n{Fore.GREEN}No vulnerabilities found.{Style.RESET_ALL}")

        print("\n" + "=" * 70 + "\n")

    def _get_severity_color(self, severity: str) -> str:
        colors = {
            'critical': Fore.MAGENTA,
            'high': Fore.RED,
            'medium': Fore.YELLOW,
            'low': Fore.BLUE
        }
        return colors.get(severity.lower(), Fore.WHITE)

    def _get_risk_color(self, risk: str) -> str:
        colors = {
            'CRITICAL': f"{Fore.MAGENTA}CRITICAL{Style.RESET_ALL}",
            'HIGH': f"{Fore.RED}HIGH{Style.RESET_ALL}",
            'MEDIUM': f"{Fore.YELLOW}MEDIUM{Style.RESET_ALL}",
            'LOW': f"{Fore.GREEN}LOW{Style.RESET_ALL}"
        }
        return colors.get(risk, f"{Fore.WHITE}{risk}{Style.RESET_ALL}")

    def _truncate_payload(self, payload: str, max_len: int = 50) -> str:
        if len(payload) > max_len:
            return payload[:max_len] + "..."
        return payload

    def export_json(self, filepath: str) -> bool:
        try:
            self.generate_summary()
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.report_data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error exporting JSON: {e}")
            return False

    def export_html(self, filepath: str) -> bool:
        try:
            self.generate_summary()
            html_content = self._generate_html_report()
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return True
        except Exception as e:
            print(f"Error exporting HTML: {e}")
            return False

    def _generate_html_report(self) -> str:
        summary = self.report_data.get('summary', {})
        vulns = self.report_data['vulnerabilities']

        vuln_rows = ""
        for vuln in vulns:
            severity_class = vuln.get('severity', 'unknown').lower()
            vuln_rows += f"""
            <tr>
                <td>{vuln['id']}</td>
                <td><span class="severity-{severity_class}">{vuln['type'].upper()}</span></td>
                <td>{vuln.get('parameter', 'N/A')}</td>
                <td><span class="severity-{severity_class}">{vuln.get('severity', 'UNKNOWN').upper()}</span></td>
                <td>{'✅' if vuln.get('verified') else '❌'}</td>
                <td>{vuln.get('payload', '')}</td>
                <td>{vuln.get('context', 'N/A')}</td>
            </tr>
            """

        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XssFleet Scan Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{ color: #1976D2; }}
        h2 {{ color: #333; margin-top: 30px; }}
        .summary-card {{
            background: #f0f4f8;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #1976D2;
            color: white;
        }}
        .severity-critical {{ background-color: #f44336; color: white; padding: 2px 8px; border-radius: 4px; }}
        .severity-high {{ background-color: #ff5722; color: white; padding: 2px 8px; border-radius: 4px; }}
        .severity-medium {{ background-color: #ff9800; color: white; padding: 2px 8px; border-radius: 4px; }}
        .severity-low {{ background-color: #4caf50; color: white; padding: 2px 8px; border-radius: 4px; }}
        .footer {{
            margin-top: 30px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ XssFleet Scan Report</h1>

        <div class="summary-card">
            <h2>Scan Information</h2>
            <p><strong>Tool:</strong> {self.report_data['scan_info']['tool']} v{self.report_data['scan_info']['version']}</p>
            <p><strong>Timestamp:</strong> {self.report_data['scan_info']['timestamp']}</p>
            <p><strong>Target:</strong> {self.report_data['target']['url']}</p>
        </div>

        <div class="summary-card">
            <h2>Summary</h2>
            <p><strong>Total Vulnerabilities:</strong> {summary.get('total_vulnerabilities', 0)}</p>
            <p><strong>Verified:</strong> {summary.get('verified_count', 0)}</p>
            <p><strong>Risk Level:</strong> <span class="severity-{summary.get('risk_level', 'UNKNOWN').lower()}">{summary.get('risk_level', 'UNKNOWN')}</span></p>
        </div>

        <h2>Vulnerabilities</h2>
        <table>
            <tr>
                <th>ID</th>
                <th>Type</th>
                <th>Parameter</th>
                <th>Severity</th>
                <th>Verified</th>
                <th>Payload</th>
                <th>Context</th>
            </tr>
            {vuln_rows}
        </table>

        <div class="footer">
            Generated by XssFleet - XSS Vulnerability Scanner
        </div>
    </div>
</body>
</html>
        """
        return html_template
