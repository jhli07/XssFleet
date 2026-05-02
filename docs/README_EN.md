# XssFleet User Manual

## Table of Contents

1. [Introduction](#introduction)
2. [Features](#features)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Basic Commands](#basic-commands)
6. [Advanced Options](#advanced-options)
7. [Exploitation Mode](#exploitation-mode)
8. [Output Reports](#output-reports)
9. [Usage Examples](#usage-examples)
10. [FAQ](#faq)

***

## Introduction

XssFleet is a professional XSS (Cross-Site Scripting) vulnerability automated penetration testing tool. It can automatically detect, verify, and exploit XSS vulnerabilities in target websites, providing a complete exploitation framework with support for cookie theft, session hijacking, and other advanced attack scenarios.

### Objectives

- **Vulnerability Detection**: Automatically scan for XSS vulnerabilities in web applications
- **Vulnerability Verification**: Verify vulnerability authenticity through browser automation
- **Exploitation**: Integrate multiple XSS attack payloads with ngrok tunneling support
- **Reporting**: Generate detailed vulnerability reports

***

## Features

### Core Features

| Feature                 | Description                                    |
| ----------------------- | ---------------------------------------------- |
| Reflected XSS Detection | Auto-detect reflected XSS in URL parameters    |
| Stored XSS Detection    | Detect stored XSS in database/files            |
| DOM-based XSS           | Analyze DOM operations in JavaScript code      |
| HTTP Header Detection   | Detect XSS in Referer, User-Agent, etc.        |
| WAF Bypass              | Multiple obfuscation techniques to bypass WAF  |
| Deep Scan               | Enable additional detection rules and payloads |

### Exploitation Features

| Feature           | Description                            |
| ----------------- | -------------------------------------- |
| Cookie Stealer    | Steal victim cookies                   |
| Session Hijacking | Steal complete session information     |
| Keylogger         | Record user keystrokes                 |
| Defacement        | Modify page content                    |
| Redirection       | Redirect users to malicious sites      |
| ngrok Integration | Automatically establish public tunnels |

### Context Recognition

| Context Type   | Description                              |
| -------------- | ---------------------------------------- |
| HTML Tag       | Payload injected directly into HTML tags |
| HTML Attribute | Payload injected into HTML attributes    |
| JavaScript     | Payload injected into JS code            |
| DOM-based      | Executed via DOM manipulation            |
| URL Parameter  | Payload as URL parameter value           |

***

## Installation

### System Requirements

- Python 3.8+
- Windows / Linux / macOS
- Chrome/Firefox browser (for vulnerability verification)

### Installation Steps

1. **Clone the project**

```bash
git clone https://github.com/jhli07/XssFleet.git
cd xssfleet
```

1. **Install dependencies**

```bash
pip install -r requirements.txt
```

1. **Install ngrok (optional, for exploitation)**

```bash
# Download ngrok: https://ngrok.com/download
# Register account and get authtoken
ngrok config add-authtoken YOUR_TOKEN
```

### Dependencies

```
requests>=2.28.0
beautifulsoup4>=4.11.0
colorama>=0.4.6
selenium>=4.0.0
flask>=2.0.0
urllib3>=1.26.0
```

***

## Quick Start

### Scan a Single URL

```bash
python xssfleet/xssfleet.py -u "http://target.com/search?q=test"
```

### Deep Scan

```bash
python xssfleet/xssfleet.py -u "http://target.com/page" --deep
```

### Batch Scan

```bash
python xssfleet/xssfleet.py -m urls.txt --deep
```

***

## Basic Commands

### Common Parameters

| Parameter         | Description                         | Example                  |
| ----------------- | ----------------------------------- | ------------------------ |
| `-u, --url`       | Target URL                          | `-u "http://target.com"` |
| `-m, --batch`     | Batch scan file                     | `-m urls.txt`            |
| `-p, --parameter` | Specific parameter to test          | `-p q`                   |
| `-d, --deep`      | Deep scan mode                      | `--deep`                 |
| `-o, --output`    | Report output directory             | `-o results/`            |
| `--verify`        | Verify vulnerabilities with browser | `--verify`               |
| `--browser`       | Show browser window                 | `--browser`              |

### HTTP Methods

```bash
# GET request
python xssfleet/xssfleet.py -u "http://target.com/search?q=test"

# POST request
python xssfleet/xssfleet.py -u "http://target.com/login" --method POST --data "user=admin&pass=test"
```

### Custom Headers

```bash
python xssfleet/xssfleet.py -u "http://target.com/api" --headers "Content-Type:application/json;Authorization:Bearer token123"
```

### Cookie Setting

```bash
python xssfleet/xssfleet.py -u "http://target.com/page" --cookie "PHPSESSID=abc123;user=admin"
```

***

## Advanced Options

### WAF Bypass

Enable obfuscation scripts to bypass WAF:

```bash
python xssfleet/xssfleet.py -u "http://target.com" --tamper=space2comment,base64encode
```

### Bypass Techniques

| Technique       | Description                    |
| --------------- | ------------------------------ |
| `space2comment` | Replace space with `/**/`      |
| `base64encode`  | Base64 encode parameter values |
| `htmlencode`    | HTML entity encoding           |
| `unicodeescape` | Unicode escape                 |
| `urlencode`     | URL encoding                   |

### Deep Scan Mode

Deep scan includes additional detection:

- DOM-based XSS detection
- More payload variants
- Blind XSS detection

```bash
python xssfleet/xssfleet.py -u "http://target.com" --deep
```

### HTTP Header Scanning

Detect XSS in headers like Referer, User-Agent:

```bash
python xssfleet/xssfleet.py -u "http://target.com" --headers-scan
```

### Timeout Setting

```bash
python xssfleet/xssfleet.py -u "http://target.com" --timeout 60
```

### Verbose Output

```bash
# Normal output
python xssfleet/xssfleet.py -u "http://target.com"

# Verbose output (-v)
python xssfleet/xssfleet.py -u "http://target.com" -v

# More verbose (-vv)
python xssfleet/xssfleet.py -u "http://target.com" -vv

# Most verbose (-vvv)
python xssfleet/xssfleet.py -u "http://target.com" -vvv
```

***

## Exploitation Mode

### Launch Exploitation Mode

```bash
python xssfleet/xssfleet.py --exploit
```

### Legal Disclaimer

The tool will display a legal disclaimer. You must enter `y` to confirm you have obtained authorization:

```
============================================================
        XSS Exploitation Feature - Legal Disclaimer
============================================================

[!] Important Notice:

This tool is for authorized security testing only!

1. You must obtain explicit written authorization from the target website owner
2. Do not use for any unauthorized testing activities
3. Comply with all applicable laws and regulations
4. Only use in authorized testing environments

Unauthorized access or attacks may be illegal!

Please ensure your testing is legal and compliant.

============================================================

Have you obtained explicit authorization from the target website owner? (y/N): y
```

### Select Attack Payload

Available attack payload types:

| Payload Type    | Description       | Applicable Scenarios   |
| --------------- | ----------------- | ---------------------- |
| `steal_cookie`  | Cookie Stealer    | reflected, stored, dom |
| `steal_session` | Session Hijacking | reflected, stored, dom |
| `keylogger`     | Keylogger         | stored                 |
| `deface`        | Defacement        | stored, reflected      |
| `redirect`      | Redirection       | reflected, stored, dom |
| `alert_test`    | Alert Test        | reflected, stored, dom |

### Select Vulnerability Context

Choose the appropriate context based on detected vulnerability type:

| Context      | Description                                 |
| ------------ | ------------------------------------------- |
| `html`       | HTML tag context                            |
| `attribute`  | HTML attribute context (needs tag closure)  |
| `javascript` | JavaScript code context                     |
| `dom_based`  | DOM manipulation context                    |
| `url_param`  | URL parameter context                       |
| `auto`       | Auto-generate multiple alternative payloads |

### Interactive Operations

After launch, the following options will be displayed:

```
Select action:
  1 - Show captured data
  2 - Generate new payloads
  3 - Stop exploitation

Enter your choice:
```

1. **Show captured data** - View stolen cookies, sessions, etc.
2. **Generate new payloads** - Switch context and generate new payloads
3. **Stop exploitation** - Close ngrok and listener server

### Complete Demo

```bash
# 1. Launch exploitation mode
python xssfleet/xssfleet.py --exploit

# 2. Confirm authorization
Have you obtained explicit authorization? (y/N): y

# 3. Select payload type
Select payload type: steal_cookie

# 4. Select context (use auto if unsure)
Select vulnerability context: auto

# 5. Get generated payload and ngrok URL

# 6. Inject payload into target vulnerability point

# 7. Wait for target to visit, select 1 to view captured data
```

***

## Output Reports

### Report Formats

| Format | Description           |
| ------ | --------------------- |
| `json` | JSON format report    |
| `html` | HTML format report    |
| `all`  | Generate both formats |

### Generate Report

```bash
# Output to specified directory
python xssfleet/xssfleet.py -u "http://target.com" -o results/

# Specify format
python xssfleet/xssfleet.py -u "http://target.com" --report-format json

# Generate all formats
python xssfleet/xssfleet.py -u "http://target.com" --report-format all
```

### Report Contents

Reports include:

- Scan target information
- List of discovered vulnerabilities
- Detailed information for each vulnerability (type, parameter, payload, risk level)
- Remediation suggestions
- Exploitation suggestions

***

## Usage Examples

### Example 1: Basic Scan

```bash
python xssfleet/xssfleet.py -u "http://example.com/search?q=test"
```

Output:

```
[*] Testing parameter: q
[*] Running XSS detection...
[+] Found 3 potential vulnerabilities!
```

### Example 2: Deep Scan + Browser Verification

```bash
python xssfleet/xssfleet.py -u "http://example.com/page" --deep --verify
```

### Example 3: Batch Scan

Create `urls.txt`:

```
http://example.com/page1?q=test
http://example.com/page2?name=test
http://example.com/search?id=123
```

Run:

```bash
python xssfleet/xssfleet.py -m urls.txt --deep -o scan_results/
```

### Example 4: WAF Bypass Scan

```bash
python xssfleet/xssfleet.py -u "http://waf-protected.com/search" --tamper=space2comment,base64encode
```

### Example 5: Test POST Request

```bash
python xssfleet/xssfleet.py -u "http://example.com/login" --method POST --data "username=test&password=123"
```

### Example 6: Cookie Theft Attack

```bash
# 1. First scan to discover vulnerability
python xssfleet/xssfleet.py -u "http://vulnerable.com/search?q=test"

# 2. Launch exploitation mode
python xssfleet/xssfleet.py --exploit

# 3. Select steal_cookie and auto

# 4. Inject generated payload into vulnerability point

# 5. Wait for target to visit, then view captured cookies
```

### Example 7: Test Hidden Parameters

```bash
python xssfleet/xssfleet.py -u "http://example.com/page" -p t_sort
```

### Example 8: Complete Penetration Testing Workflow

```bash
# Phase 1: Discover vulnerabilities
python xssfleet/xssfleet.py -u "http://target.com" --deep --verify -o phase1/

# Phase 2: Exploitation
python xssfleet/xssfleet.py --exploit

# Phase 3: Generate report
python xssfleet/xssfleet.py -u "http://target.com" --report-format all -o final_report/
```

***

## FAQ

### Q1: How to determine if a vulnerability is real?

Use `--verify` parameter with browser automation:

```bash
python xssfleet/xssfleet.py -u "http://target.com" --verify
```

### Q2: Scanning is too slow, what to do?

1. Reduce payload count (don't use `--deep`)
2. Reduce timeout value
3. Increase concurrency for batch scanning (future version support)

### Q3: Blocked by WAF?

Use obfuscation scripts:

```bash
python xssfleet/xssfleet.py -u "http://target.com" --tamper=space2comment,base64encode
```

### Q4: How to test specific parameters?

```bash
python xssfleet/xssfleet.py -u "http://target.com/page?id=1&name=test" -p name
```

### Q5: ngrok connection failed?

1. Confirm ngrok is installed and authtoken is configured
2. Check network connection
3. Confirm port 8080 is not occupied

### Q6: Where are the reports?

Default is current directory, specify with `-o`:

```bash
python xssfleet/xssfleet.py -u "http://target.com" -o ./results/
```

### Q7: How to view all available options?

```bash
python xssfleet/xssfleet.py --help
```

### Q8: What vulnerability types are supported?

- Reflected XSS
- Stored XSS
- DOM-based XSS
- Blind XSS
- SVG XSS
- JSONP XSS
- AngularJS XSS

***

## Vulnerability Context Details

### HTML Tag Context

**Characteristic**: User input becomes HTML tag directly

**Example**:

```html
<div>User Input</div>
```

**Attack Payload**:

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

### HTML Attribute Context

**Characteristic**: User input becomes HTML attribute value, needs tag closure

**Example**:

```html
<input value="User Input">
```

**Attack Payload**:

```html
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
```

### JavaScript Context

**Characteristic**: User input becomes JavaScript code

**Example**:

```javascript
<script>var name = "User Input";</script>
```

**Attack Payload**:

```javascript
";alert(1);"
';alert(1);'
```

### DOM-based Context

**Characteristic**: Content inserted through JavaScript DOM manipulation

**Example**:

```javascript
document.write(location.hash)
```

**Attack Payload**:

```
#<img src=x onerror=alert(1)>
```

***

## Disclaimer

XssFleet is for authorized security testing and research purposes only. By using this tool, you agree to:

1. Only use on targets with explicit written authorization
2. Comply with all applicable laws and regulations
3. Assume all responsibility for the use of this tool
4. Do not use this tool for any illegal purposes

The author and contributors are not responsible for any damages caused by misuse of this tool.

***

## Contact

- GitHub: <https://github.com/jhli07/XssFleet>
- Issues: <https://github.com/jhli07/XssFleet/issues>

***

**Version: v1.0.0**
