# HTTP-Header-Injection-Detector

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Status](https://img.shields.io/badge/Status-Active-green)
![Type](https://img.shields.io/badge/Type-Red--Team%20Tool-red)
![Focus](https://img.shields.io/badge/Focus-Web%20Security-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)


HTTP Header Injection Detector is a red team security tool built in Python to identify CRLF and header manipulation vulnerabilities in web applications. It performs dynamic header testing, payload injection, and response comparison to detect improper input handling. Designed for authorized penetration testing and web security research environments.


🚀 Features

Dynamic testing of multiple HTTP headers:

User-Agent

Referer

X-Forwarded-For

Cookie

Accept-Language

X-Original-URL

Host

Reflection-based injection detection

XSS payload testing in headers

SQL injection error detection via response analysis

CRLF injection and header splitting detection

Host header manipulation testing

Baseline availability check before scanning

Human-like browser header simulation

Randomized request delay for stealth testing

Immediate console-based finding output


🛠 Requirements

Python 3.8+

requests

urllib3

Install dependencies:

pip install requests urllib3


📦 Usage

Basic scan:

python header_injectionv2.py http://target.com

Scan with custom delay between requests:

python header_injectionv2.py http://target.com --delay 2

If no protocol is specified, the tool automatically prepends http://.


🔎 How It Works

Establishes a baseline connection to ensure the target is reachable.

Iterates through predefined headers.


Injects multiple payload categories:

Reflection markers

XSS payloads

SQL injection patterns

CRLF log injection payloads

Host manipulation values


Analyzes response body and headers for:

Reflected payload markers

Script execution patterns

SQL error signatures

Injected header presence

Reports potential vulnerabilities in structured format.

📊 Sample Output
[*] Testing Header: User-Agent...

[+] FOUND: HEADER REFLECTED: 'INJECT_TEST_MARKER_999' found in response body.

SCAN COMPLETE: 1 potential issues found.




⚠️ Disclaimer

This tool is intended strictly for educational purposes and authorized penetration testing. Do not use against systems without explicit permission from the asset owner.

Unauthorized testing may violate laws and regulations.
