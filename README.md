
# HTTP Header Injection Detector

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Status](https://img.shields.io/badge/Status-Active-green)
![Type](https://img.shields.io/badge/Type-Red--Team%20Tool-red)
![Focus](https://img.shields.io/badge/Focus-Web%20Security-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

A red-team focused Python tool for detecting HTTP Header Injection, CRLF injection, and header-based input reflection vulnerabilities in web applications.

Designed strictly for authorized penetration testing and security research.

---

## Overview

HTTP headers are often overlooked input vectors. Improper handling of header values can lead to:

- HTTP Header Injection
- CRLF Injection / Response Splitting
- Log Injection
- Reflected XSS via headers
- SQL error exposure
- Host Header Manipulation

This tool automates header-based payload injection and analyzes server responses to identify improper sanitization and reflection behavior.

---

## Features

- Baseline availability check before scanning  
- Dynamic testing of common injectable headers  
- Reflection-based detection engine  
- XSS payload injection via headers  
- SQL error-based detection  
- CRLF injection testing  
- Host header manipulation checks  
- Human-like browser header simulation  
- Randomized delay for stealth testing  
- Immediate structured console output  

---

## Project Structure

HTTP-Header-Injection-Detector/
│
├── header_injectionv2.py
├── LICENSE
└── README.md

---

## Requirements

- Python 3.8+
- requests
- urllib3

Create a requirements.txt file containing:

requests
urllib3

Install dependencies:

pip install -r requirements.txt

---

## Usage

Basic scan:

python header_injectionv2.py http://target.com

Custom delay between requests:

python header_injectionv2.py http://target.com --delay 2

If no scheme is provided, http:// will be automatically added.

---

## Detection Methodology

1. Establish baseline response.
2. Inject multiple payload categories across headers.
3. Analyze responses for:
   - Direct reflection markers
   - Script execution patterns
   - SQL error messages
   - Injected response headers
4. Display findings in real time.

---


## Disclaimer

This tool is intended strictly for educational purposes and authorized security testing.
Do not use against systems without explicit written permission.
