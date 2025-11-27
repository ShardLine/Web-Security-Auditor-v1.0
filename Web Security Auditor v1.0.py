#!/usr/bin/env python3
"""
 Web Security Auditor v1.0
Ethical HTTP/SSL security headers & config checker.
Only for authorized pentesting targets.
"""
import sys
import requests
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

def check_headers(url):
    """Check security headers."""
    try:
        resp = requests.get(url, timeout=5, verify=True)
        headers = resp.headers
        issues = []
        
        required = {
            'Strict-Transport-Security': 'missing HSTS',
            'X-Frame-Options': 'missing XFO',
            'X-Content-Type-Options': 'missing XCTO',
            'Content-Security-Policy': 'missing CSP',
            'Referrer-Policy': 'missing RP'
        }
        
        for header, issue in required.items():
            if header not in headers:
                issues.append(issue)
        
        return {'url': url, 'issues': issues, 'status': resp.status_code}
    except Exception as e:
        return {'url': url, 'error': str(e)}

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 auditor.py <url1> [url2...]")
        sys.exit(1)
    
    targets = sys.argv[1:]
    print(f"[+] Auditing {len(targets)} targets | {datetime.now().strftime('%Y-%m-%d %H:%M')}")

    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(check_headers, targets))

    for r in results:
        print(f"\n{r['url']}: {r.get('status', 'ERR')} | Issues: {r.get('issues', [])}")

    print("[!] Ethical use only: own lab targets.")

if __name__ == "__main__":
    main()
