"""
XSS Scanner Module - Reflected XSS detection
"""
import requests
import urllib.parse

def scan(target):
    findings = []
    scan_id = 0

    if not target.startswith('http'):
        target = f'https://{target}'

    print(f"[PHASE 4] XSS Scanner: Scanning {target}")

    payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
    ]

    params = ['q', 'search', 'id', 'name', 'user', 'comment', 'message', 'data', 'value']

    for param in params[:5]:
        for payload in payloads[:3]:
            try:
                url = f"{target}?{param}={urllib.parse.quote(payload)}"
                resp = requests.get(url, timeout=10, verify=False, headers={
                    'User-Agent': 'Mozilla/5.0 (SecurityScan/1.0)'
                })
                body = resp.text.lower()
                payload_lower = payload.lower()

                if payload_lower in body or payload.lower().replace(' ', '') in body:
                    findings.append({
                        'id': f'xss-{scan_id}',
                        'severity': 'critical',
                        'type': 'xss_reflected',
                        'title': f'Reflected XSS in Parameter "{param}"',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': f'Payload "{payload[:40]}" reflektiert in Response',
                        'remediation': 'Output-Encoding implementieren, CSP setzen, Input validieren'
                    })
                    return findings
            except:
                continue

    if not findings:
        findings.append({
            'id': 'xss-ok',
            'severity': 'info',
            'type': 'xss_scan',
            'title': 'Kein reflected XSS gefunden',
            'url': target,
            'evidence': 'XSS Payloads nicht reflektiert',
            'remediation': 'Weiterhin Output-Encoding verwenden'
        })

    return findings
