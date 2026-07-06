"""
Redirect Scanner Module - Open redirect via common params, JS redirect, meta refresh detection
"""
import requests
from urllib.parse import urlparse, urljoin
import re

def scan(target):
    findings = []
    scan_id = 0

    if not target.startswith('http'):
        target = f'https://{target}'

    print(f"[PHASE 5] Redirect Scanner: Scanning {target}")

    parsed = urlparse(target)
    base_url = f'{parsed.scheme}://{parsed.netloc}'

    # Common redirect parameters
    redirect_params = {
        'redirect': 'https://evil.com',
        'url': 'https://evil.com',
        'next': 'https://evil.com',
        'return': 'https://evil.com',
        'goto': 'https://evil.com',
        'target': 'https://evil.com',
        'redir': 'https://evil.com',
        'link': 'https://evil.com',
        'returnUrl': 'https://evil.com',
        'return_url': 'https://evil.com',
        'redirect_url': 'https://evil.com',
        'redirect_uri': 'https://evil.com',
        'callback': 'https://evil.com',
        'continue': 'https://evil.com',
        'destination': 'https://evil.com',
        'forward': 'https://evil.com',
        'return_to': 'https://evil.com',
        'success': 'https://evil.com',
        'error': 'https://evil.com',
        'logout': 'https://evil.com',
        'referer': 'https://evil.com',
        'ref': 'https://evil.com',
    }

    # Test each redirect parameter
    for param_name, redirect_url in redirect_params.items():
        test_urls = [
            f'{base_url}/?{param_name}={requests.utils.quote(redirect_url)}',
            f'{base_url}/login?{param_name}={requests.utils.quote(redirect_url)}',
            f'{base_url}/auth?{param_name}={requests.utils.quote(redirect_url)}',
            f'{base_url}/logout?{param_name}={requests.utils.quote(redirect_url)}',
        ]

        for test_url in test_urls:
            try:
                resp = requests.get(test_url, timeout=10, allow_redirects=False, verify=False, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })

                # Check for 302/301 redirect
                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get('Location', '')
                    if 'evil.com' in location or redirect_url in location:
                        findings.append({
                            'id': f'redir-{scan_id}',
                            'severity': 'high',
                            'type': 'open_redirect',
                            'title': 'Open Redirect Verwundbarkeit',
                            'url': test_url,
                            'evidence': f'Parameter "{param_name}" verursacht Redirect nach {location} (Status: {resp.status_code})',
                            'remediation': 'Redirect-URLs auf Whitelist-Validierung prüfen. Nur relative URLs oder registrierte Domains erlauben.'
                        })
                        scan_id += 1
                        break

                # Check for JavaScript redirect in body
                if resp.status_code == 200:
                    js_redirect_patterns = [
                        r'window\.location\s*=\s*[\'"]https?://evil\.com',
                        r'window\.location\.href\s*=\s*[\'"]https?://evil\.com',
                        r'window\.location\.replace\s*\(\s*[\'"]https?://evil\.com',
                        r'location\.href\s*=\s*[\'"]https?://evil\.com',
                    ]
                    for pattern in js_redirect_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            findings.append({
                                'id': f'redir-{scan_id}',
                                'severity': 'high',
                                'type': 'open_redirect_js',
                                'title': 'Open Redirect über JavaScript',
                                'url': test_url,
                                'evidence': f'JavaScript-Redirect nach evil.com durch Parameter "{param_name}"',
                                'remediation': 'Client-seitige Redirects validieren. Keine Benutzersteuerung von location.href erlauben.'
                            })
                            scan_id += 1
                            break

            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue

    # Meta refresh detection on main page
    try:
        resp = requests.get(target, timeout=10, verify=False, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        meta_refresh = re.findall(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'](\d+);\s*url=([^"\']+)["\']', resp.text, re.IGNORECASE)
        if meta_refresh:
            for delay, url in meta_refresh:
                findings.append({
                    'id': f'redir-{scan_id}',
                    'severity': 'info',
                    'type': 'meta_refresh',
                    'title': 'Meta-Refresh Redirect gefunden',
                    'url': target,
                    'evidence': f'Meta-Refresh: {delay}s -> {url}',
                    'remediation': 'Meta-Refresh durch serverseitige Redirects ersetzen.'
                })
                scan_id += 1

        # Detect JavaScript redirects in page content
        js_redirects = re.findall(r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
        js_redirects += re.findall(r'window\.location\.replace\s*\(\s*["\']([^"\']+)["\']\s*\)', resp.text, re.IGNORECASE)
        if js_redirects:
            for js_url in js_redirects[:5]:
                if not js_url.startswith('#') and not js_url.startswith('javascript:'):
                    findings.append({
                        'id': f'redir-{scan_id}',
                        'severity': 'info',
                        'type': 'js_redirect',
                        'title': 'JavaScript Redirect gefunden',
                        'url': target,
                        'evidence': f'JS Redirect nach: {js_url}',
                        'remediation': 'JavaScript-Redirects auf Benutzersteuerung prüfen.'
                    })
                    scan_id += 1

    except Exception:
        pass

    if scan_id == 0:
        findings.append({
            'id': f'redir-{scan_id}',
            'severity': 'info',
            'type': 'redirect_no_issues',
            'title': 'Keine Open Redirects gefunden',
            'url': target,
            'evidence': 'Getestete Redirect-Parameter wurden nicht umgelenkt',
            'remediation': 'Trotzdem Redirect-Validierung implementieren.'
        })

    return findings
