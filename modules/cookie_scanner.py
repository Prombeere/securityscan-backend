"""
Cookie Scanner Module - Cookie security analysis
"""
import requests

def scan(target):
    findings = []
    scan_id = 0

    if not target.startswith('http'):
        target = f'https://target}'

    print(f"[PHASE 9] Cookie Scanner: Scanning {target}")

    try:
        resp = requests.get(target, timeout=15, allow_redirects=True, verify=False)
        cookies = resp.cookies

        for cookie in cookies:
            # Secure flag
            if not cookie.secure:
                findings.append({
                    'id': f'ck-{scan_id}',
                    'severity': 'medium',
                    'type': 'cookie_no_secure',
                    'title': f'Cookie "{cookie.name}" ohne Secure-Flag',
                    'url': target,
                    'evidence': f'Set-Cookie: {cookie.name}=... (kein Secure)',
                    'remediation': 'Secure-Flag hinzufügen'
                })
                scan_id += 1

            # HttpOnly
            if not cookie.has_nonstandard_attr('HttpOnly') and not getattr(cookie, 'httponly', False):
                findings.append({
                    'id': f'ck-{scan_id}',
                    'severity': 'medium',
                    'type': 'cookie_no_httponly',
                    'title': f'Cookie "{cookie.name}" ohne HttpOnly',
                    'url': target,
                    'evidence': f'Set-Cookie: {cookie.name}=... (kein HttpOnly)',
                    'remediation': 'HttpOnly-Flag hinzufügen'
                })
                scan_id += 1

            # SameSite
            samesite = getattr(cookie, '_rest', {}).get('SameSite', '')
            if not samesite:
                findings.append({
                    'id': f'ck-{scan_id}',
                    'severity': 'low',
                    'type': 'cookie_no_samesite',
                    'title': f'Cookie "{cookie.name}" ohne SameSite',
                    'url': target,
                    'evidence': f'Set-Cookie: {cookie.name}=... (kein SameSite)',
                    'remediation': 'SameSite=Strict oder Lax hinzufügen'
                })
                scan_id += 1
            elif samesite.lower() == 'none' and not cookie.secure:
                findings.append({
                    'id': f'ck-{scan_id}',
                    'severity': 'high',
                    'type': 'cookie_samesite_none insecure',
                    'title': f'SameSite=None ohne Secure: {cookie.name}',
                    'url': target,
                    'evidence': f'SameSite=None ohne Secure-Flag',
                    'remediation': 'Secure-Flag hinzufügen oder SameSite ändern'
                })
                scan_id += 1

    except Exception as e:
        findings.append({
            'id': f'ck-{scan_id}',
            'severity': 'info',
            'type': 'cookie_error',
            'title': 'Cookie-Scan fehlgeschlagen',
            'url': target,
            'evidence': str(e),
            'remediation': 'Manuell prüfen'
        })

    return findings
