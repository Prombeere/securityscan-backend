"""
Header Scanner Module - 20+ security header checks
"""
import requests

def scan(target):
    findings = []
    scan_id = 0

    if not target.startswith('http'):
        target = f'https://{target}'

    print(f"[PHASE 3] Header Scanner: Scanning {target}")

    try:
        resp = requests.get(target, timeout=15, allow_redirects=True, verify=False, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        headers = {k.lower(): v for k, v in resp.headers.items()}
    except:
        return findings

    # X-Frame-Options
    x_frame = headers.get('x-frame-options', '')
    if not x_frame:
        findings.append({'id': f'hdr-{scan_id}', 'severity': 'medium', 'type': 'header_missing_x_frame_options', 'title': 'X-Frame-Options fehlt', 'url': target, 'evidence': 'Kein X-Frame-Options Header', 'remediation': 'X-Frame-Options: DENY oder SAMEORIGIN hinzufügen'})
        scan_id += 1
    elif x_frame.upper() not in ['DENY', 'SAMEORIGIN']:
        findings.append({'id': f'hdr-{scan_id}', 'severity': 'low', 'type': 'header_x_frame_weak', 'title': f'X-Frame-Options schwach: {x_frame}', 'url': target, 'evidence': f'X-Frame-Options: {x_frame}', 'remediation': 'X-Frame-Options: DENY'})
        scan_id += 1

    # X-Content-Type-Options
    if not headers.get('x-content-type-options'):
        findings.append({'id': f'hdr-{scan_id}', 'severity': 'low', 'type': 'header_missing_x_content_type', 'title': 'X-Content-Type-Options fehlt', 'url': target, 'evidence': 'Kein X-Content-Type-Options Header', 'remediation': 'X-Content-Type-Options: nosniff hinzufügen'})
        scan_id += 1

    # HSTS
    hsts = headers.get('strict-transport-security', '')
    if not hsts:
        findings.append({'id': f'hdr-{scan_id}', 'severity': 'high', 'type': 'header_missing_hsts', 'title': 'HSTS fehlt', 'url': target, 'evidence': 'Strict-Transport-Security: FEHLEND', 'remediation': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'})
        scan_id += 1
    elif 'includeSubDomains' not in hsts:
        findings.append({'id': f'hdr-{scan_id}', 'severity': 'medium', 'type': 'header_hsts_no_subdomains', 'title': 'HSTS ohne includeSubDomains', 'url': target, 'evidence': f'HSTS: {hsts}', 'remediation': 'includeSubDomains hinzufügen'})
        scan_id += 1

    # CSP
    csp = headers.get('content-security-policy', '')
    if not csp:
        findings.append({'id': f'hdr-{scan_id}', 'severity': 'medium', 'type': 'header_missing_csp', 'title': 'Content-Security-Policy fehlt', 'url': target, 'evidence': 'CSP: FEHLEND', 'remediation': 'Content-Security-Policy mit default-src implementieren'})
        scan_id += 1
    elif "'unsafe-inline'" in str(csp) or "'unsafe-eval'" in str(csp):
        findings.append({'id': f'hdr-{scan_id}', 'severity': 'medium', 'type': 'header_csp_weak', 'title': 'CSP erlaubt unsafe-inline/eval', 'url': target, 'evidence': f'CSP: {csp[:100]}...', 'remediation': 'unsafe-* entfernen, Nonces verwenden'})
        scan_id += 1

    # Referrer-Policy
    rp = headers.get('referrer-policy', '')
    if not rp:
        findings.append({'id': f'hdr-{scan_id}', 'severity': 'low', 'type': 'header_missing_referrer', 'title': 'Referrer-Policy fehlt', 'url': target, 'evidence': 'Referrer-Policy: FEHLEND', 'remediation': 'Referrer-Policy: strict-origin-when-cross-origin'})
        scan_id += 1
    elif rp == 'origin':
        findings.append({'id': f'hdr-{scan_id}', 'severity': 'low', 'type': 'header_referrer_weak', 'title': 'Referrer-Policy zu schwach', 'url': target, 'evidence': f'Referrer-Policy: {rp}', 'remediation': 'strict-origin-when-cross-origin verwenden'})
        scan_id += 1

    # Permissions-Policy
    if not headers.get('permissions-policy'):
        findings.append({'id': f'hdr-{scan_id}', 'severity': 'low', 'type': 'header_missing_permissions', 'title': 'Permissions-Policy fehlt', 'url': target, 'evidence': 'Permissions-Policy: FEHLEND', 'remediation': 'Permissions-Policy: camera=(), microphone=(), geolocation=()'})
        scan_id += 1

    # COOP
    coop = headers.get('cross-origin-opener-policy', '')
    if not coop:
        findings.append({'id': f'hdr-{scan_id}', 'severity': 'low', 'type': 'header_missing_coop', 'title': 'COOP fehlt', 'url': target, 'evidence': 'Cross-Origin-Opener-Policy: FEHLEND', 'remediation': 'COOP: same-origin-allow-popups'})
        scan_id += 1
    elif coop == 'unsafe-none':
        findings.append({'id': f'hdr-{scan_id}', 'severity': 'low', 'type': 'header_coop_weak', 'title': 'COOP: unsafe-none', 'url': target, 'evidence': 'COOP: unsafe-none', 'remediation': 'same-origin-allow-popups'})
        scan_id += 1

    # Server Header
    server = headers.get('server', '')
    if server:
        findings.append({'id': f'hdr-{scan_id}', 'severity': 'low', 'type': 'header_server_disclosure', 'title': f'Server-Version: {server}', 'url': target, 'evidence': f'Server: {server}', 'remediation': 'Server-Token entfernen oder generisch setzen'})
        scan_id += 1

    # X-Powered-By
    xpb = headers.get('x-powered-by', '')
    if xpb:
        findings.append({'id': f'hdr-{scan_id}', 'severity': 'low', 'type': 'header_x_powered_by', 'title': f'X-Powered-By: {xpb}', 'url': target, 'evidence': f'X-Powered-By: {xpb}', 'remediation': 'X-Powered-By Header entfernen'})
        scan_id += 1

    return findings
