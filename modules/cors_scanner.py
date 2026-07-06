"""
CORS Scanner Module - CORS misconfiguration detection
"""
import requests

def scan(target):
    findings = []
    scan_id = 0

    if not target.startswith('http'):
        target = f'https://{target}'

    print(f"[PHASE 10] CORS Scanner: Scanning {target}")

    # Test 1: Evil origin
    try:
        resp = requests.get(target, timeout=10, verify=False, headers={
            'Origin': 'https://evil.com',
            'User-Agent': 'Mozilla/5.0'
        })
        acao = resp.headers.get('Access-Control-Allow-Origin', '')
        acac = resp.headers.get('Access-Control-Allow-Credentials', '')

        if acao == 'https://evil.com':
            findings.append({
                'id': f'cors-{scan_id}',
                'severity': 'critical' if acac.lower() == 'true' else 'high',
                'type': 'cors_origin_reflection',
                'title': 'CORS Origin Reflection',
                'url': target,
                'evidence': f'Access-Control-Allow-Origin: {acao}',
                'remediation': 'Whitelist-basierte Origin-Validierung implementieren'
            })
            scan_id += 1
        elif acao == '*':
            findings.append({
                'id': f'cors-{scan_id}',
                'severity': 'medium',
                'type': 'cors_wildcard',
                'title': 'CORS Wildcard (*) erlaubt',
                'url': target,
                'evidence': 'Access-Control-Allow-Origin: *',
                'remediation': 'Spezifische Origins whitelisten'
            })
            scan_id += 1

        if acac.lower() == 'true' and (acao == '*' or acao):
            findings.append({
                'id': f'cors-{scan_id}',
                'severity': 'medium',
                'type': 'cors_credentials_wildcard',
                'title': 'CORS Allow-Credentials ohne Origin-Check',
                'url': target,
                'evidence': f'Allow-Credentials: true mit Origin: {acao}',
                'remediation': 'Credentials nur für verifizierte Origins'
            })
            scan_id += 1

    except:
        pass

    # Test 2: Null origin
    try:
        resp = requests.get(target, timeout=10, verify=False, headers={
            'Origin': 'null',
            'User-Agent': 'Mozilla/5.0'
        })
        if resp.headers.get('Access-Control-Allow-Origin') == 'null':
            findings.append({
                'id': f'cors-{scan_id}',
                'severity': 'high',
                'type': 'cors_null_origin',
                'title': 'CORS Null Origin akzeptiert',
                'url': target,
                'evidence': 'Access-Control-Allow-Origin: null',
                'remediation': 'Null Origin blockieren'
            })
    except:
        pass

    if not findings:
        findings.append({
            'id': 'cors-ok',
            'severity': 'info',
            'type': 'cors_scan',
            'title': 'Keine CORS Schwachstellen gefunden',
            'url': target,
            'evidence': 'CORS korrekt konfiguriert',
            'remediation': 'Keine Aktion'
        })

    return findings
