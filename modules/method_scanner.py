"""
Method Scanner Module - OPTIONS, PUT/DELETE/PATCH, TRACE (XST), CONNECT testing
"""
import requests
from urllib.parse import urlparse

def scan(target):
    findings = []
    scan_id = 0

    if not target.startswith('http'):
        target = f'https://{target}'

    print(f"[PHASE 6] Method Scanner: Scanning {target}")

    # OPTIONS discovery
    try:
        resp = requests.options(target, timeout=10, verify=False, allow_redirects=False)
        allow_header = resp.headers.get('Allow', '')
        allow_header_2 = resp.headers.get('Access-Control-Allow-Methods', '')
        all_methods = []
        if allow_header:
            all_methods = [m.strip() for m in allow_header.split(',')]
        elif allow_header_2:
            all_methods = [m.strip() for m in allow_header_2.split(',')]

        if all_methods:
            findings.append({
                'id': f'meth-{scan_id}',
                'severity': 'info',
                'type': 'options_methods',
                'title': f'HTTP-Methoden via OPTIONS: {", ".join(all_methods)}',
                'url': target,
                'evidence': f'Allow: {allow_header or allow_header_2}',
                'remediation': 'Nur notwendige HTTP-Methoden aktivieren.'
            })
            scan_id += 1

        # Check for dangerous methods
        dangerous = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']
        found_dangerous = [m for m in all_methods if m.upper() in dangerous]
        if found_dangerous:
            findings.append({
                'id': f'meth-{scan_id}',
                'severity': 'medium',
                'type': 'dangerous_methods_enabled',
                'title': f'Möglicherweise gefährliche HTTP-Methoden erlaubt: {", ".join(found_dangerous)}',
                'url': target,
                'evidence': f'Gefährliche Methoden in Allow-Header: {", ".join(found_dangerous)}',
                'remediation': 'Nicht benötigte HTTP-Methoden (PUT, DELETE, TRACE, CONNECT) deaktivieren.'
            })
            scan_id += 1
    except requests.exceptions.RequestException as e:
        findings.append({
            'id': f'meth-{scan_id}',
            'severity': 'info',
            'type': 'options_error',
            'title': 'OPTIONS-Anfrage fehlgeschlagen',
            'url': target,
            'evidence': f'Fehler: {str(e)}',
            'remediation': 'Server-Konfiguration prüfen.'
        })
        scan_id += 1

    # PUT testing
    try:
        test_content = '<html><body>Security Test</body></html>'
        resp = requests.put(f'{target}/security_test_put.html', data=test_content, timeout=10, verify=False, allow_redirects=False)
        if resp.status_code in [200, 201, 204]:
            findings.append({
                'id': f'meth-{scan_id}',
                'severity': 'critical',
                'type': 'put_enabled',
                'title': 'HTTP PUT-Methode aktiviert - Datei-Upload möglich',
                'url': f'{target}/security_test_put.html',
                'evidence': f'PUT-Anfrage erfolgreich mit Status {resp.status_code}',
                'remediation': 'PUT-Methode sofort deaktivieren falls nicht benötigt!'
            })
            scan_id += 1
        elif resp.status_code == 401:
            findings.append({
                'id': f'meth-{scan_id}',
                'severity': 'low',
                'type': 'put_auth_required',
                'title': 'PUT erfordert Authentifizierung',
                'url': target,
                'evidence': f'PUT gibt 401 Unauthorized zurück',
                'remediation': 'Authentifizierung für PUT sicherstellen.'
            })
            scan_id += 1
    except requests.exceptions.RequestException:
        pass
    except Exception:
        pass

    # DELETE testing
    try:
        resp = requests.delete(f'{target}/security_test_put.html', timeout=10, verify=False, allow_redirects=False)
        if resp.status_code in [200, 202, 204]:
            findings.append({
                'id': f'meth-{scan_id}',
                'severity': 'critical',
                'type': 'delete_enabled',
                'title': 'HTTP DELETE-Methode aktiviert',
                'url': target,
                'evidence': f'DELETE-Anfrage erfolgreich mit Status {resp.status_code}',
                'remediation': 'DELETE-Methode sofort deaktivieren falls nicht benötigt!'
            })
            scan_id += 1
    except requests.exceptions.RequestException:
        pass
    except Exception:
        pass

    # PATCH testing
    try:
        resp = requests.patch(f'{target}/security_test_patch', data='test=data', timeout=10, verify=False, allow_redirects=False)
        if resp.status_code in [200, 201, 204]:
            findings.append({
                'id': f'meth-{scan_id}',
                'severity': 'high',
                'type': 'patch_enabled',
                'title': 'HTTP PATCH-Methode aktiviert',
                'url': target,
                'evidence': f'PATCH-Anfrage erfolgreich mit Status {resp.status_code}',
                'remediation': 'PATCH-Methode einschränken oder deaktivieren.'
            })
            scan_id += 1
    except requests.exceptions.RequestException:
        pass
    except Exception:
        pass

    # TRACE testing (XST - Cross-Site Tracing)
    try:
        import urllib.request
        parsed = urlparse(target)
        req = urllib.request.Request(target, method='TRACE')
        req.add_header('User-Agent', 'Mozilla/5.0')
        req.add_header('Cookie', 'testcookie=trace_test')
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            body = resp.read().decode('utf-8', errors='ignore')
            if 'TRACE' in body or 'testcookie=trace_test' in body:
                findings.append({
                    'id': f'meth-{scan_id}',
                    'severity': 'high',
                    'type': 'xst_enabled',
                    'title': 'Cross-Site Tracing (XST) aktiviert - TRACE-Methode',
                    'url': target,
                    'evidence': 'TRACE-Anfrage reflektiert Cookies zurück',
                    'remediation': 'TRACE-Methode deaktivieren. In Apache: TraceEnable off, Nginx: limit_except'
                })
                scan_id += 1
        except urllib.error.HTTPError as e:
            if e.code == 405:
                findings.append({
                    'id': f'meth-{scan_id}',
                    'severity': 'info',
                    'type': 'trace_disabled',
                    'title': 'TRACE-Methode deaktiviert',
                    'url': target,
                    'evidence': 'TRACE gibt 405 Method Not Allowed zurück',
                    'remediation': 'Keine Aktion erforderlich.'
                })
                scan_id += 1
    except Exception:
        pass

    # CONNECT tunnel check
    try:
        import urllib.request
        parsed = urlparse(target)
        connect_target = f'{parsed.hostname}:{parsed.port or 443}'
        req = urllib.request.Request(target, method='CONNECT')
        req.add_header('User-Agent', 'Mozilla/5.0')
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            findings.append({
                'id': f'meth-{scan_id}',
                'severity': 'high',
                'type': 'connect_enabled',
                'title': 'HTTP CONNECT-Methode aktiviert',
                'url': target,
                'evidence': f'CONNECT-Anfrage erfolgreich (Status: {resp.getcode()})',
                'remediation': 'CONNECT-Methode deaktivieren um Proxy-Tunneling zu verhindern.'
            })
            scan_id += 1
        except urllib.error.HTTPError as e:
            if e.code == 405:
                findings.append({
                    'id': f'meth-{scan_id}',
                    'severity': 'info',
                    'type': 'connect_disabled',
                    'title': 'CONNECT-Methode deaktiviert',
                    'url': target,
                    'evidence': 'CONNECT gibt 405 zurück',
                    'remediation': 'Keine Aktion erforderlich.'
                })
                scan_id += 1
    except Exception:
        pass

    # DAV methods check
    try:
        resp = requests.request('PROPFIND', target, timeout=10, verify=False, allow_redirects=False)
        if resp.status_code not in [405, 501, 404]:
            findings.append({
                'id': f'meth-{scan_id}',
                'severity': 'medium',
                'type': 'webdav_enabled',
                'title': 'WebDAV PROPFIND-Methode aktiviert',
                'url': target,
                'evidence': f'PROPFIND gibt Status {resp.status_code} zurück',
                'remediation': 'WebDAV deaktivieren falls nicht benötigt.'
            })
            scan_id += 1
    except Exception:
        pass

    if scan_id == 0:
        findings.append({
            'id': f'meth-{scan_id}',
            'severity': 'info',
            'type': 'methods_scan_complete',
            'title': 'HTTP-Methoden-Scan abgeschlossen',
            'url': target,
            'evidence': 'Keine kritischen Methoden-Probleme gefunden',
            'remediation': 'Regelmäßig HTTP-Methoden überprüfen.'
        })

    return findings
