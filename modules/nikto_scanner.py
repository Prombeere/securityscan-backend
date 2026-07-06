#!/usr/bin/env python3
"""
Nikto Scanner Module - Comprehensive Web Server Scanner
Scans for dangerous files/CGI, outdated server software, server config issues
"""
import requests
import re

DANGEROUS_PATHS = {
    'critical': [
        ('/phpmyadmin/', 'phpMyAdmin exposed'), ('/pma/', 'phpMyAdmin alternate'),
        ('/adminer.php', 'Adminer database tool'), ('/dbadmin/', 'Database admin'),
        ('/.env', 'Environment file with secrets'), ('/.git/', 'Git repo exposed'),
        ('/.svn/', 'SVN repo exposed'), ('/.hg/', 'Mercurial repo exposed'),
        ('/backup.sql', 'Database backup'), ('/dump.sql', 'Database dump'),
        ('/config.json', 'Config file'), ('/credentials.json', 'Credentials'),
        ('/passwords.txt', 'Passwords list'), ('/secrets.json', 'Secrets file'),
    ],
    'high': [
        ('/admin/', 'Admin panel'), ('/administrator/', 'Administrator panel'),
        ('/wp-admin/', 'WordPress admin'), ('/wp-login.php', 'WordPress login'),
        ('/login/', 'Login page'), ('/install/', 'Installation page'),
        ('/setup/', 'Setup page'), ('/phpinfo.php', 'PHP Info'),
        ('/server-status', 'Apache status'), ('/actuator/env', 'Spring Boot env'),
        ('/swagger-ui.html', 'Swagger UI'), ('/api-docs/', 'API docs'),
        ('/graphql', 'GraphQL endpoint'), ('/elmah.axd', 'ELMAH error logs'),
    ],
    'medium': [
        ('/test/', 'Test directory'), ('/temp/', 'Temporary files'),
        ('/logs/', 'Log files'), ('/debug/', 'Debug info'),
        ('/dev/', 'Development files'), ('/staging/', 'Staging environment'),
        ('/upload/', 'Upload directory'), ('/cgi-bin/', 'CGI scripts'),
        ('/scripts/', 'Script directory'), ('/error/', 'Error pages'),
    ],
}


def scan(target):
    findings = []
    scan_id = 0
    if not target.startswith('http'):
        target = f'https://{target}'
    print(f"[PHASE NIKTO] Scanning {target}")

    try:
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0 (SecurityScan/3.3)'})

        resp = session.get(target, timeout=15, verify=False, allow_redirects=True)
        headers = resp.headers
        server = headers.get('Server', '')
        content = resp.text

        # Server version detection
        server_vulns = {
            r'Apache/2\.2': 'Apache 2.2.x - EOL, upgrade immediately!',
            r'IIS/6': 'IIS 6.0 - CRITICAL: EOL, upgrade immediately!',
            r'Apache-Coyote': 'Apache Tomcat - verify version and patches',
            r'mini_httpd': 'Mini_httpd - potential vulnerabilities',
        }
        if server:
            for pattern, message in server_vulns.items():
                if re.search(pattern, server, re.IGNORECASE):
                    severity = 'critical' if 'CRITICAL' in message or 'EOL' in message else 'medium'
                    findings.append({
                        'id': f'nik-{scan_id}', 'severity': severity, 'type': 'nikto_server_version',
                        'title': f'Server: {server[:60]}', 'url': target,
                        'evidence': message, 'remediation': 'Server-Software auf aktuelle Version updaten.'
                    })
                    scan_id += 1

        # Missing security headers
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'X-Frame-Options': 'Clickjacking Protection',
            'X-Content-Type-Options': 'MIME-Type Sniffing Protection',
            'Content-Security-Policy': 'Content Security Policy',
            'Referrer-Policy': 'Referrer Policy',
            'Permissions-Policy': 'Permissions Policy',
        }
        for header, desc in security_headers.items():
            if header not in headers:
                findings.append({
                    'id': f'nik-{scan_id}', 'severity': 'medium', 'type': 'nikto_missing_header',
                    'title': f'Fehlender Header: {header}', 'url': target,
                    'evidence': f'{desc} nicht konfiguriert.', 'remediation': f'{header} Header konfigurieren.'
                })
                scan_id += 1

        # Scan dangerous paths
        found_paths = []
        for severity_level, paths in DANGEROUS_PATHS.items():
            for path, desc in paths:
                try:
                    path_resp = session.get(f'{target}{path}', timeout=8, verify=False, allow_redirects=False)
                    if path_resp.status_code in [200, 201, 204, 301, 302, 401, 403, 407]:
                        found_paths.append((path, desc, severity_level, path_resp.status_code))
                except:
                    continue

        for path, desc, severity, status in found_paths[:30]:
            findings.append({
                'id': f'nik-{scan_id}', 'severity': severity, 'type': 'nikto_dangerous_path',
                'title': f'{desc}: {path}', 'url': f'{target}{path}',
                'evidence': f'Status: {status}', 'remediation': f'{path} entfernen oder schuetzen.'
            })
            scan_id += 1

        # Check TRACE method
        try:
            trace_resp = session.request('TRACE', target, timeout=10, verify=False)
            if trace_resp.status_code == 200:
                findings.append({
                    'id': f'nik-{scan_id}', 'severity': 'medium', 'type': 'nikto_trace_enabled',
                    'title': 'HTTP TRACE aktiviert', 'url': target,
                    'evidence': 'TRACE erfolgreich. XST moeglich.',
                    'remediation': 'TRACE deaktivieren. Apache: TraceEnable off'
                })
                scan_id += 1
        except:
            pass

        if found_paths:
            findings.insert(0, {
                'id': f'nik-{scan_id}', 'severity': 'info', 'type': 'nikto_summary',
                'title': f'Nikto: {len(found_paths)} sensible Pfade gefunden',
                'url': target, 'evidence': f'Gefunden: {", ".join([p[0] for p in found_paths[:10]])}',
                'remediation': 'Alle Pfade pruefen und absichern.'
            })
        else:
            findings.append({
                'id': f'nik-{scan_id}', 'severity': 'info', 'type': 'nikto_clean',
                'title': 'Nikto: Keine kritischen Pfade gefunden', 'url': target,
                'evidence': 'Alle Pfade nicht erreichbar oder geschuetzt.',
                'remediation': 'Weiterhin regelmaessig scannen.'
            })

    except Exception as e:
        findings.append({
            'id': f'nik-{scan_id}', 'severity': 'info', 'type': 'nikto_error',
            'title': 'Nikto: Scan-Fehler', 'url': target,
            'evidence': str(e), 'remediation': 'Ziel-URL pruefen.'
        })

    return findings
