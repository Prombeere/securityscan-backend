#!/usr/bin/env python3
"""
Nuclei Scanner Module - CVE and Template-based Vulnerability Scanner
Detects known vulnerabilities using signature matching
Python fallback with 10 built-in CVE signatures
"""
import requests
import re

BUILTIN_SIGNATURES = {
    'apache-struts-rce': {
        'severity': 'critical',
        'title': 'Apache Struts2 RCE (CVE-2017-5638 / CVE-2018-11776)',
        'indicators': [('header', 'Server', r'Struts'), ('content', None, r'org\.apache\.struts')],
        'remediation': 'SOFORT Apache Struts auf 2.5.22+ oder 2.3.37+ updaten!'
    },
    'log4j-rce': {
        'severity': 'critical',
        'title': 'Log4j Log4Shell RCE (CVE-2021-44228)',
        'indicators': [('header', 'X-Api-Version', r'\$\{.*\}'), ('content', None, r'log4j|log4shell')],
        'remediation': 'Log4j auf 2.17.1+ updaten!'
    },
    'spring4shell': {
        'severity': 'critical',
        'title': 'Spring4Shell RCE (CVE-2022-22965)',
        'indicators': [('header', None, r'Spring'), ('content', None, r'org\.springframework')],
        'remediation': 'Spring Framework auf 5.3.18+ / 5.2.20+ updaten!'
    },
    'exchange-proxyshell': {
        'severity': 'critical',
        'title': 'Microsoft Exchange ProxyShell (CVE-2021-34473)',
        'indicators': [('header', 'Server', r'Microsoft-IIS'), ('header', 'X-OWA-Version', None)],
        'remediation': 'Exchange auf CU21+ updaten!'
    },
    'drupalgeddon': {
        'severity': 'critical',
        'title': 'Drupalgeddon RCE (CVE-2018-7600)',
        'indicators': [('content', None, r'Drupal\s*7\.[0-6]'), ('content', None, r'Drupal\s*8\.[0-5]')],
        'remediation': 'Drupal SOFORT auf 7.86+ / 9.3.19+ / 10.0.9+ updaten!'
    },
    'joomla-cve': {
        'severity': 'high',
        'title': 'Joomla SQL Injection / RCE (CVE-2023-23752)',
        'indicators': [('content', None, r'Joomla!\s*3\.[0-9]'), ('content', None, r'Joomla!\s*4\.[0-1]')],
        'remediation': 'Joomla auf 4.3.4+ / 3.10.13+ updaten!'
    },
    'thinkphp-rce': {
        'severity': 'critical',
        'title': 'ThinkPHP RCE (CVE-2018-20062 / CVE-2019-9082)',
        'indicators': [('header', 'X-Powered-By', r'ThinkPHP'), ('content', None, r'ThinkPHP')],
        'remediation': 'ThinkPHP auf 5.0.24+ / 5.1.32+ / 6.0.14+ updaten!'
    },
    'django-debug': {
        'severity': 'high',
        'title': 'Django DEBUG Mode enabled',
        'indicators': [('content', None, r'Django[^<]+debug'), ('content', None, r'Traceback.*Django')],
        'remediation': 'DEBUG = False in settings.py setzen!'
    },
    'laravel-debug': {
        'severity': 'high',
        'title': 'Laravel DEBUG Mode / .env exposed',
        'indicators': [('content', None, r'Whoops! There was an error'), ('content', None, r'APP_KEY=')],
        'remediation': 'APP_DEBUG=false in .env setzen! .env-File schuetzen!'
    },
    'wordpress-cve': {
        'severity': 'high',
        'title': 'WordPress Unauthenticated RCE (CVE-2024-XXXX)',
        'indicators': [('content', None, r'WordPress\s*(6\.[0-3]|5\.[0-9])')],
        'remediation': 'WordPress auf 6.5+ updaten!'
    },
}


def scan(target):
    findings = []
    scan_id = 0
    if not target.startswith('http'):
        target = f'https://{target}'
    print(f"[PHASE NUCLEI] Scanning {target}")

    try:
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0 (SecurityScan/3.3)'})
        resp = session.get(target, timeout=15, verify=False, allow_redirects=True)
        content = resp.text
        headers = dict(resp.headers)
        server = resp.headers.get('Server', '').lower()

        # Check vulnerability paths
        vuln_paths = {
            '/.env': ('laravel-env', 'Laravel .env File Exposed - APP_KEY Leaked!', 'critical',
                      'APP_KEY', 'SOFORT .env schuetzen! APP_KEY rotieren!'),
            '/actuator/env': ('spring-actuator', 'Spring Boot Actuator Exposed', 'high',
                            'server.port', 'Actuator endpoints einschraenken!'),
            '/swagger-ui.html': ('swagger-ui', 'Swagger UI Exposed', 'medium',
                               'Swagger', 'Swagger UI absichern oder entfernen.'),
        }

        matched_signatures = []

        for sig_name, sig_data in BUILTIN_SIGNATURES.items():
            matched = False
            evidence_parts = []
            for indicator_type, indicator_header, indicator_pattern in sig_data['indicators']:
                if indicator_type == 'header' and indicator_header:
                    header_value = resp.headers.get(indicator_header, '')
                    if indicator_pattern and re.search(indicator_pattern, header_value, re.IGNORECASE):
                        matched = True
                        evidence_parts.append(f'Header {indicator_header}: {header_value[:100]}')
                    elif not indicator_pattern and header_value:
                        matched = True
                        evidence_parts.append(f'Header {indicator_header} present')
                elif indicator_type == 'content' and indicator_pattern:
                    if re.search(indicator_pattern, content, re.IGNORECASE):
                        matched = True
                        evidence_parts.append(f'Pattern: {indicator_pattern[:80]}')
            if matched:
                matched_signatures.append({
                    'name': sig_name, 'title': sig_data['title'], 'severity': sig_data['severity'],
                    'evidence': '\n'.join(evidence_parts), 'remediation': sig_data['remediation']
                })

        # Check vulnerability paths
        for path, (vuln_type, title, severity, check_str, remediation) in vuln_paths.items():
            try:
                path_resp = session.get(f'{target}{path}', timeout=8, verify=False, allow_redirects=False)
                if path_resp.status_code == 200 and check_str in path_resp.text:
                    matched_signatures.append({
                        'name': vuln_type, 'title': title, 'severity': severity,
                        'evidence': f'{path} accessible! {check_str} found.', 'remediation': remediation
                    })
            except:
                continue

        for sig in matched_signatures[:15]:
            findings.append({
                'id': f'nuc-{scan_id}', 'severity': sig['severity'], 'type': f'nuclei_{sig["name"]}',
                'title': f'[Nuclei] {sig["title"]}', 'url': target,
                'evidence': sig['evidence'], 'remediation': sig['remediation']
            })
            scan_id += 1

        if matched_signatures:
            findings.insert(0, {
                'id': f'nuc-{scan_id}', 'severity': 'info', 'type': 'nuclei_summary',
                'title': f'Nuclei: {len(matched_signatures)} CVE-Signaturen erkannt',
                'url': target,
                'evidence': f'Erkannt: {", ".join([s["title"] for s in matched_signatures[:5]])}',
                'remediation': 'Alle erkannten Schwachstellen sofort patchen!'
            })
        else:
            findings.append({
                'id': f'nuc-{scan_id}', 'severity': 'info', 'type': 'nuclei_clean',
                'title': 'Nuclei: Keine bekannten CVE-Signaturen',
                'url': target,
                'evidence': f'Server: {server or "unbekannt"}',
                'remediation': 'Regelmaessig scannen und Updates einspielen.'
            })

    except Exception as e:
        findings.append({
            'id': f'nuc-{scan_id}', 'severity': 'info', 'type': 'nuclei_error',
            'title': 'Nuclei: Scan-Fehler', 'url': target,
            'evidence': str(e), 'remediation': 'Ziel-URL pruefen.'
        })

    return findings
