"""
CVE Scanner - Technology-to-CVE mapping scanner
Detects technologies and maps them to known vulnerabilities
"""
import re
import requests

# Built-in CVE database: tech_name -> list of CVE entries
# Each entry: {cve_id, description, affected_versions, severity, cvss_score, remediation_url}
CVE_DATABASE = {
    'Apache': [
        {'cve_id': 'CVE-2021-41773', 'description': 'Path Traversal in Apache 2.4.49', 'affected': ('2.4.49', '2.4.49'), 'severity': 'critical', 'cvss': 9.8, 'url': 'https://httpd.apache.org/security/vulnerabilities_24.html'},
        {'cve_id': 'CVE-2021-42013', 'description': 'RCE via Path Traversal in Apache 2.4.49', 'affected': ('2.4.49', '2.4.49'), 'severity': 'critical', 'cvss': 9.8, 'url': 'https://httpd.apache.org/security/vulnerabilities_24.html'},
    ],
    'Nginx': [
        {'cve_id': 'CVE-2021-23017', 'description': 'Heap buffer overflow in Nginx resolver', 'affected': ('0.6.18', '1.20.0'), 'severity': 'high', 'cvss': 7.7, 'url': 'https://nginx.org/en/security_advisories.html'},
    ],
    'IIS': [
        {'cve_id': 'CVE-2017-7269', 'description': 'IIS 6.0 WebDAV RCE (Buffer Overflow)', 'affected': ('6.0', '6.0'), 'severity': 'high', 'cvss': 7.8, 'url': 'https://msrc.microsoft.com/'},
        {'cve_id': 'EOL-WARNING', 'description': 'IIS 6.0 is End-of-Life since July 2015', 'affected': ('6.0', '6.0'), 'severity': 'high', 'cvss': 7.0, 'url': 'https://support.microsoft.com/'},
    ],
    'PHP': [
        {'cve_id': 'CVE-2021-21708', 'description': 'Use-after-free in PHP 8.0', 'affected': ('8.0.0', '8.0.12'), 'severity': 'high', 'cvss': 8.1, 'url': 'https://www.php.net/security/'},
        {'cve_id': 'EOL-PHP7', 'description': 'PHP 7.x is End-of-Life since November 2022', 'affected': ('7.0.0', '7.4.99'), 'severity': 'high', 'cvss': 7.0, 'url': 'https://www.php.net/supported-versions.php'},
    ],
    'WordPress': [
        {'cve_id': 'CVE-2021-44223', 'description': 'SQL Injection in WordPress < 5.8.2', 'affected': ('0.0', '5.8.1'), 'severity': 'high', 'cvss': 8.1, 'url': 'https://wordpress.org/news/category/security/'},
        {'cve_id': 'WP-OUTDATED', 'description': 'WordPress version may be outdated', 'affected': ('0.0', '6.0.0'), 'severity': 'medium', 'cvss': 5.0, 'url': 'https://wordpress.org/download/'},
    ],
    'Drupal': [
        {'cve_id': 'SA-CORE-2021-011', 'description': 'Access bypass in Drupal core', 'affected': ('0.0', '9.2.0'), 'severity': 'high', 'cvss': 7.5, 'url': 'https://www.drupal.org/security'},
    ],
    'jQuery': [
        {'cve_id': 'CVE-2020-11022', 'description': 'XSS in jQuery < 3.5.0', 'affected': ('0.0', '3.4.99'), 'severity': 'medium', 'cvss': 6.1, 'url': 'https://github.com/jquery/jquery/security'},
        {'cve_id': 'CVE-2021-41182', 'description': 'XSS in jQuery UI', 'affected': ('0.0', '1.12.99'), 'severity': 'medium', 'cvss': 6.1, 'url': 'https://github.com/jquery/jquery-ui/security'},
    ],
    'Apache Struts': [
        {'cve_id': 'CVE-2017-5638', 'description': 'RCE via OGNL Expression (Struts 2)', 'affected': ('2.0.0', '2.3.32'), 'severity': 'critical', 'cvss': 10.0, 'url': 'https://cwiki.apache.org/confluence/display/WW/Security+Bulletins'},
    ],
    'Log4j': [
        {'cve_id': 'CVE-2021-44228', 'description': 'Log4Shell RCE (Log4j 2.0-2.14.1)', 'affected': ('2.0.0', '2.14.1'), 'severity': 'critical', 'cvss': 10.0, 'url': 'https://logging.apache.org/log4j/2.x/security.html'},
    ],
    'Spring': [
        {'cve_id': 'CVE-2022-22965', 'description': 'Spring4Shell RCE in Spring Framework', 'affected': ('5.3.0', '5.3.17'), 'severity': 'critical', 'cvss': 9.8, 'url': 'https://spring.io/security'},
    ],
    'Tomcat': [
        {'cve_id': 'CVE-2020-1938', 'description': 'Ghostcat - AJP file read/inclusion', 'affected': ('6.0.0', '9.0.30'), 'severity': 'critical', 'cvss': 9.8, 'url': 'https://tomcat.apache.org/security.html'},
    ],
    'Redis': [
        {'cve_id': 'CVE-2015-8080', 'description': 'Redis unauthenticated access allows RCE', 'affected': ('0.0', '99.99'), 'severity': 'critical', 'cvss': 9.0, 'url': 'https://redis.io/docs/management/security/'},
    ],
    'MongoDB': [
        {'cve_id': 'INFO-MONGO', 'description': 'MongoDB may be accessible without authentication', 'affected': ('0.0', '99.99'), 'severity': 'medium', 'cvss': 5.0, 'url': 'https://docs.mongodb.com/manual/security/'},
    ],
}

# Technology detection patterns
TECH_PATTERNS = {
    'Apache': {'headers': {'Server': r'Apache[/\s]?([0-9.]+)?'}, 'body': []},
    'Nginx': {'headers': {'Server': r'nginx[/\s]?([0-9.]+)?'}, 'body': []},
    'IIS': {'headers': {'Server': r'Microsoft-IIS[/\s]?([0-9.]+)?'}, 'body': []},
    'Tomcat': {'headers': {'Server': r'Apache-Coyote|Tomcat[/\s]?([0-9.]+)?'}, 'body': []},
    'Jetty': {'headers': {'Server': r'Jetty[/\s]?([0-9.]+)?'}, 'body': []},
    'PHP': {'headers': {'X-Powered-By': r'PHP[/\s]?([0-9.]+)?'}, 'body': []},
    'ASP.NET': {'headers': {'X-AspNet-Version': r'([0-9.]+)?', 'X-Powered-By': r'ASP\.NET'}, 'body': []},
    'Rails': {'headers': {'X-Runtime': r'.*', 'Server': r'.*Rails.*'}, 'body': []},
    'Django': {'headers': {}, 'body': [r'csrftoken', r'django'], 'cookies': ['csrftoken']},
    'Laravel': {'headers': {}, 'body': [r'laravel_session'], 'cookies': ['laravel_session']},
    'Express.js': {'headers': {'X-Powered-By': r'Express'}, 'body': []},
    'Spring': {'headers': {'X-Application-Context': r'.*'}, 'body': [r'spring']},
    'WordPress': {'headers': {}, 'body': [r'wp-content', 'wp-includes', '/wp-json/', r'generator.*wordpress']},
    'Drupal': {'headers': {'X-Generator': r'Drupal\s*([0-9.]+)?'}, 'body': []},
    'Joomla': {'headers': {}, 'body': [r'Joomla', '/media/joom']},
    'jQuery': {'headers': {}, 'body': [r'jquery[/-]([0-9.]+)?']},
    'Bootstrap': {'headers': {}, 'body': [r'bootstrap[/-]([0-9.]+)?']},
    'Angular': {'headers': {}, 'body': [r'angular[/-]([0-9.]+)?', r'ng-']},
    'React': {'headers': {}, 'body': [r'react[/-]([0-9.]+)?']},
    'Vue': {'headers': {}, 'body': [r'vue[/-]([0-9.]+)?', r'v-']},
    'Apache Struts': {'headers': {}, 'body': [r'struts', r'ognl']},
    'Log4j': {'headers': {}, 'body': [r'log4j', r'jndirmi']},
    'Redis': {'headers': {}, 'body': [r'redis']},
    'MongoDB': {'headers': {}, 'body': [r'mongodb', r'mongo']},
}


def parse_version(version_str):
    """Parse version string to tuple for comparison"""
    if not version_str:
        return None
    try:
        parts = re.findall(r'(\d+)', version_str)
        return tuple(int(p) for p in parts[:4])
    except:
        return None


def version_in_range(version, min_ver, max_ver):
    """Check if version is within affected range"""
    v = parse_version(version)
    if not v:
        return True  # If we can't parse, assume vulnerable
    lo = parse_version(min_ver)
    hi = parse_version(max_ver)
    if lo and hi:
        return lo <= v <= hi
    if lo:
        return v >= lo
    if hi:
        return v <= hi
    return True


def scan(target):
    """Run CVE scan based on technology detection"""
    findings = []
    host = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
    
    # Try to fetch the target
    urls_to_try = [f'https://{host}', f'http://{host}']
    resp = None
    final_url = None
    
    for url in urls_to_try:
        try:
            resp = requests.get(url, timeout=10, allow_redirects=False, headers={
                'User-Agent': 'Mozilla/5.0 (Security Scanner CVE)'
            })
            final_url = url
            break
        except:
            continue
    
    if not resp:
        return [{
            'id': 'cve-connect-failed',
            'severity': 'info',
            'type': 'connectivity',
            'title': 'CVE: Ziel nicht erreichbar',
            'url': host,
            'evidence': f'Weder HTTP noch HTTPS auf {host} erreichbar',
            'remediation': 'Pruefe ob das Ziel online ist.'
        }]
    
    headers = dict(resp.headers)
    body = resp.text[:8000]
    
    # ===== Detect Technologies =====
    detected_tech = {}  # tech_name -> version or None
    
    for tech_name, patterns in TECH_PATTERNS.items():
        version = None
        found = False
        
        # Check headers
        for header, pattern in patterns.get('headers', {}).items():
            if header in headers:
                match = re.search(pattern, headers[header], re.IGNORECASE)
                if match:
                    found = True
                    if match.group(1):
                        version = match.group(1)
                    break
        
        # Check body patterns
        if not found:
            for pattern in patterns.get('body', []):
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    found = True
                    if '(' in pattern and match.lastindex and match.group(1):
                        version = match.group(1)
                    break
        
        # Check cookies
        if not found and 'cookies' in patterns:
            cookies = resp.cookies.get_dict()
            for cookie_name in patterns['cookies']:
                if cookie_name in cookies:
                    found = True
                    break
        
        if found:
            detected_tech[tech_name] = version
    
    if not detected_tech:
        return [{
            'id': 'cve-no-tech',
            'severity': 'info',
            'type': 'scan_summary',
            'title': 'CVE: Keine Technologien erkannt',
            'url': final_url,
            'evidence': 'Es konnten keine Technologien fuer die CVE-Zuordnung erkannt werden.',
            'remediation': None
        }]
    
    # ===== Map to CVEs =====
    cve_findings = []
    for tech_name, version in detected_tech.items():
        if tech_name in CVE_DATABASE:
            for cve_entry in CVE_DATABASE[tech_name]:
                # Check version range
                lo_ver, hi_ver = cve_entry['affected']
                is_vulnerable = True
                if version:
                    is_vulnerable = version_in_range(version, lo_ver, hi_ver)
                
                if is_vulnerable:
                    severity = cve_entry['severity']
                    cvss = cve_entry['cvss']
                    cve_id = cve_entry['cve_id']
                    
                    evidence = f'Technologie: {tech_name}'
                    if version:
                        evidence += f' v{version}'
                    evidence += f' | {cve_id}: {cve_entry["description"]} | CVSS: {cvss}'
                    
                    cve_findings.append({
                        'id': f'cve-{cve_id.lower().replace(" ", "-")}',
                        'severity': severity,
                        'type': 'cve',
                        'title': f'{cve_id}: {cve_entry["description"]}',
                        'url': final_url,
                        'evidence': evidence,
                        'remediation': f'Siehe {cve_entry["url"]} fuer Patches und Workarounds.'
                    })
    
    # Add tech summary finding
    tech_list = []
    for tech, ver in detected_tech.items():
        tech_list.append(f'{tech} {ver}' if ver else tech)
    
    findings.append({
        'id': 'cve-tech-summary',
        'severity': 'info',
        'type': 'technology',
        'title': f'Erkannte Technologien: {len(detected_tech)}',
        'url': final_url,
        'evidence': 'Erkannt: ' + ', '.join(tech_list),
        'remediation': 'Halte alle Komponenten aktuell.'
    })
    
    findings.extend(cve_findings)
    
    # Add summary
    if cve_findings:
        critical_count = len([c for c in cve_findings if c['severity'] == 'critical'])
        high_count = len([c for c in cve_findings if c['severity'] == 'high'])
        
        findings.insert(0, {
            'id': 'cve-summary',
            'severity': 'high' if critical_count > 0 else 'medium',
            'type': 'scan_summary',
            'title': f'CVE-Scan: {len(cve_findings)} bekannte Schwachstellen gefunden',
            'url': final_url,
            'evidence': f'Kritisch: {critical_count} | Hoch: {high_count} | Medium: {len([c for c in cve_findings if c["severity"]=="medium"])} | Erkannte Tech: {len(detected_tech)}',
            'remediation': 'Alle gefundenen CVEs sofort patchen!'
        })
    else:
        findings.append({
            'id': 'cve-clean',
            'severity': 'info',
            'type': 'scan_summary',
            'title': 'CVE-Scan: Keine bekannten Schwachstellen fuer erkannte Technologien',
            'url': final_url,
            'evidence': f'Erkannte Technologien: {len(detected_tech)} - keine bekannten CVEs in der Datenbank.',
            'remediation': 'Trotzdem regelmaessig auf Updates pruefen.'
        })
    
    return findings
