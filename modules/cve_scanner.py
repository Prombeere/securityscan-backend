"""
CVE Scanner Module - Python-based CVE detection using NVD API
Checks for known vulnerabilities in detected technologies
"""
import requests
import json
import re

def _detect_tech(target):
    """Quick technology detection for CVE lookup"""
    tech = {}
    try:
        if not target.startswith('http'):
            target = f'https://{target}'
        
        resp = requests.get(target, timeout=10, verify=False, headers={
            'User-Agent': 'Mozilla/5.0 (SecurityScan/3.0)'
        })
        headers = resp.headers
        content = resp.text.lower()
        
        # Server detection
        server = headers.get('Server', '')
        if server:
            # Extract versions
            apache_match = re.search(r'Apache/(\d+\.\d+\.?\d*)', server)
            if apache_match:
                tech['apache'] = apache_match.group(1)
            nginx_match = re.search(r'nginx/(\d+\.\d+\.?\d*)', server)
            if nginx_match:
                tech['nginx'] = nginx_match.group(1)
            iis_match = re.search(r'IIS/(\d+\.?\d*)', server)
            if iis_match:
                tech['iis'] = iis_match.group(1)
        
        # Framework detection
        if 'wordpress' in content or 'wp-content' in content:
            wp_match = re.search(r'WordPress (\d+\.\d+\.?\d*)', resp.text, re.I)
            tech['wordpress'] = wp_match.group(1) if wp_match else 'unknown'
        
        if 'drupal' in content:
            drupal_match = re.search(r'Drupal (\d+\.?\d*)', resp.text, re.I)
            tech['drupal'] = drupal_match.group(1) if drupal_match else 'unknown'
        
        if 'jquery' in content:
            jq_match = re.search(r'jquery[/-](\d+\.\d+\.?\d*)', resp.text, re.I)
            tech['jquery'] = jq_match.group(1) if jq_match else 'unknown'
        
        powered = headers.get('X-Powered-By', '')
        if 'php' in powered.lower():
            php_match = re.search(r'PHP/(\d+\.\d+\.?\d*)', powered)
            tech['php'] = php_match.group(1) if php_match else 'unknown'
        if 'asp.net' in powered.lower():
            tech['aspnet'] = powered.split('/')[-1] if '/' in powered else 'unknown'
        
        # Python frameworks
        if 'django' in content or 'csrftoken' in str(headers.get('Set-Cookie', '')).lower():
            tech['django'] = 'unknown'
        if 'flask' in content or 'werkzeug' in server.lower():
            tech['flask'] = 'unknown'
        
        # Additional headers
        if headers.get('X-AspNet-Version'):
            tech['aspnet'] = headers['X-AspNet-Version']
        if headers.get('X-AspNetMvc-Version'):
            tech['aspnetmvc'] = headers['X-AspNetMvc-Version']
            
    except Exception as e:
        pass
    
    return tech


def _lookup_cves(tech_name, version):
    """Lookup CVEs via NVD API"""
    cves = []
    try:
        # Use NVD API to search for CVEs
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={tech_name}+{version}&resultsPerPage=5"
        resp = requests.get(url, timeout=15, headers={'User-Agent': 'SecurityScan/3.0'})
        
        if resp.status_code == 200:
            data = resp.json()
            for vuln in data.get('vulnerabilities', [])[:5]:
                cve = vuln.get('cve', {})
                cve_id = cve.get('id', 'CVE-Unknown')
                desc = cve.get('descriptions', [{}])[0].get('value', 'No description')[:200]
                
                # Get CVSS score
                metrics = cve.get('metrics', {})
                cvss = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 0)
                severity = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
                
                cves.append({
                    'id': cve_id,
                    'severity': severity.lower(),
                    'cvss': cvss,
                    'description': desc
                })
                
    except requests.exceptions.RequestException:
        pass
    except Exception:
        pass
    
    return cves


def scan(target):
    findings = []
    scan_id = 0
    
    print(f"[PHASE CVE] Checking known vulnerabilities for {target}")
    
    # Detect technologies
    tech = _detect_tech(target)
    
    if not tech:
        findings.append({
            'id': f'cve-{scan_id}',
            'severity': 'info',
            'type': 'cve_no_tech',
            'title': 'CVE: Keine Technologien erkannt',
            'url': target,
            'evidence': 'Keine Technologien mit Version erkannt - CVE-Lookup uebersprungen',
            'remediation': 'Technologie-Fingerprinting verbessern.'
        })
        return findings
    
    # Known CVE databases (built-in, no API needed)
    known_cves = {
        'apache': {
            '2.2': [
                {'id': 'CVE-2017-7679', 'cvss': 7.5, 'sev': 'high', 'desc': 'mod_mime buffer overread'},
                {'id': 'CVE-2016-0736', 'cvss': 5.3, 'sev': 'medium', 'desc': 'mod_session_crypto weak encryption'},
            ],
            '2.4': [
                {'id': 'CVE-2022-31813', 'cvss': 7.5, 'sev': 'high', 'desc': 'mod_proxy X-Forwarded-For bypass'},
                {'id': 'CVE-2022-30556', 'cvss': 5.3, 'sev': 'medium', 'desc': 'mod_lua info disclosure'},
            ]
        },
        'nginx': {
            '1.18': [
                {'id': 'CVE-2021-23017', 'cvss': 7.7, 'sev': 'high', 'desc': 'DNS resolver 1-byte memory overwrite'},
            ],
            '1.20': [
                {'id': 'CVE-2022-41741', 'cvss': 7.8, 'sev': 'high', 'desc': 'MP4 module worker process memory disclosure'},
            ]
        },
        'wordpress': {
            'unknown': [
                {'id': 'CVE-2024-XXXX', 'cvss': 8.1, 'sev': 'high', 'desc': 'Unpatched WordPress instance - check latest CVEs'},
            ]
        },
        'php': {
            '5.': [
                {'id': 'CVE-2019-11043', 'cvss': 9.8, 'sev': 'critical', 'desc': 'PHP-FPM RCE (CVE-2019-11043)'},
            ],
            '7.': [
                {'id': 'CVE-2019-11043', 'cvss': 9.8, 'sev': 'critical', 'desc': 'PHP-FPM RCE under certain configs'},
            ]
        },
        'jquery': {
            '1.': [
                {'id': 'CVE-2020-11022', 'cvss': 6.1, 'sev': 'medium', 'desc': 'jQuery XSS in htmlPrefilter'},
                {'id': 'CVE-2020-11023', 'cvss': 6.1, 'sev': 'medium', 'desc': 'jQuery XSS passing HTML containing <option> elements'},
            ],
            '2.': [
                {'id': 'CVE-2015-9251', 'cvss': 6.1, 'sev': 'medium', 'desc': 'jQuery XSS in Attribute Selector'},
            ],
            '3.': [
                {'id': 'CVE-2020-11022', 'cvss': 6.1, 'sev': 'medium', 'desc': 'jQuery XSS (affects 3.x < 3.5.0)'},
            ]
        }
    }
    
    # Check each detected technology
    for tech_name, version in tech.items():
        tech_findings = []
        
        # Check known CVEs
        if tech_name in known_cves:
            tech_db = known_cves[tech_name]
            # Match version prefix
            for ver_prefix, cves in tech_db.items():
                if version.startswith(ver_prefix) or ver_prefix == 'unknown':
                    for cve in cves:
                        findings.append({
                            'id': f'cve-{scan_id}',
                            'severity': cve['sev'],
                            'type': 'known_cve',
                            'title': f"{cve['id']}: {tech_name} {version}",
                            'url': target,
                            'evidence': f"Technologie: {tech_name} {version}\nCVSS: {cve['cvss']}\n{cve['desc']}",
                            'remediation': f"{tech_name} auf aktuelle Version updaten. Siehe {cve['id']} Details."
                        })
                        scan_id += 1
        
        # Also try NVD API lookup
        nvd_cves = _lookup_cves(tech_name, version)
        for cve in nvd_cves:
            findings.append({
                'id': f'cve-{scan_id}',
                'severity': cve['severity'],
                'type': 'nvd_cve',
                'title': f"{cve['id']}: {tech_name} {version}",
                'url': target,
                'evidence': f"CVSS: {cve['cvss']}\n{cve['description']}",
                'remediation': f"Patch fuer {cve['id']} einspielen."
            })
            scan_id += 1
    
    # Summary
    if findings:
        findings.insert(0, {
            'id': f'cve-{scan_id}',
            'severity': 'info',
            'type': 'cve_summary',
            'title': f'CVE-Scan: {len(tech)} Technologien, {len(findings)-1} CVEs gefunden',
            'url': target,
            'evidence': f'Ermittelte Technologien: {", ".join([f"{k} {v}" for k, v in tech.items()])}',
            'remediation': 'Alle Technologien regelmaessig patchen.'
        })
    else:
        findings.append({
            'id': f'cve-{scan_id}',
            'severity': 'info',
            'type': 'cve_clean',
            'title': f'CVE-Scan: {len(tech)} Technologien, keine bekannten CVEs',
            'url': target,
            'evidence': f'Ermittelt: {", ".join([f"{k} {v}" for k, v in tech.items()])}',
            'remediation': 'Trotzdem regelmaessig auf Updates pruefen.'
        })
    
    return findings
