"""
Content Scanner - robots.txt, sitemap, security.txt analysis
"""
import requests

def scan(target):
    findings = []
    scan_id = 0

    if not target.startswith('http'):
        target = f'https://{target}'
    target = target.rstrip('/')

    print(f"[PHASE 14] Content Scanner: Scanning {target}")

    # robots.txt
    try:
        resp = requests.get(f'{target}/robots.txt', timeout=10, verify=False)
        if resp.status_code == 200 and resp.text:
            disallowed = []
            for line in resp.text.split('\n'):
                if line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        disallowed.append(path)
            if disallowed:
                findings.append({
                    'id': f'cnt-{scan_id}',
                    'severity': 'info',
                    'type': 'robots_txt',
                    'title': f'robots.txt: {len(disallowed)} Disallow-Einträge',
                    'url': f'{target}/robots.txt',
                    'evidence': ', '.join(disallowed[:5]),
                    'remediation': 'Keine sensitiven Pfade in robots.txt'
                })
                scan_id += 1
    except:
        pass

    # sitemap.xml
    try:
        resp = requests.get(f'{target}/sitemap.xml', timeout=10, verify=False)
        if resp.status_code == 200:
            findings.append({
                'id': f'cnt-{scan_id}',
                'severity': 'info',
                'type': 'sitemap_xml',
                'title': 'sitemap.xml gefunden',
                'url': f'{target}/sitemap.xml',
                'evidence': f'HTTP {resp.status_code}',
                'remediation': 'Keine Aktion'
            })
            scan_id += 1
    except:
        pass

    # security.txt
    try:
        resp = requests.get(f'{target}/.well-known/security.txt', timeout=10, verify=False)
        if resp.status_code == 200:
            findings.append({
                'id': f'cnt-{scan_id}',
                'severity': 'info',
                'type': 'security_txt',
                'title': 'security.txt gefunden',
                'url': f'{target}/.well-known/security.txt',
                'evidence': 'security.txt existiert',
                'remediation': 'Keine Aktion'
            })
        else:
            findings.append({
                'id': f'cnt-{scan_id}',
                'severity': 'low',
                'type': 'security_txt_missing',
                'title': 'security.txt fehlt',
                'url': f'{target}/.well-known/security.txt',
                'evidence': f'HTTP {resp.status_code}',
                'remediation': 'security.txt erstellen mit Kontaktinformationen'
            })
    except:
        pass

    if not findings:
        findings.append({
            'id': 'cnt-ok',
            'severity': 'info',
            'type': 'content_scan',
            'title': 'Content-Scan abgeschlossen',
            'url': target,
            'evidence': 'Keine besonderen Funde',
            'remediation': 'Keine Aktion'
        })

    return findings
