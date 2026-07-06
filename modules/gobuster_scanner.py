"""
Gobuster Scanner - Pure Python directory/file brute-forcer
Replaces Go-based gobuster with equivalent Python implementation
"""
import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

WORDLIST_PATH = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'dirs.txt')
MAX_WORKERS = 20
TIMEOUT = 3
MAX_REQUESTS = 300

# Interesting patterns
ADMIN_PATTERNS = ['admin', 'login', 'dashboard', 'panel', 'manage', 'phpmyadmin', 'wp-admin', 'backend', 'root', 'console', 'system']
CONFIG_PATTERNS = ['.env', '.git', 'config', 'phpinfo', 'info.php', 'web.config', '.htaccess', 'server-status', 'server-info']
BACKUP_PATTERNS = ['.sql', '.zip', '.tar.gz', '.tgz', '.rar', '.7z', 'backup', 'dump', 'dump.sql']


def scan(target):
    """Run directory brute-force scan"""
    findings = []
    host = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
    
    # Determine protocol
    protocols = ['https', 'http']
    working_protocol = None
    for proto in protocols:
        try:
            r = requests.head(f'{proto}://{host}', timeout=5, allow_redirects=False)
            working_protocol = proto
            break
        except:
            continue
    
    if not working_protocol:
        return [{
            'id': 'gobuster-connect-failed',
            'severity': 'info',
            'type': 'connectivity',
            'title': 'Gobuster: Ziel nicht erreichbar',
            'url': host,
            'evidence': f'Weder HTTP noch HTTPS auf {host} erreichbar',
            'remediation': 'Pruefe ob das Ziel online ist.'
        }]
    
    base_url = f'{working_protocol}://{host}'
    
    # Load wordlist
    paths = []
    try:
        with open(WORDLIST_PATH, 'r') as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except:
        # Fallback minimal wordlist
        paths = ['admin', 'api', 'backup', 'login', 'wp-admin', 'config', '.env', 'phpinfo.php', 'robots.txt', 'server-status']
    
    # Remove duplicates while preserving order
    seen = set()
    unique_paths = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)
    paths = unique_paths
    
    results = []
    request_count = 0
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Security Scanner Gobuster)'})
    
    def check_path(path):
        try:
            url = f'{base_url}/{path}'
            resp = session.head(url, timeout=TIMEOUT, allow_redirects=False)
            return {
                'path': path,
                'url': url,
                'status': resp.status_code,
                'length': len(resp.content) if resp.content else 0,
                'headers': dict(resp.headers)
            }
        except requests.Timeout:
            return None
        except requests.ConnectionError:
            return None
        except requests.TooManyRedirects:
            return None
        except:
            return None
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_path, path): path for path in paths}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
                request_count += 1
                if request_count >= MAX_REQUESTS:
                    break
    
    # Process results
    for r in results:
        status = r['status']
        path = r['path']
        url = r['url']
        
        # Skip 404s and connection errors
        if status in [404, 0]:
            continue
        
        # Determine severity and type
        severity = 'low'
        ftype = 'directory'
        title = f'Verfzeichnis/Datei gefunden: /{path}'
        
        # Check for admin panels
        if any(ap in path.lower() for ap in ADMIN_PATTERNS):
            severity = 'medium'
            ftype = 'admin_panel'
            title = f'Admin-Panel gefunden: /{path}'
        
        # Check for config files
        if any(cp in path.lower() for cp in CONFIG_PATTERNS):
            severity = 'medium'
            ftype = 'exposed_config'
            title = f'Konfigurationsdatei gefunden: /{path}'
        
        # Check for backup files
        if any(bp in path.lower() for bp in BACKUP_PATTERNS):
            severity = 'high'
            ftype = 'exposed_backup'
            title = f'Backup-Datei gefunden: /{path}'
        
        # 403 means the resource exists but is forbidden
        if status == 403:
            severity = 'info'
            ftype = 'hidden_resource'
            title = f'Versteckte Resource (403): /{path}'
        
        findings.append({
            'id': f'gobuster-{path.replace("/", "-")}',
            'severity': severity,
            'type': ftype,
            'title': title,
            'url': url,
            'evidence': f'URL: {url} | Status: {status} | Length: {r["length"]} bytes',
            'remediation': 'Entferne nicht-oeffentliche Verzeichnisse aus dem Webroot oder schuetze sie mit Authentifizierung.'
        })
    
    # Sort by severity
    severity_order = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
    findings.sort(key=lambda x: severity_order.get(x['severity'], 99))
    
    return findings
