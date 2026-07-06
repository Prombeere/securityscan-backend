"""
Directory Scanner Module - Brute-force common paths, directory listing, backup/config files
"""
import requests
import os
from urllib.parse import urljoin

def scan(target):
    findings = []
    scan_id = 0

    if not target.startswith('http'):
        target = f'https://{target}'

    print(f"[PHASE 7] Directory Scanner: Scanning {target}")

    # Load wordlist
    wordlist_path = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'dirs.txt')
    paths = []
    try:
        with open(wordlist_path, 'r') as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        # Fallback default paths
        paths = [
            'admin', 'administrator', 'api', 'backup', 'bak', 'cgi-bin', 'config',
            'dashboard', 'db', 'debug', 'env', '.env', '.git', '.git/config',
            '.svn', 'wp-admin', 'wp-content', 'phpmyadmin', 'phpinfo.php',
            'info.php', 'server-status', 'server-info', 'actuator',
            'swagger-ui.html', 'api-docs', 'console', 'test', 'tmp',
            'temp', 'logs', 'robots.txt', 'sitemap.xml', 'web.config',
            '.htaccess', '.htpasswd', 'login', 'register', 'upload',
            'uploads', 'files', 'data', 'sql', 'dump', 'backup.sql',
            'database.sql', 'dump.sql', '.sql', '.tar.gz', '.zip',
            '.rar', '.7z', '.tar', '.bz2', '.gz', '.old', '~',
            '.bak', '.backup', '.orig', '.original', '.save',
            '.swp', '.swo', '.tmp', '.temp', '.copy', '.clone',
            '.new', '.prev', '.previous', '.dist', '.distrib',
            '.sample', '.example', '.tpl', '.template', '.inc',
            '.include', '.class', '.lib', '.module', '.plugin',
            '.theme', '.widget', '.component', '.fragment',
            '.part', '.partial', '.view', '.layout', '.page',
            '.section', '.region', '.zone', '.area', '.block',
            '.panel', '.widget', '.gadget', '.module', '.plugin',
        ]

    # Limit to 200 paths for performance
    paths = paths[:200]
    found_paths = []
    found_backups = []
    found_configs = []
    found_vcs = []
    found_dir_listings = []

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })

    for path in paths:
        url = urljoin(target, path)
        try:
            resp = session.get(url, timeout=10, allow_redirects=False, verify=False)

            # Check for interesting status codes
            if resp.status_code == 200:
                found_paths.append(url)

                # Check for directory listing
                if '<title>Index of' in resp.text or 'Directory Listing' in resp.text or 'Parent Directory' in resp.text:
                    found_dir_listings.append(url)

                # Check for backup files
                if any(url.endswith(ext) for ext in ['.bak', '.old', '~', '.zip', '.tar.gz', '.rar', '.7z', '.sql', '.dump', '.backup']):
                    found_backups.append(url)

                # Check for config files
                if any(url.endswith(ext) for ext in ['.env', '.config', 'config.json', 'config.yaml', 'config.yml', 'web.config', '.htaccess', '.htpasswd']):
                    found_configs.append(url)

                # Check for VCS
                if any(vcs in url for vcs in ['.git', '.svn', '.hg', '.bzr', '.cvs']):
                    found_vcs.append(url)

            elif resp.status_code == 301 or resp.status_code == 302:
                location = resp.headers.get('Location', '')
                if location and not location.startswith('http'):
                    # Relative redirect
                    pass

        except requests.exceptions.RequestException:
            continue
        except Exception:
            continue

    # Report findings
    if found_dir_listings:
        for url in found_dir_listings:
            findings.append({
                'id': f'dir-{scan_id}',
                'severity': 'high',
                'type': 'directory_listing',
                'title': 'Verzeichnisauflistung aktiviert',
                'url': url,
                'evidence': f'HTTP 200 mit Verzeichnisauflistung gefunden',
                'remediation': 'Directory Listing im Webserver deaktivieren (Options -Indexes in Apache, autoindex off in Nginx).'
            })
            scan_id += 1

    if found_backups:
        for url in found_backups[:5]:
            findings.append({
                'id': f'dir-{scan_id}',
                'severity': 'high',
                'type': 'backup_file_exposed',
                'title': 'Backup-Datei öffentlich zugänglich',
                'url': url,
                'evidence': f'Backup-Datei gefunden: Status 200',
                'remediation': 'Alle Backup-Dateien entfernen oder durch .htaccess/Auth schützen.'
            })
            scan_id += 1

    if found_configs:
        for url in found_configs[:5]:
            findings.append({
                'id': f'dir-{scan_id}',
                'severity': 'critical',
                'type': 'config_file_exposed',
                'title': 'Konfigurationsdatei öffentlich zugänglich',
                'url': url,
                'evidence': f'Konfigurationsdatei gefunden: Status 200',
                'remediation': 'Konfigurationsdateien sofort entfernen oder schützen!'
            })
            scan_id += 1

    if found_vcs:
        for url in found_vcs[:5]:
            findings.append({
                'id': f'dir-{scan_id}',
                'severity': 'high',
                'type': 'vcs_exposed',
                'title': 'Versionskontrollsystem öffentlich zugänglich',
                'url': url,
                'evidence': f'Versionskontrollverzeichnis gefunden: Status 200',
                'remediation': '.git, .svn und andere VCS-Verzeichnisse sofort entfernen oder blockieren!'
            })
            scan_id += 1

    # Report exposed paths
    if found_paths:
        findings.append({
            'id': f'dir-{scan_id}',
            'severity': 'info',
            'type': 'dir_found_paths',
            'title': f'{len(found_paths)} Pfade gefunden',
            'url': target,
            'evidence': f'Gefundene Pfade (erste 20): {", ".join(found_paths[:20])}',
            'remediation': 'Alle öffentlich zugänglichen Pfade auf Notwendigkeit prüfen.'
        })
        scan_id += 1
    else:
        findings.append({
            'id': f'dir-{scan_id}',
            'severity': 'info',
            'type': 'dir_no_paths',
            'title': 'Keine versteckten Pfade gefunden',
            'url': target,
            'evidence': 'Keine der getesteten Pfade war zugänglich',
            'remediation': 'Weiterhin Zugriffskontrollen aufrechterhalten.'
        })
        scan_id += 1

    return findings
