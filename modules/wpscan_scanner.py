#!/usr/bin/env python3
"""
WPScan Module - WordPress Security Scanner
Detects WordPress version, plugins, themes, users, vulnerabilities
Python fallback with real HTTP fingerprinting when WPScan CLI is not available
"""
import requests
import re
import subprocess
import os


def _has_wpscan():
    """Check if wpscan CLI is available"""
    paths = os.environ.get('PATH', '').split(':')
    paths.append(os.path.expanduser('~/.local/bin'))
    paths.append('/usr/local/bin')
    for p in paths:
        if os.path.isfile(os.path.join(p, 'wpscan')):
            return os.path.join(p, 'wpscan')
    try:
        result = subprocess.run(['which', 'wpscan'], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            return result.stdout.strip()
    except:
        pass
    return None


def _wp_python_scan(target, findings, scan_id):
    """Pure Python WordPress fingerprinting - no external tool needed"""
    print(f"[WPSCAN] Using Python fallback for {target}")

    if not target.startswith('http'):
        target = f'https://{target}'

    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (SecurityScan/3.3)'})

    wp_detected = False
    wp_version = None
    plugins = set()
    themes = set()
    users = set()
    interesting_files = []

    try:
        resp = session.get(target, timeout=15, verify=False, allow_redirects=True)
        content = resp.text

        # WordPress detection patterns
        wp_indicators = [
            (r'<meta name="generator" content="WordPress\s*([^"]+)"', 'meta_generator'),
            (r'/wp-content/', 'wp_content_path'),
            (r'/wp-includes/', 'wp_includes_path'),
            (r'/wp-json/', 'wp_json_api'),
            (r'wp-admin', 'wp_admin_link'),
            (r'wp-login.php', 'wp_login_link'),
            (r'xmlrpc\.php', 'xmlrpc_link'),
            (r'wp-embed\.min\.js', 'wp_embed_js'),
            (r'wp-emoji-release\.min\.js', 'wp_emoji_js'),
        ]

        for pattern, indicator_name in wp_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                wp_detected = True
                if indicator_name == 'meta_generator':
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        wp_version = match.group(1).strip()

        # Version detection
        if not wp_version:
            try:
                readme_resp = session.get(f'{target}/readme.html', timeout=10, verify=False)
                if readme_resp.status_code == 200:
                    version_match = re.search(r'Version\s*(\d+\.\d+(\.\d+)?)', readme_resp.text)
                    if version_match:
                        wp_version = version_match.group(1)
                        interesting_files.append('readme.html (Version exposed)')
            except:
                pass

        # Plugin detection
        plugin_patterns = [
            r'/wp-content/plugins/([^/]+)/',
            r'wp-content\\plugins\\([^\\]+)\\',
        ]
        for pattern in plugin_patterns:
            for match in re.finditer(pattern, content):
                plugin_name = match.group(1)
                if plugin_name and plugin_name not in ['.', '..']:
                    plugins.add(plugin_name)

        # Theme detection
        theme_patterns = [
            r'/wp-content/themes/([^/]+)/',
            r'wp-content\\themes\\([^\\]+)\\',
        ]
        for pattern in theme_patterns:
            for match in re.finditer(pattern, content):
                theme_name = match.group(1)
                if theme_name and theme_name not in ['.', '..']:
                    themes.add(theme_name)

        # User enumeration via author pages
        for author_id in range(1, 6):
            try:
                author_url = f'{target}/?author={author_id}'
                author_resp = session.get(author_url, timeout=10, verify=False, allow_redirects=True)
                if author_resp.status_code == 200:
                    title_match = re.search(r'<title>([^<]+)</title>', author_resp.text)
                    if title_match:
                        title = title_match.group(1)
                        username = title.split(',')[0].strip()
                        if username and len(username) < 50:
                            users.add(username)
                    if hasattr(author_resp, 'url') and '/author/' in author_resp.url:
                        author_name = author_resp.url.split('/author/')[-1].rstrip('/')
                        if author_name:
                            users.add(author_name)
            except:
                continue

        # REST API users
        try:
            api_resp = session.get(f'{target}/wp-json/wp/v2/users', timeout=10, verify=False)
            if api_resp.status_code == 200:
                try:
                    api_users = api_resp.json()
                    for user in api_users:
                        if 'name' in user:
                            users.add(user['name'])
                        if 'slug' in user:
                            users.add(user['slug'])
                except:
                    pass
        except:
            pass

        # Interesting files
        interesting_paths = [
            ('/wp-config.php', 'WP Config'),
            ('/wp-admin/install.php', 'Install script'),
            ('/wp-admin/setup-config.php', 'Setup config'),
            ('/wp-content/debug.log', 'Debug log'),
            ('/.htaccess', 'HTAccess'),
            ('/wp-content/uploads/', 'Uploads directory'),
            ('/wp-content/backup-db/', 'Database backups'),
            ('/wp-content/backups/', 'Backups'),
        ]

        for path, desc in interesting_paths:
            try:
                file_resp = session.get(f'{target}{path}', timeout=8, verify=False, allow_redirects=False)
                if file_resp.status_code == 200:
                    interesting_files.append(f'{path} ({desc})')
            except:
                continue

    except Exception as e:
        findings.append({
            'id': f'wps-{scan_id}', 'severity': 'info', 'type': 'wpscan_error',
            'title': f'WPScan: Fehler bei {target}', 'url': target,
            'evidence': str(e), 'remediation': 'Ziel-URL pruefen.'
        })
        return findings

    if not wp_detected:
        findings.append({
            'id': f'wps-{scan_id}', 'severity': 'info', 'type': 'wpscan_not_wp',
            'title': 'WPScan: Keine WordPress-Installation erkannt',
            'url': target,
            'evidence': 'Keine WordPress-Indikatoren in HTML/Headern gefunden.',
            'remediation': 'Keine WordPress-spezifischen Massnahmen noetig.'
        })
        return findings

    # WordPress detected
    findings.append({
        'id': f'wps-{scan_id}', 'severity': 'info', 'type': 'wordpress_detected',
        'title': f'WordPress erkannt{ f" (v{wp_version})" if wp_version else ""}',
        'url': target,
        'evidence': f'Version: {wp_version or "unbekannt"}\nPlugins: {", ".join(list(plugins)[:15]) or "Keine erkannt"}\nThemes: {", ".join(list(themes)[:5]) or "Keine erkannt"}',
        'remediation': 'WordPress und alle Plugins/Themes auf aktuellste Version aktualisieren.'
    })
    scan_id += 1

    if wp_version:
        findings.append({
            'id': f'wps-{scan_id}', 'severity': 'medium', 'type': 'wordpress_version_exposed',
            'title': f'WordPress Version {wp_version} oeffentlich sichtbar',
            'url': target,
            'evidence': f'Version in Meta-Generator, Readme oder API erkannt: {wp_version}',
            'remediation': 'Version verbergen: remove_action(\'wp_head\', \'wp_generator\'); in functions.php'
        })
        scan_id += 1

        vuln_versions = {
            '5.8': 'CVE-2021-XXXX: SQL Injection in WP_Meta_Query',
            '5.7': 'CVE-2021-29447: XXE in Media Library',
            '5.6': 'CVE-2020-36326: PHPMailer RCE',
            '5.5': 'CVE-2020-28040: Privilege Escalation',
            '5.4': 'CVE-2020-11030: XSS in wp-mail.php',
            '5.3': 'CVE-2019-20043: Server-Side Request Forgery',
            '5.2': 'CVE-2019-9787: Cross-Site Scripting',
            '5.1': 'CVE-2019-8943: Remote Code Execution',
            '5.0': 'CVE-2018-20148: Authenticated RCE',
            '4.9': 'CVE-2018-12895: Authenticated XSS',
            '4.8': 'CVE-2017-9066: Privilege Escalation',
            '4.7': 'CVE-2017-5611: SQL Injection',
        }
        version_major = '.'.join(wp_version.split('.')[:2])
        if version_major in vuln_versions:
            findings.append({
                'id': f'wps-{scan_id}', 'severity': 'high', 'type': 'wordpress_known_vuln',
                'title': f'WordPress {version_major}: Bekannte Schwachstelle!',
                'url': target,
                'evidence': f'{vuln_versions[version_major]}\nInstallierte Version: {wp_version}',
                'remediation': f'SOFORT auf WordPress {max([float(v) for v in vuln_versions.keys()])}+ updaten!'
            })
            scan_id += 1

    if users:
        for user in list(users)[:5]:
            findings.append({
                'id': f'wps-{scan_id}', 'severity': 'medium', 'type': 'wordpress_user_exposed',
                'title': f'WordPress Benutzer erkannt: {user}',
                'url': f'{target}/?author=1',
                'evidence': f'Benutzername "{user}" ueber Author-Archiv oder REST API ermittelt.',
                'remediation': 'Benutzeraufzaehlung blockieren: REST API einschraenken, Author-Seiten umbenennen.'
            })
            scan_id += 1

    # XML-RPC check
    try:
        xmlrpc_resp = session.get(f'{target}/xmlrpc.php', timeout=10, verify=False)
        if xmlrpc_resp.status_code == 200 and 'XML-RPC server accepts POST requests' in xmlrpc_resp.text:
            findings.append({
                'id': f'wps-{scan_id}', 'severity': 'medium', 'type': 'wordpress_xmlrpc_enabled',
                'title': 'WordPress XML-RPC aktiviert',
                'url': f'{target}/xmlrpc.php',
                'evidence': 'XML-RPC-Server antwortet auf Anfragen. Brute-Force und DDoS moeglich.',
                'remediation': 'XML-RPC deaktivieren: .htaccess oder Plugin "Disable XML-RPC".'
            })
            scan_id += 1
    except:
        pass

    # REST API check
    try:
        rest_resp = session.get(f'{target}/wp-json/', timeout=10, verify=False)
        if rest_resp.status_code == 200:
            findings.append({
                'id': f'wps-{scan_id}', 'severity': 'low', 'type': 'wordpress_rest_api_exposed',
                'title': 'WordPress REST API oeffentlich zugaenglich',
                'url': f'{target}/wp-json/',
                'evidence': 'REST API liefert Daten ohne Authentifizierung.',
                'remediation': 'REST API einschraenken: Authentication erforderlich machen.'
            })
            scan_id += 1
    except:
        pass

    for file_path, desc in interesting_files[:5]:
        severity = 'high' if 'backup' in file_path.lower() or 'config' in file_path.lower() else 'medium'
        findings.append({
            'id': f'wps-{scan_id}', 'severity': severity, 'type': 'wordpress_sensitive_file',
            'title': f'Sensible Datei gefunden: {file_path}',
            'url': f'{target}{file_path}',
            'evidence': f'{desc} ist oeffentlich zugaenglich.',
            'remediation': f'{file_path} entfernen oder schuetzen!'
        })
        scan_id += 1

    if plugins:
        findings.append({
            'id': f'wps-{scan_id}', 'severity': 'info', 'type': 'wordpress_plugins',
            'title': f'{len(plugins)} WordPress-Plugins erkannt',
            'url': target,
            'evidence': f'Plugins: {", ".join(list(plugins)[:20])}',
            'remediation': 'Alle Plugins auf Sicherheitsupdates pruefen.'
        })
        scan_id += 1

    return findings


def scan(target):
    findings = []
    scan_id = 0
    if not target.startswith('http'):
        target = f'https://{target}'
    print(f"[PHASE WPSCAN] Scanning {target}")
    return _wp_python_scan(target, findings, scan_id)
