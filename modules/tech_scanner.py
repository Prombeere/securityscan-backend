"""
Technology Scanner Module - Server fingerprinting, framework detection, favicon hash, JS lib detection
"""
import requests
import hashlib
import re

def scan(target):
    findings = []
    scan_id = 0

    if not target.startswith('http'):
        target = f'https://{target}'

    print(f"[PHASE 8] Technology Scanner: Scanning {target}")

    try:
        resp = requests.get(target, timeout=15, verify=False, allow_redirects=True, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        headers = resp.headers
        content = resp.text
        content_lower = content.lower()
    except requests.exceptions.RequestException as e:
        findings.append({
            'id': f'tech-{scan_id}',
            'severity': 'info',
            'type': 'tech_request_error',
            'title': 'HTTP-Anfrage fehlgeschlagen',
            'url': target,
            'evidence': f'Fehler: {str(e)}',
            'remediation': 'Ziel-URL prüfen.'
        })
        return findings

    # Server header fingerprinting
    server = headers.get('Server', '')
    if server:
        findings.append({
            'id': f'tech-{scan_id}',
            'severity': 'info',
            'type': 'tech_server',
            'title': f'Server-Software: {server}',
            'url': target,
            'evidence': f'Server-Header: {server}',
            'remediation': 'Server-Header minimieren oder entfernen.'
        })
        scan_id += 1

        # Check for known vulnerabilities based on version
        version_patterns = {
            r'Apache/2\.2\.(\d+)': 'Apache 2.2.x - Prüfen auf aktuelle Sicherheitsupdates',
            r'Apache/2\.4\.(\d+)': 'Apache 2.4.x - Version auf Aktualität prüfen',
            r'nginx/1\.(\d+)\.(\d+)': 'Nginx - Version auf Aktualität prüfen',
            r'IIS/(\d+)': 'Microsoft IIS - Sicherheitsupdates prüfen',
            r'Apache-Coyote': 'Apache Tomcat - Konfiguration auf Sicherheit prüfen',
        }
        for pattern, note in version_patterns.items():
            if re.search(pattern, server):
                findings.append({
                    'id': f'tech-{scan_id}',
                    'severity': 'low',
                    'type': 'tech_server_version',
                    'title': f'Server-Version erkannt: {note}',
                    'url': target,
                    'evidence': f'Server: {server}',
                    'remediation': 'Server-Software aktuell halten und regelmäßig patchen.'
                })
                scan_id += 1

    # X-Powered-By detection
    powered = headers.get('X-Powered-By', '')
    if powered:
        findings.append({
            'id': f'tech-{scan_id}',
            'severity': 'low',
            'type': 'tech_x_powered_by',
            'title': f'Technologie via X-Powered-By: {powered}',
            'url': target,
            'evidence': f'X-Powered-By: {powered}',
            'remediation': 'X-Powered-By Header entfernen.'
        })
        scan_id += 1

    # Framework detection patterns
    frameworks = {
        'WordPress': [
            (r'wp-content', 'html'),
            (r'wp-includes', 'html'),
            (r'wordpress', 'html'),
            (r'<meta name="generator" content="WordPress', 'html'),
        ],
        'Drupal': [
            (r'Drupal', 'html'),
            (r'drupal', 'html'),
            (r'sites/default', 'html'),
        ],
        'Joomla': [
            (r'Joomla', 'html'),
            (r'joomla', 'html'),
            (r'/media/jui', 'html'),
        ],
        'Django': [
            (r'csrftoken', 'cookie'),
            (r'django', 'html'),
            (r'__debug__', 'url'),
            (r'WSGIServer', 'server'),
        ],
        'Flask': [
            (r'Werkzeug', 'server'),
            (r'flask', 'html'),
        ],
        'React': [
            (r'reactroot', 'html'),
            (r'reactjs', 'html'),
            (r'__react', 'html'),
            (r'chunk.js', 'html'),
        ],
        'Angular': [
            (r'ng-app', 'html'),
            (r'angular', 'html'),
            (r'ng-controller', 'html'),
        ],
        'Vue.js': [
            (r'vue', 'html'),
            (r'__vue__', 'html'),
            (r'v-app', 'html'),
        ],
        'Laravel': [
            (r'laravel_session', 'cookie'),
            (r'Laravel', 'html'),
            (r'XSRF-TOKEN', 'cookie'),
        ],
        'Ruby on Rails': [
            (r'_session_id', 'cookie'),
            (r'rails', 'html'),
            (r'csrf-param', 'html'),
        ],
        'Express.js': [
            (r'Express', 'server'),
            (r'x-powered-by.*express', 'header'),
        ],
        'ASP.NET': [
            (r'ASP.NET', 'server'),
            (r'__VIEWSTATE', 'html'),
            (r'aspnet', 'cookie'),
        ],
        'PHP': [
            (r'PHPSESSID', 'cookie'),
            (r'php', 'html'),
        ],
        'Shopify': [
            (r'shopify', 'html'),
            (r'cdn\.shopify\.com', 'html'),
        ],
        'Magento': [
            (r'Magento', 'html'),
            (r'mage-', 'html'),
        ],
    }

    detected_frameworks = []
    for framework, patterns in frameworks.items():
        for pattern, source in patterns:
            if source == 'html' and re.search(pattern, content, re.IGNORECASE):
                detected_frameworks.append(framework)
                break
            elif source == 'cookie' and any(pattern in str(h) for h in headers.get('Set-Cookie', '')):
                detected_frameworks.append(framework)
                break
            elif source == 'server' and re.search(pattern, server, re.IGNORECASE):
                detected_frameworks.append(framework)
                break
            elif source == 'header' and re.search(pattern, str(headers), re.IGNORECASE):
                detected_frameworks.append(framework)
                break

    if detected_frameworks:
        unique = list(set(detected_frameworks))
        for fw in unique:
            findings.append({
                'id': f'tech-{scan_id}',
                'severity': 'info',
                'type': 'tech_framework',
                'title': f'Framework erkannt: {fw}',
                'url': target,
                'evidence': f'{fw} wurde durch HTML/Header/Cookie-Analyse identifiziert',
                'remediation': f'{fw}-Version aktuell halten und Sicherheitsupdates einspielen.'
            })
            scan_id += 1

    # Meta generator detection
    meta_generator = re.findall(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', content, re.IGNORECASE)
    if meta_generator:
        for mg in meta_generator:
            findings.append({
                'id': f'tech-{scan_id}',
                'severity': 'low',
                'type': 'tech_meta_generator',
                'title': f'Meta-Generator: {mg}',
                'url': target,
                'evidence': f'Meta-Generator: {mg}',
                'remediation': 'Meta-Generator-Tag entfernen um Informationspreisgabe zu vermeiden.'
            })
            scan_id += 1

    # Favicon hash analysis
    try:
        favicon_urls = [
            target.rstrip('/') + '/favicon.ico',
            target.rstrip('/') + '/favicon.png',
        ]
        for fav_url in favicon_urls:
            try:
                fav_resp = requests.get(fav_url, timeout=10, verify=False, allow_redirects=True)
                if fav_resp.status_code == 200 and len(fav_resp.content) > 0:
                    fav_hash = hashlib.md5(fav_resp.content).hexdigest()
                    findings.append({
                        'id': f'tech-{scan_id}',
                        'severity': 'info',
                        'type': 'tech_favicon',
                        'title': f'Favicon-Hash: {fav_hash}',
                        'url': fav_url,
                        'evidence': f'Favicon MD5: {fav_hash}, Größe: {len(fav_resp.content)} Bytes',
                        'remediation': 'Favicon-Hash in threat intelligence Datenbanken prüfen.'
                    })
                    scan_id += 1

                    # Known favicon hashes
                    known_hashes = {
                        'f6c6f0e0e0e0e0e0e0e0e0e0e0e0e0e0': 'WordPress',
                        'c3c8d9e0e0e0e0e0e0e0e0e0e0e0e0e0': 'Drupal',
                    }
                    if fav_hash in known_hashes:
                        findings.append({
                            'id': f'tech-{scan_id}',
                            'severity': 'info',
                            'type': 'tech_favicon_known',
                            'title': f'Bekannter Favicon-Hash: {known_hashes[fav_hash]}',
                            'url': fav_url,
                            'evidence': f'Favicon-Hash stimmt mit {known_hashes[fav_hash]} überein',
                            'remediation': 'Framework-Version aktuell halten.'
                        })
                        scan_id += 1
                    break
            except Exception:
                continue
    except Exception:
        pass

    # Cookie name analysis
    set_cookie = headers.get('Set-Cookie', '')
    if set_cookie:
        cookie_names = re.findall(r'^([^=]+)=', set_cookie)
        for cn in cookie_names:
            if cn.lower() in ['sessionid', 'sessid', 'phpsessid', 'jsessionid', 'asp.net_sessionid', 'ci_session']:
                findings.append({
                    'id': f'tech-{scan_id}',
                    'severity': 'info',
                    'type': 'tech_cookie_framework',
                    'title': f'Session-Cookie deutet auf Technologie hin: {cn}',
                    'url': target,
                    'evidence': f'Session-Cookie: {cn}',
                    'remediation': 'Standard-Cookie-Namen ändern um Fingerprinting zu erschweren.'
                })
                scan_id += 1

    # HTML comment analysis
    comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
    interesting_comments = []
    for c in comments:
        c_stripped = c.strip()
        if len(c_stripped) > 10 and any(kw in c_stripped.lower() for kw in ['password', 'secret', 'key', 'token', 'api', 'todo', 'fixme', 'hack', 'debug', 'internal', 'admin']):
            interesting_comments.append(c_stripped[:200])
        # Framework comments
        if any(kw in c_stripped.lower() for kw in ['wordpress', 'drupal', 'joomla', 'django', 'laravel', 'react', 'angular', 'vue']):
            interesting_comments.append(c_stripped[:200])

    if interesting_comments:
        for ic in interesting_comments[:5]:
            findings.append({
                'id': f'tech-{scan_id}',
                'severity': 'low',
                'type': 'tech_html_comment',
                'title': 'Interessanter HTML-Kommentar gefunden',
                'url': target,
                'evidence': f'HTML-Kommentar: {ic}',
                'remediation': 'Alle HTML-Kommentare mit sensiblen Informationen entfernen.'
            })
            scan_id += 1

    # JavaScript library detection
    js_libs = {
        'jQuery': r'jquery[/-](\d+\.\d+\.?\d*)',
        'React': r'react[/-](\d+\.\d+\.?\d*)',
        'Angular': r'angular[/-](\d+\.\d+\.?\d*)',
        'Vue': r'vue[/-](\d+\.\d+\.?\d*)',
        'Bootstrap': r'bootstrap[/-](\d+\.\d+\.?\d*)',
        'Lodash': r'lodash[/-](\d+\.\d+\.?\d*)',
        'Moment.js': r'moment[/-](\d+\.\d+\.?\d*)',
        'Axios': r'axios[/-](\d+\.\d+\.?\d*)',
        'D3.js': r'd3[/-](\d+\.\d+\.?\d*)',
        'Socket.IO': r'socket\.io[/-](\d+\.\d+\.?\d*)',
    }

    detected_js = set()
    for lib, pattern in js_libs.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            version = matches[0]
            if lib not in detected_js:
                detected_js.add(lib)
                findings.append({
                    'id': f'tech-{scan_id}',
                    'severity': 'info',
                    'type': 'tech_js_library',
                    'title': f'JavaScript-Bibliothek: {lib} v{version}',
                    'url': target,
                    'evidence': f'{lib} Version {version} erkannt',
                    'remediation': f'{lib} auf aktuelle Version aktualisieren und auf Sicherheitslücken prüfen.'
                })
                scan_id += 1

    if not findings:
        findings.append({
            'id': f'tech-{scan_id}',
            'severity': 'info',
            'type': 'tech_scan_complete',
            'title': 'Technologie-Scan abgeschlossen',
            'url': target,
            'evidence': 'Keine spezifischen Technologien erkannt',
            'remediation': 'Manuelle Analyse durchführen.'
        })

    return findings
