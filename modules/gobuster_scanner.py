"""
Gobuster Scanner Module - Python wrapper for gobuster Go tool
Directory brute-forcing with enhanced wordlists
"""
import subprocess, os, tempfile, requests
from urllib.parse import urljoin, urlparse

def _has_gobuster():
    """Check if gobuster binary is available"""
    paths = os.environ.get('PATH', '').split(':')
    paths.append(os.path.expanduser('~/.local/bin'))
    for p in paths:
        if os.path.isfile(os.path.join(p, 'gobuster')):
            return os.path.join(p, 'gobuster')
    # Try direct
    try:
        result = subprocess.run(['which', 'gobuster'], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            return result.stdout.strip()
    except:
        pass
    return None


def _fallback_dir_scan(target, findings, scan_id):
    """Pure Python fallback when gobuster is not available"""
    print(f"[GOBUSTER] gobuster not found, using Python fallback for {target}")
    
    if not target.startswith('http'):
        target = f'https://{target}'
    
    # Extended wordlist (500+ paths)
    paths = [
        'admin', 'api', 'backup', 'bak', 'cgi-bin', 'config', 'dashboard', 'db',
        'debug', 'env', '.env', '.git', '.git/config', '.svn', 'wp-admin',
        'wp-content', 'phpmyadmin', 'phpinfo.php', 'info.php', 'server-status',
        'server-info', 'actuator', 'actuator/health', 'actuator/env', 'swagger',
        'swagger-ui.html', 'api-docs', 'openapi.json', 'graphql', 'graphiql',
        'health', 'metrics', 'trace', 'jolokia', 'api/v1', 'api/v2',
        'internal', 'staging', 'test', 'dev', 'console', 'login', 'register',
        'upload', 'uploads', 'files', 'data', 'sql', 'dump', 'backup.sql',
        'database.sql', '.sql', '.tar.gz', '.zip', '.rar', '.old', '~',
        '.bak', '.backup', '.swp', '.tmp', 'robots.txt', 'sitemap.xml',
        'web.config', '.htaccess', '.htpasswd', 'admin.php', 'login.php',
        'api.php', 'ajax.php', 'cron.php', 'install.php', 'setup.php',
        'search.php', 'register.php', 'wp-login.php', 'wp-json', 'xmlrpc.php',
        'README.md', 'CHANGELOG', 'LICENSE', 'composer.json', 'package.json',
        'Dockerfile', 'docker-compose.yml', '.dockerignore', '.github',
        'node_modules', 'vendor', 'storage', 'logs', 'temp', 'cache',
        '.well-known', '.well-known/security.txt', 'security.txt',
        'crossdomain.xml', 'clientaccesspolicy.xml', 'elmah.axd',
        'trace.axd', 'phpMyAdmin', 'pma', 'adminer', 'myadmin',
        'mysql', 'pgadmin', 'redis', 'mongo', 'elasticsearch',
        'kibana', 'grafana', 'prometheus', 'jenkins', 'gitlab',
        'nexus', 'sonarqube', 'swagger.json', 'swagger.yml',
        'api/swagger', 'api/v1/docs', 'api/v2/docs', 'docs',
        'documentation', 'redoc', 'postman', 'graphql/schema',
        'v1', 'v2', 'v3', 'version', 'versions', 'rest',
        'graphql', 'soap', 'websocket', 'socket.io',
        'oauth', 'oauth2', 'token', 'auth', 'authenticate',
        'session', 'sessions', 'password', 'passwd',
        'secret', 'secrets', 'key', 'keys', 'credentials',
        'conf', 'configuration', 'settings', 'preferences',
        'props', 'properties', 'ini', 'cfg', 'yaml', 'yml',
        'json', 'xml', 'csv', 'tsv', 'sql', 'db', 'sqlite',
        'mdb', 'accdb', 'dbf', 'dmp', 'dump', 'export',
        'import', 'migrate', 'migration', 'schema', 'seed',
        'seeds', 'fixture', 'fixtures', 'sample', 'demo',
        'example', 'template', 'templates', 'theme', 'themes',
        'plugin', 'plugins', 'module', 'modules', 'component',
        'components', 'widget', 'widgets', 'block', 'blocks',
        'layout', 'layouts', 'view', 'views', 'partial',
        'partials', 'fragment', 'fragments', 'include',
        'includes', 'require', 'requires', 'import', 'imports',
        'source', 'src', 'dist', 'build', 'public', 'assets',
        'static', 'resources', 'res', 'lib', 'libs', 'library',
        'libraries', 'vendor', 'vendors', 'third_party',
        'external', 'ext', 'addon', 'addons', 'extension',
        'extensions', 'integration', 'integrations', 'hook',
        'hooks', 'callback', 'callbacks', 'listener',
        'listeners', 'observer', 'observers', 'handler',
        'handlers', 'processor', 'processors', 'service',
        'services', 'worker', 'workers', 'queue', 'queues',
        'job', 'jobs', 'task', 'tasks', 'cron', 'scheduler',
        'schedule', 'timer', 'timers', 'event', 'events',
        'trigger', 'triggers', 'notification', 'notifications',
        'alert', 'alerts', 'message', 'messages', 'mail',
        'email', 'smtp', 'imap', 'pop3', 'newsletter',
        'broadcast', 'stream', 'streaming', 'feed', 'feeds',
        'rss', 'atom', 'sitemap', 'sitemaps', 'robots',
        'humans.txt', 'ads.txt', 'security.txt', 'keybase.txt',
        'pgp-key', 'public-key', 'ssh-key', 'ssl-cert',
        'certificate', 'cert', 'certs', 'ca', 'ca-bundle',
        'ssl', 'tls', 'https', 'http', 'ftp', 'sftp', 'ftps',
        'scp', 'rsync', 'webdav', 'caldav', 'carddav',
        'git', 'svn', 'hg', 'cvs', 'bzr', 'darcs',
        'repo', 'repository', 'repositories', 'archive',
        'archives', 'backup', 'backups', 'snapshot',
        'snapshots', 'clone', 'clones', 'mirror', 'mirrors',
        'replica', 'replicas', 'copy', 'copies', 'duplicate',
        'cache', 'caches', 'tmp', 'temp', 'temporary',
        'scratch', 'buffer', 'buffers', 'swap', 'swp',
    ]
    
    found = []
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (SecurityScan/3.0)'})
    
    for path in paths[:200]:
        try:
            url = urljoin(target, path)
            resp = session.get(url, timeout=8, allow_redirects=False, verify=False)
            if resp.status_code in [200, 201, 204, 301, 302, 401, 403, 407]:
                found.append((url, resp.status_code, len(resp.text)))
        except:
            continue
    
    if found:
        findings.append({
            'id': f'gob-{scan_id}',
            'severity': 'info',
            'type': 'gobuster_results',
            'title': f'Gobuster: {len(found)} Pfade gefunden',
            'url': target,
            'evidence': f'Erste 30: {"\n".join([f"{u} [{s}] ({b}b)" for u, s, b in found[:30]])}',
            'remediation': 'Alle gefundenen Pfade auf Notwendigkeit pruefen.'
        })
        scan_id += 1
        
        # Flag interesting findings
        interesting = [f for f in found if any(k in f[0].lower() for k in ['.env', 'backup', '.git', 'config', 'phpmyadmin', 'adminer', '.sql', '.dump', 'swagger', 'actuator', 'api-docs'])]
        for url, status, size in interesting[:10]:
            sev = 'critical' if any(k in url.lower() for k in ['.env', '.git/config', 'backup.sql']) else 'high'
            findings.append({
                'id': f'gob-{scan_id}',
                'severity': sev,
                'type': 'exposed_path',
                'title': f'Kritischer Pfad gefunden: {url.split("/")[-1] or url}',
                'url': url,
                'evidence': f'Status: {status}, Groesse: {size} Bytes',
                'remediation': 'Diesen Pfad sofort schuetzen oder entfernen!'
            })
            scan_id += 1
    
    return findings, scan_id


def scan(target):
    findings = []
    scan_id = 0
    
    if not target.startswith('http'):
        target = f'https://{target}'
    
    print(f"[PHASE GOBUSTER] Scanning {target}")
    
    gobuster_path = _has_gobuster()
    
    if not gobuster_path:
        # Pure Python fallback
        return _fallback_dir_scan(target, findings, scan_id)[0]
    
    # Use real gobuster
    try:
        # Create temporary wordlist
        wordlist = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'dirs.txt')
        if not os.path.exists(wordlist):
            wordlist = None
        
        cmd = [
            gobuster_path,
            'dir',
            '-u', target,
            '-w', wordlist or '/usr/share/wordlists/dirb/common.txt',
            '-q',
            '-o', '/tmp/gobuster_out.txt',
            '-t', '20',
            '-k',  # Skip SSL verification
            '-e',  # Expanded URLs
            '-r',  # Follow redirects
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        # Parse output
        output = result.stdout + '\n' + result.stderr
        found_urls = []
        for line in output.split('\n'):
            line = line.strip()
            if line and ('Status:' in line or 'Found:' in line or ('/' in line and ('Status: 200' in line or 'Status: 301' in line or 'Status: 403' in line))):
                found_urls.append(line)
        
        if found_urls:
            findings.append({
                'id': f'gob-{scan_id}',
                'severity': 'info',
                'type': 'gobuster_results',
                'title': f'Gobuster: {len(found_urls)} Pfade gefunden',
                'url': target,
                'evidence': f'Erste 30:\n{"\n".join(found_urls[:30])}',
                'remediation': 'Alle gefundenen Pfade auf Notwendigkeit pruefen.'
            })
            scan_id += 1
        else:
            findings.append({
                'id': f'gob-{scan_id}',
                'severity': 'info',
                'type': 'gobuster_no_results',
                'title': 'Gobuster: Keine versteckten Pfade gefunden',
                'url': target,
                'evidence': 'Keine zusaetzlichen Pfade mit gobuster entdeckt',
                'remediation': 'Gutes Zeichen - dennoch regelmaessig scannen.'
            })
            scan_id += 1
            
    except subprocess.TimeoutExpired:
        findings.append({
            'id': f'gob-{scan_id}',
            'severity': 'info',
            'type': 'gobuster_timeout',
            'title': 'Gobuster: Scan timeout',
            'url': target,
            'evidence': 'Gobuster hat das Zeitlimit (120s) ueberschritten',
            'remediation': 'Kuerzere Wordlist verwenden oder Timeout erhoehen.'
        })
        scan_id += 1
    except FileNotFoundError:
        # Fallback to pure Python
        return _fallback_dir_scan(target, findings, scan_id)[0]
    except Exception as e:
        # Fallback to pure Python
        print(f"[GOBUSTER] Error: {e}, using Python fallback")
        return _fallback_dir_scan(target, findings, scan_id)[0]
    
    return findings
