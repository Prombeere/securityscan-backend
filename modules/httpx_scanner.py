"""
HTTPX Scanner - Pure Python HTTP fingerprinter
Replaces Go-based httpx with equivalent Python implementation
Performs comprehensive HTTP fingerprinting, WAF/CDN detection, and TLS analysis
"""
import re
import ssl
import socket
import requests
from urllib.parse import urlparse
from datetime import datetime

# WAF/CDN signatures
WAF_SIGNATURES = {
    'Cloudflare': {'headers': ['CF-RAY', 'CF-Cache-Status', 'CF-Connecting-IP'], 'body': []},
    'Akamai': {'headers': ['X-Akamai-Request-BC', 'X-Akamai-Cache-Status', 'X-Akamai-Transformed'], 'body': []},
    'AWS CloudFront': {'headers': ['X-Amz-Cf-Id', 'X-Amz-Cf-Pop', 'Via'], 'body': []},
    'Fastly': {'headers': ['X-Served-By', 'X-Timer', 'Fastly-Debug-Digest'], 'body': []},
    'Sucuri': {'headers': ['X-Sucuri-ID', 'X-Sucuri-Cache'], 'body': ['sucuri']},
    'Imperva/Incapsula': {'headers': ['X-Iinfo', 'X-CDN', 'X-WJ-Debug'], 'body': ['incapsula']},
    'ModSecurity': {'headers': ['X-Mod-Security'], 'body': []},
    'AWS WAF': {'headers': ['X-Amzn-Requestid', 'X-Amzn-Trace-Id'], 'body': []},
    'Barracuda': {'headers': ['X-Barracuda'], 'body': []},
    'F5 BIG-IP': {'headers': ['X-WA-Info', 'X-PvInfo', 'X-Cnection'], 'body': []},
    'Wordfence': {'headers': ['X-WF-SID'], 'body': []},
}

# Technology signatures
TECH_SIGNATURES = {
    'Apache': {'headers': ['Server'], 'patterns': [r'Apache[/\s]?([0-9.]+)?']},
    'Nginx': {'headers': ['Server'], 'patterns': [r'nginx[/\s]?([0-9.]+)?']},
    'IIS': {'headers': ['Server'], 'patterns': [r'Microsoft-IIS[/\s]?([0-9.]+)?']},
    'lighttpd': {'headers': ['Server'], 'patterns': [r'lighttpd']},
    'Caddy': {'headers': ['Server'], 'patterns': [r'Caddy']},
    'Tomcat': {'headers': ['Server', 'X-Powered-By'], 'patterns': [r'Apache-Coyote', r'Tomcat']},
    'Jetty': {'headers': ['Server'], 'patterns': [r'Jetty']},
    'PHP': {'headers': ['X-Powered-By'], 'patterns': [r'PHP[/\s]?([0-9.]+)?']},
    'ASP.NET': {'headers': ['X-Powered-By', 'X-AspNet-Version'], 'patterns': [r'ASP\.NET']},
    'Rails': {'headers': ['X-Runtime', 'X-Request-Id'], 'patterns': [r'Ruby|Rails']},
    'Django': {'headers': [], 'patterns': [], 'cookies': ['csrftoken', 'django_session']},
    'Laravel': {'headers': ['X-RateLimit-Limit'], 'patterns': [], 'cookies': ['laravel_session']},
    'Express.js': {'headers': ['X-Powered-By'], 'patterns': [r'Express']},
    'Spring Boot': {'headers': ['X-Application-Context'], 'patterns': [r'Spring']},
    'WordPress': {'headers': [], 'patterns': [r'wp-content|wp-includes|/wp-json/|generator.*wordpress', 'WordPress']},
    'Drupal': {'headers': ['X-Generator'], 'patterns': [r'Drupal']},
    'Joomla': {'headers': [], 'patterns': [r'Joomla|/media/joom']},
    'Magento': {'headers': ['X-Magento'], 'patterns': [r'Magento']},
    'Shopify': {'headers': ['X-ShopId', 'X-Shopify-Stage'], 'patterns': [r'Shopify']},
    'Varnish': {'headers': ['X-Varnish', 'Age', 'X-Cache-Hits'], 'patterns': [r'Varnish']},
    'HAProxy': {'headers': ['X-Haproxy-Server-State'], 'patterns': [r'HAProxy']},
    'OpenResty': {'headers': ['Server'], 'patterns': [r'openresty']},
}

# Proxy headers that should NOT be in responses
PROXY_HEADERS = [
    'X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Proto',
    'X-Real-IP', 'X-Original-URL', 'X-Rewrite-URL',
    'X-Http-Host-Override', 'X-Forwarded-Port', 'X-Forwarded-Server',
    'X-ProxyUser-Ip', 'X-Remote-IP', 'X-Remote-Addr',
    'X-Client-IP', 'True-Client-IP'
]


def get_tls_info(hostname):
    """Get TLS certificate information"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                return {
                    'version': version,
                    'cipher': cipher[0] if cipher else 'Unknown',
                    'subject': cert.get('subject'),
                    'issuer': cert.get('issuer'),
                    'not_after': cert.get('notAfter'),
                    'not_before': cert.get('notBefore'),
                    'san': cert.get('subjectAltName', []),
                }
    except Exception as e:
        return {'error': str(e)}


def scan(target):
    """Run HTTPX-style fingerprinting scan"""
    findings = []
    host = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
    
    # Try HTTPS first
    urls_to_try = [f'https://{host}', f'http://{host}']
    resp = None
    final_url = None
    
    for url in urls_to_try:
        try:
            resp = requests.get(url, timeout=10, allow_redirects=False, headers={
                'User-Agent': 'Mozilla/5.0 (Security Scanner HTTPX)'
            })
            final_url = url
            break
        except:
            continue
    
    if not resp:
        return [{
            'id': 'httpx-connect-failed',
            'severity': 'info',
            'type': 'connectivity',
            'title': 'HTTPX: Ziel nicht erreichbar',
            'url': host,
            'evidence': f'Weder HTTP noch HTTPS auf {host} erreichbar',
            'remediation': 'Pruefe ob das Ziel online ist.'
        }]
    
    headers = dict(resp.headers)
    body = resp.text[:5000]
    status = resp.status_code
    
    # ===== WAF/CDN Detection =====
    detected_wafs = []
    for waf_name, sigs in WAF_SIGNATURES.items():
        for header in sigs['headers']:
            if header in headers:
                detected_wafs.append(waf_name)
                break
        for pattern in sigs['body']:
            if pattern.lower() in body.lower():
                detected_wafs.append(waf_name)
                break
    
    detected_wafs = list(set(detected_wafs))
    if detected_wafs:
        findings.append({
            'id': 'httpx-waf-detected',
            'severity': 'medium',
            'type': 'cdn_waf',
            'title': f'WAF/CDN erkannt: {", ".join(detected_wafs)}',
            'url': final_url,
            'evidence': f'Erkannt anhand Header/Body-Signaturen: {", ".join(detected_wafs)}',
            'remediation': 'WAF ist gut, aber sollte nicht die einzige Verteidigungslinie sein.'
        })
    
    # ===== Technology Detection =====
    detected_tech = []
    for tech_name, sigs in TECH_SIGNATURES.items():
        found = False
        for header in sigs.get('headers', []):
            if header in headers:
                for pattern in sigs.get('patterns', []):
                    if re.search(pattern, headers[header], re.IGNORECASE):
                        detected_tech.append(f'{tech_name} ({headers[header]})')
                        found = True
                        break
                if not found and not sigs.get('patterns'):
                    detected_tech.append(tech_name)
                    found = True
                if found:
                    break
        if not found:
            for pattern in sigs.get('patterns', []):
                if re.search(pattern, body, re.IGNORECASE):
                    detected_tech.append(tech_name)
                    break
        if not found and 'cookies' in sigs:
            cookies = resp.cookies.get_dict()
            for cookie_name in sigs['cookies']:
                if cookie_name in cookies or cookie_name in str(resp.cookies):
                    detected_tech.append(tech_name)
                    break
    
    detected_tech = list(set(detected_tech))
    if detected_tech:
        findings.append({
            'id': 'httpx-tech-detected',
            'severity': 'info',
            'type': 'technology',
            'title': f'Technologien erkannt: {len(detected_tech)}',
            'url': final_url,
            'evidence': 'Erkannt: ' + '; '.join(detected_tech[:15]),
            'remediation': 'Entferne unnötige Header wie X-Powered-By und Server.'
        })
    
    # ===== Exposed Headers =====
    exposed_headers = []
    for header in ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime', 'X-Generator']:
        if header in headers:
            exposed_headers.append(f'{header}: {headers[header]}')
    
    if exposed_headers:
        findings.append({
            'id': 'httpx-exposed-headers',
            'severity': 'low',
            'type': 'information_disclosure',
            'title': f'Veratende Header: {len(exposed_headers)}',
            'url': final_url,
            'evidence': '; '.join(exposed_headers),
            'remediation': 'Entferne Server- und X-Powered-By Header in der Webserver-Konfiguration.'
        })
    
    # ===== Proxy Header Reflection =====
    reflected_proxy = []
    for ph in PROXY_HEADERS:
        if ph.lower() in str(headers).lower() or ph in body:
            reflected_proxy.append(ph)
    
    if reflected_proxy:
        findings.append({
            'id': 'httpx-proxy-reflection',
            'severity': 'high',
            'type': 'proxy_header_reflection',
            'title': 'Proxy-Header werden reflektiert!',
            'url': final_url,
            'evidence': f'Reflektierte Proxy-Header: {", ".join(reflected_proxy)}',
            'remediation': 'Stelle sicher dass Proxy-Header nicht in Response-Headern oder Body sichtbar sind.'
        })
    
    # ===== HTTP/2 Check =====
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(['h2', 'http/1.1'])
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                protocol = ssock.selected_alpn_protocol()
                if protocol == 'h2':
                    findings.append({
                        'id': 'httpx-http2',
                        'severity': 'info',
                        'type': 'protocol',
                        'title': 'HTTP/2 wird unterstuetzt',
                        'url': f'https://{host}',
                        'evidence': 'ALPN-Verhandlung ergab HTTP/2 (h2)',
                        'remediation': None
                    })
    except:
        pass
    
    # ===== Redirect Chain =====
    if status in [301, 302, 307, 308]:
        try:
            r = requests.get(final_url, timeout=10, allow_redirects=True, headers={
                'User-Agent': 'Mozilla/5.0 (Security Scanner HTTPX)'
            })
            redirect_chain = []
            for hist in r.history:
                redirect_chain.append(f'{hist.status_code} -> {hist.headers.get("Location", "N/A")}')
            if redirect_chain:
                findings.append({
                    'id': 'httpx-redirect-chain',
                    'severity': 'info',
                    'type': 'redirect',
                    'title': f'Redirect-Chain: {len(redirect_chain)} Spruenge',
                    'url': final_url,
                    'evidence': ' -> '.join(redirect_chain[:5]),
                    'remediation': 'Pruefe ob Redirects erwartet sind und nicht zu HTTP zurueckfallen.'
                })
        except:
            pass
    
    # ===== TLS Info =====
    tls_info = get_tls_info(host)
    if 'error' not in tls_info:
        tls_evidence = f'TLS Version: {tls_info["version"]} | Cipher: {tls_info["cipher"]}'
        
        # Check for weak TLS
        if tls_info['version'] in ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']:
            findings.append({
                'id': 'httpx-weak-tls',
                'severity': 'high',
                'type': 'tls',
                'title': f'Schwache TLS-Version: {tls_info["version"]}',
                'url': f'https://{host}',
                'evidence': tls_evidence,
                'remediation': 'Deaktiviere TLS 1.0 und 1.1, aktiviere nur TLS 1.2+.'
            })
        
        # Check cert expiry
        if tls_info.get('not_after'):
            try:
                expiry = datetime.strptime(tls_info['not_after'], '%b %d %H:%M:%S %Y %Z')
                days_until = (expiry - datetime.utcnow()).days
                if days_until < 0:
                    findings.append({
                        'id': 'httpx-cert-expired',
                        'severity': 'high',
                        'type': 'tls',
                        'title': 'TLS-Zertifikat ABGELAUFEN!',
                        'url': f'https://{host}',
                        'evidence': f'Ablaufdatum: {tls_info["not_after"]} ({abs(days_until)} Tage ueberfaellig)',
                        'remediation': 'Sofort Zertifikat erneuern!'
                    })
                elif days_until < 30:
                    findings.append({
                        'id': 'httpx-cert-expiring',
                        'severity': 'medium',
                        'type': 'tls',
                        'title': f'TLS-Zertifikat laeuft bald ab ({days_until} Tage)',
                        'url': f'https://{host}',
                        'evidence': f'Ablaufdatum: {tls_info["not_after"]}',
                        'remediation': 'Zertifikat rechtzeitig erneuern.'
                    })
            except:
                pass
    
    # ===== Directory Listing =====
    if '<title>Index of' in body or 'Directory Listing' in body or 'Parent Directory' in body:
        findings.append({
            'id': 'httpx-dir-listing',
            'severity': 'medium',
            'type': 'directory_listing',
            'title': 'Directory Listing aktiviert',
            'url': final_url,
            'evidence': 'Verzeichnisinhalt wird direkt im Browser angezeigt',
            'remediation': 'Deaktiviere Directory Listing im Webserver.'
        })
    
    return findings
