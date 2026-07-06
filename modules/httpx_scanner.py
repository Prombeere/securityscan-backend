"""
HTTPX Scanner Module - Python wrapper for httpx Go tool
Fast HTTP prober with advanced fingerprinting
"""
import subprocess, os, requests, json
from urllib.parse import urlparse

def _has_httpx():
    """Check if httpx binary is available"""
    paths = os.environ.get('PATH', '').split(':')
    paths.append(os.path.expanduser('~/.local/bin'))
    for p in paths:
        if os.path.isfile(os.path.join(p, 'httpx')):
            return os.path.join(p, 'httpx')
    try:
        result = subprocess.run(['which', 'httpx'], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            return result.stdout.strip()
    except:
        pass
    return None


def _fallback_httpx(target, findings, scan_id):
    """Pure Python HTTP fingerprinting when httpx is not available"""
    print(f"[HTTPX] httpx not found, using Python fallback for {target}")
    
    if not target.startswith('http'):
        urls = [f'https://{target}', f'http://{target}']
    else:
        urls = [target]
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (SecurityScan/3.0)'})
    
    for url in urls:
        try:
            resp = session.get(url, timeout=15, verify=False, allow_redirects=True)
            headers = resp.headers
            
            # Technology fingerprinting
            tech = []
            server = headers.get('Server', '')
            powered = headers.get('X-Powered-By', '')
            
            if server: tech.append(f'Server: {server}')
            if powered: tech.append(f'Powered-By: {powered}')
            
            # Detect CDN/WAF
            cf_ray = headers.get('CF-RAY', '')
            if cf_ray: tech.append('CDN: Cloudflare')
            akamai = headers.get('X-Akamai-Transformed', '')
            if akamai: tech.append('CDN: Akamai')
            fastly = headers.get('X-Fastly-Request-ID', '')
            if fastly: tech.append('CDN: Fastly')
            
            # Detect WAF
            waf_headers = ['X-WAF-Event-Info', 'X-Sucuri-ID', 'X-CDN', 'X-Edge-IP',
                          'X-Protected-By', 'X-Frame-Options', 'X-XSS-Protection']
            for wh in waf_headers:
                if headers.get(wh):
                    tech.append(f'WAF-Header: {wh}={headers[wh][:50]}')
            
            # JARM-like TLS fingerprint
            tls_info = headers.get('Strict-Transport-Security', '')
            if tls_info: tech.append(f'HSTS: {tls_info[:50]}')
            
            findings.append({
                'id': f'hpx-{scan_id}',
                'severity': 'info',
                'type': 'httpx_fingerprint',
                'title': f'HTTPX Fingerprint: {url}',
                'url': url,
                'evidence': f'Status: {resp.status_code}\nGroesse: {len(resp.text)} Bytes\nTechnologien: {", ".join(tech) if tech else "Keine spezifischen erkannt"}',
                'remediation': 'Technologien regelmaessig auf Sicherheitsupdates pruefen.'
            })
            scan_id += 1
            
            # Check for security headers
            sec_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'Clickjacking-Schutz',
                'X-Content-Type-Options': 'MIME-Sniffing-Schutz',
                'Referrer-Policy': 'Referrer-Kontrolle',
                'Permissions-Policy': 'Feature-Policy'
            }
            
            for header, desc in sec_headers.items():
                if not headers.get(header):
                    findings.append({
                        'id': f'hpx-{scan_id}',
                        'severity': 'medium',
                        'type': 'missing_security_header',
                        'title': f'HTTPX: {desc} fehlt ({header})',
                        'url': url,
                        'evidence': f'Header "{header}" nicht im Response vorhanden',
                        'remediation': f'Header "{header}" im Webserver konfigurieren.'
                    })
                    scan_id += 1
            
        except Exception as e:
            findings.append({
                'id': f'hpx-{scan_id}',
                'severity': 'info',
                'type': 'httpx_error',
                'title': f'HTTPX: Verbindungsfehler zu {url}',
                'url': url,
                'evidence': str(e),
                'remediation': 'Ziel-URL und Netzwerkverbindung pruefen.'
            })
            scan_id += 1
    
    return findings, scan_id


def scan(target):
    findings = []
    scan_id = 0
    
    hostname = target.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
    
    print(f"[PHASE HTTPX] Probing {hostname}")
    
    httpx_path = _has_httpx()
    
    if not httpx_path:
        return _fallback_httpx(target, findings, scan_id)[0]
    
    try:
        # Write target to temp file
        with open('/tmp/httpx_targets.txt', 'w') as f:
            f.write(hostname + '\n')
        
        cmd = [
            httpx_path,
            '-l', '/tmp/httpx_targets.txt',
            '-title',
            '-tech-detect',
            '-status-code',
            '-web-server',
            '-content-type',
            '-response-time',
            '-no-color',
            '-json',
            '-o', '/tmp/httpx_out.json'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        # Parse JSON output
        try:
            with open('/tmp/httpx_out.json', 'r') as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        url = data.get('url', hostname)
                        status = data.get('status_code', 0)
                        title = data.get('title', '')
                        tech = data.get('tech', [])
                        server = data.get('webserver', '')
                        
                        findings.append({
                            'id': f'hpx-{scan_id}',
                            'severity': 'info',
                            'type': 'httpx_probe',
                            'title': f'HTTPX: {url} [{status}]',
                            'url': url,
                            'evidence': f'Title: {title}\nServer: {server}\nTech: {", ".join(tech) if tech else "N/A"}',
                            'remediation': 'Erkannte Technologien auf Aktualitaet pruefen.'
                        })
                        scan_id += 1
        except:
            pass
        
        if scan_id == 0:
            return _fallback_httpx(target, findings, scan_id)[0]
            
    except FileNotFoundError:
        return _fallback_httpx(target, findings, scan_id)[0]
    except subprocess.TimeoutExpired:
        findings.append({
            'id': f'hpx-{scan_id}',
            'severity': 'info',
            'type': 'httpx_timeout',
            'title': 'HTTPX: Timeout',
            'url': target,
            'evidence': 'HTTPX Scan hat Zeitlimit ueberschritten',
            'remediation': 'Timeout erhoehen.'
        })
        scan_id += 1
    except Exception as e:
        return _fallback_httpx(target, findings, scan_id)[0]
    
    return findings
