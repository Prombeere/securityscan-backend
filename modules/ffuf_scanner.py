"""
FFUF Scanner Module - Python wrapper for ffuf Go tool
Fast web fuzzer for parameter and path discovery
"""
import subprocess, os, requests, re
from urllib.parse import urljoin

def _has_ffuf():
    """Check if ffuf binary is available"""
    paths = os.environ.get('PATH', '').split(':')
    paths.append(os.path.expanduser('~/.local/bin'))
    for p in paths:
        if os.path.isfile(os.path.join(p, 'ffuf')):
            return os.path.join(p, 'ffuf')
    try:
        result = subprocess.run(['which', 'ffuf'], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            return result.stdout.strip()
    except:
        pass
    return None


def _fallback_fuzz(target, findings, scan_id):
    """Pure Python parameter fuzzing when ffuf is not available"""
    print(f"[FFUF] ffuf not found, using Python fallback for {target}")
    
    if not target.startswith('http'):
        target = f'https://{target}'
    
    # Common parameter fuzzing
    params_file = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'params.txt')
    params = []
    try:
        with open(params_file, 'r') as f:
            params = [line.strip() for line in f if line.strip() and not line.startswith('#')][:100]
    except FileNotFoundError:
        params = ['id', 'page', 'q', 'search', 'file', 'path', 'url', 'redirect', 'callback', 
                  'data', 'cmd', 'exec', 'query', 'username', 'password', 'email', 'token',
                  'api_key', 'key', 'secret', 'admin', 'debug', 'test', 'source', 'include']
    
    found_params = []
    interesting = []
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (SecurityScan/3.0)'})
    
    for param in params:
        test_url = f'{target}/?{param}=test123'
        try:
            resp = session.get(test_url, timeout=8, allow_redirects=False, verify=False)
            # If response differs from baseline or contains reflection
            if resp.status_code == 200 and 'test123' in resp.text:
                found_params.append((param, 'reflected'))
                if param in ['cmd', 'exec', 'command', 'run', 'shell', 'system', 'eval', 'source', 'include']:
                    interesting.append((param, 'potential_command_param'))
            elif resp.status_code not in [404, 500]:
                found_params.append((param, f'status_{resp.status_code}'))
        except:
            continue
    
    if found_params:
        findings.append({
            'id': f'ffuf-{scan_id}',
            'severity': 'info',
            'type': 'ffuf_param_results',
            'title': f'FFUF: {len(found_params)} Parameter analysiert',
            'url': target,
            'evidence': f'Reflected: {", ".join([p for p, t in found_params if t == "reflected"][:20])}',
            'remediation': 'Alle Parameter auf Injection-Schwachstellen pruefen.'
        })
        scan_id += 1
    
    if interesting:
        for param, reason in interesting[:5]:
            findings.append({
                'id': f'ffuf-{scan_id}',
                'severity': 'medium',
                'type': 'suspicious_param',
                'title': f'Verdaechtiger Parameter: {param}',
                'url': f'{target}/?{param}=test',
                'evidence': f'Parameter "{param}" koennte fuer Command Injection genutzt werden ({reason})',
                'remediation': f'Parameter "{param}" validieren und absichern.'
            })
            scan_id += 1
    
    # Virtual host fuzzing
    vhosts = ['admin', 'api', 'dev', 'staging', 'test', 'panel', 'manage', 'internal']
    found_vhosts = []
    hostname = target.replace('https://', '').replace('http://', '').split('/')[0]
    
    for vhost in vhosts:
        try:
            resp = session.get(target, headers={'Host': f'{vhost}.{hostname}'}, timeout=5, verify=False)
            if resp.status_code != 404 and len(resp.text) > 100:
                found_vhosts.append(f'{vhost}.{hostname}')
        except:
            continue
    
    if found_vhosts:
        findings.append({
            'id': f'ffuf-{scan_id}',
            'severity': 'high',
            'type': 'vhost_found',
            'title': f'FFUF: {len(found_vhosts)} Virtual Hosts gefunden',
            'url': target,
            'evidence': f'Virtual Hosts: {", ".join(found_vhosts)}',
            'remediation': 'Virtual Hosts auf Sicherheit pruefen. Unnoetige VHosts deaktivieren.'
        })
        scan_id += 1
    
    return findings, scan_id


def scan(target):
    findings = []
    scan_id = 0
    
    if not target.startswith('http'):
        target = f'https://{target}'
    
    print(f"[PHASE FFUF] Fuzzing {target}")
    
    ffuf_path = _has_ffuf()
    
    if not ffuf_path:
        return _fallback_fuzz(target, findings, scan_id)[0]
    
    try:
        # Parameter discovery
        cmd = [
            ffuf_path,
            '-u', f'{target}/?FUZZ=test',
            '-w', os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'params.txt'),
            '-mc', '200,301,302,401,403,500',
            '-t', '30',
            '-s',
            '-timeout', '8'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        output = result.stdout.strip()
        
        if output:
            lines = [l for l in output.split('\n') if l.strip()]
            findings.append({
                'id': f'ffuf-{scan_id}',
                'severity': 'info',
                'type': 'ffuf_results',
                'title': f'FFUF: {len(lines)} Parameter gefunden',
                'url': target,
                'evidence': f'Parameter: {", ".join(lines[:30])}',
                'remediation': 'Alle Parameter validieren und auf Injection pruefen.'
            })
            scan_id += 1
        
    except FileNotFoundError:
        return _fallback_fuzz(target, findings, scan_id)[0]
    except subprocess.TimeoutExpired:
        findings.append({
            'id': f'ffuf-{scan_id}',
            'severity': 'info',
            'type': 'ffuf_timeout',
            'title': 'FFUF: Timeout',
            'url': target,
            'evidence': 'FFUF Scan hat Zeitlimit ueberschritten',
            'remediation': 'Timeout erhoehen oder kuerzere Wordlist verwenden.'
        })
        scan_id += 1
    except Exception as e:
        return _fallback_fuzz(target, findings, scan_id)[0]
    
    return findings
