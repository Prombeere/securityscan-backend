"""
FFUF Scanner - Pure Python parameter fuzzer
Replaces Go-based ffuf with equivalent Python implementation
Tests URL parameters for reflected values, errors, and behavioral changes
"""
import os
import re
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

WORDLIST_PATH = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'params.txt')
MAX_WORKERS = 25
TIMEOUT = 4
MAX_PARAMS = 400
TEST_VALUE = 'test123'


def scan(target):
    """Run parameter fuzzing scan"""
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
            'id': 'ffuf-connect-failed',
            'severity': 'info',
            'type': 'connectivity',
            'title': 'FFUF: Ziel nicht erreichbar',
            'url': host,
            'evidence': f'Weder HTTP noch HTTPS auf {host} erreichbar',
            'remediation': 'Pruefe ob das Ziel online ist.'
        }]
    
    base_url = f'{working_protocol}://{host}'
    
    # Load parameter wordlist
    params = []
    try:
        with open(WORDLIST_PATH, 'r') as f:
            params = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except:
        # Fallback minimal wordlist
        params = ['id', 'page', 'q', 'search', 'file', 'path', 'url', 'redirect', 'next', 'callback']
    
    # Deduplicate
    seen = set()
    unique_params = []
    for p in params:
        if p not in seen and '=' not in p:
            seen.add(p)
            unique_params.append(p)
    params = unique_params[:MAX_PARAMS]
    
    # Establish baseline (3 requests, take median)
    baseline_sizes = []
    baseline_times = []
    for _ in range(3):
        try:
            start = time.time()
            r = requests.get(base_url, timeout=TIMEOUT, allow_redirects=False)
            baseline_sizes.append(len(r.text))
            baseline_times.append(time.time() - start)
        except:
            pass
    
    if not baseline_sizes:
        return [{
            'id': 'ffuf-baseline-failed',
            'severity': 'info',
            'type': 'scan_error',
            'title': 'FFUF: Baseline-Messung fehlgeschlagen',
            'url': base_url,
            'evidence': 'Konnte keine Baseline fuer das Ziel ermitteln',
            'remediation': 'Ziel ist moeglicherweise nicht stabil erreichbar.'
        }]
    
    baseline_size = sorted(baseline_sizes)[len(baseline_sizes) // 2]
    baseline_time = sorted(baseline_times)[len(baseline_times) // 2] if baseline_times else 1.0
    
    # Error keywords that indicate interesting behavior
    error_keywords = [
        'sql syntax', 'mysql_fetch', 'pg_query', 'ora-', 'sqlite3',
        'warning:', 'fatal error', 'parse error', 'syntax error',
        'undefined index', 'undefined variable', 'invalid query',
        'unclosed quotation', 'incorrect syntax', 'division by zero'
    ]
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Security Scanner FFUF)'})
    
    def check_param(param):
        try:
            url = f'{base_url}/?{param}={TEST_VALUE}'
            start = time.time()
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=False)
            elapsed = time.time() - start
            
            return {
                'param': param,
                'url': url,
                'status': resp.status_code,
                'size': len(resp.text),
                'time': elapsed,
                'body': resp.text[:2000],
                'headers': dict(resp.headers)
            }
        except:
            return None
    
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_param, param): param for param in params}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    
    # Analyze results
    reflected_params = []
    error_params = []
    size_diff_params = []
    redirect_params = []
    
    for r in results:
        param = r['param']
        body = r['body']
        status = r['status']
        size = r['size']
        elapsed = r['time']
        
        # Check for reflection
        if TEST_VALUE in body:
            reflected_params.append(r)
        
        # Check for error messages
        body_lower = body.lower()
        for keyword in error_keywords:
            if keyword in body_lower:
                error_params.append({**r, 'error_keyword': keyword})
                break
        
        # Check for significant size difference
        size_diff = abs(size - baseline_size)
        if size_diff > 50:
            size_diff_params.append({**r, 'size_diff': size_diff})
        
        # Check for redirects
        if status in [301, 302, 307, 308]:
            redirect_params.append(r)
    
    # Create findings
    if reflected_params:
        for r in reflected_params[:10]:  # Limit to top 10
            findings.append({
                'id': f'ffuf-reflect-{r["param"]}',
                'severity': 'low',
                'type': 'reflected_parameter',
                'title': f'Reflektierter Parameter: {r["param"]}',
                'url': r['url'],
                'evidence': f'Parameter "{r["param"]}" mit Wert "{TEST_VALUE}" wird im Response reflektiert. Status: {r["status"]}, Groesse: {r["size"]} bytes',
                'remediation': 'Validiere alle Eingaben. Nutze Output-Encoding um XSS zu verhindern.'
            })
    
    if error_params:
        for r in error_params[:10]:
            findings.append({
                'id': f'ffuf-error-{r["param"]}',
                'severity': 'medium',
                'type': 'parameter_error',
                'title': f'Fehlermeldung bei Parameter: {r["param"]}',
                'url': r['url'],
                'evidence': f'Parameter "{r["param"]}" loeste Fehler aus ({r["error_keyword"]}). Status: {r["status"]}',
                'remediation': 'Unterdruecke detaillierte Fehlermeldungen in Produktivumgebungen.'
            })
    
    if redirect_params:
        for r in redirect_params[:5]:
            findings.append({
                'id': f'ffuf-redirect-{r["param"]}',
                'severity': 'low',
                'type': 'open_redirect',
                'title': f'Open Redirect Parameter: {r["param"]}',
                'url': r['url'],
                'evidence': f'Parameter "{r["param"]}" verursacht Redirect (Status {r["status"]}). Location: {r["headers"].get("Location", "N/A")}',
                'remediation': 'Validiere Redirect-URLs gegen eine Whitelist.'
            })
    
    # Summary finding
    total_tested = len(results)
    if total_tested > 0:
        findings.insert(0, {
            'id': 'ffuf-summary',
            'severity': 'info',
            'type': 'scan_summary',
            'title': f'FFUF Parameter Scan: {total_tested} Parameter getestet',
            'url': base_url,
            'evidence': f'Getestet: {total_tested} Parameter | Reflektiert: {len(reflected_params)} | Fehler: {len(error_params)} | Redirects: {len(redirect_params)} | Groessen-Diff: {len(size_diff_params)} | Baseline-Groesse: {baseline_size} bytes',
            'remediation': None
        })
    
    return findings
