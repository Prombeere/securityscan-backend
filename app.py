"""
Security Scanner Backend v3.3.1 - Main Flask Application
Orchestrates 24 security scanning modules with real HTTP requests
+ Kimi K2-0711-preview AI analysis + Blind SQLi PoC Detector
+ WPScan, Nuclei, Nikto, SQLMap, Gobuster, FFUF, HTTPX, CVE
Auto-detects kimi.com vs moonshot.cn API based on key format
"""
import os
import sys
import time
import json
import traceback
import importlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

# ============== CORS - Manual (covers ALL routes) ==============
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Max-Age', '86400')
    return response

@app.route('/', methods=['OPTIONS'])
@app.route('/health', methods=['OPTIONS'])
@app.route('/api/scan', methods=['OPTIONS'])
@app.route('/api/modules', methods=['OPTIONS'])
@app.route('/api/kimi-test', methods=['OPTIONS'])
@app.route('/api/kimi-debug', methods=['OPTIONS'])
@app.route('/api/scan/<path:path>', methods=['OPTIONS'])
def handle_options(path=None):
    response = make_response()
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Max-Age', '86400')
    return response, 204

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

# ============== 24 SCANNER MODULES ==============
MODULE_DEFINITIONS = [
    ('dns', 'dns_scanner', 'DNS-Analyse: Records, SPF, DMARC, DNSSEC'),
    ('ssl', 'ssl_scanner', 'SSL/TLS-Analyse: Zertifikat, Cipher-Suites, HSTS'),
    ('headers', 'header_scanner', 'Security-Header: 20+ Header-Pruefungen'),
    ('xss', 'xss_scanner', 'XSS-Scan: Reflektierte Payloads, DOM-Sinks'),
    ('redirect', 'redirect_scanner', 'Open-Redirect: Parameter-Tests, JS-Redirects'),
    ('methods', 'method_scanner', 'HTTP-Methoden: OPTIONS, PUT, DELETE, TRACE'),
    ('directory', 'dir_scanner', 'Verzeichnis-Scan: 989 Pfade, Backups, Configs'),
    ('tech', 'tech_scanner', 'Technologie-Erkennung: Frameworks, Bibliotheken'),
    ('cookies', 'cookie_scanner', 'Cookie-Analyse: Secure, HttpOnly, SameSite'),
    ('cors', 'cors_scanner', 'CORS-Scan: Origin-Reflection, Wildcards'),
    ('subdomain', 'subdomain_scanner', 'Subdomain-Enumeration: 1780 Subdomains'),
    ('ports', 'port_scanner', 'Port-Scan: 22 Ports + Banner-Grabbing'),
    ('whois', 'whois_scanner', 'WHOIS-Abfrage: Registrar, Ablaufdatum'),
    ('content', 'content_scanner', 'Content-Scan: robots.txt, sitemap, 404'),
    ('injection', 'injection_scanner', 'Injection-Tests: SQLi, CMDi, NoSQLi, SSTI'),
    ('sqli_poc', 'blind_sqli_detector', 'SQLi PoC: Boolean/Time/Union/Error Beweise'),
    ('wpscan', 'wpscan_scanner', 'WPScan: WordPress Version, Plugins, Themes, Users'),
    ('nuclei', 'nuclei_scanner', 'Nuclei: CVE-Signaturen, Template-Matching'),
    ('nikto', 'nikto_scanner', 'Nikto: Gefaerliche Pfade, Server-Config, Headers'),
    ('sqlmap', 'sqlmap_scanner', 'SQLMap: Fortgeschrittene SQL-Injection-Detection'),
    ('gobuster', 'gobuster_scanner', 'Gobuster: Verzeichnis-Brute-Force'),
    ('ffuf', 'ffuf_scanner', 'FFUF: Parameter-Fuzzing + Virtual-Host-Discovery'),
    ('httpx', 'httpx_scanner', 'HTTPX: HTTP-Fingerprinting + WAF/CDN-Erkennung'),
    ('cve', 'cve_scanner', 'CVE-Scanner: Bekannte Schwachstellen pro Technologie'),
]

SCANNER_MODULES = []
MODULE_LOAD_ERRORS = {}

for mod_name, mod_file, mod_desc in MODULE_DEFINITIONS:
    try:
        mod = importlib.import_module(f'modules.{mod_file}')
        SCANNER_MODULES.append((mod_name, mod, mod_desc))
        print(f"[OK] Loaded module: {mod_name}")
    except Exception as e:
        MODULE_LOAD_ERRORS[mod_name] = str(e)
        print(f"[WARN] Skipped module {mod_name}: {e}")

kimi_analyzer = None
try:
    kimi_analyzer = importlib.import_module('modules.kimi_analyzer')
    print("[OK] Loaded module: kimi_analyzer")
except Exception as e:
    MODULE_LOAD_ERRORS['kimi'] = str(e)
    print(f"[WARN] Skipped module kimi_analyzer: {e}")

print(f"[INFO] {len(SCANNER_MODULES)} of {len(MODULE_DEFINITIONS)} scanner modules loaded")


def run_scanner(module_name, module, target):
    try:
        findings = module.scan(target)
        return {'module': module_name, 'status': 'completed', 'findings': findings if findings else []}
    except Exception as e:
        print(f"[ERROR] Module {module_name} failed: {str(e)}")
        return {'module': module_name, 'status': 'error', 'findings': [{
            'id': f'{module_name}-error', 'severity': 'info', 'type': 'scan_error',
            'title': f'Scanner-Modul {module_name} fehlgeschlagen', 'url': target,
            'evidence': f'Fehler: {str(e)}', 'remediation': 'Scan manuell pruefen.'
        }]}


def severity_score(severity):
    scores = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
    return scores.get(severity.lower(), 0)


@app.route('/')
def index():
    return jsonify({
        'name': 'Security Scanner Backend',
        'version': '3.3.1',
        'modules_loaded': len(SCANNER_MODULES),
        'modules_total': len(MODULE_DEFINITIONS),
        'modules': [name for name, _, _ in SCANNER_MODULES],
        'module_errors': MODULE_LOAD_ERRORS
    })


@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'modules_loaded': len(SCANNER_MODULES),
        'modules_total': len(MODULE_DEFINITIONS)
    })


@app.route('/api/modules', methods=['GET'])
def list_modules():
    return jsonify({
        'modules': [{'name': name, 'description': desc} for name, _, desc in SCANNER_MODULES],
        'errors': MODULE_LOAD_ERRORS
    })


def _get_kimi_key():
    """Read and clean Kimi API key from environment"""
    key = os.environ.get('KIMI_API_KEY', '')
    key = key.replace('\n', '').replace('\r', '').replace(' ', '')
    key = key.strip().strip('"').strip("'").strip()
    return key


def _get_kimi_api_url():
    """Get Kimi API URL - auto-detects based on key format"""
    key = _get_kimi_key()
    if key.startswith('sk-kimi-'):
        return 'https://api.kimi.com/coding/v1/chat/completions'
    return os.environ.get('KIMI_API_URL', 'https://api.moonshot.cn/v1/chat/completions')


def _get_kimi_model():
    """Get correct model name based on key format"""
    key = _get_kimi_key()
    if key.startswith('sk-kimi-'):
        return 'kimi-for-coding'
    return 'kimi-k2-0711-preview'


@app.route('/api/kimi-test', methods=['GET'])
def kimi_test():
    api_key = _get_kimi_key()
    api_url = _get_kimi_api_url()
    model = _get_kimi_model()
    diagnostics = {
        'key_present': bool(api_key),
        'key_length': len(api_key),
        'key_prefix': api_key[:10] + '...' if len(api_key) > 10 else 'too_short',
        'api_url_used': api_url,
        'model_used': model,
    }
    if not api_key:
        diagnostics['status'] = 'no_key'
        diagnostics['message'] = 'KIMI_API_KEY nicht gesetzt!'
        return jsonify(diagnostics)
    try:
        import urllib.request
        req_data = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": "Say OK"}],
            "max_tokens": 10
        }).encode('utf-8')
        req = urllib.request.Request(
            api_url,
            data=req_data,
            headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {api_key}'},
            method='POST')
        resp = urllib.request.urlopen(req, timeout=15)
        result = json.loads(resp.read().decode('utf-8'))
        diagnostics['status'] = 'success'
        diagnostics['message'] = 'Kimi API funktioniert!'
        diagnostics['credits_used'] = True
    except urllib.error.HTTPError as e:
        err = e.read().decode('utf-8', errors='ignore')[:1000] if hasattr(e, 'read') else ''
        diagnostics['status'] = f'http_error_{e.code}'
        diagnostics['error_details'] = err
        if e.code == 401:
            diagnostics['message'] = 'Key ungueltig (401)!'
        elif e.code == 429:
            diagnostics['message'] = 'Rate Limit (429)!'
        elif e.code == 403:
            diagnostics['message'] = 'Kein Zugriff (403)!'
        else:
            diagnostics['message'] = f'Fehler {e.code}: {err}'
    except Exception as e:
        diagnostics['status'] = 'network_error'
        diagnostics['message'] = str(e)
    return jsonify(diagnostics)


@app.route('/api/kimi-debug', methods=['GET'])
def kimi_debug():
    """Advanced debug - tests ALL API endpoint combinations"""
    raw_key = os.environ.get('KIMI_API_KEY', '')
    clean_key = _get_kimi_key()
    
    key_chars = []
    for i, c in enumerate(raw_key[:30]):
        key_chars.append({'pos': i, 'char': c if c.isprintable() else f'\\x{ord(c):02x}', 'ascii': ord(c)})
    
    result = {
        'key_analysis': {
            'raw_length': len(raw_key),
            'clean_length': len(clean_key),
            'clean_prefix': clean_key[:15] if clean_key else 'EMPTY',
            'first_10_chars': key_chars,
            'starts_with_sk_kimi': clean_key.startswith('sk-kimi-'),
            'detected_api_url': _get_kimi_api_url(),
            'detected_model': _get_kimi_model(),
        },
        'api_tests': {}
    }
    
    if not clean_key:
        result['api_tests'] = {'error': 'No key found after cleaning'}
        return jsonify(result)
    
    api_urls_to_test = [
        ('api.moonshot.cn', 'https://api.moonshot.cn/v1/chat/completions', 'kimi-k2-0711-preview'),
        ('api.kimi.com (WRONG path)', 'https://api.kimi.com/v1/chat/completions', 'kimi-k2-0711-preview'),
        ('api.kimi.com/coding (CORRECT)', 'https://api.kimi.com/coding/v1/chat/completions', 'kimi-for-coding'),
    ]
    
    for api_name, api_url, model in api_urls_to_test:
        try:
            import urllib.request
            req_data = json.dumps({
                "model": model,
                "messages": [{"role": "user", "content": "Say OK"}],
                "max_tokens": 10
            }).encode('utf-8')
            req = urllib.request.Request(
                api_url,
                data=req_data,
                headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {clean_key}'},
                method='POST')
            resp = urllib.request.urlopen(req, timeout=15)
            resp_json = json.loads(resp.read().decode('utf-8'))
            result['api_tests'][api_name] = {
                'status': 'success',
                'url': api_url,
                'model': model,
                'response': resp_json['choices'][0]['message']['content'][:50] if resp_json.get('choices') else 'no content'
            }
        except urllib.error.HTTPError as e:
            err_body = e.read().decode('utf-8', errors='ignore')[:2000] if hasattr(e, 'read') else ''
            result['api_tests'][api_name] = {
                'status': f'error_{e.code}',
                'url': api_url,
                'model': model,
                'error_body_full': err_body,
                'error_headers': dict(e.headers) if hasattr(e, 'headers') else 'no headers',
            }
        except Exception as e:
            result['api_tests'][api_name] = {
                'status': 'exception',
                'url': api_url,
                'model': model,
                'error': str(e)
            }
    
    return jsonify(result)


@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    target = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]

    selected_modules = data.get('modules', [])
    if selected_modules:
        modules_to_run = [(name, mod, desc) for name, mod, desc in SCANNER_MODULES if name in selected_modules]
    else:
        modules_to_run = SCANNER_MODULES

    if not modules_to_run:
        return jsonify({'error': 'No modules available'}), 500

    print(f"\n{'='*60}")
    print(f"[SCAN START] Target: {target} | Modules: {len(modules_to_run)}")
    print(f"{'='*60}\n")

    start_time = time.time()
    all_results = {}
    all_findings = []
    phase_log = []

    # CRITICAL FIX: try/except around ThreadPool to prevent backend crash
    try:
        with ThreadPoolExecutor(max_workers=min(len(modules_to_run), 12)) as executor:
            future_to_module = {
                executor.submit(run_scanner, name, mod, target): (name, desc)
                for name, mod, desc in modules_to_run
            }

            for i, future in enumerate(as_completed(future_to_module), 1):
                name, desc = future_to_module[future]
                try:
                    result = future.result(timeout=120)
                    all_results[name] = result
                    if result['findings']:
                        all_findings.extend(result['findings'])
                    phase_log.append({'phase': i, 'module': name, 'description': desc,
                                      'status': result['status'], 'findings_count': len(result['findings'])})
                    print(f"[PHASE {i}] {name}: {result['status']} ({len(result['findings'])} findings)")
                except Exception as e:
                    phase_log.append({'phase': i, 'module': name, 'description': desc,
                                      'status': 'timeout', 'findings_count': 0, 'error': str(e)})
                    print(f"[PHASE {i}] {name}: TIMEOUT - {str(e)}")
    except Exception as e:
        print(f"[CRITICAL] ThreadPool failed: {e}")
        traceback.print_exc()

    elapsed = time.time() - start_time
    all_findings.sort(key=lambda f: severity_score(f.get('severity', 'info')), reverse=True)

    severity_counts = {}
    for f in all_findings:
        sev = f.get('severity', 'info')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    risk_score = min(severity_counts.get('critical', 0) * 20 + severity_counts.get('high', 0) * 10 +
                     severity_counts.get('medium', 0) * 5 + severity_counts.get('low', 0) * 2, 100)

    risk_level = 'critical' if risk_score >= 70 else 'high' if risk_score >= 40 else 'medium' if risk_score >= 20 else 'low' if risk_score >= 5 else 'info'

    ai_findings = []
    ai_report = None
    ai_enabled = False
    if kimi_analyzer is not None:
        try:
            ai_enabled = kimi_analyzer.check_api_key()
        except:
            ai_enabled = False
        if ai_enabled and all_findings:
            try:
                ai_findings = kimi_analyzer.analyze_with_kimi(target, all_findings)
                ai_report = kimi_analyzer.generate_report(target, all_findings)
                all_findings.extend(ai_findings)
            except Exception as e:
                print(f"[KIMI K2] Error: {e}")

    print(f"\n[SCAN COMPLETE] {target} | {elapsed:.1f}s | {len(all_findings)} findings | Risk: {risk_score}/100")
    print(f"{'='*60}\n")

    return jsonify({
        'target': target,
        'scan_time': datetime.utcnow().isoformat(),
        'duration_seconds': round(elapsed, 2),
        'modules_scanned': len(modules_to_run),
        'modules_completed': len([p for p in phase_log if p['status'] == 'completed']),
        'modules_error': len([p for p in phase_log if p['status'] == 'error']),
        'risk_score': risk_score,
        'risk_level': risk_level,
        'summary': {'total_findings': len(all_findings), 'severity_breakdown': severity_counts},
        'phases': phase_log,
        'ai_analysis': {
            'enabled': ai_enabled,
            'model': _get_kimi_model() if ai_enabled else None,
            'findings_count': len(ai_findings),
            'executive_summary': ai_report
        },
        'findings': all_findings,
        'modules': {name: {'status': res['status'], 'findings_count': len(res['findings'])}
                    for name, res in all_results.items()}
    })


@app.route('/api/scan/<module>', methods=['POST'])
def scan_single(module):
    data = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    target = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]

    module_map = {name: (mod, desc) for name, mod, desc in SCANNER_MODULES}
    if module not in module_map:
        return jsonify({'error': f'Unknown module: {module}'}), 404

    mod, desc = module_map[module]
    result = run_scanner(module, mod, target)
    result['findings'].sort(key=lambda f: severity_score(f.get('severity', 'info')), reverse=True)

    return jsonify({
        'target': target, 'module': module,
        'status': result['status'], 'findings_count': len(result['findings']),
        'findings': result['findings']
    })


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Internal error', 'message': str(error)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting Security Scanner Backend v3.3.1 on port {port}")
    app.run(host='0.0.0.0', port=port)
