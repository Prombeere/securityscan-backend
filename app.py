#!/usr/bin/env python3
"""
Security Scanner Backend v3.3 - Main Flask Application
Orchestrates 24 security scanning modules with real HTTP requests
+ Kimi K2-0711-preview AI analysis + Blind SQLi PoC Detector
+ WPScan, Nuclei, Nikto, SQLMap, Gobuster, FFUF, HTTPX, CVE
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
    # NEW: Advanced scanners
    ('wpscan', 'wpscan_scanner', 'WPScan: WordPress Version, Plugins, Themes, Users'),
    ('nuclei', 'nuclei_scanner', 'Nuclei: CVE-Signaturen, Template-Matching'),
    ('nikto', 'nikto_scanner', 'Nikto: Gefaerliche Pfade, Server-Config, Headers'),
    ('sqlmap', 'sqlmap_scanner', 'SQLMap: Fortgeschrittene SQL-Injection-Detection'),
    # Go tools with Python fallbacks
    ('gobuster', 'gobuster_scanner', 'Gobuster: Verzeichnis-Brute-Force'),
    ('ffuf', 'ffuf_scanner', 'FFUF: Parameter-Fuzzing + Virtual-Host-Discovery'),
    ('httpx', 'httpx_scanner', 'HTTPX: HTTP-Fingerprinting + WAF/CDN-Erkennung'),
    ('cve', 'cve_scanner', 'CVE-Scanner: Bekannte Schwachstellen pro Technologie'),
]

# Robust module loading
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

# Kimi analyzer
kimi_analyzer = None
try:
    kimi_analyzer = importlib.import_module('modules.kimi_analyzer')
    print("[OK] Loaded module: kimi_analyzer")
except Exception as e:
    MODULE_LOAD_ERRORS['kimi'] = str(e)
    print(f"[WARN] Skipped module kimi_analyzer: {e}")

print(f"[INFO] {len(SCANNER_MODULES)} of {len(MODULE_DEFINITIONS)} scanner modules loaded")
if MODULE_LOAD_ERRORS:
    print(f"[INFO] Module load errors: {MODULE_LOAD_ERRORS}")


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
        'version': '3.3.0',
        'description': 'Comprehensive security scanning with 24 modules + Kimi K2 AI',
        'endpoints': {
            '/api/scan': 'POST - Start a security scan',
            '/api/modules': 'GET - List all modules',
            '/api/kimi-test': 'GET - Test Kimi API key',
            '/api/kimi-debug': 'GET - Advanced Kimi debug',
            '/health': 'GET - Health check'
        },
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
    # CRITICAL: Remove ALL whitespace, newlines, quotes - keys must be single-line
    key = key.replace('\n', '').replace('\r', '').replace(' ', '')
    key = key.strip().strip('"').strip("'").strip()
    return key


@app.route('/api/kimi-test', methods=['GET'])
def kimi_test():
    api_key = _get_kimi_key()
    diagnostics = {
        'key_present': bool(api_key),
        'key_length': len(api_key),
        'key_prefix': api_key[:10] + '...' if len(api_key) > 10 else 'too_short',
        'key_format_ok': bool(api_key.startswith('sk-') and len(api_key) > 20),
    }
    if not api_key:
        diagnostics['status'] = 'no_key'
        diagnostics['message'] = 'KIMI_API_KEY nicht gesetzt!'
        return jsonify(diagnostics)
    try:
        import urllib.request
        req_data = json.dumps({
            "model": "kimi-k2-0711-preview",
            "messages": [{"role": "user", "content": "Say OK"}],
            "max_tokens": 10
        }).encode('utf-8')
        req = urllib.request.Request(
            "https://api.moonshot.cn/v1/chat/completions",
            data=req_data,
            headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {api_key}'},
            method='POST')
        resp = urllib.request.urlopen(req, timeout=15)
        result = json.loads(resp.read().decode('utf-8'))
        diagnostics['status'] = 'success'
        diagnostics['message'] = 'Kimi K2 funktioniert!'
        diagnostics['credits_used'] = True
    except urllib.error.HTTPError as e:
        err = e.read().decode('utf-8', errors='ignore')[:500] if hasattr(e, 'read') else ''
        diagnostics['status'] = f'http_error_{e.code}'
        diagnostics['error_details'] = err
        if e.code == 401:
            diagnostics['message'] = 'Key ungueltig (401)! Pruefe ob der Key aktiv ist auf platform.moonshot.cn'
        elif e.code == 429:
            diagnostics['message'] = 'Rate Limit (429)! Zu viele Anfragen.'
        elif e.code == 403:
            diagnostics['message'] = 'Kein Zugriff (403)! Konto hat moeglicherweise kein Guthaben.'
        else:
            diagnostics['message'] = f'Fehler {e.code}: {err}'
    except Exception as e:
        diagnostics['status'] = 'network_error'
        diagnostics['message'] = str(e)
    return jsonify(diagnostics)


@app.route('/api/kimi-debug', methods=['GET'])
def kimi_debug():
    """Advanced debug endpoint - tests multiple models and shows key info"""
    raw_key = os.environ.get('KIMI_API_KEY', '')
    clean_key = _get_kimi_key()
    
    # Key analysis
    key_chars = []
    for i, c in enumerate(raw_key[:30]):
        key_chars.append({'pos': i, 'char': c if c.isprintable() else f'\\x{ord(c):02x}', 'ascii': ord(c)})
    
    result = {
        'key_analysis': {
            'raw_length': len(raw_key),
            'clean_length': len(clean_key),
            'raw_prefix': raw_key[:15] if raw_key else 'EMPTY',
            'raw_suffix': raw_key[-10:] if len(raw_key) > 10 else 'N/A',
            'clean_prefix': clean_key[:15] if clean_key else 'EMPTY',
            'first_10_chars': key_chars,
            'starts_with_sk': clean_key.startswith('sk-'),
        },
        'model_tests': {}
    }
    
    if not clean_key:
        result['model_tests'] = {'error': 'No key found after cleaning'}
        return jsonify(result)
    
    # Test both models
    for model_name in ['kimi-k2-0711-preview', 'kimi-latest']:
        try:
            import urllib.request
            req_data = json.dumps({
                "model": model_name,
                "messages": [{"role": "user", "content": "Say OK"}],
                "max_tokens": 10
            }).encode('utf-8')
            req = urllib.request.Request(
                "https://api.moonshot.cn/v1/chat/completions",
                data=req_data,
                headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {clean_key}'},
                method='POST')
            resp = urllib.request.urlopen(req, timeout=15)
            resp_json = json.loads(resp.read().decode('utf-8'))
            result['model_tests'][model_name] = {
                'status': 'success',
                'response': resp_json['choices'][0]['message']['content'][:50] if resp_json.get('choices') else 'no content'
            }
        except urllib.error.HTTPError as e:
            err_body = e.read().decode('utf-8', errors='ignore')[:500] if hasattr(e, 'read') else ''
            result['model_tests'][model_name] = {
                'status': f'error_{e.code}',
                'error_body': err_body
            }
        except Exception as e:
            result['model_tests'][model_name] = {
                'status': 'exception',
                'error': str(e)
            }
    
    return jsonify(result)


@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()

    if not target:
        return jsonify({'error': 'Target is required', 'message': 'Provide {"target": "example.com"}'}), 400

    target = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]

    # Allow specific modules to be selected
    selected_modules = data.get('modules', [])
    if selected_modules:
        modules_to_run = [(name, mod, desc) for name, mod, desc in SCANNER_MODULES if name in selected_modules]
    else:
        modules_to_run = SCANNER_MODULES  # ALL modules run by default

    if not modules_to_run:
        return jsonify({'error': 'No modules available'}), 500

    print(f"\n{'='*60}")
    print(f"[SCAN START] Target: {target} | Modules: {len(modules_to_run)}")
    print(f"{'='*60}\n")

    start_time = time.time()
    all_results = {}
    all_findings = []
    phase_log = []

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

    elapsed = time.time() - start_time

    # Sort findings
    all_findings.sort(key=lambda f: severity_score(f.get('severity', 'info')), reverse=True)

    # Statistics
    severity_counts = {}
    for f in all_findings:
        sev = f.get('severity', 'info')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    risk_score = min(severity_counts.get('critical', 0) * 20 + severity_counts.get('high', 0) * 10 +
                     severity_counts.get('medium', 0) * 5 + severity_counts.get('low', 0) * 2, 100)

    risk_level = 'critical' if risk_score >= 70 else 'high' if risk_score >= 40 else 'medium' if risk_score >= 20 else 'low' if risk_score >= 5 else 'info'

    # Kimi K2 AI Analysis
    ai_findings = []
    ai_report = None
    ai_enabled = False
    if kimi_analyzer is not None:
        try:
            ai_enabled = kimi_analyzer.check_api_key()
        except:
            ai_enabled = False
        if ai_enabled and all_findings:
            print("[KIMI K2] Starting deep analysis...")
            try:
                ai_findings = kimi_analyzer.analyze_with_kimi(target, all_findings)
                ai_report = kimi_analyzer.generate_report(target, all_findings)
                all_findings.extend(ai_findings)
                print(f"[KIMI K2] Analysis complete: {len(ai_findings)} findings")
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
        'summary': {
            'total_findings': len(all_findings),
            'severity_breakdown': severity_counts,
        },
        'phases': phase_log,
        'ai_analysis': {
            'enabled': ai_enabled,
            'model': 'kimi-k2-0711-preview' if ai_enabled else None,
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
        return jsonify({'error': f'Unknown module: {module}', 'available': list(module_map.keys())}), 404

    mod, desc = module_map[module]
    result = run_scanner(module, mod, target)
    result['findings'].sort(key=lambda f: severity_score(f.get('severity', 'info')), reverse=True)

    return jsonify({
        'target': target, 'module': module, 'description': desc,
        'scan_time': datetime.utcnow().isoformat(),
        'status': result['status'], 'findings_count': len(result['findings']),
        'findings': result['findings']
    })


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found', 'available': ['/api/scan', '/api/modules', '/api/kimi-test', '/api/kimi-debug', '/health']}), 404


@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Internal error', 'message': str(error)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting Security Scanner Backend v3.3 on port {port}")
    print(f"Modules: {len(SCANNER_MODULES)}/{len(MODULE_DEFINITIONS)}")
    app.run(host='0.0.0.0', port=port)
