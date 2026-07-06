"""
Security Scanner Backend v3.0 - Main Flask Application
Orchestrates 19 security scanning modules with real HTTP requests
+ Kimi K2-0711-preview AI analysis
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
    """Add CORS headers to every single response"""
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
@app.route('/api/scan/<path:path>', methods=['OPTIONS'])
def handle_options(path=None):
    """Handle all OPTIONS preflight requests"""
    response = make_response()
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Max-Age', '86400')
    return response, 204

# Add modules directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

# Module import definitions: (name, module_name, description)
MODULE_DEFINITIONS = [
    ('dns', 'dns_scanner', 'DNS-Analyse: Records, SPF, DMARC, DNSSEC'),
    ('ssl', 'ssl_scanner', 'SSL/TLS-Analyse: Zertifikat, Cipher-Suites, HSTS'),
    ('headers', 'header_scanner', 'Security-Header: 20+ Header-Pruefungen'),
    ('xss', 'xss_scanner', 'XSS-Scan: Reflektierte Payloads, DOM-Sinks'),
    ('redirect', 'redirect_scanner', 'Open-Redirect: Parameter-Tests, JS-Redirects'),
    ('methods', 'method_scanner', 'HTTP-Methoden: OPTIONS, PUT, DELETE, TRACE'),
    ('directory', 'dir_scanner', 'Verzeichnis-Scan: 200+ Pfade, Backups, Configs'),
    ('tech', 'tech_scanner', 'Technologie-Erkennung: Frameworks, Bibliotheken'),
    ('cookies', 'cookie_scanner', 'Cookie-Analyse: Secure, HttpOnly, SameSite'),
    ('cors', 'cors_scanner', 'CORS-Scan: Origin-Reflection, Wildcards'),
    ('subdomain', 'subdomain_scanner', 'Subdomain-Enumeration: 100 Subdomains'),
    ('ports', 'port_scanner', 'Port-Scan: 22 Ports + Banner-Grabbing'),
    ('whois', 'whois_scanner', 'WHOIS-Abfrage: Registrar, Ablaufdatum'),
    ('content', 'content_scanner', 'Content-Scan: robots.txt, sitemap, 404'),
    ('injection', 'injection_scanner', 'Injection-Tests: SQLi, CMDi, NoSQLi, SSTI'),
    # Go tools (with Python fallbacks)
    ('gobuster', 'gobuster_scanner', 'Gobuster: Verzeichnis-Brute-Force (500+ Pfade)'),
    ('ffuf', 'ffuf_scanner', 'FFUF: Parameter-Fuzzing + Virtual-Host-Discovery'),
    ('httpx', 'httpx_scanner', 'HTTPX: HTTP-Fingerprinting + WAF/CDN-Erkennung'),
    ('cve', 'cve_scanner', 'CVE-Scanner: Bekannte Schwachstellen pro Technologie'),
]

# Robust module loading - each module gets its own try/except
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

# Load kimi analyzer separately (optional - no API key needed for basic function)
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
    """Run a single scanner module with error handling"""
    try:
        findings = module.scan(target)
        return {
            'module': module_name,
            'status': 'completed',
            'findings': findings if findings else []
        }
    except Exception as e:
        traceback_str = traceback.format_exc()
        print(f"[ERROR] Module {module_name} failed: {str(e)}")
        return {
            'module': module_name,
            'status': 'error',
            'findings': [{
                'id': f'{module_name}-error',
                'severity': 'info',
                'type': 'scan_error',
                'title': f'Scanner-Modul {module_name} fehlgeschlagen',
                'url': target,
                'evidence': f'Fehler: {str(e)}',
                'remediation': 'Scan-Ergebnis manuell pruefen.'
            }]
        }


def severity_score(severity):
    """Convert severity to numeric score for sorting"""
    scores = {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'info': 1,
    }
    return scores.get(severity.lower(), 0)


@app.route('/')
def index():
    """Root endpoint with API info"""
    return jsonify({
        'name': 'Security Scanner Backend',
        'version': '3.0.0',
        'description': 'Comprehensive security scanning with 19 modules + Kimi K2 AI',
        'endpoints': {
            '/api/scan': 'POST - Start a security scan (JSON body: {"target": "example.com"})',
            '/api/modules': 'GET - List all available scanner modules',
            '/health': 'GET - Health check'
        },
        'modules_loaded': len(SCANNER_MODULES),
        'modules_total': len(MODULE_DEFINITIONS),
        'modules': [name for name, _, _ in SCANNER_MODULES],
        'module_errors': MODULE_LOAD_ERRORS
    })


@app.route('/health')
def health():
    """Health check endpoint - ALWAYS returns 200"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'modules_loaded': len(SCANNER_MODULES),
        'modules_total': len(MODULE_DEFINITIONS)
    })


@app.route('/api/modules', methods=['GET'])
def list_modules():
    """List all available scanner modules"""
    return jsonify({
        'modules': [
            {
                'name': name,
                'description': desc,
            }
            for name, _, desc in SCANNER_MODULES
        ],
        'errors': MODULE_LOAD_ERRORS
    })


@app.route('/api/scan', methods=['POST'])
def scan():
    """Main scan endpoint - runs all scanner modules"""
    data = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()

    if not target:
        return jsonify({
            'error': 'Target is required',
            'message': 'Please provide a target URL or hostname in the JSON body: {"target": "example.com"}'
        }), 400

    # Clean target
    target = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]

    # Allow specific modules to be selected
    selected_modules = data.get('modules', [])
    if selected_modules:
        modules_to_run = [
            (name, mod, desc)
            for name, mod, desc in SCANNER_MODULES
            if name in selected_modules
        ]
    else:
        modules_to_run = SCANNER_MODULES

    if not modules_to_run:
        return jsonify({
            'error': 'No modules available',
            'message': 'No scanner modules could be loaded. Check server logs.',
            'module_errors': MODULE_LOAD_ERRORS
        }), 500

    print(f"\n{'='*60}")
    print(f"[SCAN START] Target: {target}")
    print(f"[SCAN START] Modules: {len(modules_to_run)}")
    print(f"{'='*60}\n")

    start_time = time.time()
    all_results = {}
    all_findings = []
    phase_log = []

    # Run scanners in parallel with thread pool
    with ThreadPoolExecutor(max_workers=min(len(modules_to_run), 10)) as executor:
        future_to_module = {
            executor.submit(run_scanner, name, mod, target): (name, desc)
            for name, mod, desc in modules_to_run
        }

        for i, future in enumerate(as_completed(future_to_module), 1):
            name, desc = future_to_module[future]
            try:
                result = future.result(timeout=90)
                all_results[name] = result
                if result['findings']:
                    all_findings.extend(result['findings'])

                phase_entry = {
                    'phase': i,
                    'module': name,
                    'description': desc,
                    'status': result['status'],
                    'findings_count': len(result['findings'])
                }
                phase_log.append(phase_entry)
                print(f"[PHASE {i}] {name}: {desc} - {result['status']} ({len(result['findings'])} findings)")

            except Exception as e:
                phase_entry = {
                    'phase': i,
                    'module': name,
                    'description': desc,
                    'status': 'timeout',
                    'findings_count': 0,
                    'error': str(e)
                }
                phase_log.append(phase_entry)
                print(f"[PHASE {i}] {name}: TIMEOUT - {str(e)}")

    elapsed = time.time() - start_time

    # Sort findings by severity
    all_findings.sort(key=lambda f: severity_score(f.get('severity', 'info')), reverse=True)

    # Calculate statistics
    severity_counts = {}
    type_counts = {}
    for f in all_findings:
        sev = f.get('severity', 'info')
        typ = f.get('type', 'unknown')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        type_counts[typ] = type_counts.get(typ, 0) + 1

    # Risk score calculation
    risk_score = (
        severity_counts.get('critical', 0) * 20 +
        severity_counts.get('high', 0) * 10 +
        severity_counts.get('medium', 0) * 5 +
        severity_counts.get('low', 0) * 2
    )
    risk_score = min(risk_score, 100)

    # Risk level
    if risk_score >= 70:
        risk_level = 'critical'
    elif risk_score >= 40:
        risk_level = 'high'
    elif risk_score >= 20:
        risk_level = 'medium'
    elif risk_score >= 5:
        risk_level = 'low'
    else:
        risk_level = 'info'

    # Kimi K2 AI Analysis (if available and API key is configured)
    ai_findings = []
    ai_report = None
    ai_enabled = False
    if kimi_analyzer is not None:
        try:
            ai_enabled = kimi_analyzer.check_api_key()
        except:
            ai_enabled = False
        if ai_enabled and all_findings:
            print("[KIMI K2] Starting deep security analysis...")
            try:
                ai_findings = kimi_analyzer.analyze_with_kimi(target, all_findings)
                ai_report = kimi_analyzer.generate_report(target, all_findings)
                all_findings.extend(ai_findings)
                print(f"[KIMI K2] Analysis complete: {len(ai_findings)} AI findings")
            except Exception as e:
                print(f"[KIMI K2] Error: {e}")

    print(f"\n{'='*60}")
    print(f"[SCAN COMPLETE] Target: {target}")
    print(f"[SCAN COMPLETE] Duration: {elapsed:.1f}s")
    print(f"[SCAN COMPLETE] Total findings: {len(all_findings)}")
    print(f"[SCAN COMPLETE] Risk score: {risk_score}/100 ({risk_level})")
    if ai_report:
        print(f"[SCAN COMPLETE] Kimi K2 Analysis: YES")
    print(f"{'='*60}\n")

    response = {
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
            'top_findings_types': dict(sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10])
        },
        'phases': phase_log,
        'ai_analysis': {
            'enabled': ai_enabled,
            'model': 'kimi-k2-0711-preview' if ai_enabled else None,
            'findings_count': len(ai_findings),
            'executive_summary': ai_report
        },
        'findings': all_findings,
        'modules': {name: {
            'status': res['status'],
            'findings_count': len(res['findings'])
        } for name, res in all_results.items()}
    }

    return jsonify(response)


@app.route('/api/scan/<module>', methods=['POST'])
def scan_single(module):
    """Run a single scanner module"""
    data = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    target = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]

    # Find module
    module_map = {name: (mod, desc) for name, mod, desc in SCANNER_MODULES}
    if module not in module_map:
        return jsonify({
            'error': f'Unknown module: {module}',
            'available_modules': list(module_map.keys())
        }), 404

    mod, desc = module_map[module]
    print(f"[SINGLE SCAN] {module}: {desc} - Target: {target}")

    start_time = time.time()
    result = run_scanner(module, mod, target)
    elapsed = time.time() - start_time

    # Sort findings
    result['findings'].sort(
        key=lambda f: severity_score(f.get('severity', 'info')),
        reverse=True
    )

    return jsonify({
        'target': target,
        'module': module,
        'description': desc,
        'scan_time': datetime.utcnow().isoformat(),
        'duration_seconds': round(elapsed, 2),
        'status': result['status'],
        'findings_count': len(result['findings']),
        'findings': result['findings']
    })


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found', 'available': ['/api/scan', '/api/modules', '/health']}), 404


@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Internal server error', 'message': str(error)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    print(f"Starting Security Scanner Backend v3.0 on port {port}")
    print(f"Modules loaded: {len(SCANNER_MODULES)}")
    app.run(host='0.0.0.0', port=port, debug=debug)
