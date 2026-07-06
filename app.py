"""
Security Scanner Backend v3.3.2 - Clean rebuild
24 modules, Kimi API, robust error handling
"""
import os
import sys
import time
import json
import traceback
import importlib
from datetime import datetime

from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

# ============== CORS ==============
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    return response

@app.route('/', methods=['OPTIONS'])
@app.route('/health', methods=['OPTIONS'])
@app.route('/api/scan', methods=['OPTIONS'])
@app.route('/api/kimi-test', methods=['OPTIONS'])
def handle_options():
    return make_response(), 204

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

# ============== 24 MODULES ==============
MODULE_DEFINITIONS = [
    ('dns', 'dns_scanner', 'DNS-Analyse'),
    ('ssl', 'ssl_scanner', 'SSL/TLS-Analyse'),
    ('headers', 'header_scanner', 'Security-Header'),
    ('xss', 'xss_scanner', 'XSS-Scan'),
    ('redirect', 'redirect_scanner', 'Open-Redirect'),
    ('methods', 'method_scanner', 'HTTP-Methoden'),
    ('directory', 'dir_scanner', 'Verzeichnis-Scan'),
    ('tech', 'tech_scanner', 'Technologie-Erkennung'),
    ('cookies', 'cookie_scanner', 'Cookie-Analyse'),
    ('cors', 'cors_scanner', 'CORS-Scan'),
    ('subdomain', 'subdomain_scanner', 'Subdomain-Enumeration'),
    ('ports', 'port_scanner', 'Port-Scan'),
    ('whois', 'whois_scanner', 'WHOIS-Abfrage'),
    ('content', 'content_scanner', 'Content-Scan'),
    ('injection', 'injection_scanner', 'Injection-Tests'),
    ('sqli_poc', 'blind_sqli_detector', 'SQLi PoC'),
    ('wpscan', 'wpscan_scanner', 'WPScan'),
    ('nuclei', 'nuclei_scanner', 'Nuclei'),
    ('nikto', 'nikto_scanner', 'Nikto'),
    ('sqlmap', 'sqlmap_scanner', 'SQLMap'),
    ('gobuster', 'gobuster_scanner', 'Gobuster'),
    ('ffuf', 'ffuf_scanner', 'FFUF'),
    ('httpx', 'httpx_scanner', 'HTTPX'),
    ('cve', 'cve_scanner', 'CVE-Scanner'),
]

SCANNER_MODULES = []
MODULE_LOAD_ERRORS = {}

for mod_name, mod_file, mod_desc in MODULE_DEFINITIONS:
    try:
        mod = importlib.import_module(f'modules.{mod_file}')
        SCANNER_MODULES.append((mod_name, mod, mod_desc))
        print(f"[OK] {mod_name}")
    except Exception as e:
        MODULE_LOAD_ERRORS[mod_name] = str(e)
        print(f"[WARN] {mod_name}: {e}")

# Kimi
kimi_analyzer = None
try:
    kimi_analyzer = importlib.import_module('modules.kimi_analyzer')
    print("[OK] kimi_analyzer")
except Exception as e:
    MODULE_LOAD_ERRORS['kimi'] = str(e)
    print(f"[WARN] kimi_analyzer: {e}")

print(f"[INFO] {len(SCANNER_MODULES)}/{len(MODULE_DEFINITIONS)} modules loaded")


def run_scanner(module_name, module, target):
    try:
        findings = module.scan(target)
        return {'module': module_name, 'status': 'completed', 'findings': findings or []}
    except Exception as e:
        print(f"[ERROR] {module_name}: {e}")
        return {'module': module_name, 'status': 'error', 'findings': [{
            'id': f'{module_name}-error', 'severity': 'info', 'type': 'scan_error',
            'title': f'{module_name} fehlgeschlagen', 'url': target,
            'evidence': str(e), 'remediation': None
        }]}

def severity_score(s):
    return {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}.get(s.lower(), 0)


# ============== ROUTES ==============
@app.route('/')
def index():
    return jsonify({'name': 'Security Scanner', 'version': '3.3.2',
                    'modules_loaded': len(SCANNER_MODULES), 'modules_total': 24})

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'modules_loaded': len(SCANNER_MODULES), 'modules_total': 24})


@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'Target required'}), 400

    target = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
    modules_to_run = SCANNER_MODULES

    print(f"\n[SCAN] {target} | {len(modules_to_run)} modules")
    start = time.time()
    all_findings = []
    phase_log = []

    # Sequential execution - more stable than ThreadPool
    for i, (name, mod, desc) in enumerate(modules_to_run, 1):
        print(f"[{i}/{len(modules_to_run)}] {name}...")
        result = run_scanner(name, mod, target)
        if result['findings']:
            all_findings.extend(result['findings'])
        phase_log.append({'phase': i, 'module': name, 'status': result['status'],
                          'findings_count': len(result['findings'])})

    elapsed = time.time() - start
    all_findings.sort(key=lambda f: severity_score(f.get('severity', 'info')), reverse=True)

    sev_count = {}
    for f in all_findings:
        s = f.get('severity', 'info')
        sev_count[s] = sev_count.get(s, 0) + 1

    risk = min(sev_count.get('critical', 0) * 20 + sev_count.get('high', 0) * 10 +
               sev_count.get('medium', 0) * 5 + sev_count.get('low', 0) * 2, 100)

    # Kimi analysis (optional)
    ai_findings = []
    ai_report = None
    if kimi_analyzer:
        try:
            if hasattr(kimi_analyzer, 'check_api_key') and kimi_analyzer.check_api_key():
                ai_findings = kimi_analyzer.analyze_with_kimi(target, all_findings)
                ai_report = kimi_analyzer.generate_report(target, all_findings)
                all_findings.extend(ai_findings)
        except Exception as e:
            print(f"[KIMI] Error: {e}")

    print(f"[DONE] {target} | {elapsed:.1f}s | {len(all_findings)} findings\n")

    return jsonify({
        'target': target,
        'duration_seconds': round(elapsed, 2),
        'risk_score': risk,
        'summary': {'total_findings': len(all_findings), 'severity_breakdown': sev_count},
        'phases': phase_log,
        'ai_analysis': {'enabled': bool(ai_findings), 'findings_count': len(ai_findings),
                        'executive_summary': ai_report},
        'findings': all_findings,
    })


@app.route('/api/kimi-test', methods=['GET'])
def kimi_test():
    if not kimi_analyzer:
        return jsonify({'status': 'no_module', 'message': 'kimi_analyzer not loaded'})
    try:
        key = os.environ.get('KIMI_API_KEY', '').strip().strip('"').strip("'")
        if not key:
            return jsonify({'status': 'no_key'})

        import urllib.request
        url = 'https://api.kimi.com/coding/v1/chat/completions' if key.startswith('sk-kimi-') else \
              os.environ.get('KIMI_API_URL', 'https://api.moonshot.cn/v1/chat/completions')
        model = 'kimi-for-coding' if key.startswith('sk-kimi-') else 'kimi-k2-0711-preview'

        req_data = json.dumps({"model": model, "messages": [{"role": "user", "content": "OK"}],
                               "max_tokens": 5}).encode('utf-8')
        req = urllib.request.Request(url, data=req_data,
                                     headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {key}'},
                                     method='POST')
        urllib.request.urlopen(req, timeout=15)
        return jsonify({'status': 'success', 'api_url': url, 'model': model})
    except urllib.error.HTTPError as e:
        return jsonify({'status': f'error_{e.code}', 'message': e.read().decode()[:200]})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting v3.3.2 on port {port}")
    app.run(host='0.0.0.0', port=port)
