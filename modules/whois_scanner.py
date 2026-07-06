"""
WHOIS Scanner Module - WHOIS lookup, registrar info, creation/expiration dates, name server info
"""
import socket
import whois
from datetime import datetime
from urllib.parse import urlparse

def scan(target):
    findings = []
    scan_id = 0

    hostname = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]

    # Remove www. prefix
    if hostname.startswith('www.'):
        domain = hostname[4:]
    else:
        domain = hostname

    print(f"[PHASE 13] WHOIS Scanner: Scanning {domain}")

    try:
        w = whois.whois(domain)
    except Exception as e:
        findings.append({
            'id': f'whois-{scan_id}',
            'severity': 'info',
            'type': 'whois_error',
            'title': 'WHOIS-Abfrage fehlgeschlagen',
            'url': domain,
            'evidence': f'Fehler: {str(e)}',
            'remediation': 'Domain-Name prüfen und Netzwerkverbindung sicherstellen.'
        })
        scan_id += 1
        # Try alternative socket-based WHOIS
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect(("whois.iana.org", 43))
            s.send(f"{domain}\r\n".encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()
            raw_whois = response.decode('utf-8', errors='ignore')
            if raw_whois and 'domain' not in raw_whois.lower() and 'not found' not in raw_whois.lower():
                findings.append({
                    'id': f'whois-{scan_id}',
                    'severity': 'info',
                    'type': 'whois_raw',
                    'title': 'RAW WHOIS-Daten',
                    'url': domain,
                    'evidence': raw_whois[:500],
                    'remediation': 'WHOIS-Daten auf Korrektheit prüfen.'
                })
                scan_id += 1
        except Exception:
            pass
        return findings

    # Registrar info
    registrar = w.registrar
    if registrar:
        findings.append({
            'id': f'whois-{scan_id}',
            'severity': 'info',
            'type': 'whois_registrar',
            'title': f'Registrar: {registrar}',
            'url': domain,
            'evidence': f'Registrar: {registrar}',
            'remediation': 'Registrardaten aktuell halten.'
        })
        scan_id += 1

    # Creation date
    creation_date = w.creation_date
    if creation_date:
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, datetime):
            age_days = (datetime.now() - creation_date).days
            findings.append({
                'id': f'whois-{scan_id}',
                'severity': 'info',
                'type': 'whois_creation',
                'title': f'Domain registriert am: {creation_date.strftime("%Y-%m-%d")}',
                'url': domain,
                'evidence': f'Domain-Alter: {age_days} Tage',
                'remediation': 'Domain-Registrierung aktuell halten.'
            })
            scan_id += 1

    # Expiration date
    expiration_date = w.expiration_date
    if expiration_date:
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if isinstance(expiration_date, datetime):
            days_until_expiry = (expiration_date - datetime.now()).days
            if days_until_expiry < 0:
                findings.append({
                    'id': f'whois-{scan_id}',
                    'severity': 'critical',
                    'type': 'whois_expired',
                    'title': 'Domain ist abgelaufen!',
                    'url': domain,
                    'evidence': f'Ablaufdatum: {expiration_date.strftime("%Y-%m-%d")}',
                    'remediation': 'Domain sofort erneuern um Domain-Hijacking zu verhindern!'
                })
                scan_id += 1
            elif days_until_expiry < 30:
                findings.append({
                    'id': f'whois-{scan_id}',
                    'severity': 'high',
                    'type': 'whois_expiring',
                    'title': f'Domain läuft bald ab ({days_until_expiry} Tage)',
                    'url': domain,
                    'evidence': f'Ablaufdatum: {expiration_date.strftime("%Y-%m-%d")}',
                    'remediation': 'Domain rechtzeitig erneuern.'
                })
                scan_id += 1
            else:
                findings.append({
                    'id': f'whois-{scan_id}',
                    'severity': 'info',
                    'type': 'whois_valid',
                    'title': f'Domain gültig bis: {expiration_date.strftime("%Y-%m-%d")}',
                    'url': domain,
                    'evidence': f'Noch {days_until_expiry} Tage gültig',
                    'remediation': 'Domain-Renewal im Blick behalten.'
                })
                scan_id += 1

    # Name servers
    name_servers = w.name_servers or w.name_server
    if name_servers:
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        ns_list = []
        for ns in name_servers:
            if ns:
                ns_list.append(str(ns))
        if ns_list:
            findings.append({
                'id': f'whois-{scan_id}',
                'severity': 'info',
                'type': 'whois_nameservers',
                'title': f'Name-Server: {", ".join(ns_list[:4])}',
                'url': domain,
                'evidence': f'Name-Server: {", ".join(ns_list)}',
                'remediation': 'Name-Server auf redundante Verteilung prüfen.'
            })
            scan_id += 1

    # Status codes
    status = w.status
    if status:
        if isinstance(status, str):
            status = [status]
        status_strs = [str(s) for s in status if s]
        if status_strs:
            findings.append({
                'id': f'whois-{scan_id}',
                'severity': 'info',
                'type': 'whois_status',
                'title': f'Domain-Status: {", ".join(status_strs[:3])}',
                'url': domain,
                'evidence': f'Status-Codes: {", ".join(status_strs)}',
                'remediation': 'Domain-Status-Codes auf Schutzmechanismen prüfen (clientTransferProhibited etc.).'
            })
            scan_id += 1

    # DNSSEC in WHOIS
    dnssec = w.dnssec
    if dnssec:
        findings.append({
            'id': f'whois-{scan_id}',
            'severity': 'info',
            'type': 'whois_dnssec',
            'title': f'WHOIS DNSSEC: {dnssec}',
            'url': domain,
            'evidence': f'DNSSEC laut WHOIS: {dnssec}',
            'remediation': 'DNSSEC aktivieren falls nicht vorhanden.'
        })
        scan_id += 1

    # WHOIS privacy check
    if w.emails:
        emails = w.emails if isinstance(w.emails, list) else [w.emails]
        public_emails = [e for e in emails if e and not any(x in str(e).lower() for x in ['privacy', 'proxy', 'whoisguard', 'cloudflare'])]
        if public_emails:
            findings.append({
                'id': f'whois-{scan_id}',
                'severity': 'low',
                'type': 'whois_public_contact',
                'title': 'Öffentliche Kontaktdaten in WHOIS',
                'url': domain,
                'evidence': f'Öffentliche E-Mail: {public_emails[0]}',
                'remediation': 'WHOIS-Privacy-Schutz aktivieren um E-Mail-Harvesting zu verhindern.'
            })
            scan_id += 1

    if scan_id == 0:
        findings.append({
            'id': f'whois-{scan_id}',
            'severity': 'info',
            'type': 'whois_minimal',
            'title': 'WHOIS-Daten begrenzt verfügbar',
            'url': domain,
            'evidence': 'WHOIS-Abfrage lieferte begrenzte Daten (möglicherweise Privacy-Schutz)',
            'remediation': 'Domain-Registrierung und Privacy-Einstellungen prüfen.'
        })

    return findings
