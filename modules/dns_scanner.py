"""
DNS Scanner Module - DNS enumeration and analysis
"""
import socket
import dns.resolver

def scan(target):
    findings = []
    scan_id = 0

    # Clean target
    hostname = target.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]

    print(f"[PHASE 1] DNS Scanner: Scanning {hostname}")

    # A Record
    try:
        ip = socket.gethostbyname(hostname)
        findings.append({
            'id': f'dns-{scan_id}',
            'severity': 'info',
            'type': 'dns_a_record',
            'title': f'DNS A-Record: {ip}',
            'url': hostname,
            'evidence': f'{hostname} -> {ip}',
            'remediation': 'Keine Aktion'
        })
        scan_id += 1
    except Exception as e:
        findings.append({
            'id': f'dns-{scan_id}',
            'severity': 'info',
            'type': 'dns_error',
            'title': 'DNS A-Record Lookup fehlgeschlagen',
            'url': hostname,
            'evidence': str(e),
            'remediation': 'DNS-Konfiguration prüfen'
        })
        scan_id += 1
        return findings

    # MX Records
    try:
        answers = dns.resolver.resolve(hostname, 'MX')
        mx_records = [str(rdata.exchange) for rdata in answers]
        findings.append({
            'id': f'dns-{scan_id}',
            'severity': 'info',
            'type': 'dns_mx_record',
            'title': f'MX-Records: {len(mx_records)} gefunden',
            'url': hostname,
            'evidence': ', '.join(mx_records[:5]),
            'remediation': 'Keine Aktion'
        })
        scan_id += 1
    except:
        pass

    # TXT/SPF Records
    try:
        answers = dns.resolver.resolve(hostname, 'TXT')
        txt_records = [str(rdata) for rdata in answers]
        spf_found = any('v=spf1' in txt for txt in txt_records)
        dmarc_found = False
        try:
            dmarc_answers = dns.resolver.resolve(f'_dmarc.{hostname}', 'TXT')
            dmarc_found = any('v=DMARC1' in str(rdata) for rdata in dmarc_answers)
        except:
            pass

        if not spf_found:
            findings.append({
                'id': f'dns-{scan_id}',
                'severity': 'medium',
                'type': 'dns_spf_missing',
                'title': 'SPF Record fehlt',
                'url': hostname,
                'evidence': 'Kein v=spf1 TXT Record gefunden',
                'remediation': 'SPF Record hinzufügen: v=spf1 include:_spf.google.com ~all'
            })
            scan_id += 1

        if not dmarc_found:
            findings.append({
                'id': f'dns-{scan_id}',
                'severity': 'medium',
                'type': 'dns_dmarc_missing',
                'title': 'DMARC Record fehlt',
                'url': hostname,
                'evidence': 'Kein _dmarc TXT Record gefunden',
                'remediation': 'DMARC Record hinzufügen: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com'
            })
            scan_id += 1
    except:
        pass

    # NS Records
    try:
        answers = dns.resolver.resolve(hostname, 'NS')
        ns_records = [str(rdata) for rdata in answers]
        findings.append({
            'id': f'dns-{scan_id}',
            'severity': 'info',
            'type': 'dns_ns_record',
            'title': f'NS-Records: {len(ns_records)}',
            'url': hostname,
            'evidence': ', '.join(ns_records),
            'remediation': 'Keine Aktion'
        })
    except:
        pass

    return findings
