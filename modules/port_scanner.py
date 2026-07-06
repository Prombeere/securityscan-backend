"""
Port Scanner Module - Common web port check, service banner grabbing
"""
import socket
from urllib.parse import urlparse

def scan(target):
    findings = []
    scan_id = 0

    hostname = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]

    print(f"[PHASE 12] Port Scanner: Scanning {hostname}")

    # Common web ports to check
    ports = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        9200: 'Elasticsearch',
        27017: 'MongoDB',
    }

    open_ports = []

    for port, service in ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((hostname, port))
            sock.close()

            if result == 0:
                open_ports.append((port, service))

                # Banner grabbing
                banner = ''
                try:
                    grab_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    grab_sock.settimeout(5)
                    grab_sock.connect((hostname, port))
                    banner = grab_sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    grab_sock.close()
                except Exception:
                    pass

                evidence = f'Port {port}/{service} ist offen'
                if banner:
                    evidence += f' - Banner: {banner[:100]}'

                # Severity based on service
                severity = 'info'
                if service in ['Telnet', 'FTP']:
                    severity = 'high'
                elif service in ['SSH', 'RDP', 'VNC', 'SMB']:
                    severity = 'medium'
                elif service in ['MySQL', 'PostgreSQL', 'MSSQL', 'MongoDB', 'Redis', 'Elasticsearch']:
                    severity = 'high'
                elif port in [8080, 8443]:
                    severity = 'info'

                findings.append({
                    'id': f'port-{scan_id}',
                    'severity': severity,
                    'type': 'open_port',
                    'title': f'Offener Port: {port}/{service}',
                    'url': f'{hostname}:{port}',
                    'evidence': evidence,
                    'remediation': f'Port {port} ({service}) schließen falls nicht benötigt. Firewall-Regeln prüfen.'
                })
                scan_id += 1

                # Specific checks for risky services
                if service == 'Telnet':
                    findings.append({
                        'id': f'port-{scan_id}',
                        'severity': 'critical',
                        'type': 'telnet_exposed',
                        'title': 'Telnet-Dienst öffentlich erreichbar',
                        'url': f'{hostname}:{port}',
                        'evidence': f'Telnet (Port 23) ist offen',
                        'remediation': 'Telnet sofort deaktivieren! SSH als sichere Alternative verwenden.'
                    })
                    scan_id += 1

                if service == 'FTP' and port == 21:
                    findings.append({
                        'id': f'port-{scan_id}',
                        'severity': 'medium',
                        'type': 'ftp_exposed',
                        'title': 'FTP-Dienst öffentlich erreichbar',
                        'url': f'{hostname}:{port}',
                        'evidence': f'FTP (Port 21) ist offen',
                        'remediation': 'FTP durch SFTP (Port 22) ersetzen falls Dateiübertragung benötigt wird.'
                    })
                    scan_id += 1

        except socket.gaierror:
            findings.append({
                'id': f'port-{scan_id}',
                'severity': 'info',
                'type': 'port_dns_error',
                'title': 'DNS-Auflösung fehlgeschlagen',
                'url': hostname,
                'evidence': f'Hostname {hostname} konnte nicht aufgelöst werden',
                'remediation': 'Hostname und DNS-Konfiguration prüfen.'
            })
            scan_id += 1
            break
        except Exception:
            continue

    if open_ports:
        findings.append({
            'id': f'port-{scan_id}',
            'severity': 'info',
            'type': 'port_summary',
            'title': f'{len(open_ports)} offene Ports gefunden',
            'url': hostname,
            'evidence': f'Offene Ports: {", ".join([f"{p[0]}/{p[1]}" for p in open_ports])}',
            'remediation': 'Nur notwendige Ports öffnen. Firewall-Regeln regelmäßig überprüfen.'
        })
        scan_id += 1
    else:
        findings.append({
            'id': f'port-{scan_id}',
            'severity': 'info',
            'type': 'port_none_open',
            'title': 'Keine offenen Ports aus der Standardliste gefunden',
            'url': hostname,
            'evidence': 'Alle getesteten Ports sind geschlossen oder gefiltert',
            'remediation': 'Port-Sicherheit ist gut. Weiterhin Firewall-Regeln überwachen.'
        })
        scan_id += 1

    return findings
