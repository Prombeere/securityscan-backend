"""
SSL/TLS Scanner Module - Certificate and TLS analysis
"""
import ssl
import socket
import datetime

def scan(target):
    findings = []
    scan_id = 0

    hostname = target.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]

    print(f"[PHASE 2] SSL Scanner: Scanning {hostname}")

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(10)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            version = s.version()
            cipher = s.cipher()

        # TLS Version
        if version in ('TLSv1', 'TLSv1.1'):
            findings.append({
                'id': f'ssl-{scan_id}',
                'severity': 'high',
                'type': 'ssl_old_version',
                'title': f'Veraltete TLS-Version: {version}',
                'url': f'https://{hostname}',
                'evidence': f'Verbindung nutzt {version}',
                'remediation': 'TLS 1.2 oder höher erzwingen'
            })
            scan_id += 1
        elif version == 'TLSv1.2':
            findings.append({
                'id': f'ssl-{scan_id}',
                'severity': 'low',
                'type': 'ssl_tls12',
                'title': 'TLS 1.2 wird verwendet',
                'url': f'https://{hostname}',
                'evidence': 'TLSv1.2',
                'remediation': 'TLS 1.3 bevorzugen'
            })
            scan_id += 1
        elif version == 'TLSv1.3':
            findings.append({
                'id': f'ssl-{scan_id}',
                'severity': 'info',
                'type': 'ssl_tls13',
                'title': 'TLS 1.3 wird verwendet',
                'url': f'https://{hostname}',
                'evidence': 'TLSv1.3',
                'remediation': 'Keine Aktion'
            })
            scan_id += 1

        # Certificate Expiry
        if cert and 'notAfter' in cert:
            expiry = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (expiry - datetime.datetime.utcnow()).days
            if days_left < 30:
                findings.append({
                    'id': f'ssl-{scan_id}',
                    'severity': 'high',
                    'type': 'ssl_cert_expiry',
                    'title': f'Zertifikat läuft in {days_left} Tagen ab',
                    'url': f'https://{hostname}',
                    'evidence': f'notAfter: {cert["notAfter"]}',
                    'remediation': 'Zertifikat erneuern'
                })
                scan_id += 1
            elif days_left < 90:
                findings.append({
                    'id': f'ssl-{scan_id}',
                    'severity': 'medium',
                    'type': 'ssl_cert_expiry_soon',
                    'title': f'Zertifikat läuft in {days_left} Tagen ab',
                    'url': f'https://{hostname}',
                    'evidence': f'notAfter: {cert["notAfter"]}',
                    'remediation': 'Zertifikat bald erneuern'
                })
                scan_id += 1

        # Cipher Suite
        if cipher:
            cipher_name = cipher[0]
            weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']
            if any(w in cipher_name for w in weak_ciphers):
                findings.append({
                    'id': f'ssl-{scan_id}',
                    'severity': 'high',
                    'type': 'ssl_weak_cipher',
                    'title': f'Schwache Cipher-Suite: {cipher_name}',
                    'url': f'https://{hostname}',
                    'evidence': f'Cipher: {cipher_name}',
                    'remediation': 'Starke Cipher-Suites konfigurieren'
                })
                scan_id += 1

    except Exception as e:
        findings.append({
            'id': f'ssl-{scan_id}',
            'severity': 'info',
            'type': 'ssl_error',
            'title': 'SSL/TLS Scan fehlgeschlagen',
            'url': f'https://{hostname}',
            'evidence': str(e),
            'remediation': 'SSL-Konfiguration prüfen'
        })

    return findings
