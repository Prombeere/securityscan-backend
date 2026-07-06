"""
Subdomain Scanner Module - Wordlist-based enumeration, wildcard detection, CNAME analysis
"""
import dns.resolver
import socket
import os

def scan(target):
    findings = []
    scan_id = 0

    # Extract domain
    hostname = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]

    # Remove www. prefix to get base domain
    if hostname.startswith('www.'):
        domain = hostname[4:]
    else:
        domain = hostname

    print(f"[PHASE 11] Subdomain Scanner: Scanning {domain}")

    # Load subdomain wordlist
    wordlist_path = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'subdomains.txt')
    subdomains = []
    try:
        with open(wordlist_path, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'admin', 'test', 'dev', 'staging',
            'api', 'blog', 'shop', 'forum', 'news', 'support', 'help', 'cpanel',
            'webmail', 'ns1', 'ns2', 'vpn', 'dns', 'mx', 'server', 'host',
            'portal', 'cloud', 'cdn', 'media', 'static', 'assets', 'app',
            'mobile', 'beta', 'demo', 'preview', 'stage', 'prod', 'secure',
            'auth', 'login', 'account', 'user', 'member', 'panel', 'dashboard',
            'manage', 'console', 'remote', 'git', 'gitlab', 'github', 'ci',
            'jenkins', 'jira', 'confluence', 'wiki', 'docs', 'kb',
            'monitor', 'grafana', 'prometheus', 'nagios', 'zabbix',
            'db', 'mysql', 'postgres', 'mongo', 'redis', 'elasticsearch',
            'kibana', 'log', 'logs', 'splunk', 'graylog',
            'backup', 'storage', 's3', 'nfs', 'share',
            'private', 'internal', 'intranet', 'extranet',
            'old', 'legacy', 'archive', 'v1', 'v2', 'v3',
            'sandbox', 'lab', 'testbed', 'experimental',
            'corp', 'business', 'enterprise', 'partner',
            'api-v1', 'api-v2', 'rest', 'graphql', 'gateway',
            'ws', 'websocket', 'socket', 'io', 'rtmp',
            'sip', 'voip', 'pbx', 'meet', 'video',
            'chat', 'bot', 'hooks', 'callback', 'webhook',
        ]

    # Limit to 100 subdomains for performance
    subdomains = subdomains[:100]

    found_subdomains = []
    wildcard_detected = False

    # Wildcard detection first
    try:
        random_sub = f'wildcardsdajdslkjdlsfjlksdjf.{domain}'
        answers = dns.resolver.resolve(random_sub, 'A', lifetime=5)
        wildcard_ips = [rdata.address for rdata in answers]
        if wildcard_ips:
            wildcard_detected = True
            findings.append({
                'id': f'sub-{scan_id}',
                'severity': 'info',
                'type': 'subdomain_wildcard',
                'title': 'Wildcard-DNS-Eintrag erkannt',
                'url': domain,
                'evidence': f'Zufällige Subdomain resolved zu: {", ".join(wildcard_ips)}',
                'remediation': 'Wildcard-Einträge können Subdomain-Enumeration erschweren.'
            })
            scan_id += 1
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.Timeout):
        pass
    except Exception:
        pass

    # Enumerate subdomains
    for sub in subdomains:
        subdomain = f'{sub}.{domain}'
        try:
            answers = dns.resolver.resolve(subdomain, 'A', lifetime=3)
            for rdata in answers:
                ip = rdata.address
                found_subdomains.append((subdomain, ip))

                # CNAME check
                try:
                    cname_answers = dns.resolver.resolve(subdomain, 'CNAME', lifetime=3)
                    for cdata in cname_answers:
                        findings.append({
                            'id': f'sub-{scan_id}',
                            'severity': 'info',
                            'type': 'subdomain_cname',
                            'title': f'Subdomain CNAME: {subdomain}',
                            'url': subdomain,
                            'evidence': f'{subdomain} CNAME -> {cdata.target} (A: {ip})',
                            'remediation': 'CNAME-Einträge auf unbeabsichtigte Delegation prüfen.'
                        })
                        scan_id += 1
                except Exception:
                    findings.append({
                        'id': f'sub-{scan_id}',
                        'severity': 'info',
                        'type': 'subdomain_found',
                        'title': f'Subdomain gefunden: {subdomain}',
                        'url': subdomain,
                        'evidence': f'{subdomain} -> {ip}',
                        'remediation': 'Subdomains auf Sicherheitskonfiguration und unnötige Exposition prüfen.'
                    })
                    scan_id += 1

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.Timeout):
            continue
        except Exception:
            continue

    if found_subdomains:
        findings.append({
            'id': f'sub-{scan_id}',
            'severity': 'info',
            'type': 'subdomain_summary',
            'title': f'{len(found_subdomains)} Subdomains gefunden',
            'url': domain,
            'evidence': f'Gefundene Subdomains: {", ".join([s[0] for s in found_subdomains[:20]])}',
            'remediation': 'Alle Subdomains auf Schwachstellen und unnötige Exposition scannen.'
        })
        scan_id += 1
    else:
        findings.append({
            'id': f'sub-{scan_id}',
            'severity': 'info',
            'type': 'subdomain_none',
            'title': 'Keine zusätzlichen Subdomains gefunden',
            'url': domain,
            'evidence': f'Keine der getesteten Subdomains resolved für {domain}',
            'remediation': 'Weitere Enumeration mit erweiterter Wordlist in Betracht ziehen.'
        })
        scan_id += 1

    return findings
