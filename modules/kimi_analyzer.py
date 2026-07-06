#!/usr/bin/env python3
"""
KIMI K2 API INTEGRATION - Advanced Security Analysis
Uses Kimi K2-0711-preview (strongest model) for deep vulnerability analysis
"""

import json, os

KIMI_API_URL = "https://api.moonshot.cn/v1/chat/completions"
# Kimi K2-0711-preview: strongest model for complex security analysis
KIMI_MODEL = "kimi-k2-0711-preview"


def _get_key():
    """Read API key dynamically - strips spaces AND quotes that might be in Replit Secrets"""
    key = os.environ.get('KIMI_API_KEY', '')
    # Aggressive cleanup: spaces, quotes, newlines
    key = key.strip().strip('"').strip("'").strip()
    return key


def analyze_with_kimi(target, findings):
    """Deep security analysis using Kimi K2 - returns enhanced findings"""
    api_key = _get_key()
    if not api_key or api_key == 'your-api-key-here':
        return [{
            "id": "AI-ERR",
            "severity": "info",
            "type": "ai_error",
            "title": "Kimi K2 API Key nicht gesetzt",
            "url": target,
            "evidence": "Kein gueltiger KIMI_API_KEY gefunden.",
            "remediation": "Replit Secrets -> KIMI_API_KEY hinzufuegen. Dann Backend Stop/Run."
        }]

    try:
        import urllib.request

        # Build rich findings summary for K2
        findings_summary = "\n".join([
            f"[{f['severity'].upper()}] {f['type']}: {f['title']}\n  URL: {f.get('url', 'N/A')}\n  Evidence: {f.get('evidence', 'N/A')[:150]}"
            for f in findings[:25]
        ])

        prompt = f"""Du bist ein CISSP-zertifizierter Senior Security Analyst mit 15 Jahren Erfahrung im Penetration Testing. Fuehre eine Tiefenanalyse der folgenden Scan-Ergebnisse durch.

ZIEL: {target}

SCAN-ERGEBNISSE:
{findings_summary}

ANALYSEANFORDERUNGEN:
1. Bewerte das Gesamtrisiko (0-100) mit Begruendung
2. Priorisiere die TOP 5 kritischsten Schwachstellen
3. Beschreibe konkrete Exploit-Szenarien (Schritt-fuer-Schritt)
4. Nenne CVSS-Schaetzungen wo moeglich
5. Empfehle sofortige Gegenmassnahmen
6. Pruefe auf chained vulnerabilities (Mehrfachausnutzung)

ANTWORTFORMAT - striktes JSON-Array:
[
  {{"id": "AI-001", "severity": "critical|high|medium|low|info", "type": "ai_analysis", "title": "Kurztitel", "url": "{target}", "evidence": "Detaillierte Analyse...", "remediation": "Konkrete Fix-Schritte..."}}
]

WICHTIG: Nur das JSON-Array ausgeben, kein Markdown, keine Erklaerungen davor/danach. AUF DEUTSCH."""

        req_data = json.dumps({
            "model": KIMI_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 4000
        }).encode('utf-8')

        req = urllib.request.Request(
            KIMI_API_URL,
            data=req_data,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {api_key}'
            },
            method='POST'
        )

        resp = urllib.request.urlopen(req, timeout=60)
        result = json.loads(resp.read().decode('utf-8'))

        ai_response = result['choices'][0]['message']['content']

        # Parse JSON array from response
        try:
            json_start = ai_response.find('[')
            json_end = ai_response.rfind(']') + 1
            if json_start >= 0 and json_end > json_start:
                ai_findings = json.loads(ai_response[json_start:json_end])
                # Tag as K2 analysis
                for f in ai_findings:
                    f['type'] = 'kimi_k2_analysis'
                    f['title'] = f"[K2] {f.get('title', 'AI Analysis')}"
                return ai_findings
        except Exception as parse_err:
            print(f"[K2] JSON parse error: {parse_err}")
            pass

        # Fallback: structured analysis
        return [{
            "id": "AI-001",
            "severity": "info",
            "type": "kimi_k2_analysis",
            "title": "[K2] Erweiterte Sicherheitsanalyse",
            "url": target,
            "evidence": ai_response[:800],
            "remediation": "Siehe detaillierte Analyse oben. Priorisierte Fixes in der Evidence beschrieben."
        }]

    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8', errors='ignore') if hasattr(e, 'read') else ''
        if e.code == 401:
            return [{
                "id": "AI-ERR",
                "severity": "info",
                "type": "ai_error",
                "title": "[K2] API Key ungueltig (401)",
                "url": target,
                "evidence": f"Key abgelehnt. Laenge: {len(api_key)} chars. Details: {err_body[:200]}",
                "remediation": "1. Key in Replit Secrets pruefen (keine Anfuehrungszeichen!). 2. Neuen Key von https://platform.moonshot.cn erstellen."
            }]
        elif e.code == 429:
            return [{
                "id": "AI-ERR",
                "severity": "info",
                "type": "ai_error",
                "title": "[K2] Rate Limit erreicht (429)",
                "url": target,
                "evidence": "Zu viele Anfragen. Bitte warten.",
                "remediation": "Einige Minuten warten und erneut scannen."
            }]
        return [{
            "id": "AI-ERR",
            "severity": "info",
            "type": "ai_error",
            "title": f"[K2] API Fehler {e.code}",
            "url": target,
            "evidence": str(e),
            "remediation": "Spaeter erneut versuchen."
        }]
    except Exception as e:
        return [{
            "id": "AI-ERR",
            "severity": "info",
            "type": "ai_error",
            "title": "[K2] Netzwerkfehler",
            "url": target,
            "evidence": str(e),
            "remediation": "Netzwerkverbindung pruefen."
        }]


def generate_report(target, findings):
    """Generate executive summary using Kimi K2"""
    api_key = _get_key()
    if not api_key:
        return None

    try:
        import urllib.request

        sev_count = {}
        for f in findings:
            sev_count[f['severity']] = sev_count.get(f['severity'], 0) + 1

        prompt = f"""Erstelle einen professionellen Security-Scan-Bericht (Executive Summary) fuer {target}.

Statistik:
- Critical: {sev_count.get('critical', 0)}
- High: {sev_count.get('high', 0)}
- Medium: {sev_count.get('medium', 0)}
- Low: {sev_count.get('low', 0)}
- Info: {sev_count.get('info', 0)}

Anforderungen:
1. Executive Summary (3-4 praezise Saetze auf Deutsch)
2. Top 3 Risiken mit Business-Impact
3. Sofortmassnahmen (priorisiert)
4. Frist fuer Fixes empfehlen

Format: Reiner Text, kein Markdown. Max 300 Woerter."""

        req_data = json.dumps({
            "model": KIMI_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 1500
        }).encode('utf-8')

        req = urllib.request.Request(
            KIMI_API_URL,
            data=req_data,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {api_key}'
            },
            method='POST'
        )

        resp = urllib.request.urlopen(req, timeout=60)
        result = json.loads(resp.read().decode('utf-8'))
        return result['choices'][0]['message']['content']

    except Exception as e:
        return f"K2 Berichtsgenerierung fehlgeschlagen: {e}"


def check_api_key():
    """Check if Kimi API key is configured and appears valid"""
    key = _get_key()
    return bool(key and len(key) > 20 and key != 'your-api-key-here')
