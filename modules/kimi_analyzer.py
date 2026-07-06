#!/usr/bin/env python3
"""
KIMI API INTEGRATION - Intelligente Analyse mit Moonshot AI
Nutzt die Kimi API fuer Advanced Analysis der Scan-Ergebnisse
"""

import json, os

KIMI_API_URL = "https://api.moonshot.cn/v1/chat/completions"
KIMI_MODEL = "kimi-latest"


def _get_key():
    """Read API key dynamically - works even if key was set after server start"""
    return os.environ.get('KIMI_API_KEY', '').strip()


def analyze_with_kimi(target, findings):
    """Sende Scan-Ergebnisse an Kimi API fuer intelligente Analyse."""
    api_key = _get_key()
    if not api_key or api_key == 'your-api-key-here':
        return [{
            "id": "AI-ERR",
            "severity": "info",
            "type": "ai_error",
            "title": "Kimi API Key nicht gesetzt",
            "url": target,
            "evidence": "Kein gueltiger KIMI_API_KEY gefunden. Setze ihn als Replit Secret und starte das Backend neu.",
            "remediation": "1. Replit Secrets -> KIMI_API_KEY hinzufuegen. 2. Backend Stop/Run."
        }]

    try:
        import urllib.request

        findings_summary = "\n".join([
            f"- [{f['severity'].upper()}] {f['title']} ({f['type']}): {f.get('evidence', 'N/A')[:100]}"
            for f in findings[:20]
        ])

        prompt = f"""Du bist ein Senior Security Analyst. Analysiere diese Scan-Ergebnisse fuer {target} und gib erweiterte, praxisnahe Empfehlungen.

GEFUNDENE SCHWACHSTELLEN:
{findings_summary}

Erstelle eine detaillierte Analyse mit:
1. Risiko-Bewertung (0-100 Score)
2. Top 3 priorisierte Fix-Empfehlungen
3. Moegliche Angriffsszenarien
4. Compliance-Auswirkungen (ISO 27001, BSI)

Formatiere als JSON-Array von findings mit id, severity, type, title, url, evidence, remediation.
AUF DEUTSCH antworten."""

        req_data = json.dumps({
            "model": KIMI_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 2000
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

        resp = urllib.request.urlopen(req, timeout=30)
        result = json.loads(resp.read().decode('utf-8'))

        ai_response = result['choices'][0]['message']['content']

        # Versuche JSON zu parsen
        try:
            json_start = ai_response.find('[')
            json_end = ai_response.rfind(']') + 1
            if json_start >= 0 and json_end > json_start:
                ai_findings = json.loads(ai_response[json_start:json_end])
                return ai_findings
        except:
            pass

        # Fallback: Erstelle ein Info-Finding mit der AI-Analyse
        return [{
            "id": "AI-001",
            "severity": "info",
            "type": "ai_analysis",
            "title": "Kimi AI Erweiterte Analyse",
            "url": target,
            "evidence": ai_response[:500],
            "remediation": "Detaillierte Analyse von Kimi API"
        }]

    except urllib.error.HTTPError as e:
        if e.code == 401:
            return [{
                "id": "AI-ERR",
                "severity": "info",
                "type": "ai_error",
                "title": "Kimi API Key ungueltig (401 Unauthorized)",
                "url": target,
                "evidence": "Der API Key wurde abgelehnt. Pruefe: 1. Key ist korrekt kopiert? 2. Key hat noch Credits? 3. Key ist nicht abgelaufen?",
                "remediation": "Neuen Key von https://platform.moonshot.cn erstellen und als Replit Secret setzen."
            }]
        return [{
            "id": "AI-ERR",
            "severity": "info",
            "type": "ai_error",
            "title": f"Kimi API Fehler {e.code}",
            "url": target,
            "evidence": str(e),
            "remediation": "Spaeter erneut versuchen."
        }]
    except Exception as e:
        return [{
            "id": "AI-ERR",
            "severity": "info",
            "type": "ai_error",
            "title": "Kimi API nicht erreichbar",
            "url": target,
            "evidence": str(e),
            "remediation": "Netzwerkverbindung pruefen."
        }]


def generate_report(target, findings):
    """Generiere einen menschenlesbaren Bericht mit Kimi"""
    api_key = _get_key()
    if not api_key:
        return None

    try:
        import urllib.request

        sev_count = {}
        for f in findings:
            sev_count[f['severity']] = sev_count.get(f['severity'], 0) + 1

        prompt = f"""Erstelle einen professionellen Security-Scan-Bericht fuer {target}.

Zusammenfassung:
- Critical: {sev_count.get('critical', 0)}
- High: {sev_count.get('high', 0)}
- Medium: {sev_count.get('medium', 0)}
- Low: {sev_count.get('low', 0)}
- Info: {sev_count.get('info', 0)}
- Total: {len(findings)}

Gib einen Executive Summary (3-4 Saetze) auf DEUTSCH."""

        req_data = json.dumps({
            "model": KIMI_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.4,
            "max_tokens": 1000
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

        resp = urllib.request.urlopen(req, timeout=30)
        result = json.loads(resp.read().decode('utf-8'))
        return result['choices'][0]['message']['content']

    except Exception as e:
        return f"Berichtsgenerierung fehlgeschlagen: {e}"


def check_api_key():
    """Pruefe ob Kimi API Key konfiguriert ist"""
    key = _get_key()
    return bool(key and key != 'your-api-key-here')
