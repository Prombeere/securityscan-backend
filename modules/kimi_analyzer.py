#!/usr/bin/env python3
"""
KIMI API INTEGRATION - Intelligente Analyse mit Moonshot AI
Nutzt die Kimi API fuer Advanced Analysis der Scan-Ergebnisse
Unterstuetzt sowohl moonshot.cn als auch kimi.com Code API
"""

import json, os

# ========== MUST be defined FIRST before any calls ==========

def _get_key():
    """Lies API Key dynamisch - entfernt alle Newlines/Spaces/Quotes"""
    key = os.environ.get('KIMI_API_KEY', '')
    # WICHTIG: Keys koennen durch Copy-Paste Newlines enthalten
    key = key.replace('\n', '').replace('\r', '').replace(' ', '')
    key = key.strip().strip('"').strip("'")
    return key


# NOW we can safely call _get_key()
KIMI_API_KEY = _get_key()  # Initialer Wert


def _get_api_url():
    """Auto-detect API URL - kimi.com Code keys need /coding/v1/ path"""
    key = _get_key()
    if key.startswith('sk-kimi-'):
        # CRITICAL: kimi.com Code API uses /coding/v1/ path!
        # Docs: https://www.kimi.com/code/docs/#api-%E6%8E%A5%E5%85%A5
        return 'https://api.kimi.com/coding/v1/chat/completions'
    return os.environ.get('KIMI_API_URL', 'https://api.moonshot.cn/v1/chat/completions')


def _get_model():
    """Auto-detect model - kimi.com Code uses 'kimi-for-coding'"""
    key = _get_key()
    if key.startswith('sk-kimi-'):
        return 'kimi-for-coding'
    return 'kimi-k2-0711-preview'


def analyze_with_kimi(target, findings):
    """
    Sende Scan-Ergebnisse an Kimi API fuer intelligente Analyse.
    Gibt AI-generierte Empfehlungen und erweiterte Analyse zurueck.
    """
    key = _get_key()  # IMMER dynamisch lesen!
    if not key:
        return []  # Kein API Key -> keine AI-Analyse
    
    try:
        import urllib.request
        
        # Baute Prompt
        findings_summary = "\n".join([
            f"- [{f['severity'].upper()}] {f['title']} ({f['type']}): {f.get('evidence', 'N/A')[:100]}"
            for f in findings[:20]  # Max 20 findings
        ])
        
        prompt = f"""Du bist ein Senior Security Analyst. Analysiere diese Scan-Ergebnisse fuer {target} und gib erweiterte, praxisnahe Empfehlungen.

GEFUNDENE SCHWACHSTELLEN:
{findings_summary}

Erstelle eine detaillierte Analyse mit:
1. Risiko-Bewertung (0-100 Score)
2. Top 3 priorisierte Fix-Empfehlungen
3. Moegliche Angriffsszenarien
4. Compliance-Auswirkungen (ISO 27001, BSI)

Formattiere als JSON-Array von findings mit id, severity, type, title, url, evidence, remediation.
AUF DEUTSCH antworten."""

        req_data = json.dumps({
            "model": _get_model(),
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 2000
        }).encode('utf-8')
        
        req = urllib.request.Request(
            _get_api_url(),
            data=req_data,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {key}'
            },
            method='POST'
        )
        
        resp = urllib.request.urlopen(req, timeout=30)
        result = json.loads(resp.read().decode('utf-8'))
        
        ai_response = result['choices'][0]['message']['content']
        
        # Versuche JSON zu parsen
        try:
            # Extrahiere JSON aus der Response
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
        
    except Exception as e:
        return [{
            "id": "AI-ERR",
            "severity": "info", 
            "type": "ai_error",
            "title": "Kimi API nicht verfuegbar",
            "url": target,
            "evidence": str(e),
            "remediation": "KIMI_API_KEY Umgebungsvariable setzen"
        }]


def generate_report(target, findings):
    """Generiere einen menschenlesbaren Bericht mit Kimi"""
    key = _get_key()
    if not key:
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

Anforderungen:
1. Executive Summary (3-4 Saetze)
2. Top 3 Risiken
3. Sofortmassnahmen

AUF DEUTSCH. Max 300 Woerter."""

        req_data = json.dumps({
            "model": _get_model(),
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.4,
            "max_tokens": 1000
        }).encode('utf-8')
        
        req = urllib.request.Request(
            _get_api_url(),
            data=req_data,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {key}'
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
    return bool(key and key != 'your-api-key-here' and len(key) > 20)
