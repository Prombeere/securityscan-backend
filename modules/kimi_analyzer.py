#!/usr/bin/env python3
"""
KIMI API INTEGRATION - Intelligente Analyse mit Moonshot AI
Nutzt die Kimi API für Advanced Analysis der Scan-Ergebnisse
"""

import json, os

# Kimi API Configuration
KIMI_API_KEY = os.environ.get('KIMI_API_KEY', '')
KIMI_API_URL = "https://api.moonshot.cn/v1/chat/completions"
KIMI_MODEL = "kimi-latest"


def analyze_with_kimi(target, findings):
    """
    Sende Scan-Ergebnisse an Kimi API für intelligente Analyse.
    Gibt AI-generierte Empfehlungen und erweiterte Analyse zurück.
    """
    if not KIMI_API_KEY:
        return []  # Kein API Key → keine AI-Analyse
    
    try:
        import urllib.request
        
        # Baute Prompt
        findings_summary = "\n".join([
            f"- [{f['severity'].upper()}] {f['title']} ({f['type']}): {f.get('evidence', 'N/A')[:100]}"
            for f in findings[:20]  # Max 20 findings
        ])
        
        prompt = f"""Du bist ein Senior Security Analyst. Analysiere diese Scan-Ergebnisse für {target} und gib erweiterte, praxisnahe Empfehlungen.

GEFUNDENE SCHWACHSTELLEN:
{findings_summary}

Erstelle eine detaillierte Analyse mit:
1. Risiko-Bewertung (0-100 Score)
2. Top 3 priorisierte Fix-Empfehlungen
3. Mögliche Angriffsszenarien
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
                'Authorization': f'Bearer {KIMI_API_KEY}'
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
            "title": "Kimi API nicht verfügbar",
            "url": target,
            "evidence": str(e),
            "remediation": "KIMI_API_KEY Umgebungsvariable setzen"
        }]


def generate_report(target, findings):
    """Generiere einen menschenlesbaren Bericht mit Kimi"""
    if not KIMI_API_KEY:
        return None
    
    try:
        import urllib.request
        
        sev_count = {}
        for f in findings:
            sev_count[f['severity']] = sev_count.get(f['severity'], 0) + 1
        
        prompt = f"""Erstelle einen professionellen Security-Scan-Bericht für {target}.

Zusammenfassung:
- Critical: {sev_count.get('critical', 0)}
- High: {sev_count.get('high', 0)}
- Medium: {sev_count.get('medium', 0)}
- Low: {sev_count.get('low', 0)}
- Info: {sev_count.get('info', 0)}
- Total: {len(findings)}

Gib einen Executive Summary (3-4 Sätze) auf DEUTSCH."""

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
                'Authorization': f'Bearer {KIMI_API_KEY}'
            },
            method='POST'
        )
        
        resp = urllib.request.urlopen(req, timeout=30)
        result = json.loads(resp.read().decode('utf-8'))
        return result['choices'][0]['message']['content']
        
    except Exception as e:
        return f"Berichtsgenerierung fehlgeschlagen: {e}"


def check_api_key():
    """Prüfe ob Kimi API Key konfiguriert ist"""
    return bool(KIMI_API_KEY and KIMI_API_KEY != 'your-api-key-here')
