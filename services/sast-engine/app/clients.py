import requests
from typing import List, Dict, Any

from app.config import MITRE_SERVICE_URL, CORRELATION_ENGINE_URL


def enrich_findings_with_mitre(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not findings:
        return []

    response = requests.post(
        f"{MITRE_SERVICE_URL}/enrich/findings",
        json=findings,
        timeout=60
    )
    response.raise_for_status()
    return response.json()


def generate_incidents_from_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    response = requests.post(
        f"{CORRELATION_ENGINE_URL}/incidents",
        json={"findings": findings},
        timeout=60
    )
    response.raise_for_status()
    return response.json()