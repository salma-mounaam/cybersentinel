from fastapi import FastAPI
from typing import List

from app.schemas import Finding, EnrichedFinding
from app.mapper import map_finding_to_mitre
from app.mitre_client import get_all_techniques, get_technique_by_id

app = FastAPI(title="CyberSentinel MITRE Service")


@app.get("/")
def root():
    return {"service": "mitre-service", "status": "running"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/techniques")
def techniques():
    return get_all_techniques()


@app.get("/techniques/{technique_id}")
def technique_by_id(technique_id: str):
    technique = get_technique_by_id(technique_id)
    return technique if technique else {"message": "Technique not found"}


@app.post("/enrich/finding", response_model=EnrichedFinding)
def enrich_finding(finding: Finding):
    mitre = map_finding_to_mitre(finding)
    enriched = finding.model_dump()
    enriched["mitre"] = mitre
    return enriched


@app.post("/enrich/findings", response_model=List[EnrichedFinding])
def enrich_findings(findings: List[Finding]):
    enriched_list = []

    for f in findings:
        mitre = map_finding_to_mitre(f)
        enriched = f.model_dump()
        enriched["mitre"] = mitre
        enriched_list.append(enriched)

    return enriched_list