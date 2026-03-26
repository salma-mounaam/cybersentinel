from typing import List
from uuid import uuid4

from app.schemas import Finding, Incident, MitreTechnique
from app.scoring import compute_finding_score, compute_group_context
from app.r_engine import compute_r_score_for_incident
from app.utils import (
    build_evidence_line,
    deduplicate_strings,
    deduplicate_mitre,
    infer_category,
    infer_surface,
    normalize_severity,
)


def generate_incident_title(category: str, surface: str, findings: List[Finding]) -> str:
    has_secret = any(
        any(x in (f.title or "").lower() for x in ["secret", "password", "token", "apikey"])
        for f in findings
    )
    has_sqli = any("sql" in (f.title or "").lower() for f in findings)
    has_rce = any(any(x in (f.title or "").lower() for x in ["command injection", "rce", "exec"]) for f in findings)
    has_cve = any(f.cve_id for f in findings)
    has_network = any(infer_category(f) == "network_alert" for f in findings)

    if has_sqli and has_secret:
        return "Exposition applicative critique avec risque d’exploitation initiale"
    if has_rce:
        return "Risque d’exécution de commandes sur surface exposée"
    if has_sqli:
        return "Risque d’injection sur composant applicatif exposé"
    if has_secret:
        return "Exposition de secrets sensibles dans l’application"
    if has_cve:
        return "Composants vulnérables avec risque d’exploitation"
    if has_network:
        return "Activité réseau anormale corrélée"
    return f"Incident corrélé de sécurité sur surface {surface}"


def generate_summary(category: str, surface: str, findings: List[Finding], incident_score: int) -> str:
    count = len(findings)
    tools = sorted({f.tool for f in findings if f.tool})
    return (
        f"{count} finding(s) corrélés ont été regroupés sur la surface '{surface}' "
        f"dans la catégorie '{category}'. "
        f"Les preuves proviennent de {', '.join(tools)}. "
        f"Le score global calculé pour cet incident est {incident_score}/100."
    )


def generate_recommendations(findings: List[Finding]) -> List[str]:
    recos = []

    for f in findings:
        title = (f.title or "").lower()
        category = infer_category(f)

        if "sql" in title:
            recos.append("Corriger les requêtes SQL en utilisant des paramètres préparés.")
            recos.append("Valider et filtrer strictement les entrées utilisateur.")
        if "command injection" in title or "rce" in title or "exec" in title:
            recos.append("Supprimer les appels shell non sécurisés et utiliser des APIs sûres.")
        if "secret" in title or "password" in title or "token" in title or "apikey" in title:
            recos.append("Révoquer immédiatement les secrets exposés et les déplacer vers un coffre sécurisé.")
        if f.cve_id:
            recos.append("Mettre à jour la dépendance vulnérable vers une version corrigée.")
        if f.fix_available:
            recos.append("Appliquer le correctif disponible dès que possible.")
        if category == "network_alert":
            recos.append("Analyser le flux réseau et vérifier la légitimité de la source détectée.")

        if f.mitre and f.mitre.technique_id == "T1190":
            recos.append("Renforcer les contrôles de sécurité sur les points d’entrée exposés publiquement.")
        if f.mitre and f.mitre.technique_id == "T1552":
            recos.append("Limiter l’exposition des identifiants et renforcer la gestion des secrets.")
        if f.mitre and f.mitre.technique_id == "T1059":
            recos.append("Contrôler et journaliser l’exécution de scripts et commandes système.")

    if not recos:
        recos.append("Analyser manuellement le finding pour confirmer son exploitabilité.")
        recos.append("Prioriser la correction selon l’exposition réelle et l’impact métier.")

    return deduplicate_strings(recos)


def consolidate_severity(findings: List[Finding], incident_score: int) -> str:
    severities = [normalize_severity(f.severity) for f in findings]
    if "CRITICAL" in severities or incident_score >= 80:
        return "CRITICAL"
    if "HIGH" in severities or incident_score >= 60:
        return "HIGH"
    if "MEDIUM" in severities or incident_score >= 40:
        return "MEDIUM"
    if "LOW" in severities or incident_score >= 20:
        return "LOW"
    return "INFO"


def generate_incident(group_id: str, findings: List[Finding]) -> Incident:
    ctx = compute_group_context(findings)

    heuristic_scores = [
        compute_finding_score(
            finding=f,
            same_group_count=ctx["same_group_count"],
            correlated_tools_count=ctx["correlated_tools_count"],
        )[0]
        for f in findings
    ]
    heuristic_score = min(int(sum(heuristic_scores) / len(heuristic_scores)) if heuristic_scores else 0, 100)

    r_breakdown = compute_r_score_for_incident(findings)
    incident_score = r_breakdown.final_score
    risk_level = r_breakdown.final_level

    category = infer_category(findings[0]) if findings else "generic_security_finding"
    surface = infer_surface(findings[0]) if findings else "application"

    title = generate_incident_title(category, surface, findings)
    summary = generate_summary(category, surface, findings, incident_score)

    sources = deduplicate_strings([f.tool for f in findings if f.tool])
    affected_files = deduplicate_strings([f.file for f in findings if f.file])
    evidence = deduplicate_strings([build_evidence_line(f) for f in findings])

    mitre_list: List[MitreTechnique] = [f.mitre for f in findings if f.mitre]
    mitre_list = deduplicate_mitre(mitre_list)

    recommendations = generate_recommendations(findings)
    severity = consolidate_severity(findings, incident_score if incident_score > 0 else heuristic_score)

    return Incident(
        incident_id=f"INC-{uuid4().hex[:8].upper()}",
        title=title,
        severity=severity,
        r_score=incident_score,
        risk_level=risk_level,
        category=category,
        summary=summary,
        sources=sources,
        affected_files=affected_files,
        evidence_count=len(evidence),
        evidence=evidence,
        mitre=mitre_list,
        recommendations=recommendations,
        grouped_by={
            "group_id": group_id,
            "surface": surface,
            "source_count": len(sources),
        },
        r_score_breakdown=r_breakdown,
    )