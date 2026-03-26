from typing import List, Optional
from app.schemas import Finding, MitreTechnique


def normalize_severity(severity: Optional[str]) -> str:
    if not severity:
        return "LOW"
    severity = severity.upper().strip()
    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return "LOW"
    return severity


def risk_level_from_score(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"


def safe_lower(value: Optional[str]) -> str:
    return value.lower().strip() if value else ""


def deduplicate_strings(items: List[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        cleaned = item.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return result


def deduplicate_mitre(techniques: List[MitreTechnique]) -> List[MitreTechnique]:
    seen = set()
    result = []
    for tech in techniques:
        key = tech.technique_id
        if key not in seen:
            seen.add(key)
            result.append(tech)
    return result


def build_evidence_line(finding: Finding) -> str:
    location = ""
    if finding.file and finding.line:
        location = f" in {finding.file}:{finding.line}"
    elif finding.file:
        location = f" in {finding.file}"

    if finding.cve_id:
        return f"{finding.tool}: {finding.title} ({finding.cve_id}){location}"

    return f"{finding.tool}: {finding.title}{location}"


def infer_category(finding: Finding) -> str:
    title = safe_lower(finding.title)
    ftype = safe_lower(finding.type)
    category = safe_lower(finding.category)

    if category:
        return category

    if "secret" in title or "token" in title or "password" in title or "apikey" in title:
        return "secret_exposure"
    if "sql" in title or "injection" in title:
        return "code_vulnerability"
    if "command" in title or "rce" in title:
        return "code_vulnerability"
    if finding.cve_id or "cve" in title or "dependency" in ftype:
        return "dependency_vulnerability"
    if "credential" in title:
        return "credential_exposure"
    if "container" in title or "docker" in title:
        return "container_risk"

    if ftype:
        return ftype

    return "generic_security_finding"


def infer_surface(finding: Finding) -> str:
    title = safe_lower(finding.title)
    file_ = safe_lower(finding.file)
    surface = safe_lower(finding.surface)

    if surface:
        return surface

    if "sql" in title or "http" in title or "flask" in title or "django" in title or "controller" in file_:
        return "web"
    if "auth" in title or "login" in title or "jwt" in title or "credential" in title:
        return "auth"
    if "secret" in title or "token" in title or "password" in title:
        return "secrets"
    if "docker" in file_ or "container" in title:
        return "container"
    if finding.cve_id or "package" in title or "requirements" in file_ or "pom.xml" in file_:
        return "dependency_chain"

    return "application"