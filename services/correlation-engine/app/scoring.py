from typing import Dict, Tuple, List
from app.schemas import Finding
from app.utils import normalize_severity, infer_category


SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 5,
    "INFO": 0,
}

CATEGORY_WEIGHTS = {
    "secret_exposure": 20,
    "credential_exposure": 20,
    "code_vulnerability": 15,
    "dependency_vulnerability": 12,
    "container_risk": 10,
    "generic_security_finding": 5,
}


def compute_finding_score(
    finding: Finding,
    same_group_count: int = 1,
    correlated_tools_count: int = 1
) -> Tuple[int, Dict[str, int]]:
    """
    Score borné à 100.
    """

    breakdown: Dict[str, int] = {}

    severity = normalize_severity(finding.severity)
    breakdown["severity"] = SEVERITY_WEIGHTS.get(severity, 5)

    category = infer_category(finding)
    breakdown["category"] = CATEGORY_WEIGHTS.get(category, 5)

    breakdown["mitre"] = 10 if finding.mitre else 0

    breakdown["multi_tool_correlation"] = 15 if correlated_tools_count >= 2 else 0

    breakdown["multiple_evidence"] = 10 if same_group_count >= 2 else 0

    breakdown["fix_available"] = 5 if finding.fix_available else 0

    confidence = finding.confidence or 0.5
    if confidence >= 0.9:
        breakdown["confidence"] = 10
    elif confidence >= 0.75:
        breakdown["confidence"] = 7
    elif confidence >= 0.5:
        breakdown["confidence"] = 4
    else:
        breakdown["confidence"] = 1

    # Bonus spécifiques
    title = (finding.title or "").lower()
    breakdown["exposure"] = 0

    if "secret" in title or "password" in title or "token" in title or "apikey" in title:
        breakdown["exposure"] += 20

    if "sql injection" in title or "command injection" in title or "rce" in title:
        breakdown["exposure"] += 15

    total = sum(breakdown.values())
    total = min(total, 100)

    return total, breakdown


def compute_group_context(findings: List[Finding]) -> Dict[str, int]:
    tools = {f.tool for f in findings if f.tool}
    return {
        "same_group_count": len(findings),
        "correlated_tools_count": len(tools),
    }