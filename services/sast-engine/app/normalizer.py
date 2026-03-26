from typing import List
from app.schemas import Finding


def map_semgrep_severity(severity: str) -> str:
    sev = str(severity).upper().strip()

    mapping = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    }

    return mapping.get(sev, "LOW")


def normalize_semgrep_results(semgrep_json: dict) -> List[Finding]:
    findings = []

    results = semgrep_json.get("results", [])
    for result in results:
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        severity = (
            extra.get("severity")
            or metadata.get("severity")
            or "UNKNOWN"
        )

        title = (
            extra.get("message")
            or result.get("check_id")
            or "Semgrep finding"
        )

        description = (
            metadata.get("shortDescription")
            or metadata.get("description")
            or extra.get("message")
            or "No description provided"
        )

        recommendation = (
            metadata.get("remediation")
            or metadata.get("fix")
            or "Review the code and apply secure coding practices"
        )

        start = result.get("start", {})
        path = result.get("path")

        findings.append(
            Finding(
                tool="semgrep",
                type="code_vulnerability",
                severity=map_semgrep_severity(severity),
                title=title,
                file=path,
                line=start.get("line"),
                rule_id=result.get("check_id"),
                description=description,
                recommendation=recommendation,
                category="code_vulnerability",
                confidence=0.85,
            )
        )

    return findings


def normalize_trivy_results(trivy_json: dict) -> List[Finding]:
    findings = []

    results = trivy_json.get("Results", [])
    for result in results:
        target = result.get("Target")

        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(
                Finding(
                    tool="trivy",
                    type="dependency_vulnerability",
                    severity=str(vuln.get("Severity", "UNKNOWN")).upper(),
                    title=vuln.get("Title") or vuln.get("VulnerabilityID") or "Dependency vulnerability",
                    file=target,
                    line=None,
                    rule_id=vuln.get("VulnerabilityID"),
                    description=vuln.get("Description") or "No description provided",
                    recommendation=(
                        f"Upgrade {vuln.get('PkgName')} to a fixed version"
                        if vuln.get("FixedVersion")
                        else "Upgrade the affected dependency or apply vendor remediation"
                    ),
                    category="dependency_vulnerability",
                    cve_id=vuln.get("VulnerabilityID"),
                    package_name=vuln.get("PkgName"),
                    fix_available=bool(vuln.get("FixedVersion")),
                    confidence=0.90,
                    metadata={
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "primary_url": vuln.get("PrimaryURL"),
                    }
                )
            )

        for misconf in result.get("Misconfigurations", []) or []:
            findings.append(
                Finding(
                    tool="trivy",
                    type="misconfiguration",
                    severity=str(misconf.get("Severity", "UNKNOWN")).upper(),
                    title=misconf.get("Title") or misconf.get("ID") or "Misconfiguration detected",
                    file=target,
                    line=None,
                    rule_id=misconf.get("ID"),
                    description=misconf.get("Description") or "No description provided",
                    recommendation=(
                        misconf.get("Resolution")
                        or "Review the configuration and apply secure defaults"
                    ),
                    category="misconfiguration",
                    confidence=0.80,
                )
            )

        for secret in result.get("Secrets", []) or []:
            findings.append(
                Finding(
                    tool="trivy",
                    type="secret_exposure",
                    severity=str(secret.get("Severity", "UNKNOWN")).upper(),
                    title=secret.get("Title") or secret.get("RuleID") or "Secret detected",
                    file=target,
                    line=secret.get("StartLine"),
                    rule_id=secret.get("RuleID"),
                    description=secret.get("Match") or "Potential secret detected",
                    recommendation="Remove the secret from source code and rotate credentials",
                    category="secret_exposure",
                    confidence=0.88,
                )
            )

    return findings


def normalize_gitleaks_results(gitleaks_json: list) -> List[Finding]:
    findings = []

    for secret in gitleaks_json:
        findings.append(
            Finding(
                tool="gitleaks",
                type="secret_exposure",
                severity="CRITICAL",
                title=secret.get("RuleID") or "Secret detected",
                file=secret.get("File"),
                line=secret.get("StartLine"),
                rule_id=secret.get("RuleID"),
                description=secret.get("Description") or "Potential secret detected",
                recommendation="Remove the secret from source code, store it securely, and rotate the exposed credential",
                category="secret_exposure",
                confidence=0.95,
            )
        )

    return findings