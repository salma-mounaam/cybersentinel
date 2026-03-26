from app.schemas import MitreTechnique, Finding


def map_finding_to_mitre(finding: Finding) -> MitreTechnique | None:
    title = (finding.title or "").lower()
    rule_id = (finding.rule_id or "").lower()
    description = (getattr(finding, "description", None) or "").lower()
    text = f"{title} {rule_id} {description}"

    # SQLi / web exploit
    if any(x in text for x in [
        "sql injection",
        "sqli",
        "tainted-sql-string",
        "manually-constructed sql string",
        "sql string"
    ]):
        return MitreTechnique(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactics=["Initial Access"],
            mitre_url="https://attack.mitre.org/techniques/T1190",
            confidence=0.90,
            source="rule_mapping"
        )

    # Command injection / exec / eval / RCE
    if any(x in text for x in [
        "command injection",
        "remote code execution",
        "rce",
        "tainted-exec",
        "exec-use",
        "eval-use",
        "executes a shell command"
    ]):
        return MitreTechnique(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactics=["Execution"],
            mitre_url="https://attack.mitre.org/techniques/T1059",
            confidence=0.88,
            source="rule_mapping"
        )

    # Secrets / API keys / credentials
    if any(x in text for x in [
        "secret",
        "token",
        "apikey",
        "api key",
        "password",
        "credential",
        "generic-api-key"
    ]):
        return MitreTechnique(
            technique_id="T1552",
            technique_name="Unsecured Credentials",
            tactics=["Credential Access"],
            mitre_url="https://attack.mitre.org/techniques/T1552",
            confidence=0.90,
            source="rule_mapping"
        )

    # XSS / DOM sink
    if any(x in text for x in [
        "innerhtml",
        "document.write",
        "xss"
    ]):
        return MitreTechnique(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactics=["Execution"],
            mitre_url="https://attack.mitre.org/techniques/T1059",
            confidence=0.65,
            source="rule_mapping"
        )

    return None