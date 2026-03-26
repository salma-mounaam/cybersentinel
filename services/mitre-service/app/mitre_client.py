from attackcti import attack_client

lift = attack_client()


def _extract_external_id(technique: dict):
    for ref in technique.get("external_references", []):
        if ref.get("external_id", "").startswith("T"):
            return ref.get("external_id")
    return None


def _extract_tactics(technique: dict):
    return [
        phase.get("phase_name")
        for phase in technique.get("kill_chain_phases", [])
        if phase.get("phase_name")
    ]


def get_all_techniques():
    techniques = lift.get_techniques()
    result = []

    for t in techniques:
        try:
            ext_id = _extract_external_id(t)
            if not ext_id:
                continue

            result.append({
                "technique_id": ext_id,
                "technique_name": t.get("name"),
                "tactics": _extract_tactics(t),
                "mitre_url": f"https://attack.mitre.org/techniques/{ext_id}"
            })
        except Exception:
            continue

    return result


def get_technique_by_id(technique_id: str):
    techniques = lift.get_techniques()

    for t in techniques:
        ext_id = _extract_external_id(t)
        if ext_id == technique_id:
            return {
                "technique_id": ext_id,
                "technique_name": t.get("name"),
                "tactics": _extract_tactics(t),
                "mitre_url": f"https://attack.mitre.org/techniques/{ext_id}"
            }

    return None