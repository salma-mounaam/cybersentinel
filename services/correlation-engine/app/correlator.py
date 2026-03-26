from collections import defaultdict
from typing import Dict, List, Tuple
from app.schemas import Finding
from app.utils import infer_category, infer_surface


def build_group_key(finding: Finding) -> Tuple[str, str, str, str]:
    """
    Corrélation sur 4 axes :
    - fichier
    - catégorie
    - surface
    - technique MITRE
    """
    file_key = finding.file or "unknown_file"
    category_key = infer_category(finding)
    surface_key = infer_surface(finding)
    mitre_key = finding.mitre.technique_id if finding.mitre else "no_mitre"

    return (file_key, category_key, surface_key, mitre_key)


def correlate_findings(findings: List[Finding]) -> Dict[str, List[Finding]]:
    groups = defaultdict(list)

    for finding in findings:
        file_key, category_key, surface_key, mitre_key = build_group_key(finding)

        # clé textuelle lisible
        group_id = f"{category_key}|{surface_key}|{mitre_key}|{file_key}"
        groups[group_id].append(finding)

    return dict(groups)