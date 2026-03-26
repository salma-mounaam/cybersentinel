def infer_asset_criticality(finding, asset_context: dict) -> float:
    file_path = (finding.file or "").lower()
    title = (finding.title or "").lower()

    if asset_context.get("criticality") is not None:
        return float(asset_context["criticality"])

    if "auth" in file_path or "login" in title or "token" in title:
        return 0.90

    if "config" in file_path or "secret" in title or "password" in title:
        return 0.95

    if "api" in file_path or "controller" in file_path:
        return 0.80

    if "dockerfile" in file_path:
        return 0.50

    return 0.60