import json
import shutil
import uuid
import zipfile
from pathlib import Path
from typing import List, Dict, Optional, Any

from app.schemas import (
    Finding,
    ToolSummary,
    SeveritySummary,
    GlobalSummary,
    RiskScore,
)


BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def generate_scan_id() -> str:
    return str(uuid.uuid4())


def create_scan_workspace(scan_id: Optional[str] = None) -> Path:
    if scan_id is None:
        scan_id = generate_scan_id()

    workspace = UPLOAD_DIR / scan_id
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


def save_uploaded_file(upload_file, destination: Path) -> Path:
    file_path = destination / upload_file.filename
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(upload_file.file, buffer)
    return file_path


def extract_zip(zip_path: Path, extract_to: Path) -> Path:
    project_dir = extract_to / "project"
    project_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(project_dir)

    return project_dir


def is_zip_file(filename: str) -> bool:
    return filename.lower().endswith(".zip")


def cleanup_directory(path: Path):
    if path.exists() and path.is_dir():
        shutil.rmtree(path, ignore_errors=True)


def compute_risk_score(severity_counts: Dict[str, int]) -> RiskScore:
    weights = {
        "CRITICAL": 40,
        "HIGH": 20,
        "MEDIUM": 10,
        "LOW": 5,
        "INFO": 1,
        "UNKNOWN": 3,
    }

    raw_score = sum(
        severity_counts.get(severity, 0) * weight
        for severity, weight in weights.items()
    )

    score = min(raw_score, 100)

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    elif score >= 10:
        level = "LOW"
    else:
        level = "INFO"

    return RiskScore(score=score, level=level)


def build_global_summary(
    findings: List[Finding],
    tool_statuses: Dict[str, Dict]
) -> GlobalSummary:
    severity_counts: Dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "UNKNOWN": 0,
    }

    real_tool_counts: Dict[str, int] = {}

    for finding in findings:
        sev = (finding.severity or "UNKNOWN").upper()
        if sev not in severity_counts:
            sev = "UNKNOWN"
        severity_counts[sev] += 1

        tool_name = finding.tool
        real_tool_counts[tool_name] = real_tool_counts.get(tool_name, 0) + 1

    by_tool = []
    for tool_name in ["semgrep", "trivy", "gitleaks"]:
        tool_info = tool_statuses.get(tool_name, {})
        by_tool.append(
            ToolSummary(
                tool=tool_name,
                total_findings=real_tool_counts.get(tool_name, 0),
                status=tool_info.get("status", "not_executed"),
                error=tool_info.get("error"),
            )
        )

    by_severity = SeveritySummary(**severity_counts)
    risk = compute_risk_score(severity_counts)

    return GlobalSummary(
        total_findings=len(findings),
        by_tool=by_tool,
        by_severity=by_severity,
        risk=risk,
    )


def save_json_report(scan_id: str, payload: dict) -> Path:
    report_path = REPORT_DIR / f"{scan_id}.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return report_path


def findings_to_dicts(findings: List[Finding]) -> List[Dict[str, Any]]:
    return [finding.model_dump() for finding in findings]