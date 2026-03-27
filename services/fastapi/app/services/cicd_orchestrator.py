import os
import shutil
import tempfile
import zipfile
from typing import Any, Dict

import requests

from app.core.config import settings
from app.services.github_client import set_commit_status
from app.services.quality_gate import evaluate_quality_gate


def _github_headers() -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"

    return headers


def download_repo_archive(owner: str, repo: str, sha: str) -> str:
    """
    Télécharge l'archive ZIP du commit GitHub.
    Compatible dépôts publics.
    Pour dépôts privés, le token GitHub est ajouté si disponible.
    """
    archive_url = f"{settings.GITHUB_API_URL}/repos/{owner}/{repo}/zipball/{sha}"

    tmp_dir = tempfile.mkdtemp(prefix="cybersentinel_cicd_")
    zip_path = os.path.join(tmp_dir, "repo.zip")
    extract_dir = os.path.join(tmp_dir, "src")

    print(f"[PIPELINE] Downloading archive for {owner}/{repo}@{sha}")

    response = requests.get(
        archive_url,
        headers=_github_headers(),
        timeout=settings.REQUEST_TIMEOUT_LONG,
    )
    response.raise_for_status()

    with open(zip_path, "wb") as f:
        f.write(response.content)

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(extract_dir)

    return extract_dir


def _find_real_source_root(extract_dir: str) -> str:
    """
    L’archive GitHub contient en général un dossier racine unique.
    On retourne ce dossier si trouvé.
    """
    entries = [os.path.join(extract_dir, entry) for entry in os.listdir(extract_dir)]
    dirs = [entry for entry in entries if os.path.isdir(entry)]

    if len(dirs) == 1:
        return dirs[0]

    return extract_dir


def run_sast_scan(source_path: str) -> Dict[str, Any]:
    """
    Appel réel vers le SAST engine.
    Adapte le payload si ton endpoint /scan/all attend un autre format.
    """
    url = f"{settings.SAST_ENGINE_URL}/scan/all"

    payload = {
        "source_type": "local_path",
        "source_path": source_path,
    }

    print(f"[PIPELINE] Running SAST scan on: {source_path}")

    try:
        response = requests.post(
            url,
            json=payload,
            timeout=settings.REQUEST_TIMEOUT_LONG,
        )
        response.raise_for_status()
        data = response.json()

        if isinstance(data, dict):
            data.setdefault("findings", [])
            data.setdefault("status", "completed")
            return data

        return {
            "status": "completed",
            "findings": [],
            "raw_response": data,
        }

    except Exception as exc:
        print(f"[PIPELINE] SAST error: {exc}")
        return {
            "status": "error",
            "findings": [],
            "error": str(exc),
        }


def _should_run_dast(source_path: str) -> bool:
    if not settings.ENABLE_DAST_IN_CICD:
        return False

    web_indicators = {
        "package.json",
        "requirements.txt",
        "pom.xml",
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
    }

    try:
        for _, _, files in os.walk(source_path):
            for file_name in files:
                if file_name in web_indicators:
                    return True
    except Exception:
        return False

    return False


def run_dast_scan_if_needed(source_path: str, github_context: Dict[str, Any]) -> Dict[str, Any]:
    """
    V1:
    - skipped par défaut
    - activable via ENABLE_DAST_IN_CICD=true
    """
    if not _should_run_dast(source_path):
        print("[PIPELINE] DAST skipped")
        return {
            "status": "skipped",
            "findings": [],
            "exploit_confirmed": False,
        }

    url = f"{settings.DAST_ENGINE_URL}/scan/from-source"

    payload = {
        "source_path": source_path,
        "repository": github_context["repository_full_name"],
        "branch": github_context["branch"],
        "commit_sha": github_context["commit_sha"],
    }

    print("[PIPELINE] Running DAST scan")

    try:
        response = requests.post(
            url,
            json=payload,
            timeout=settings.REQUEST_TIMEOUT_LONG,
        )
        response.raise_for_status()
        data = response.json()

        if isinstance(data, dict):
            data.setdefault("status", "completed")
            data.setdefault("findings", [])
            data.setdefault("exploit_confirmed", False)
            return data

        return {
            "status": "completed",
            "findings": [],
            "exploit_confirmed": False,
            "raw_response": data,
        }

    except Exception as exc:
        print(f"[PIPELINE] DAST error: {exc}")
        return {
            "status": "error",
            "findings": [],
            "exploit_confirmed": False,
            "error": str(exc),
        }


def run_correlation(
    github_context: Dict[str, Any],
    sast_result: Dict[str, Any],
    dast_result: Dict[str, Any],
) -> Dict[str, Any]:
    url = f"{settings.CORRELATION_ENGINE_URL}/correlate"

    payload = {
        "source": "github",
        "repository": github_context["repository_full_name"],
        "branch": github_context["branch"],
        "commit_sha": github_context["commit_sha"],
        "delivery_id": github_context["delivery_id"],
        "author_name": github_context.get("author_name"),
        "author_email": github_context.get("author_email"),
        "sast_result": sast_result,
        "dast_result": dast_result,
    }

    print("[PIPELINE] Running correlation")

    try:
        response = requests.post(
            url,
            json=payload,
            timeout=settings.REQUEST_TIMEOUT_LONG,
        )
        response.raise_for_status()
        data = response.json()

        if isinstance(data, dict):
            data.setdefault("status", "completed")
            data.setdefault("r_score", 0.0)
            data.setdefault("ml_anomaly", False)
            return data

        return {
            "status": "completed",
            "r_score": 0.0,
            "ml_anomaly": False,
            "raw_response": data,
        }

    except Exception as exc:
        print(f"[PIPELINE] Correlation error: {exc}")
        return {
            "status": "error",
            "r_score": 0.0,
            "ml_anomaly": False,
            "error": str(exc),
        }


def map_gate_to_github_state(gate_status: str) -> str:
    if gate_status == "FAIL":
        return "failure"

    if gate_status == "WARNING":
        return "success"

    return "success"


def build_status_description(quality_gate: Dict[str, Any]) -> str:
    status = quality_gate.get("status", "UNKNOWN")
    reasons = quality_gate.get("reasons", []) or []

    if status == "PASS":
        return "CyberSentinel quality gate passed"

    if status == "WARNING":
        return f"CyberSentinel warning: {reasons[0][:90] if reasons else 'warning detected'}"

    if status == "FAIL":
        return f"CyberSentinel failed: {reasons[0][:90] if reasons else 'blocking issue detected'}"

    return "CyberSentinel finished"


def execute_pipeline(github_context: Dict[str, Any]) -> Dict[str, Any]:
    owner = github_context["owner"]
    repo = github_context["repo"]
    sha = github_context["commit_sha"]

    work_dir = None

    print(f"[PIPELINE] Started for {owner}/{repo}@{sha}")

    set_commit_status(
        owner=owner,
        repo=repo,
        sha=sha,
        state="pending",
        description="CyberSentinel scan in progress",
    )

    try:
        extracted_dir = download_repo_archive(owner, repo, sha)
        work_dir = extracted_dir

        source_root = _find_real_source_root(extracted_dir)
        print(f"[PIPELINE] Source root: {source_root}")

        sast_result = run_sast_scan(source_root)
        dast_result = run_dast_scan_if_needed(source_root, github_context)
        correlation_result = run_correlation(github_context, sast_result, dast_result)

        quality_gate = evaluate_quality_gate(
            sast_result=sast_result,
            dast_result=dast_result,
            correlation_result=correlation_result,
        )

        github_state = map_gate_to_github_state(quality_gate["status"])
        description = build_status_description(quality_gate)

        print(f"[PIPELINE] Quality gate: {quality_gate['status']}")
        print(f"[PIPELINE] Sending final GitHub status: {github_state}")

        set_commit_status(
            owner=owner,
            repo=repo,
            sha=sha,
            state=github_state,
            description=description,
        )

        return {
            "pipeline_status": quality_gate["status"],
            "sast_result": sast_result,
            "dast_result": dast_result,
            "correlation_result": correlation_result,
            "quality_gate": quality_gate,
        }

    except Exception as exc:
        print(f"[PIPELINE] Pipeline error: {exc}")

        try:
            set_commit_status(
                owner=owner,
                repo=repo,
                sha=sha,
                state="error",
                description=f"CyberSentinel pipeline error: {str(exc)[:90]}",
            )
        except Exception as status_exc:
            print(f"[PIPELINE] Failed to send error status to GitHub: {status_exc}")

        raise

    finally:
        if work_dir and os.path.exists(os.path.dirname(work_dir)):
            shutil.rmtree(os.path.dirname(work_dir), ignore_errors=True)
            print("[PIPELINE] Temporary files cleaned up")