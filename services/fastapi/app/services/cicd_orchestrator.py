import io
import os
import shutil
import tempfile
import zipfile
from typing import Any, Dict, Tuple

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
    entries = [os.path.join(extract_dir, entry) for entry in os.listdir(extract_dir)]
    dirs = [entry for entry in entries if os.path.isdir(entry)]

    if len(dirs) == 1:
        return dirs[0]

    return extract_dir


def _zip_directory_to_bytes(source_path: str) -> bytes:
    memory_file = io.BytesIO()

    with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(source_path):
            for file_name in files:
                full_path = os.path.join(root, file_name)
                arcname = os.path.relpath(full_path, source_path)
                zipf.write(full_path, arcname)

    memory_file.seek(0)
    return memory_file.read()


def _normalize_scan_result(data: Any) -> Dict[str, Any]:
    if isinstance(data, dict):
        data.setdefault("findings", [])
        data.setdefault("status", "completed")
        return data

    return {
        "status": "completed",
        "findings": [],
        "raw_response": data,
    }


def _try_post_json(url: str, payload: Dict[str, Any], timeout: int) -> Tuple[bool, Dict[str, Any]]:
    response = requests.post(url, json=payload, timeout=timeout)
    if response.status_code < 400:
        return True, _normalize_scan_result(response.json())

    return False, {
        "status_code": response.status_code,
        "response_text": response.text[:1000],
        "payload_type": "json",
        "payload_preview": str(payload)[:500],
    }


def _try_post_file(url: str, file_bytes: bytes, timeout: int) -> Tuple[bool, Dict[str, Any]]:
    files = {
        "file": ("repo.zip", file_bytes, "application/zip"),
    }

    response = requests.post(url, files=files, timeout=timeout)
    if response.status_code < 400:
        return True, _normalize_scan_result(response.json())

    return False, {
        "status_code": response.status_code,
        "response_text": response.text[:1000],
        "payload_type": "multipart_file",
    }


def run_sast_scan(source_path: str) -> Dict[str, Any]:
    url = f"{settings.SAST_ENGINE_URL}/scan/all"
    zip_bytes = _zip_directory_to_bytes(source_path)

    print(f"[PIPELINE] Running SAST scan on: {source_path}")

    attempts = [
        ("multipart_file", None),
        ("json_local_path", {"source_type": "local_path", "source_path": source_path}),
        ("json_path_only", {"source_path": source_path}),
        ("json_repo_path", {"path": source_path}),
    ]

    errors = []

    for mode, payload in attempts:
        try:
            print(f"[PIPELINE] SAST attempt: {mode}")

            if mode == "multipart_file":
                ok, result = _try_post_file(url, zip_bytes, settings.REQUEST_TIMEOUT_LONG)
            else:
                ok, result = _try_post_json(url, payload, settings.REQUEST_TIMEOUT_LONG)

            if ok:
                print("[PIPELINE] SAST completed")
                return result

            errors.append({"mode": mode, **result})

        except Exception as exc:
            errors.append({"mode": mode, "error": str(exc)})

    print(f"[PIPELINE] SAST error: all attempts failed")

    return {
        "status": "error",
        "findings": [],
        "error": "All SAST request formats failed",
        "attempts": errors,
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

    print("[PIPELINE] Running correlation")

    attempts = [
        {
            "source": "github",
            "repository": github_context["repository_full_name"],
            "branch": github_context["branch"],
            "commit_sha": github_context["commit_sha"],
            "delivery_id": github_context["delivery_id"],
            "author_name": github_context.get("author_name"),
            "author_email": github_context.get("author_email"),
            "sast_result": sast_result,
            "dast_result": dast_result,
        },
        {
            "source": "github",
            "repository": github_context["repository_full_name"],
            "branch": github_context["branch"],
            "commit_sha": github_context["commit_sha"],
            "delivery_id": github_context["delivery_id"],
            "sast_findings": sast_result.get("findings", []),
            "dast_findings": dast_result.get("findings", []),
            "exploit_confirmed": dast_result.get("exploit_confirmed", False),
        },
        {
            "repository": github_context["repository_full_name"],
            "commit_sha": github_context["commit_sha"],
            "sast_findings": sast_result.get("findings", []),
            "dast_result": dast_result,
        },
    ]

    errors = []

    for index, payload in enumerate(attempts, start=1):
        try:
            print(f"[PIPELINE] Correlation attempt: {index}")
            response = requests.post(
                url,
                json=payload,
                timeout=settings.REQUEST_TIMEOUT_LONG,
            )

            if response.status_code < 400:
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

            errors.append({
                "attempt": index,
                "status_code": response.status_code,
                "response_text": response.text[:1000],
            })

        except Exception as exc:
            errors.append({
                "attempt": index,
                "error": str(exc),
            })

    print("[PIPELINE] Correlation error: all attempts failed")

    return {
        "status": "error",
        "r_score": 0.0,
        "ml_anomaly": False,
        "error": "All correlation request formats failed",
        "attempts": errors,
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