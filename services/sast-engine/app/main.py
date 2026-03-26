from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.encoders import jsonable_encoder

from app.schemas import ScanResponse, AllScanResponse, Finding
from app.utils import (
    generate_scan_id,
    create_scan_workspace,
    save_uploaded_file,
    extract_zip,
    is_zip_file,
    cleanup_directory,
    build_global_summary,
    save_json_report,
    findings_to_dicts,
)
from app.semgrep_runner import run_semgrep_scan
from app.trivy_runner import run_trivy_scan
from app.gitleaks_runner import run_gitleaks_scan
from app.normalizer import (
    normalize_semgrep_results,
    normalize_trivy_results,
    normalize_gitleaks_results,
)
from app.clients import (
    enrich_findings_with_mitre,
    generate_incidents_from_findings,
)

app = FastAPI(title="CyberSentinel SAST Engine")


@app.get("/")
def root():
    return {
        "service": "sast-engine",
        "status": "running",
        "phase": "6-mitre-correlation-integrated"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/scan/semgrep", response_model=ScanResponse)
async def scan_semgrep(file: UploadFile = File(...)):
    if not file.filename or not is_zip_file(file.filename):
        raise HTTPException(
            status_code=400,
            detail="Only .zip project archives are supported"
        )

    scan_id = generate_scan_id()
    workspace = create_scan_workspace(scan_id)

    try:
        zip_path = save_uploaded_file(file, workspace)
        project_path = extract_zip(zip_path, workspace)

        semgrep_raw = run_semgrep_scan(project_path)
        findings = normalize_semgrep_results(semgrep_raw)

        return ScanResponse(
            status="success",
            tool="semgrep",
            total_findings=len(findings),
            findings=findings
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        cleanup_directory(workspace)


@app.post("/scan/trivy", response_model=ScanResponse)
async def scan_trivy(file: UploadFile = File(...)):
    if not file.filename or not is_zip_file(file.filename):
        raise HTTPException(
            status_code=400,
            detail="Only .zip project archives are supported"
        )

    scan_id = generate_scan_id()
    workspace = create_scan_workspace(scan_id)

    try:
        zip_path = save_uploaded_file(file, workspace)
        project_path = extract_zip(zip_path, workspace)

        trivy_raw = run_trivy_scan(project_path)
        findings = normalize_trivy_results(trivy_raw)

        return ScanResponse(
            status="success",
            tool="trivy",
            total_findings=len(findings),
            findings=findings
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        cleanup_directory(workspace)


@app.post("/scan/gitleaks", response_model=ScanResponse)
async def scan_gitleaks(file: UploadFile = File(...)):
    if not file.filename or not is_zip_file(file.filename):
        raise HTTPException(
            status_code=400,
            detail="Only .zip project archives are supported"
        )

    scan_id = generate_scan_id()
    workspace = create_scan_workspace(scan_id)

    try:
        zip_path = save_uploaded_file(file, workspace)
        project_path = extract_zip(zip_path, workspace)

        gitleaks_raw = run_gitleaks_scan(project_path)
        findings = normalize_gitleaks_results(gitleaks_raw)

        return ScanResponse(
            status="success",
            tool="gitleaks",
            total_findings=len(findings),
            findings=findings
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        cleanup_directory(workspace)


@app.post("/scan/all", response_model=AllScanResponse)
async def scan_all(file: UploadFile = File(...)):
    if not file.filename or not is_zip_file(file.filename):
        raise HTTPException(
            status_code=400,
            detail="Only .zip project archives are supported"
        )

    scan_id = generate_scan_id()
    workspace = create_scan_workspace(scan_id)

    tool_statuses = {
        "semgrep": {"status": "not_executed", "error": None},
        "trivy": {"status": "not_executed", "error": None},
        "gitleaks": {"status": "not_executed", "error": None},
        "mitre": {"status": "not_executed", "error": None},
        "correlation": {"status": "not_executed", "error": None},
    }

    all_findings = []
    enriched_findings = []
    correlation_result = None
    incidents = []

    try:
        zip_path = save_uploaded_file(file, workspace)
        project_path = extract_zip(zip_path, workspace)

        try:
            semgrep_raw = run_semgrep_scan(project_path)
            semgrep_findings = normalize_semgrep_results(semgrep_raw)
            all_findings.extend(semgrep_findings)
            tool_statuses["semgrep"] = {"status": "success", "error": None}
        except Exception as e:
            tool_statuses["semgrep"] = {"status": "failed", "error": str(e)}

        try:
            trivy_raw = run_trivy_scan(project_path)
            trivy_findings = normalize_trivy_results(trivy_raw)
            all_findings.extend(trivy_findings)
            tool_statuses["trivy"] = {"status": "success", "error": None}
        except Exception as e:
            tool_statuses["trivy"] = {"status": "failed", "error": str(e)}

        try:
            gitleaks_raw = run_gitleaks_scan(project_path)
            gitleaks_findings = normalize_gitleaks_results(gitleaks_raw)
            all_findings.extend(gitleaks_findings)
            tool_statuses["gitleaks"] = {"status": "success", "error": None}
        except Exception as e:
            tool_statuses["gitleaks"] = {"status": "failed", "error": str(e)}

        success_count = sum(
            1 for name, tool in tool_statuses.items()
            if name in {"semgrep", "trivy", "gitleaks"} and tool["status"] == "success"
        )

        if success_count == 3:
            final_status = "success"
        elif success_count > 0:
            final_status = "partial_success"
        else:
            final_status = "failed"

        summary = build_global_summary(all_findings, tool_statuses)

        if all_findings:
            try:
                enriched_findings = enrich_findings_with_mitre(findings_to_dicts(all_findings))
                tool_statuses["mitre"] = {"status": "success", "error": None}
            except Exception as e:
                enriched_findings = findings_to_dicts(all_findings)
                tool_statuses["mitre"] = {"status": "failed", "error": str(e)}
        else:
            enriched_findings = []

        if enriched_findings:
            try:
                correlation_result = generate_incidents_from_findings(enriched_findings)
                incidents = correlation_result.get("incidents", [])
                tool_statuses["correlation"] = {"status": "success", "error": None}
            except Exception as e:
                correlation_result = None
                incidents = []
                tool_statuses["correlation"] = {"status": "failed", "error": str(e)}

        final_findings = [Finding(**item) for item in enriched_findings] if enriched_findings else all_findings

        response_payload = AllScanResponse(
            status=final_status,
            tool="sast-engine",
            summary=summary,
            findings=final_findings,
            report_path=None,
            enriched_findings_count=len(enriched_findings),
            incidents_count=len(incidents),
            incidents=incidents,
            correlation=correlation_result,
        )

        report_data = jsonable_encoder(response_payload)
        report_data["tool_errors"] = tool_statuses
        report_data["enriched_findings"] = enriched_findings

        report_path = save_json_report(scan_id, report_data)
        response_payload.report_path = str(report_path)

        if final_status == "failed":
            raise HTTPException(
                status_code=500,
                detail={
                    "message": "All scanning tools failed",
                    "tool_errors": tool_statuses,
                    "report_path": str(report_path),
                }
            )

        return response_payload

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cleanup_directory(workspace)