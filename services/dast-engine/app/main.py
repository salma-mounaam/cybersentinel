from fastapi import FastAPI, HTTPException
from app.schemas import (
    SandboxCreateRequest,
    SandboxCreateResponse,
    SandboxDeleteResponse
)
from app.sandbox_manager import SandboxManager
from app.dast_service import run_dast_scan

app = FastAPI(title="CyberSentinel DAST Sandbox Manager")
sandbox_manager = SandboxManager()


@app.get("/")
def root():
    return {
        "service": "dast-sandbox-manager",
        "status": "running"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/sandbox/create", response_model=SandboxCreateResponse)
def create_sandbox(request: SandboxCreateRequest):
    try:
        result = sandbox_manager.create_target_container(
            scan_id=request.scan_id,
            target_type=request.target_type
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur création sandbox: {str(e)}")


@app.delete("/sandbox/{scan_id}", response_model=SandboxDeleteResponse)
def delete_sandbox(scan_id: str):
    try:
        result = sandbox_manager.delete_target_container(scan_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur suppression sandbox: {str(e)}")


@app.post("/sandbox/cleanup")
def cleanup_sandboxes():
    try:
        return sandbox_manager.cleanup_all_sandboxes()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur cleanup: {str(e)}")
    
@app.post("/dast/scan/{scan_id}")
def run_dast(scan_id: str):
    try:
        result = run_dast_scan(scan_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))