from pydantic import BaseModel


class SandboxCreateRequest(BaseModel):
    scan_id: str
    target_type: str = "dvwa"


class SandboxCreateResponse(BaseModel):
    scan_id: str
    container_name: str
    target_url: str
    network: str
    status: str


class SandboxDeleteResponse(BaseModel):
    scan_id: str
    container_name: str
    status: str