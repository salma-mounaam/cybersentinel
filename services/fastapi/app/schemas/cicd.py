from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GitHubPushContext(BaseModel):
    delivery_id: str
    event_type: str = "push"

    repository_name: str
    repository_full_name: str
    repository_clone_url: Optional[str] = None
    repository_html_url: Optional[str] = None

    owner: str
    repo: str
    branch: str
    commit_sha: str
    before_sha: Optional[str] = None

    author_name: Optional[str] = None
    author_email: Optional[str] = None
    sender_login: Optional[str] = None
    compare_url: Optional[str] = None


class QualityGateResult(BaseModel):
    status: str
    reasons: List[str] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)


class PipelineResult(BaseModel):
    pipeline_status: str
    sast_result: Dict[str, Any] = Field(default_factory=dict)
    dast_result: Dict[str, Any] = Field(default_factory=dict)
    correlation_result: Dict[str, Any] = Field(default_factory=dict)
    quality_gate: QualityGateResult