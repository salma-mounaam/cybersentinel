import json
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request

from app.core.config import settings
from app.services.cicd_orchestrator import execute_pipeline
from app.services.github_signature import verify_github_signature

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def parse_push_payload(payload: dict, delivery_id: str) -> dict:
    repository = payload.get("repository", {}) or {}
    head_commit = payload.get("head_commit", {}) or {}
    sender = payload.get("sender", {}) or {}

    full_name = repository.get("full_name", "")
    if "/" not in full_name:
        raise ValueError("Invalid repository full_name")

    owner, repo = full_name.split("/", 1)

    ref = payload.get("ref", "")
    branch = ref.replace("refs/heads/", "") if ref.startswith("refs/heads/") else ref

    return {
        "delivery_id": delivery_id,
        "event_type": "push",
        "repository_name": repository.get("name"),
        "repository_full_name": full_name,
        "repository_clone_url": repository.get("clone_url"),
        "repository_html_url": repository.get("html_url"),
        "owner": owner,
        "repo": repo,
        "branch": branch,
        "commit_sha": payload.get("after"),
        "before_sha": payload.get("before"),
        "author_name": (head_commit.get("author") or {}).get("name"),
        "author_email": (head_commit.get("author") or {}).get("email"),
        "sender_login": sender.get("login"),
        "compare_url": payload.get("compare"),
    }


def run_pipeline_task(github_context: dict) -> None:
    execute_pipeline(github_context)


@router.post("/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: Optional[str] = Header(default=None),
    x_hub_signature_256: Optional[str] = Header(default=None),
    x_github_delivery: Optional[str] = Header(default=None),
):
    raw_body = await request.body()

    if not verify_github_signature(
        settings.GITHUB_WEBHOOK_SECRET,
        raw_body,
        x_hub_signature_256,
    ):
        raise HTTPException(status_code=401, detail="Invalid GitHub webhook signature")

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    print(f"[WEBHOOK] Event: {x_github_event} | Delivery: {x_github_delivery}")

    if x_github_event == "ping":
        return {
            "status": "ok",
            "message": "GitHub webhook configured successfully",
            "delivery_id": x_github_delivery,
        }

    if x_github_event != "push":
        return {
            "status": "ignored",
            "message": f"Unsupported event: {x_github_event}",
            "delivery_id": x_github_delivery,
        }

    if not x_github_delivery:
        raise HTTPException(status_code=400, detail="Missing X-GitHub-Delivery header")

    try:
        github_context = parse_push_payload(payload, x_github_delivery)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    background_tasks.add_task(run_pipeline_task, github_context)

    return {
        "status": "accepted",
        "message": "Push webhook received, pipeline scheduled",
        "delivery_id": x_github_delivery,
        "repository": github_context["repository_full_name"],
        "branch": github_context["branch"],
        "commit_sha": github_context["commit_sha"],
    }