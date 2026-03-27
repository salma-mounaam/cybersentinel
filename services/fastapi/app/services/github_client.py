from typing import Optional

import requests

from app.core.config import settings


def _headers() -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"

    return headers


def set_commit_status(
    owner: str,
    repo: str,
    sha: str,
    state: str,
    description: str,
    context: Optional[str] = None,
    target_url: Optional[str] = None,
) -> dict:
    """
    state: pending | success | failure | error
    """
    url = f"{settings.GITHUB_API_URL}/repos/{owner}/{repo}/statuses/{sha}"

    payload = {
        "state": state,
        "description": description[:140],
        "context": context or settings.CICD_CONTEXT_NAME,
    }

    if target_url:
        payload["target_url"] = target_url

    print(f"[GITHUB] Sending status to {owner}/{repo}@{sha}")
    print(f"[GITHUB] State: {state}")
    print(f"[GITHUB] Context: {payload['context']}")

    response = requests.post(
        url,
        headers=_headers(),
        json=payload,
        timeout=settings.REQUEST_TIMEOUT_SHORT,
    )

    print(f"[GITHUB] Response status: {response.status_code}")
    if response.text:
        print(f"[GITHUB] Response body: {response.text[:500]}")

    response.raise_for_status()
    return response.json()