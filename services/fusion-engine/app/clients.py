import os
import requests

CORRELATION_ENGINE_URL = os.getenv("CORRELATION_ENGINE_URL", "http://correlation-engine:8006")


def send_to_correlation_engine(findings: list) -> dict:
    response = requests.post(
        f"{CORRELATION_ENGINE_URL}/incidents",
        json={"findings": findings},
        timeout=120
    )
    response.raise_for_status()
    return response.json()