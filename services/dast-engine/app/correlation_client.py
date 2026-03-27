import os
import requests

CORRELATION_ENGINE_URL = os.getenv(
    "CORRELATION_ENGINE_URL",
    "http://correlation-engine:8006"
)


def send_dast_result(payload: dict):
    url = f"{CORRELATION_ENGINE_URL}/correlate/dast"
    response = requests.post(url, json=payload, timeout=30)
    response.raise_for_status()
    return response.json()