import os
import requests

ML_ENGINE_URL = os.getenv("ML_ENGINE_URL", "http://ml-engine:8000")


def send_features_to_ml(features: list):
    url = f"{ML_ENGINE_URL}/predict"

    response = requests.post(url, json={"features": features}, timeout=30)
    response.raise_for_status()
    return response.json()