import os
import requests

ML_ENGINE_URL = os.getenv("ML_ENGINE_URL", "http://ml-engine:8000")


def send_features_to_ml(features: dict):
    """
    Envoie un dictionnaire de features numériques au ml-engine.

    Format attendu par ml-engine :
    {
        "features": {
            "Flow Duration": 12.5,
            "Total Fwd Packets": 40.0,
            ...
        }
    }
    """
    url = f"{ML_ENGINE_URL}/predict"
    response = requests.post(url, json={"features": features}, timeout=30)
    response.raise_for_status()
    return response.json()