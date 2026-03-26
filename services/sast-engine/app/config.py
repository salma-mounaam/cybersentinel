import os

MITRE_SERVICE_URL = os.getenv("MITRE_SERVICE_URL", "http://mitre-service:8005")
CORRELATION_ENGINE_URL = os.getenv("CORRELATION_ENGINE_URL", "http://correlation-engine:8006")