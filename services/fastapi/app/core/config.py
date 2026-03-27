import os


class Settings:
    APP_NAME: str = os.getenv("APP_NAME", "CyberSentinel API")

    GITHUB_WEBHOOK_SECRET: str = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
    GITHUB_API_URL: str = os.getenv("GITHUB_API_URL", "https://api.github.com")

    SAST_ENGINE_URL: str = os.getenv("SAST_ENGINE_URL", "http://sast-engine:8004")
    CORRELATION_ENGINE_URL: str = os.getenv("CORRELATION_ENGINE_URL", "http://correlation-engine:8006")
    DAST_ENGINE_URL: str = os.getenv("DAST_ENGINE_URL", "http://dast-engine:8008")

    ENABLE_DAST_IN_CICD: bool = os.getenv("ENABLE_DAST_IN_CICD", "false").lower() == "true"
    CICD_CONTEXT_NAME: str = os.getenv("CICD_CONTEXT_NAME", "CyberSentinel Security Scan")

    REQUEST_TIMEOUT_SHORT: int = int(os.getenv("REQUEST_TIMEOUT_SHORT", "30"))
    REQUEST_TIMEOUT_LONG: int = int(os.getenv("REQUEST_TIMEOUT_LONG", "300"))


settings = Settings()