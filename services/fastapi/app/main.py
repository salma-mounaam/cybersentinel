from fastapi import FastAPI

from app.api.github_webhook import router as github_webhook_router
from app.core.config import settings

app = FastAPI(title=settings.APP_NAME)

app.include_router(github_webhook_router)


@app.get("/")
def root():
    return {
        "service": settings.APP_NAME,
        "status": "running",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }