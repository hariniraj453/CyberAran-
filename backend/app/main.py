"""FastAPI application for CyberAran."""

from fastapi import FastAPI
from pydantic import BaseModel, HttpUrl

from app.url_checker import analyze_url

app = FastAPI(
    title="CyberAran API",
    description="Cybersecurity Threat Reporting and Intelligence Platform",
    version="0.2.0",
)


class URLCheckRequest(BaseModel):
    """Request body for checking a URL."""

    url: HttpUrl


@app.get("/")
def home() -> dict[str, str]:
    """Return the CyberAran welcome message."""
    return {
        "project": "CyberAran",
        "message": "Your Digital Fortress",
        "status": "running",
    }


@app.get("/health")
def health_check() -> dict[str, str]:
    """Check whether the API is running."""
    return {"status": "healthy"}


@app.post("/check-url")
def check_url(request: URLCheckRequest) -> dict:
    """Analyze a submitted URL and return its preliminary risk assessment."""
    return analyze_url(str(request.url))
