from fastapi import FastAPI

app = FastAPI(
    title="CyberAran API",
    description="Cybersecurity Threat Reporting and Intelligence Platform",
    version="0.1.0",
)


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
