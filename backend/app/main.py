
"""FastAPI application for CyberAran."""

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from app import models
from app.database import Base, SessionLocal, engine
from app.threat_reports import ThreatReportRequest
from app.url_checker import analyze_url

app = FastAPI(
    title="CyberAran API",
    description="Cybersecurity Threat Reporting and Intelligence Platform",
    version="0.3.0",
)

Base.metadata.create_all(bind=engine)


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


@app.post("/threat-reports", status_code=201)
def submit_threat_report(request: ThreatReportRequest) -> dict:
    """Save a submitted threat report to the database."""

    db: Session = SessionLocal()

    try:
        report = models.ThreatReport(
            report_id=str(uuid4()),
            url=str(request.url),
            description=request.description,
            reporter=request.reporter,
            created_at=datetime.now(timezone.utc),
            status="received",
        )

        db.add(report)
        db.commit()
        db.refresh(report)

        return {
            "report_id": report.report_id,
            "url": report.url,
            "description": report.description,
            "reporter": report.reporter,
            "created_at": report.created_at.isoformat(),
            "status": report.status,
        }

    finally:
        db.close()


@app.get("/threat-reports")
def get_threat_reports() -> list[dict]:
    """Retrieve all submitted threat reports."""

    db: Session = SessionLocal()

    try:
        reports = (
            db.query(models.ThreatReport)
            .order_by(models.ThreatReport.created_at.desc())
            .all()
        )

        return [
            {
                "report_id": report.report_id,
                "url": report.url,
                "description": report.description,
                "reporter": report.reporter,
                "created_at": report.created_at.isoformat(),
                "status": report.status,
            }
            for report in reports
        ]

    finally:
        db.close()
