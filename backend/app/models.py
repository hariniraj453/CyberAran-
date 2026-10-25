
"""Database models for CyberAran."""

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String, Text

from app.database import Base


class ThreatReport(Base):
    """Database table for submitted threat reports."""

    __tablename__ = "threat_reports"

    report_id = Column(String(36), primary_key=True)
    url = Column(Text, nullable=False)
    description = Column(Text, nullable=False)
    reporter = Column(String(100), nullable=False, default="Anonymous")
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    status = Column(String(20), nullable=False, default="received")
