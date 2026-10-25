
"""Validate threat reports submitted to CyberAran."""

from pydantic import BaseModel, Field, HttpUrl


class ThreatReportRequest(BaseModel):
    """Data required to submit a threat report."""

    url: HttpUrl
    description: str = Field(min_length=5, max_length=1000)
    reporter: str = Field(default="Anonymous", max_length=100)
