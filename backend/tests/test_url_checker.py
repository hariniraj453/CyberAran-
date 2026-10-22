
"""Tests for the CyberAran URL checker."""

from app.url_checker import analyze_url


def test_normal_url_has_low_risk():
    """A normal-looking URL should have low risk."""
    result = analyze_url("https://example.com")
    assert result["risk_level"] == "low"


def test_login_keyword_is_flagged():
    """A URL containing a sensitive keyword should be flagged."""
    result = analyze_url("https://example.com/login")
    assert result["risk_level"] == "medium"
    assert "Contains a security-sensitive keyword" in result["reasons"]


def test_suspicious_tld_is_high_risk():
    """A URL using a flagged TLD should receive high risk."""
    result = analyze_url("https://example.xyz")
    assert result["risk_level"] == "high"


def test_result_contains_required_fields():
    """The result should contain the expected fields."""
    result = analyze_url("https://example.com")
    assert "url" in result
    assert "risk_level" in result
    assert "reasons" in result
    assert "note" in result
