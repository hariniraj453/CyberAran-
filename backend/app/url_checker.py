"""Analyze URLs for potentially suspicious characteristics."""

import ipaddress
import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "account",
    "password",
    "confirm",
    "signin",
    "secure",
}

SUSPICIOUS_TLDS = {".click", ".top", ".xyz", ".zip"}


def analyze_url(url: str) -> dict:
    """Return a preliminary rule-based risk assessment for a URL."""
    value = url.strip()
    candidate = value if "://" in value else f"https://{value}"
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    reasons = []

    if parsed.scheme not in {"http", "https"}:
        reasons.append("Unsupported URL scheme")

    if not host or "." not in host:
        reasons.append("Invalid or incomplete hostname")

    if "@" in parsed.netloc:
        reasons.append("URL contains an @ symbol in its authority")

    if host:
        try:
            ipaddress.ip_address(host)
            reasons.append("Uses an IP address instead of a domain name")
        except ValueError:
            pass

    if re.search(r"https?://[^/]*-[^/]*\.", candidate, re.IGNORECASE):
        reasons.append("Hostname contains hyphens")

    if any(word in value.lower() for word in SUSPICIOUS_KEYWORDS):
        reasons.append("Contains a security-sensitive keyword")

    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        reasons.append("Uses a TLD that warrants extra scrutiny")

    if len(host) > 50:
        reasons.append("Hostname is unusually long")

    if parsed.scheme == "http":
        reasons.append("Uses unencrypted HTTP")

    if any("Invalid" in reason for reason in reasons):
        risk = "high"
    elif any(
        reason in reasons
        for reason in [
            "URL contains an @ symbol in its authority",
            "Uses an IP address instead of a domain name",
            "Uses a TLD that warrants extra scrutiny",
        ]
    ):
        risk = "high"
    elif reasons:
        risk = "medium"
    else:
        risk = "low"

    return {
        "url": value,
        "risk_level": risk,
        "reasons": reasons,
        "note": (
            "This is a preliminary rule-based assessment, not proof "
            "that a URL is safe or malicious."
        ),
    }
