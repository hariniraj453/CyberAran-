"""Analyze URLs for potentially suspicious characteristics."""

from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "account",
    "password",
    "confirm",
}

SUSPICIOUS_TLDS = {".click", ".top", ".xyz", ".zip"}


def analyze_url(url: str) -> dict:
    """Return a preliminary risk assessment for a URL."""
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

    if any(word in value.lower() for word in SUSPICIOUS_KEYWORDS):
        reasons.append("Contains a security-sensitive keyword")

    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        reasons.append("Uses a TLD that warrants extra scrutiny")

    if len(host) > 50:
        reasons.append("Hostname is unusually long")

    if any("Invalid" in reason for reason in reasons):
        risk = "high"
    elif (
        "URL contains an @ symbol in its authority" in reasons
        or "Uses a TLD that warrants extra scrutiny" in reasons
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
            "This is a preliminary rule-based assessment, "
            "not proof that a URL is safe or malicious."
        ),
    }
