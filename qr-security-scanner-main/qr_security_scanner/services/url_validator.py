"""URL validation and normalization. This module does not assess safety."""
import re
from typing import Tuple
from urllib.parse import urlparse

_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$")


def normalize_url(data: str) -> str:
    text = (data or "").strip()
    if not text:
        return ""
    parsed = urlparse(text)
    if parsed.scheme in ("http", "https"):
        return text
    if text.lower().startswith("www.") or _DOMAIN_RE.match(text.split("/", 1)[0]):
        return "https://" + text
    return text


def validate_url(data: str) -> Tuple[bool, str]:
    text = normalize_url(data)
    if not text:
        return False, "No data to validate."
    try:
        parsed = urlparse(text)
    except ValueError:
        return False, "Could not parse this as a URL."
    if parsed.scheme not in ("http", "https"):
        return False, "Unsupported or missing scheme. Expected http or https."
    if not parsed.hostname:
        return False, "URL has no domain/host."
    if any(ch.isspace() for ch in text):
        return False, "URL contains whitespace."
    if parsed.username or parsed.password:
        return False, "URLs containing embedded credentials are not accepted."
    return True, "URL format is valid."
