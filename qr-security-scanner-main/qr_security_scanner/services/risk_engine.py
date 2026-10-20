"""Deterministic, evidence-based risk assessment for QR URLs."""
import ipaddress
from typing import Any, Dict, List
from urllib.parse import urlparse

# Link shorteners hide the real destination, which is exactly what a
# malicious QR code wants. Common in legitimate QR codes too, so this is a
# caution, never proof of anything.
SHORTENER_DOMAINS = (
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "v.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
    "t.ly", "s.id", "qrco.de",
)


def _is_ip_host(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _is_shortener(host: str) -> bool:
    host = (host or "").lower()
    return any(host == d or host.endswith("." + d) for d in SHORTENER_DOMAINS)


def _url_signals(url: str) -> List[str]:
    """Simple URL-shape cautions. These are warnings only, never proof of danger."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    signals = []
    if parsed.scheme.lower() == "http":
        signals.append("The URL uses HTTP instead of HTTPS, so the connection is not encrypted")
    if _is_ip_host(host):
        signals.append("The URL uses a raw IP address instead of a domain name")
    if "@" in parsed.netloc:
        signals.append("The URL contains an @ character in its authority section")
    if _is_shortener(host):
        signals.append("This is a shortened link, so the real destination is hidden")
    if len(url) > 2048:
        signals.append("The URL is unusually long")
    return signals


def assess_url(vt_stats: Dict[str, int], url: str) -> Dict[str, Any]:
    """Return a deterministic risk label from VT evidence and simple URL signals.

    VirusTotal detections dominate the decision. URL heuristics can raise a
    caution, but HTTPS or a normal-looking domain never proves a URL is safe.
    """
    malicious = int(vt_stats.get("malicious", 0) or 0)
    suspicious = int(vt_stats.get("suspicious", 0) or 0)
    harmless = int(vt_stats.get("harmless", 0) or 0)
    undetected = int(vt_stats.get("undetected", 0) or 0)
    stats = {"malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": undetected}

    url_signals = _url_signals(url)

    if malicious > 0:
        return {
            "verdict": "DANGER",
            "title": "High Risk",
            "emoji": "🔴",
            "reason": f"VirusTotal reported {malicious} malicious detection(s).",
            "signals": [f"{malicious} malicious detection(s)"] + url_signals,
            "score": 100,
            "confidence": "strong",
            "stats": stats,
        }

    signals: List[str] = []
    if suspicious > 0:
        signals.append(f"{suspicious} suspicious detection(s) from VirusTotal")
    signals.extend(url_signals)

    if signals:
        verdict, title, emoji = "WARNING", "Use Caution", "🟡"
        reason = signals[0]
        score = min(80, 20 + suspicious * 15 + len(url_signals) * 10)
    else:
        verdict, title, emoji = "LOW_RISK", "No Known Threat Detected", "🟢"
        reason = "VirusTotal reported no malicious or suspicious detections for this URL."
        signals = [reason]
        score = 0

    return {
        "verdict": verdict,
        "title": title,
        "emoji": emoji,
        "reason": reason,
        "signals": signals,
        "score": score,
        "confidence": "limited",
        "stats": stats,
    }
