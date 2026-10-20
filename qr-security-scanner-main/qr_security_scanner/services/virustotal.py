"""VirusTotal API v3 integration for URL reputation."""
import base64
import time
from typing import Any, Dict, Optional

import requests

from utils.helpers import extract_error_message

VT_BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT = 20

# Public VT API is limited to 4 requests/minute. After a fresh submission we
# make at most two status requests, spaced far enough apart to stay conservative.
POLL_DELAYS = (20, 20)

# A cached VirusTotal report older than this is not trusted: a site that was
# clean last year may be hosting phishing today, so we ask VT to re-scan it.
MAX_REPORT_AGE_SECONDS = 7 * 24 * 3600

_COUNT_KEYS = ("malicious", "suspicious", "harmless", "undetected")


class VirusTotalError(Exception):
    """User-facing VirusTotal error."""


class VirusTotalPending(VirusTotalError):
    """The submitted URL is still being analyzed."""


def _url_to_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _extract_stats(stats: dict) -> Dict[str, int]:
    return {key: int(stats.get(key, 0) or 0) for key in _COUNT_KEYS}


def _has_engine_results(stats: Dict[str, int]) -> bool:
    """True if at least one engine actually analysed the URL.

    A report whose counts are all zero means "never analysed", NOT "clean".
    """
    return sum(stats[key] for key in _COUNT_KEYS) > 0


def _result(stats: Dict[str, int], analyzed_at: Optional[int], final_url: Optional[str], stale: bool = False) -> Dict[str, Any]:
    return {**stats, "analyzed_at": analyzed_at, "final_url": final_url, "stale": stale}


def _request(method: str, url: str, api_key: str, **kwargs) -> requests.Response:
    headers = kwargs.pop("headers", {})
    headers["x-apikey"] = api_key
    headers["Accept"] = "application/json"
    try:
        return requests.request(method, url, headers=headers, timeout=DEFAULT_TIMEOUT, **kwargs)
    except requests.exceptions.Timeout as exc:
        raise VirusTotalError("VirusTotal timed out. Please try again.") from exc
    except requests.exceptions.RequestException as exc:
        raise VirusTotalError(f"Could not reach VirusTotal: {exc}") from exc


def _raise_api_error(response: requests.Response, action: str) -> None:
    detail = extract_error_message(response)
    if response.status_code == 401:
        raise VirusTotalError("VirusTotal rejected the API key. Check VIRUSTOTAL_API_KEY.")
    if response.status_code == 403:
        raise VirusTotalError("VirusTotal denied this API request (403). Check the key and API permissions.")
    if response.status_code == 429:
        raise VirusTotalError("VirusTotal rate limit reached. Wait a minute and try again.")
    msg = f"VirusTotal {action} failed ({response.status_code})."
    if detail:
        msg += f" {detail}"
    raise VirusTotalError(msg)


def _parse_url_report(response: requests.Response) -> Dict[str, Any]:
    try:
        attrs = response.json()["data"]["attributes"]
        stats = _extract_stats(attrs.get("last_analysis_stats") or {})
        analyzed_at = attrs.get("last_analysis_date")
        return _result(
            stats,
            int(analyzed_at) if analyzed_at else None,
            attrs.get("last_final_url"),
        )
    except (ValueError, KeyError, TypeError) as exc:
        raise VirusTotalError("VirusTotal returned an unexpected URL report format.") from exc


def _parse_analysis(response: requests.Response) -> tuple[str, Optional[Dict[str, int]], Optional[int]]:
    try:
        attrs = response.json()["data"]["attributes"]
        status = attrs.get("status", "")
        stats = _extract_stats(attrs.get("stats") or {})
        date = attrs.get("date")
        return status, stats if _has_engine_results(stats) else None, int(date) if date else None
    except (ValueError, KeyError, TypeError) as exc:
        raise VirusTotalError("VirusTotal returned an unexpected analysis format.") from exc


def _is_fresh(report: Dict[str, Any]) -> bool:
    analyzed_at = report.get("analyzed_at")
    if not analyzed_at or not _has_engine_results(report):
        return False
    return (time.time() - analyzed_at) <= MAX_REPORT_AGE_SECONDS


def _submit_and_wait(url: str, api_key: str) -> Dict[str, Any]:
    """Submit a URL for a new scan and poll (rate-limit-consciously) for the result."""
    submit = _request("POST", f"{VT_BASE_URL}/urls", api_key, data={"url": url})
    if submit.status_code != 200:
        _raise_api_error(submit, "URL submission")

    try:
        analysis_id = submit.json()["data"]["id"]
    except (ValueError, KeyError, TypeError) as exc:
        raise VirusTotalError("VirusTotal did not return an analysis ID.") from exc

    for delay in POLL_DELAYS:
        time.sleep(delay)
        analysis = _request("GET", f"{VT_BASE_URL}/analyses/{analysis_id}", api_key)
        if analysis.status_code != 200:
            _raise_api_error(analysis, "analysis lookup")
        status, stats, date = _parse_analysis(analysis)
        if status == "completed" and stats is not None:
            return _result(stats, date or int(time.time()), None)

    raise VirusTotalPending(
        "VirusTotal accepted the URL, but the analysis is still processing. Try again in about a minute."
    )


def get_or_scan_url(url: str, api_key: Optional[str]) -> Dict[str, Any]:
    """
    Return VirusTotal results for a URL.

    Result keys: malicious, suspicious, harmless, undetected (ints),
    analyzed_at (unix time or None), final_url (where VT saw the URL
    redirect to, or None), stale (True if an old report is being shown
    because a fresh scan was still processing).

    A cached report is only used if it is recent and actually contains
    engine results. Otherwise a new scan is requested.
    """
    if not api_key:
        raise VirusTotalError(
            "VirusTotal API key is not configured. Add VIRUSTOTAL_API_KEY to .streamlit/secrets.toml "
            "(or set it as an environment variable)."
        )

    cached: Optional[Dict[str, Any]] = None
    report = _request("GET", f"{VT_BASE_URL}/urls/{_url_to_id(url)}", api_key)

    if report.status_code == 200:
        cached = _parse_url_report(report)
        if _is_fresh(cached):
            return cached
    elif report.status_code != 404:
        _raise_api_error(report, "URL lookup")

    try:
        return _submit_and_wait(url, api_key)
    except VirusTotalPending:
        # The re-scan isn't done yet. An old report with real results is
        # better than nothing, as long as the UI says it is out of date.
        if cached is not None and _has_engine_results(cached):
            return {**cached, "stale": True}
        raise
