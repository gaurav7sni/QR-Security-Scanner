"""End-to-end UI test: real QR image -> real app.py, with the network mocked."""
import io
import time
from unittest.mock import MagicMock, patch

import pytest
import qrcode
from streamlit.testing.v1 import AppTest


def _png(data: str) -> io.BytesIO:
    buf = io.BytesIO()
    qrcode.make(data).save(buf, format="PNG")
    buf.seek(0)
    return buf


def _resp(status, body):
    r = MagicMock(); r.status_code = status; r.json.return_value = body; r.text = ""; return r


def _run_app(image, vt_payloads, gemini_body=None):
    """Run app.py with a fake uploaded file; returns the AppTest after clicking Analyze (if a button exists)."""
    script = f"""
import io, streamlit as st
st.file_uploader = lambda *a, **k: io.BytesIO({image.getvalue()!r})
import runpy; runpy.run_path("app.py", run_name="__main__")
"""
    with patch("services.virustotal.requests.request", side_effect=vt_payloads) as vt_mock, \
         patch("services.virustotal.time.sleep"), \
         patch("services.gemini.requests.post", return_value=_resp(200, gemini_body or {})) as gm_mock, \
         patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "k1", "GEMINI_API_KEY": "k2"}):
        at = AppTest.from_string(script).run(timeout=30)
        buttons = [b for b in at.button if "Analyze" in (b.label or "")]
        if buttons:
            buttons[0].click().run(timeout=30)
    return at, vt_mock, gm_mock


def _text(at):
    parts = [e.value for e in at.markdown] + [e.value for e in at.warning] + [e.value for e in at.error] \
        + [e.value for e in at.success] + [e.value for e in at.info] + [e.value for e in at.caption]
    return "\n".join(str(p) for p in parts)


GEMINI_OK = {"candidates": [{"content": {"parts": [{"text": '{"explanation": "Looks fine.", "recommendation": "Proceed carefully."}'}]}}]}


def _report(stats):
    return _resp(200, {"data": {"attributes": {"last_analysis_stats": stats, "last_analysis_date": int(time.time())}}})


@pytest.fixture(autouse=True)
def clear_scan_cache():
    import streamlit as st
    st.cache_resource.clear()


def test_safe_url_full_flow():
    stats = {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 15}
    at, vt_mock, _ = _run_app(_png("https://example.com/hello"), [_report(stats)], GEMINI_OK)
    assert not at.exception
    text = _text(at)
    assert "No Known Threat Detected" in text and "Looks fine." in text
    assert vt_mock.call_count == 1


def test_malicious_url_shows_danger():
    stats = {"malicious": 5, "suspicious": 0, "harmless": 50, "undetected": 10}
    at, _, _ = _run_app(_png("https://evil.example.net/login"), [_report(stats)], GEMINI_OK)
    assert not at.exception and "High Risk" in _text(at)


def test_wifi_qr_never_calls_apis():
    at, vt_mock, gm_mock = _run_app(_png("WIFI:T:WPA;S:Home;P:secret;H:false;;"), [])
    assert not at.exception
    assert "WiFi" in _text(at) and vt_mock.call_count == 0 and gm_mock.call_count == 0


def test_missing_keys_show_friendly_message():
    script = """
import io, streamlit as st
st.file_uploader = lambda *a, **k: io.BytesIO(%r)
import runpy; runpy.run_path("app.py", run_name="__main__")
""" % _png("https://example.com").getvalue()
    with patch.dict("os.environ", {}, clear=True):
        at = AppTest.from_string(script).run(timeout=30)
        [b for b in at.button if "Analyze" in b.label][0].click().run(timeout=30)
    assert not at.exception and "not configured" in _text(at)


def test_gemini_failure_does_not_hide_the_technical_result():
    stats = {"malicious": 0, "suspicious": 1, "harmless": 50, "undetected": 10}
    at, _, _ = _run_app(_png("https://example.com"), [_report(stats)], None)
    text = _text(at)
    assert not at.exception and "Use Caution" in text
