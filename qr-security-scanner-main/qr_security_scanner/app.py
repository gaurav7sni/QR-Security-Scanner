"""QR Security Scanner Streamlit application."""
import time
from datetime import datetime, timezone

import streamlit as st
from PIL import Image, UnidentifiedImageError

from services.qr_decoder import decode_qr
from services.payload_analyzer import analyze_payload, PAYLOAD_MESSAGES
from services.url_validator import validate_url, normalize_url
from services.virustotal import get_or_scan_url, VirusTotalError, VirusTotalPending
from services.risk_engine import assess_url
from services.gemini import get_explanation, GeminiError
from utils.helpers import get_secret

MAX_IMAGE_PIXELS = 25_000_000   # reject absurdly large images (decompression bombs)
SCAN_CACHE_SECONDS = 3600       # reuse a fresh result for the same URL for an hour
SCAN_CACHE_MAX_ENTRIES = 500

st.set_page_config(page_title="QR Security Scanner", page_icon="🔐", layout="centered")


@st.cache_resource
def _scan_cache() -> dict:
    """Process-wide cache so repeat scans of one URL don't burn VirusTotal's tiny free quota."""
    return {}


def scan_url_cached(url: str, api_key: str) -> dict:
    cache = _scan_cache()
    hit = cache.get(url)
    if hit and time.time() - hit[0] < SCAN_CACHE_SECONDS:
        return hit[1]
    result = get_or_scan_url(url, api_key)
    if not result.get("stale"):          # never cache an out-of-date fallback
        if len(cache) >= SCAN_CACHE_MAX_ENTRIES:
            cache.pop(next(iter(cache)))
        cache[url] = (time.time(), result)
    return result


def _format_date(timestamp) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%d %b %Y")


st.title("🔐 QR Security Scanner")
st.caption("Scan Before You Visit")

for key, default in {
    "scan_url": None, "vt_stats": None, "assessment": None,
    "vt_error": None, "ai_explanation": None, "ai_error": None,
}.items():
    st.session_state.setdefault(key, default)

uploaded_file = st.file_uploader("Upload a QR code image", type=["png", "jpg", "jpeg", "webp"])

if uploaded_file is None:
    st.info("Upload a QR code image to get started.")
    st.stop()

try:
    image = Image.open(uploaded_file)
    if image.width * image.height > MAX_IMAGE_PIXELS:
        st.error("This image is too large. Please upload a smaller photo or screenshot of the QR code.")
        st.stop()
    image.load()
except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
    st.error("The uploaded file is not a valid image.")
    st.stop()

st.image(image, caption="Uploaded QR code", width=280)
decoded_data = decode_qr(image)

if decoded_data is None:
    st.error("❌ No QR code detected. Try a sharper, well-lit image with the full QR code visible.")
    st.stop()

st.success("QR code detected ✓")
payload = analyze_payload(decoded_data)
payload_type = payload["type"]
details = payload["details"]
st.subheader(f"Payload type: {payload_type}")

if payload_type != "URL":
    st.info(PAYLOAD_MESSAGES.get(payload_type, "This QR code contains data that is not a website URL."))
    if payload_type == "WiFi":
        st.write(f"**SSID:** {details.get('ssid') or 'Not provided'}")
        st.write(f"**Encryption:** {details.get('encryption') or 'Not provided'}")
        if details.get("password"):
            if st.checkbox("Show Wi-Fi password", key="show_wifi_password"):
                st.code(details["password"])
            else:
                st.caption("Wi-Fi password hidden by default.")
    else:
        for label, value in details.items():
            if value not in (None, ""):
                st.write(f"**{label.replace('_', ' ').title()}:** {value}")
    st.stop()

raw_url = details["url"]
url = normalize_url(raw_url)
is_valid, reason = validate_url(url)
st.code(url, language=None)

if not is_valid:
    st.warning(f"⚠️ {reason}")
    st.stop()

st.success(f"✅ {reason}")

if st.session_state.get("scan_url") != url:
    for key in ("vt_stats", "assessment", "vt_error", "ai_explanation", "ai_error"):
        st.session_state[key] = None
    st.session_state["scan_url"] = url

if st.button("🔍 Analyze Security", type="primary"):
    st.session_state.update({"vt_stats": None, "assessment": None, "vt_error": None, "ai_explanation": None, "ai_error": None})
    vt_key = get_secret("VIRUSTOTAL_API_KEY")
    gemini_key = get_secret("GEMINI_API_KEY")

    with st.spinner("Checking VirusTotal (a brand-new scan can take up to ~40 seconds)..."):
        try:
            stats = scan_url_cached(url, vt_key)
            assessment = assess_url(stats, url)
            st.session_state["vt_stats"] = stats
            st.session_state["assessment"] = assessment
        except VirusTotalPending as exc:
            st.session_state["vt_error"] = str(exc)
        except VirusTotalError as exc:
            st.session_state["vt_error"] = str(exc)

    if st.session_state["assessment"] and gemini_key:
        with st.spinner("Generating a plain-language explanation..."):
            try:
                st.session_state["ai_explanation"] = get_explanation(url, st.session_state["assessment"], gemini_key)
            except GeminiError as exc:
                st.session_state["ai_error"] = str(exc)

st.caption(
    "🔒 Privacy: the URL is sent to VirusTotal (submitted URLs may be visible to its community) and, "
    "if configured, to Google Gemini. Don't scan QR codes that contain private links or tokens."
)

if st.session_state.get("vt_error"):
    st.warning(f"⚠️ {st.session_state['vt_error']}")

stats = st.session_state.get("vt_stats")
assessment = st.session_state.get("assessment")
if stats and assessment:
    st.markdown(f"## {assessment['emoji']} {assessment['title']}")
    if assessment["verdict"] == "DANGER":
        st.error(assessment["reason"])
    elif assessment["verdict"] == "WARNING":
        st.warning(assessment["reason"])
    else:
        st.success(assessment["reason"])

    st.markdown("**Why?**")
    for signal in assessment["signals"]:
        st.write(f"• {signal}")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Malicious", stats["malicious"])
    c2.metric("Suspicious", stats["suspicious"])
    c3.metric("Harmless", stats["harmless"])
    c4.metric("Undetected", stats["undetected"])

    final_url = stats.get("final_url")
    if final_url and final_url.rstrip("/") != url.rstrip("/"):
        st.write("**VirusTotal saw this link redirect to:**")
        st.code(final_url, language=None)

    if stats.get("stale") and stats.get("analyzed_at"):
        st.warning(
            f"This VirusTotal report is from {_format_date(stats['analyzed_at'])} and may be out of date — "
            "a fresh scan was still processing. Try again in a minute."
        )
    elif stats.get("analyzed_at"):
        st.caption(f"VirusTotal analysis date: {_format_date(stats['analyzed_at'])}")

    if assessment["verdict"] == "LOW_RISK":
        st.caption("No known threat was detected by the available evidence. This is not a guarantee that the website is safe.")
    else:
        st.caption("This assessment is based on available security evidence and should not be treated as a guarantee.")

    explanation = st.session_state.get("ai_explanation")
    if explanation:
        st.subheader("🤖 AI Explanation")
        st.write(explanation["explanation"])
        st.info(f"Recommendation: {explanation['recommendation']}")
    elif st.session_state.get("ai_error"):
        st.info(f"AI explanation unavailable: {st.session_state['ai_error']}")
