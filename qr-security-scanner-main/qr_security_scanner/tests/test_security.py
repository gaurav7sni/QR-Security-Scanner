from services.risk_engine import assess_url
from services.url_validator import normalize_url, validate_url
from services.payload_analyzer import analyze_payload

CLEAN = {"malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 10}


def test_normalize_bare_domain():
    assert normalize_url("example.com") == "https://example.com"


def test_reject_embedded_credentials():
    ok, _ = validate_url("https://user:pass@example.com")
    assert not ok


def test_reject_non_http_scheme():
    ok, _ = validate_url("javascript:alert(1)")
    assert not ok


def test_malicious_is_danger():
    result = assess_url({**CLEAN, "malicious": 1}, "https://example.com")
    assert result["verdict"] == "DANGER"


def test_suspicious_is_warning():
    result = assess_url({**CLEAN, "suspicious": 1}, "https://example.com")
    assert result["verdict"] == "WARNING"


def test_no_detection_is_low_risk_not_guaranteed_safe():
    result = assess_url(CLEAN, "https://example.com")
    assert result["verdict"] == "LOW_RISK"


def test_http_alone_is_a_caution():
    result = assess_url(CLEAN, "http://example.com")
    assert result["verdict"] == "WARNING"
    assert any("HTTP" in s for s in result["signals"])


def test_raw_ip_is_a_caution():
    assert assess_url(CLEAN, "https://192.168.1.10/login")["verdict"] == "WARNING"


def test_shortener_is_a_caution_including_subdomains():
    assert assess_url(CLEAN, "https://bit.ly/abc123")["verdict"] == "WARNING"
    assert assess_url(CLEAN, "https://go.bit.ly/abc123")["verdict"] == "WARNING"
    # look-alike domain that merely *ends with* the same letters must not match
    assert assess_url(CLEAN, "https://orbit.ly.example.com/x")["verdict"] == "LOW_RISK"


def test_danger_still_lists_url_signals():
    result = assess_url({**CLEAN, "malicious": 3}, "http://example.com")
    assert result["verdict"] == "DANGER" and len(result["signals"]) == 2


def test_wifi_parser():
    result = analyze_payload("WIFI:T:WPA;S:Home;P:secret;H:false;;")
    assert result["type"] == "WiFi"
    assert result["details"]["ssid"] == "Home"


def test_payload_types():
    assert analyze_payload("https://example.com")["type"] == "URL"
    assert analyze_payload("upi://pay?pa=a@bank&pn=Shop&am=10&cu=INR")["type"] == "UPI Payment"
    assert analyze_payload("tel:+911234567890")["type"] == "Phone"
    assert analyze_payload("just some text")["type"] == "Text"
