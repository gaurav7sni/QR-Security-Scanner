"""
payload_analyzer.py
--------------------
Classifies decoded QR data into a payload type (URL, WiFi, vCard,
Email, SMS, Phone, Location, UPI Payment, or plain Text) and extracts
the type-specific fields worth showing the user.

This runs right after QR decoding and before URL-specific analysis:
only a "URL" payload continues on to url_validator / VirusTotal /
Gemini. Every other type is informational only — there's no website
to check the safety of, so we just show the user what's inside it.

Formats recognized follow the common QR "special payload" conventions
(WIFI:, BEGIN:VCARD, mailto:, MATMSG:, SMSTO:, tel:, geo:, upi://).
"""

from typing import Any, Dict
from urllib.parse import urlparse, parse_qs, unquote

PAYLOAD_MESSAGES = {
    "WiFi": "This QR code contains WiFi network credentials.",
    "vCard": "This QR code contains a contact card.",
    "Email": "This QR code contains an email draft.",
    "SMS": "This QR code contains a pre-filled text message.",
    "Phone": "This QR code contains a phone number to call.",
    "Location": "This QR code contains GPS coordinates.",
    "UPI Payment": "This QR code contains a UPI payment request.",
    "Text": "This QR code contains plain text — not a URL or a recognized format.",
}


def analyze_payload(data: str) -> Dict[str, Any]:
    """
    Classify decoded QR text and extract its key fields.

    Args:
        data: The raw string decoded from the QR code.

    Returns:
        {"type": <str>, "details": <dict>}
        `type` is one of: URL, WiFi, vCard, Email, SMS, Phone,
        Location, UPI Payment, Text, Unknown (only for empty input).
    """
    if not data:
        return {"type": "Unknown", "details": {}}

    text = data.strip()

    if _looks_like_url(text):
        return {"type": "URL", "details": {"url": text}}

    if text.upper().startswith("WIFI:"):
        return {"type": "WiFi", "details": _parse_wifi(text)}

    if text.upper().startswith("BEGIN:VCARD"):
        return {"type": "vCard", "details": _parse_vcard(text)}

    if text.lower().startswith("mailto:") or text.upper().startswith("MATMSG:"):
        return {"type": "Email", "details": _parse_email(text)}

    if text.upper().startswith("SMSTO:") or text.upper().startswith("SMS:"):
        return {"type": "SMS", "details": _parse_sms(text)}

    if text.lower().startswith("tel:"):
        return {"type": "Phone", "details": {"phone_number": text[len("tel:"):].strip()}}

    if text.lower().startswith("geo:"):
        return {"type": "Location", "details": _parse_geo(text)}

    if text.lower().startswith("upi://"):
        return {"type": "UPI Payment", "details": _parse_upi(text)}

    return {"type": "Text", "details": {"text": text}}


def _looks_like_url(text: str) -> bool:
    try:
        return urlparse(text).scheme in ("http", "https")
    except ValueError:
        return False


def _parse_wifi(text: str) -> Dict[str, Any]:
    # Format: WIFI:T:WPA;S:MyNetwork;P:MyPassword;H:false;;
    body = text[len("WIFI:"):]
    fields = {"T": "", "S": "", "P": "", "H": "false"}
    for part in body.split(";"):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        key = key.strip().upper()
        if key in fields:
            fields[key] = value.strip()
    return {
        "ssid": fields["S"],
        "password": fields["P"],
        "encryption": fields["T"] or "None",
        "hidden": fields["H"].lower() == "true",
    }


def _parse_vcard(text: str) -> Dict[str, str]:
    details: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        upper = line.upper()
        if upper.startswith("FN:"):
            details["name"] = line.split(":", 1)[1]
        elif upper.startswith("TEL"):
            details["phone"] = line.split(":", 1)[-1]
        elif upper.startswith("EMAIL"):
            details["email"] = line.split(":", 1)[-1]
        elif upper.startswith("ORG:"):
            details["organization"] = line.split(":", 1)[1]
    return details


def _parse_email(text: str) -> Dict[str, str]:
    if text.lower().startswith("mailto:"):
        parsed = urlparse(text)
        query = parse_qs(parsed.query)
        return {
            "to": parsed.path,
            "subject": query.get("subject", [""])[0],
            "body": query.get("body", [""])[0],
        }
    # MATMSG:TO:person@example.com;SUB:Hello;BODY:Hi there;;
    fields = {"TO": "", "SUB": "", "BODY": ""}
    for part in text[len("MATMSG:"):].split(";"):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        key = key.strip().upper()
        if key in fields:
            fields[key] = value.strip()
    return {"to": fields["TO"], "subject": fields["SUB"], "body": fields["BODY"]}


def _parse_sms(text: str) -> Dict[str, str]:
    # Format: SMSTO:+1234567890:message text
    body = text.split(":", 1)[1] if ":" in text else text
    number, _, message = body.partition(":")
    return {"phone_number": number.strip(), "message": message.strip()}


def _parse_geo(text: str) -> Dict[str, str]:
    # Format: geo:37.786971,-122.399677
    coords = text[len("geo:"):].split(",")
    return {
        "latitude": coords[0].strip() if len(coords) > 0 else "",
        "longitude": coords[1].strip() if len(coords) > 1 else "",
    }


def _parse_upi(text: str) -> Dict[str, str]:
    # Format: upi://pay?pa=someone@bank&pn=Some+Name&am=100&cu=INR
    parsed = urlparse(text)
    query = parse_qs(parsed.query)
    return {
        "payee_address": query.get("pa", [""])[0],
        "payee_name": unquote(query.get("pn", [""])[0]),
        "amount": query.get("am", [""])[0],
        "currency": query.get("cu", [""])[0],
    }
