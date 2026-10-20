# 🔐 QR Security Scanner — *Scan Before You Visit*

Upload a photo or screenshot of a QR code and find out what's inside **before** you open it.

- Decodes the QR code (OpenCV — no system libraries needed)
- Identifies the payload: **URL, Wi-Fi, vCard, Email, SMS, Phone, Location, UPI payment, or plain text**
- For URLs: checks reputation with **VirusTotal**, applies a **deterministic risk engine**, and (optionally) asks **Gemini** to explain the result in plain language

## How the verdict works

| Verdict | When |
|---|---|
| 🔴 **High Risk** | VirusTotal reports one or more *malicious* detections |
| 🟡 **Use Caution** | VirusTotal reports *suspicious* detections, **or** the URL uses HTTP, a raw IP address, a shortened link (bit.ly etc.), an `@` in the address, or is unusually long |
| 🟢 **No Known Threat Detected** | Nothing found — *not* a guarantee the site is safe |

The verdict is decided by plain rules in `services/risk_engine.py`. Gemini never decides it; it only explains it.

Reports older than 7 days, or with no engine results, are not trusted — the app asks VirusTotal for a fresh scan instead.

## Run locally

Requires Python 3.10+.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
```

Edit `.streamlit/secrets.toml` (it must sit next to `app.py`, in the `.streamlit` folder) and add your keys:

- VirusTotal (free): https://www.virustotal.com/gui/join-us
- Gemini (free tier): https://aistudio.google.com/apikey

```bash
streamlit run app.py
```

Gemini is optional — without a key you still get the full technical result.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

All network calls are mocked, so no API keys are needed to run the tests.

## Deploy

**Streamlit Community Cloud** — push the repo to GitHub, create an app pointing at `app.py`, and paste your two keys into *App settings → Secrets* (same format as `secrets.toml.example`).

**Docker**

```bash
docker build -t qr-security-scanner .
docker run -p 8501:8501 \
  -e VIRUSTOTAL_API_KEY=your-key \
  -e GEMINI_API_KEY=your-key \
  qr-security-scanner
```

Then open http://localhost:8501.

## Limits & things to know

- **VirusTotal free API:** 4 requests/minute and 500/day, and it is for **non-commercial** use only ([terms](https://docs.virustotal.com/reference/public-vs-premium-api)). A brand-new URL takes up to ~40 seconds to scan. If the limit is hit, the app says so. Results are cached for an hour per URL to save quota. A public deployment shares one key between all visitors.
- **Privacy:** URLs are sent to VirusTotal (submitted URLs may be visible to its community) and to Google Gemini. Don't scan QR codes containing private links or tokens.
- **Shortened links:** the app flags them and shows where VirusTotal saw them redirect, but it never visits links itself.
- **Not a guarantee.** No scanner catches everything, especially brand-new phishing pages.

## Project layout

```
app.py                     Streamlit UI
services/
  qr_decoder.py            image -> text (OpenCV)
  payload_analyzer.py      classify the QR payload
  url_validator.py         URL format checks (not safety)
  virustotal.py            VirusTotal API v3
  risk_engine.py           deterministic verdict
  gemini.py                plain-language explanation
utils/helpers.py           secrets/env lookup, error parsing
tests/                     unit + end-to-end tests
```

## Security notes

- **Never commit `.streamlit/secrets.toml`** (the `.gitignore` blocks it in every folder) or paste keys into code.
- If a key is ever exposed, revoke it in the provider's dashboard and create a new one.
