# qr-security-scanner
A security-focused QR scanner that analyzes QR payloads, checks URLs with VirusTotal, and explains security findings in plain language.
# 🔐 QR Security Scanner

### Scan Before You Visit

A security-focused QR code scanner that analyzes QR payloads **before you interact with them**.

QR codes can hide phishing links, malicious websites, fake payment destinations, tracking URLs, and other potentially risky content. This project provides an additional security layer by decoding the QR code, analyzing its payload, validating URLs, checking threat intelligence, and presenting the findings in an easy-to-understand format.

> ⚠️ **Important:** A result such as "No Known Threat Detected" does not guarantee that a QR code or URL is safe. This tool is designed as a security-assistance layer, not as a guarantee of safety.

---

## ✨ Features

* 📷 Decode QR codes from uploaded images
* 🔍 Analyze QR payloads before opening them
* 🌐 Validate and normalize URLs
* 🛡️ Detect suspicious URL characteristics
* 🔎 Check URLs against VirusTotal threat intelligence
* 🧠 Generate optional plain-language explanations using Google Gemini
* ⚙️ Use deterministic security rules for the final risk decision
* 📊 Display security findings in a Streamlit interface
* 🚀 Run locally, with Docker, or through Streamlit deployment
* 🧪 Automated security and application tests
* 🔒 Designed with security and privacy considerations in mind

---

## 🎯 Why This Project?

Scanning a QR code normally means trusting whatever content is hidden behind it.

That can be risky.

A QR code may contain:

* A phishing website
* A malicious or compromised URL
* A shortened URL
* A suspicious IP-based URL
* A fake payment destination
* A tracking URL
* Wi-Fi credentials
* Contact information
* Email or SMS instructions
* Other untrusted content

QR Security Scanner adds an inspection step:

```text
              WITHOUT SCANNER

QR Code
   ↓
Scan
   ↓
Open Destination
   ↓
Potential Risk


              WITH QR SECURITY SCANNER

QR Code
   ↓
Decode
   ↓
Analyze Payload
   ↓
Validate URL
   ↓
Check Threat Intelligence
   ↓
Calculate Risk
   ↓
Explain Findings
   ↓
User Decides Whether to Continue
```

---

## 🧠 Security Decision Model

A key design principle of this project is that **AI does not make the final security decision**.

The application uses a deterministic risk engine to evaluate security signals.

Gemini is an optional explanation layer.

```text
QR Image
   ↓
QR Decoder
   ↓
Payload Analyzer
   ↓
URL Validator
   ↓
Security Signals
   ↓
VirusTotal Intelligence
   ↓
Deterministic Risk Engine
   ↓
Security Verdict
   ↓
Optional Gemini Explanation
```

### Why separate AI from the security decision?

Generative AI can produce useful explanations, but it should not be treated as the sole authority for a security decision.

Therefore:

```text
Risk Engine
     ↓
Final Security Verdict

Gemini
     ↓
Human-readable Explanation
```

This separation helps keep the security decision predictable and testable.

---

## 🔍 Supported QR Payload Types

The application can identify several common QR payload types, including:

| Payload Type   | Example Use                    |
| -------------- | ------------------------------ |
| 🌐 URL         | Websites and web links         |
| 📶 Wi-Fi       | Wireless network configuration |
| 👤 vCard       | Contact information            |
| 📧 Email       | Email address and message      |
| 💬 SMS         | SMS destination and message    |
| 📞 Phone       | Telephone number               |
| 📍 Location    | Geographic coordinates         |
| 💳 UPI Payment | Payment-related QR payload     |
| 📝 Text        | Plain text                     |

---

## 🛡️ URL Security Analysis

When a QR code contains a URL, the application can analyze characteristics such as:

* HTTP vs HTTPS
* Raw IP addresses
* URL shorteners
* Suspicious URL formatting
* Unusually long URLs
* URL structure
* External threat-intelligence results

These signals are indicators and should not be interpreted as absolute proof that a URL is malicious or safe.

---

## 🦠 VirusTotal Integration

The project can use VirusTotal to obtain additional threat-intelligence information about URLs.

VirusTotal results can provide additional evidence such as known detections from security engines.

However:

> A URL with no known VirusTotal detections is not guaranteed to be safe.

Threat intelligence can be incomplete, delayed, or change over time.

### API considerations

The VirusTotal Public API has usage restrictions and should be used according to the current VirusTotal terms and policies.

Users deploying this project should review the applicable VirusTotal API terms before using the integration.

---

## 🤖 Google Gemini Integration

Google Gemini can optionally be used to explain security findings in plain language.

For example, instead of only displaying:

```text
Risk: Medium
```

the application can provide a more understandable explanation of the security signals that contributed to the result.

### Important

Gemini does **not** determine the final security verdict.

The application follows:

```text
Deterministic Risk Engine
        ↓
Security Verdict

Gemini
        ↓
Explanation
```

QR-derived content is treated as untrusted data when provided to the explanation layer.

---

## 🏗️ Architecture

```text
                         ┌──────────────────┐
                         │    QR Image      │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │   QR Decoder     │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │ Payload Analyzer │
                         └────────┬─────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
             ┌──────────────┐           ┌──────────────┐
             │ URL Validator│           │ Other Payload│
             └──────┬───────┘           └──────┬───────┘
                    │                          │
                    └─────────────┬────────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │   Risk Engine    │
                         └────────┬─────────┘
                                  │
                       ┌──────────┴──────────┐
                       │                     │
                       ▼                     ▼
                ┌─────────────┐      ┌─────────────┐
                │ VirusTotal  │      │   Gemini    │
                │ Intelligence│      │ Explanation │
                └──────┬──────┘      └──────┬──────┘
                       │                     │
                       └──────────┬──────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │  Streamlit UI    │
                         └──────────────────┘
```

For more details, see:

`docs/ARCHITECTURE.md`

---

## 🛠️ Tech Stack

| Technology        | Purpose                  |
| ----------------- | ------------------------ |
| Python            | Core application         |
| Streamlit         | Web interface            |
| OpenCV            | QR decoding              |
| VirusTotal API    | Threat intelligence      |
| Google Gemini API | Security explanations    |
| Pytest            | Automated testing        |
| Docker            | Containerized deployment |
| GitHub Actions    | CI testing               |
| CodeQL            | Security analysis        |

---

## 📁 Project Structure

```text
qr-security-scanner/
│
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   │
│   ├── workflows/
│   │   ├── tests.yml
│   │   └── codeql.yml
│   │
│   └── pull_request_template.md
│
├── .streamlit/
│   ├── config.toml
│   └── secrets.toml.example
│
├── docs/
│   ├── ARCHITECTURE.md
│   └── RELEASE_CHECKLIST.md
│
├── services/
│   ├── __init__.py
│   ├── gemini.py
│   ├── payload_analyzer.py
│   ├── qr_decoder.py
│   ├── risk_engine.py
│   ├── url_validator.py
│   └── virustotal.py
│
├── tests/
│   ├── test_apis.py
│   ├── test_app.py
│   └── test_security.py
│
├── utils/
│   ├── __init__.py
│   └── helpers.py
│
├── .dockerignore
├── .gitignore
├── CHANGELOG.md
├── CONTRIBUTING.md
├── Dockerfile
├── LICENSE
├── README.md
├── SECURITY.md
├── app.py
├── pytest.ini
├── requirements-dev.txt
└── requirements.txt
```

---

# 🚀 Getting Started

## Prerequisites

Make sure you have:

* Python 3.10+
* pip
* Git

Optional:

* Docker
* VirusTotal API key
* Google Gemini API key

---

## 📥 Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/qr-security-scanner.git
```

Move into the project:

```bash
cd qr-security-scanner
```

Create a virtual environment:

```bash
python -m venv .venv
```

### Windows

```bash
.venv\Scripts\activate
```

### Linux/macOS

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

For development and testing:

```bash
pip install -r requirements-dev.txt
```

---

# 🔑 API Configuration

The project can use external APIs for additional analysis.

Create:

```text
.streamlit/secrets.toml
```

Use the example file:

```text
.streamlit/secrets.toml.example
```

Example:

```toml
VIRUSTOTAL_API_KEY = "your_virustotal_api_key_here"

GEMINI_API_KEY = "your_gemini_api_key_here"
```

Replace the placeholder values with your actual API keys.

### ⚠️ Never commit this file

Do not upload:

```text
.streamlit/secrets.toml
```

to GitHub.

The real secrets file is excluded through `.gitignore`.

Only commit:

```text
.streamlit/secrets.toml.example
```

---

# ▶️ Run the Application

Start Streamlit:

```bash
streamlit run app.py
```

The application will normally be available at:

```text
http://localhost:8501
```

Open the URL in your browser and upload a QR-code image.

---

# 🧪 Run Tests

Run all tests:

```bash
pytest -q
```

Run security tests:

```bash
pytest tests/test_security.py -q
```

Run API tests:

```bash
pytest tests/test_apis.py -q
```

Run application tests:

```bash
pytest tests/test_app.py -q
```

---

# 🐳 Docker

Build the Docker image:

```bash
docker build -t qr-security-scanner .
```

Run the container:

```bash
docker run -p 8501:8501 qr-security-scanner
```

Then open:

```text
http://localhost:8501
```

Do not bake API keys into the Docker image.

Supply secrets securely through your deployment environment.

---

# ☁️ Streamlit Deployment

The project can be deployed using Streamlit Community Cloud.

General deployment flow:

```text
GitHub Repository
       ↓
Streamlit Deployment
       ↓
Configure Secrets
       ↓
Deploy
       ↓
Open Application
```

When configuring the deployment, add your API keys through the platform's secrets configuration.

Do not commit API credentials to the repository.

---

# 🔒 Security & Privacy

QR Security Scanner is designed around the principle that QR-code content should be treated as untrusted input.

### The application:

* Does not execute QR payloads.
* Validates URLs before external processing.
* Uses deterministic security rules.
* Treats external API results as evidence.
* Keeps AI-generated explanations separate from security decisions.
* Provides warnings about uncertainty.

### Important limitations

No security scanner can guarantee that a QR code or URL is safe.

Possible limitations include:

* New malicious domains
* Newly compromised websites
* False positives
* False negatives
* Incomplete threat intelligence
* API failures
* Obfuscated URLs
* Social-engineering attacks
* Malicious content that has not yet been detected

Users should independently verify important URLs and payment destinations.

---

# 🔐 Security Policy

If you discover a potential security vulnerability, please do not publicly disclose sensitive technical details through a GitHub issue.

Read:

```text
SECURITY.md
```

for the project's security-reporting guidance.

---

# 🤝 Contributing

Contributions are welcome.

Before contributing, read:

```text
CONTRIBUTING.md
```

You can contribute through:

* Bug fixes
* Security improvements
* New tests
* Payload analysis improvements
* UI improvements
* Documentation
* Performance improvements
* New integrations

---

# 🧪 Continuous Integration

GitHub Actions automatically runs the test suite for supported Python versions.

The repository includes:

```text
.github/workflows/tests.yml
```

The test workflow checks:

```text
Python 3.10
Python 3.11
Python 3.12
```

The repository also includes CodeQL analysis:

```text
.github/workflows/codeql.yml
```

This provides an additional automated security-analysis layer.

---

# 📊 Security Philosophy

The project follows several principles.

### 1. Treat QR content as untrusted

A QR code should not automatically be trusted simply because it is displayed by a legitimate-looking source.

### 2. Inspect before interacting

The goal is:

```text
Scan → Inspect → Decide
```

rather than:

```text
Scan → Immediately Open
```

### 3. Deterministic security decisions

Security verdicts are generated using application logic rather than relying solely on generative AI.

### 4. AI explains; it does not decide

Gemini can help users understand security findings, but it does not override the risk engine.

### 5. Threat intelligence is evidence

VirusTotal can provide useful external intelligence, but absence of detections does not prove that a URL is safe.

---

# 🗺️ Roadmap

Potential future improvements include:

* [ ] Additional QR payload formats
* [ ] More URL security heuristics
* [ ] Domain reputation analysis
* [ ] Expanded phishing detection
* [ ] More threat-intelligence providers
* [ ] Improved visualization of security signals
* [ ] Batch QR scanning
* [ ] Scan history
* [ ] Exportable security reports
* [ ] Additional automated security tests
* [ ] Improved accessibility
* [ ] Performance improvements

---

# 📜 License

This project is licensed under the MIT License.

See:

```text
LICENSE
```

for the complete license text.

---

# 👨‍💻 Author

**Gaurav Jha**

Built as a cybersecurity-focused project exploring QR-code security, URL analysis, threat intelligence, deterministic risk assessment, and AI-assisted security explanations.

---

# ⭐ Support the Project

If you find this project useful:

* ⭐ Star the repository
* 🐛 Report bugs
* 💡 Suggest features
* 🔐 Report security issues responsibly
* 🤝 Contribute improvements
* 📢 Share the project

---

## ⚠️ Final Security Disclaimer

QR Security Scanner is a security-assistance tool.

It does **not** guarantee that a QR code, URL, website, payment destination, or other payload is safe.

Always verify important links, websites, and payment destinations independently before providing sensitive information or completing a transaction.

**Scan Before You Visit.**
