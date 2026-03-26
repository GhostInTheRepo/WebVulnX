# 🛡️ WebVulnX — Professional Web Vulnerability Scanner

<div align="center">

![WebVulnX Banner](Style/img/3.png)

**A comprehensive, modular web security assessment platform built with Python & Flask.**

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()

</div>

---

## 📖 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Scanning Modules](#scanning-modules)
- [Nuclei Templates](#nuclei-templates)
- [PDF Reports](#pdf-reports)
- [Configuration](#configuration)
- [Security Notice](#security-notice)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

**WebVulnX** is a full-stack web security assessment tool that combines a **Flask REST API backend** with a sleek, dark-themed **single-page frontend**. It integrates multiple industry-standard scanning techniques — vulnerability detection, port scanning via Nmap, directory fuzzing, technology fingerprinting, DNS reconnaissance, DMARC policy analysis, custom Nuclei template scanning, and CVE intelligence lookup — all accessible through a single unified interface.

Results from any combination of scans can be exported as a **branded PDF report** with executive summaries, CVSS scoring, and remediation recommendations.

---

## Features

| Feature | Description |
|---|---|
| 🔍 **Vulnerability Scanner** | Checks security headers, CORS, sensitive file exposure, LFI, open redirect, SSL/TLS |
| 🔌 **Port Scanner** | Nmap-based scanning with `quick` and `full` modes; risk-level assessment per port |
| 📁 **Directory Fuzzer** | Built-in 100+ path wordlist; optional `ffuf` integration; status-code filtering |
| 🔧 **Technology Detector** | Fingerprints 30+ technologies from headers, cookies, and page body |
| 🌍 **DNS Reconnaissance** | A, AAAA, MX, NS, TXT, SOA records via Google DoH + IP geolocation |
| ⚛️ **Nuclei Scanner** | Runs custom YAML templates (XSS, SQLi, CSRF) via Nuclei engine |
| 📧 **DMARC Analyzer** | Queries DMARC DNS records and classifies email protection level |
| 🔎 **CVE Xplorer** | Looks up CVE details (description, CVSS, PoCs, affected products, Nuclei templates) via `vulnx` |
| 📄 **PDF Report Generator** | Branded, 12-section security reports using ReportLab |
| 🎨 **Dark/Light Theme** | Persistent theme toggle with cyberpunk dark mode and clean light mode |
| 🔽 **Filter Severity** | Nuclei findings can be filtered by severity (Critical / High / Medium / Low) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Browser (SPA)                          │
│   index.html + style.css + app.js                           │
│   (Sidebar navigation, scan views, PDF export)              │
└───────────────────┬─────────────────────────────────────────┘
                    │  HTTP REST (JSON)
                    ▼
┌─────────────────────────────────────────────────────────────┐
│                  Flask API  (app.py)                        │
│  /api/vuln-scan   /api/port-scan   /api/dir-fuzz            │
│  /api/tech-detect /api/dns-recon   /api/nuclei-scan         │
│  /api/dmarc-scan  /api/cve-xplorer /api/generate-pdf        │
│  /api/scan-all    /api/health                               │
└──┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬────────┘
   │      │      │      │      │      │      │      │
   ▼      ▼      ▼      ▼      ▼      ▼      ▼      ▼
scanner  port  dir_   tech_  dns_  nuclei dmarc  cve_    pdf_
  .py  scanner fuzzer detect recon scanner scanner xplorer generator
       (nmap)  (ffuf)       (DoH) (yaml)  (dig)  (vulnx) (ReportLab)
```

---

## Project Structure

```
WebVulnX/
├── app.py                  # Flask application — all API endpoints & URL validation
│
├── Backend/
│   ├── scanner.py          # Core vulnerability scanner (headers, CORS, LFI, SSL…)
│   ├── port_scanner.py     # Nmap-based port scanner
│   ├── dir_fuzzer.py       # Directory & file discovery
│   ├── tech_detector.py    # Technology fingerprinting
│   ├── dns_recon.py        # DNS reconnaissance (Google DoH)
│   ├── nuclei_scanner.py   # Nuclei template runner (JSONL output parser)
│   ├── dmarc_scanner.py    # DMARC DNS policy checker (dig)
│   └── cve_xplorer.py      # CVE intelligence lookup via vulnx CLI
│
├── Frontend/
│   └── index.html          # Single-page application shell
│
├── Style/
│   ├── css/style.css       # Full dark/light theme stylesheet
│   ├── js/app.js           # Frontend logic (API calls, rendering, filtering)
│   └── img/                # Assets (logo, icons, cover page)
│
├── Nuclei/
│   ├── nuclei.exe          # Nuclei binary (Windows)
│   ├── xss.yaml            # Reflected, Stored & DOM XSS detection
│   ├── sqlinjection.yaml   # SQL Injection & auth bypass detection
│   ├── multi_csrf.yaml     # Multi-type CSRF misconfiguration detection
│   └── advanced_csrf.yaml  # Advanced CSRF token enforcement check
│
├── utils/
│   └── pdf_generator.py    # ReportLab PDF report generator (12 sections)
│
└── Diagram/
    ├── README.md           # This file — project documentation
    ├── uml_diagrams.md     # UML class diagrams (Mermaid)
    ├── flow_chart.md       # System flowchart (Mermaid)
    └── system_architecture.md  # C4 system architecture diagram (Mermaid)
```

---

## Prerequisites

Ensure the following are installed and available in your system `PATH`:

| Tool | Purpose | Required |
|---|---|---|
| Python 3.9+ | Backend runtime | ✅ Required |
| [Nmap](https://nmap.org/download.html) | Port scanning | ✅ Required |
| [Nuclei](https://github.com/projectdiscovery/nuclei/releases) | Template-based scanning | ✅ Required |
| `dig` (part of BIND tools) | DMARC DNS queries | ✅ Required |
| [vulnx](https://github.com/vulncheck-oss/cli) | CVE intelligence lookup | ✅ Required |
| [ffuf](https://github.com/ffuf/ffuf) | Directory fuzzing (fast mode) | ⚠️ Optional |

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/WebVulnX.git
cd WebVulnX
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

**`requirements.txt`:**
```
Flask
Flask-Cors
requests
reportlab
beautifulsoup4
lxml
Werkzeug
```

### 4. Start the Server

```bash
python app.py
```

Open your browser at: **`http://127.0.0.1:5000`**

---

## Usage

1. **Select a scan type** from the sidebar (Vulnerability Scan, Port Scan, Dir Fuzz, etc.)
2. **Enter a target** URL or domain in the input field
3. Click **Scan / Start** — results load into the results panel
4. **View results** rendered in the results panel
5. Optionally **filter** results (severity for Nuclei, status code for Dir Fuzz)
6. Click **Generate PDF** to download a professional 12-section report

> 💡 **CVE Xplorer**: Enter a CVE ID (e.g. `CVE-2021-44228`) to instantly retrieve full vulnerability intelligence.

> 💡 **Scan All**: Use the `Scan All` endpoint to chain all modules against a single target.

---

## API Reference

All endpoints accept and return JSON (except `/api/generate-pdf` which returns `application/pdf`).

| Method | Endpoint | Body | Description |
|---|---|---|---|
| `GET` | `/api/health` | — | Health check |
| `POST` | `/api/vuln-scan` | `{ "target": "https://example.com" }` | Full vulnerability assessment |
| `POST` | `/api/port-scan` | `{ "target": "https://example.com", "scan_type": "quick" }` | Nmap port scan |
| `POST` | `/api/dir-fuzz` | `{ "target": "https://example.com" }` | Directory fuzzing |
| `POST` | `/api/tech-detect` | `{ "target": "https://example.com" }` | Technology detection |
| `POST` | `/api/dns-recon` | `{ "target": "https://example.com" }` | DNS reconnaissance |
| `POST` | `/api/nuclei-scan` | `{ "target": "https://example.com" }` | Nuclei template scan |
| `POST` | `/api/dmarc-scan` | `{ "target": "https://example.com" }` | DMARC policy check |
| `POST` | `/api/cve-xplorer` | `{ "cve_id": "CVE-2021-44228" }` | CVE intelligence lookup |
| `POST` | `/api/generate-pdf` | `{ scan results object }` | Generate PDF report |
| `POST` | `/api/scan-all` | `{ "target": "https://example.com" }` | Run all modules |

### Example Request

```bash
curl -X POST http://127.0.0.1:5000/api/vuln-scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'
```

### Example Response

```json
{
  "success": true,
  "results": {
    "target": "example.com",
    "ip_address": "93.184.216.34",
    "vulnerabilities": [
      {
        "name": "Missing Content-Security-Policy Header",
        "severity": "low",
        "cvss_score": 4.3,
        "cwe": "CWE-693",
        "description": "...",
        "recommendation": ["..."],
        "references": ["https://..."]
      }
    ]
  }
}
```

### CVE Xplorer Example Response

```json
{
  "success": true,
  "results": {
    "cve_id": "CVE-2021-44228",
    "name": "Log4Shell",
    "severity": "Critical",
    "cvss_score": 10.0,
    "description": "...",
    "is_kev": true,
    "affected_products": [...],
    "pocs": [...],
    "is_template": true
  }
}
```

---

## Scanning Modules

### 🔍 Vulnerability Scanner (`scanner.py`)
Performs HTTP-based security checks:
- **Security Headers**: CSP, X-Frame-Options, HSTS, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy
- **CORS Misconfiguration**: Wildcard origins, credential exposure, origin reflection
- **Sensitive File Exposure**: `.env`, `.git/config`, `wp-config.php`, `phpinfo.php`, `backup.sql`, etc.
- **Local File Inclusion (LFI)**: Common path traversal payloads across multiple parameters
- **Open Redirect**: Unvalidated redirect parameters
- **SSL/TLS Issues**: Certificate validity and HTTP vs HTTPS enforcement
- **Shodan CVE Check**: Queries Shodan API for known CVEs on the resolved IP
- **CVSS Scoring**: All findings include CVSS v3 score and CWE classification

### 🔌 Port Scanner (`port_scanner.py`)
- Wraps **Nmap** via `subprocess`
- `quick` mode: `nmap -Pn <target>` (default ports)
- `full` mode: `nmap -Pn -p- <target>` (all 65535 ports)
- Risk classification per port (High / Medium / Low)
- Resolves hostname to IP address before scanning

### 📁 Directory Fuzzer (`dir_fuzzer.py`)
- Built-in wordlist of 100+ common paths (`/admin`, `/api`, `/.env`, `/backup`, etc.)
- Falls back to **ffuf** if installed for high-speed fuzzing
- Categorizes findings: `admin`, `api`, `auth`, `sensitive`, `backup`, `other`
- Status-code filter dropdown (200 / 301 / 401 / 403 / 500)

### 🔧 Technology Detector (`tech_detector.py`)
- Signature-based detection from HTTP headers, cookies, and page body
- Covers: Web servers, CMSs, frameworks, analytics, CDNs, JavaScript libraries
- Optional **WhatCMS API** and **WhatWeb** CLI integration
- Returns name, version, category, confidence %, and icon per technology

### 🌍 DNS Recon (`dns_recon.py`)
- Uses **Google DNS-over-HTTPS** (`dns.google`)
- Queries: A, AAAA, MX, NS, TXT, SOA records
- IP geolocation via `ip-api.com`
- Format: grouped by record type with TTL and geo info

### ⚛️ Nuclei Scanner (`nuclei_scanner.py`)
- Executes the `nuclei` binary with templates from the `Nuclei/` directory
- Uses `-jsonl` output mode for robust structured parsing
- Parses JSONL output into structured findings with type, severity, URL, description, and recommendation
- Severity filter dropdown (Critical / High / Medium / Low / All)

### 📧 DMARC Scanner (`dmarc_scanner.py`)
- Queries `_dmarc.<domain>` via `dig ... TXT +short`
- Validates and extracts domain from full URLs automatically
- Parses `p=` (policy), `rua=` (reporting URI)
- Protection levels: **Strong** (`reject`), **Moderate** (`quarantine`), **Weak** (`none` or missing)

### 🔎 CVE Xplorer (`cve_xplorer.py`)
- Validates CVE ID format (`CVE-YYYY-NNNNN`) before querying
- Executes `vulnx id -j --silent <CVE-ID>` to fetch structured JSON data
- Returns: CVE name, CVSS score, severity, description, impact, affected products, PoC links, CISA KEV status, and Nuclei template availability
- Displayed in a rich details card in the frontend

---

## Nuclei Templates

Custom templates in the `Nuclei/` directory:

| Template | ID | Severity | Tests |
|---|---|---|---|
| `xss.yaml` | `Multi-XSS-Detection` | High | Reflected, Stored, DOM-based XSS |
| `sqlinjection.yaml` | `Login-SQLi-Auth-Bypass-Encoded` | Critical | Auth bypass, Union, Time-based SQLi |
| `multi_csrf.yaml` | `Multi-CSRF-Detection` | Medium | GET/POST CSRF, Login CSRF, CORS CSRF |
| `advanced_csrf.yaml` | `Advanced-CSRF-Detection` | Medium | Token extraction & enforcement bypass |

> Nuclei templates follow the [Nuclei YAML DSL](https://docs.projectdiscovery.io/templates/introduction). You can add custom templates to the `Nuclei/` folder and they'll be picked up automatically.

---

## PDF Reports

Generated via **ReportLab** and downloadable directly from the UI.

Each report includes **12 sections**:

1. **Cover Page** — Target, IP, scan date, scanner version, confidentiality notice
2. **Table of Contents** — All section listings
3. **Executive Summary** — Risk level, severity counts, key findings overview
4. **Key Recommendations** — Prioritized remediation guidance by severity
5. **Security Headers Checker** — List of analyzed headers and their importance
6. **Port Scanning** — Open ports table with state, service, and source
7. **Directory Fuzzing** — Discovered paths with HTTP status and type
8. **Technology Detection** — Grouped by category with version and confidence
9. **DNS Reconnaissance** — Grouped DNS records by type
10. **DMARC Scanner** — Policy configuration and raw TXT record
11. **Nuclei Scan Findings** — Template, severity, URL, description, recommendations
12. **Security Headers Findings** — Full vulnerability details (CVSS, CWE, evidence, recommendations, references)
13. **CVE Xplorer Findings** — CVE details, impact, affected products, PoCs, Nuclei template link
14. **Appendix** — CVSS scoring reference table

---

## Configuration

No `.env` file is required for basic operation. Optional integrations:

```python
# In scanner.py — Shodan API key
SHODAN_API_KEY = "your_api_key_here"

# In tech_detector.py — WhatCMS API key
WHATCMS_API_KEY = "your_api_key_here"
```

The Flask server binds to `0.0.0.0:5000` by default. To change this, edit `app.py`:

```python
app.run(debug=True, host='0.0.0.0', port=5000)
```

---

## Security Notice

> ⚠️ **WebVulnX is intended for authorized security testing only.**

- Only use this tool against systems you **own** or have **explicit written permission** to test
- Unauthorized scanning may be **illegal** under the Computer Fraud and Abuse Act (CFAA), GDPR, and other laws
- The authors accept no liability for misuse of this software

---

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/my-new-scanner`
3. Commit your changes: `git commit -m 'Add: new scanner module'`
4. Push to the branch: `git push origin feature/my-new-scanner`
5. Open a Pull Request

### Adding a New Scanner Module

1. Create `Backend/my_scanner.py` with a `scan(target)` → `dict` function
2. Add a route in `app.py`: `@app.route('/api/my-scan', methods=['POST'])`
3. Add a sidebar item and scan view section in `Frontend/index.html`
4. Add the render function and API call in `Style/js/app.js`

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](../LICENSE) file for details.

---

<div align="center">

**Built with ❤️ for the security community**

🛡️ *WebVulnX — Know Your Attack Surface*

</div>
