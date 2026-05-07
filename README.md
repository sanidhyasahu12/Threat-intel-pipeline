# 🔴 Threat Intel Pipeline

> Automated threat intelligence enrichment tool built for SOC analysts.
> Paste any IP, domain, or file hash — get instant enrichment from
> VirusTotal, Shodan, and MITRE ATT&CK with a live web dashboard.

![Python](https://img.shields.io/badge/Python-3.14-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20App-black?style=flat-square&logo=flask)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API-blue?style=flat-square)
![Shodan](https://img.shields.io/badge/Shodan-API-red?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-orange?style=flat-square)

---

## What it does

A SOC analyst receives dozens of suspicious IPs, domains, and file
hashes every shift. Manually checking each one across multiple platforms
takes 15-20 minutes per IOC. This tool automates that entire workflow
in under 5 seconds.

**Input:** A suspicious IP address, domain name, or file hash

**Output:** A complete enrichment report including:
- VirusTotal scan results across 90+ antivirus engines
- Shodan intelligence — open ports, country, org, tags
- MITRE ATT&CK technique mapping (TTP identification)
- Threat score (0-100) with animated gauge
- Exportable PDF report
- Persistent scan history with live stats

---

## Live Demo

🔴 **[threatintel-pipeline.onrender.com](https://threatintel-pipeline.onrender.com)**

---

## Architecture

---

## Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3.14 | Core scripting language |
| Flask | Web server and REST API |
| VirusTotal API | Malware and reputation scanning |
| Shodan API | Internet-facing asset intelligence |
| MITRE ATT&CK | TTP mapping and threat classification |
| python-dotenv | Secure API key management |
| jsPDF | Client-side PDF export |

---

## Setup & Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/threat-intel-pipeline.git
cd threat-intel-pipeline
```

### 2. Create virtual environment
```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Add your API keys
Create a `.env` file in the root directory:

Get free API keys:
- VirusTotal: https://www.virustotal.com
- Shodan: https://account.shodan.io

### 5. Run the web dashboard
```bash
python app.py
```
Open `http://localhost:5000` in your browser.

### 6. Or run the CLI pipeline
Add IOCs to `data/iocs.txt` (one per line), then:
```bash
python main.py
```

---

## Features

- **Multi-type IOC support** — IP addresses, domains, file hashes
- **Automated enrichment** — parallel checks across VirusTotal and Shodan
- **MITRE ATT&CK mapping** — maps IOC behaviour to known attack techniques
- **Threat scoring** — 0-100 risk score with animated visual gauge
- **PDF export** — download full enrichment report with one click
- **Scan history** — session-based history table with verdict badges
- **Live stats** — running totals of malicious, suspicious, and clean IOCs
- **CLI mode** — run headless from terminal, saves JSON reports to output/

---

## Project Structure

---

## Skills Demonstrated

- REST API integration (VirusTotal, Shodan)
- Python scripting and modular code architecture
- Threat intelligence enrichment workflow
- MITRE ATT&CK framework application
- SOAR-style automation thinking
- Flask web development
- Secure credential management with dotenv
- Professional documentation

---

## Author

Built by SANIDHYA SAHU  — Junior SOC Analyst
[LinkedIn] https://www.linkedin.com/in/sanidhyasahu12/ 