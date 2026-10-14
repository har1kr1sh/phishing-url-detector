# Phishing URL & Threat Intelligence Analyzer

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![License MIT](https://img.shields.io/badge/license-MIT-green.svg)
![SOC L2 Project](https://img.shields.io/badge/SOC-Detection%20Engineering-navy)

An automated URL analysis and threat intelligence enrichment CLI tool engineered for SOC L2 analysts, incident responders, and detection engineers. It performs heuristic feature extractions, entropy analysis, DNS/WHOIS age calculations, and queries community threat intelligence APIs (VirusTotal & URLhaus).

---

## Key Features

- **Multi-Factor Heuristic Engine:** Analyzes URL length, domain entropy (Shannon Entropy for DGAs), subdomain depth, IPv4 host usage, and keyword targeting.
- **WHOIS Registration Age Guardrail:** Identifies newly registered domains (<30 days) commonly leveraged in disposable phishing infrastructure.
- **DNS Record Verification:** Queries Mail Exchange (MX) records to evaluate domain legitimacy.
- **Threat Intel Integration:** Seamlessly connects with **Abuse.ch URLhaus** and **VirusTotal v3 API** using local `config/config.txt` parameters.
- **Interactive Triage Banner:** Custom ASCII banner loaded dynamically from the `banner/` folder with interactive CLI prompt support.

---

## Installation & Setup

```bash
# Clone the repository
git clone [https://github.com/har1kr1sh/phishing-url-detector.git](https://github.com/har1kr1sh/phishing-url-detector.git)
cd phishing-url-detector

# Install Python dependencies
pip install -r requirements.txt

# Set up your local configuration
cp config/config.example.txt config/config.txt
# Add your VirusTotal API key inside config/config.txt
```

---

## Usage

Run the script interactively:
```bash
python main.py
```

Or analyze a specific target URL via command-line arguments:
```bash
python main.py -u "[http://login.verification-account.security-update.com/signin/](http://login.verification-account.security-update.com/signin/)"
```

Batch process from samples:
```bash
python main.py -f samples/test_urls.txt -o output_report.json
```

---

## Author

**Hari Krishnan**
- GitHub: [@har1kr1sh](https://github.com/har1kr1sh)[cite: 1]
- Role: SOC L2 Analyst | Detection Engineering & Threat Hunting