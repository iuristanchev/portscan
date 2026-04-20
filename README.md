# Network Security Port Scanner & Auditor

A comprehensive Python-based security tool designed for automated network discovery, service fingerprinting, and vulnerability auditing. It combines fast socket-based discovery with heavy-duty Nmap analysis and web-specific vulnerability checks.

## 🚀 Features

- **Hybrid Scanning**: Uses high-speed multi-threaded socket checks for discovery, followed by Nmap for service versioning.
- **Vulnerability Mapping**: Automatically categorizes findings into **OWASP Top 10** categories.
- **Web Audit Engine**: Checks for exposed `.env`, `.git`, and sensitive admin panels on identified HTTP services.
- **Delta Analysis**: Detects and highlights "New Ports" that weren't present in previous scans of the same host.
- **Persistent Storage**: All results are stored in a local SQLite database for historical tracking.
- **Interactive Reports**: Generates a searchable, modern HTML report for stake-holder review.
- **Credential Logging**: Automatically logs credential audit attempts to a CSV file for compliance.

## 📋 Prerequisites

- **Python 3.x**
- **Nmap**: Must be installed on your system path.
  - *Linux*: `sudo apt install nmap`
  - *macOS*: `brew install nmap`
  - *Windows*: Download from [nmap.org](https://nmap.org/download.html)

## Usage
python portscan.py 10.0.0.1 -p 22,80,443,8000-9000

## Output Files
security_report.html: The interactive visual report.
port_scan_results.db: SQLite database containing all historical data.
tested_credentials.csv: Log of credential audit attempts.

## Legal Disclaimer
This tool is for educational and authorized security testing purposes only. Running AXFR attacks or scraping logs against targets without explicit permission may be illegal.

## Author
[Yuriy Stanchev](iuri.stanchev@gmail.com)