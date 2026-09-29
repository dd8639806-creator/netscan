# Netscan — Network Vulnerability Scanner

A lightweight network vulnerability scanner that parses Nmap scan results and generates a clean, styled HTML report flagging services with known vulnerabilities.

## Features
- Parses Nmap XML scan output (`sample_scan.xml`)
- Cross-references discovered services/versions against a vulnerability database (`vuln_db.json`)
- Generates a readable HTML report (`report.html`) with clean/vulnerable status badges per port
- Built and tested against a Metasploitable2 target in an isolated lab environment

## How it works
1. Run an Nmap scan and export results as XML:
2. Run the scanner:
3. Open the generated `report.html` in a browser to view results.

## Example output
The scanner flags each discovered port/service as `CLEAN` or `VULNERABLE` based on known CVEs matched against service versions, with a summary table for quick review.

## Tech
- Python 3
- Nmap for scanning
- Custom vulnerability matching against `vuln_db.json`

## Disclaimer
Built for educational and authorized penetration testing purposes only. Only run against systems you own or have explicit permission to test.

## Author
Praveen