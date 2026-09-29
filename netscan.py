#!/usr/bin/env python3
"""
Automated Network Vulnerability Scanner (v3 — live NVD API)
--------------------------------------------------------------
Wraps Nmap (service/version detection scan), parses the XML output,
and cross-references detected service versions against:
  1. A local curated vulnerability database (fast, works offline)
  2. The live NVD (National Vulnerability Database) API 2.0, for
     services not found locally — real, current CVE data.

Generates a terminal report and a color-coded HTML report with an
overall risk rating.

Usage:
    python3 netscan.py <target>              # real scan, uses local DB + live NVD
    python3 netscan.py <target> --demo       # fully offline demo (local DB only)
    python3 netscan.py <target> --offline    # live scan, but skip NVD (local DB only)
"""

import argparse
import json
import subprocess
import sys
import time
import webbrowser
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

BASE_DIR = Path(__file__).resolve().parent
VULN_DB_PATH = BASE_DIR / "vuln_db.json"
SAMPLE_XML_PATH = BASE_DIR / "sample_scan.xml"
REPORT_PATH = BASE_DIR / "report.html"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY_SECONDS = 6  # NVD's recommended delay between unauthenticated requests

SEVERITY_COLOR = {
    "CRITICAL": "#DC2626",
    "HIGH": "#EA580C",
    "MEDIUM": "#D97706",
    "LOW": "#65A30D",
    "UNKNOWN": "#64748B",
}
SEVERITY_WEIGHT = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "UNKNOWN": 0}


def load_vuln_db():
    with open(VULN_DB_PATH) as f:
        return json.load(f)


def run_nmap_scan(target):
    print(f"[*] Scanning {target} with Nmap (-sV)...")
    result = subprocess.run(
        ["nmap", "-sV", "-oX", "-", target],
        capture_output=True, text=True, timeout=300
    )
    if result.returncode != 0:
        raise RuntimeError(f"nmap failed: {result.stderr}")
    return result.stdout


def load_demo_scan():
    print("[*] DEMO MODE: loading sample_scan.xml (no live scan performed)")
    return SAMPLE_XML_PATH.read_text()


def parse_nmap_xml(xml_data):
    root = ET.fromstring(xml_data)
    findings = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        ip = addr_el.get("addr") if addr_el is not None else "unknown"
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid")
            service_el = port.find("service")
            service = service_el.get("name") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            findings.append({
                "ip": ip, "port": portid, "service": service,
                "product": product, "version": version,
            })
    return findings


def match_local(product_version, vuln_db):
    key = product_version.lower()
    for db_key, info in vuln_db.items():
        if db_key.lower() in key:
            return dict(info, source="local")
    return None


def query_nvd(product, version):
    """Query the live NVD API 2.0 for a CVE matching this product+version.
    Returns None on any failure — callers must handle that gracefully."""
    if not HAVE_REQUESTS or not product:
        return None
    keyword = f"{product} {version}".strip()
    try:
        resp = requests.get(
            NVD_API_URL,
            params={"keywordSearch": keyword, "resultsPerPage": 3},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        cve_item = vulns[0]["cve"]
        cve_id = cve_item.get("id", "UNKNOWN")

        descriptions = cve_item.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        if len(desc) > 200:
            desc = desc[:197] + "..."

        severity = "UNKNOWN"
        metrics = cve_item.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(metric_key)
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                severity = (cvss_data.get("baseSeverity") or entries[0].get("baseSeverity") or "UNKNOWN").upper()
                break

        return {
            "cve": cve_id,
            "severity": severity if severity in SEVERITY_WEIGHT else "UNKNOWN",
            "description": desc or "See NVD for full details.",
            "fix": f"Review {cve_id} on nvd.nist.gov for the patched version.",
            "source": "live NVD",
        }
    except Exception:
        return None


def match_vulnerabilities(findings, vuln_db, use_live_nvd):
    report = []
    nvd_queries_made = 0
    for f in findings:
        key = f"{f['product']} {f['version']}".strip()
        matched = match_local(key, vuln_db) if key else None

        if matched is None and use_live_nvd and f["product"]:
            if nvd_queries_made > 0:
                time.sleep(NVD_DELAY_SECONDS)
            print(f"    [*] Checking live NVD database for {key} ...")
            matched = query_nvd(f["product"], f["version"])
            nvd_queries_made += 1

        f["vulnerability"] = matched
        report.append(f)
    return report


def compute_risk_rating(report):
    score = sum(SEVERITY_WEIGHT.get(r["vulnerability"]["severity"], 0)
                for r in report if r["vulnerability"])
    if score >= 6:
        return "CRITICAL", score
    elif score >= 3:
        return "HIGH", score
    elif score >= 1:
        return "MEDIUM", score
    return "LOW", score


def print_report(report):
    print("\n" + "=" * 70)
    print(f"VULNERABILITY SCAN REPORT — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 70)
    risky = [r for r in report if r["vulnerability"]]

    for r in report:
        line = f"[{r['ip']}:{r['port']}] {r['service']} — {r['product']} {r['version']}".strip()
        print(line)
        if r["vulnerability"]:
            v = r["vulnerability"]
            src = "local DB" if v.get("source") == "local" else "LIVE NVD"
            print(f"    !! [{src}] {v['cve']} — {v['severity']} — {v['description']}")
            print(f"       FIX: {v['fix']}")

    rating, score = compute_risk_rating(report)
    print("-" * 70)
    print(f"Open ports scanned : {len(report)}")
    print(f"Flagged as risky   : {len(risky)}")
    print(f"Overall risk rating: {rating}  (score: {score})")
    print("=" * 70)
    print(f"[*] HTML report written to {REPORT_PATH}")


def generate_html_report(report, target, used_live_nvd):
    rating, score = compute_risk_rating(report)
    risky = [r for r in report if r["vulnerability"]]
    rating_color = SEVERITY_COLOR.get(rating, "#65A30D")

    rows = ""
    for r in report:
        if r["vulnerability"]:
            v = r["vulnerability"]
            color = SEVERITY_COLOR.get(v["severity"], "#65A30D")
            src_badge = "LIVE NVD" if v.get("source") == "live NVD" else "LOCAL DB"
            src_color = "#0D9488" if v.get("source") == "live NVD" else "#64748B"
            rows += f"""
            <tr>
              <td>{r['ip']}:{r['port']}</td>
              <td>{r['service']}</td>
              <td>{r['product']} {r['version']}</td>
              <td><span class="badge" style="background:{color}">{v['severity']}</span></td>
              <td>{v['cve']}</td>
              <td><span class="srcbadge" style="background:{src_color}">{src_badge}</span></td>
              <td>{v['description']}</td>
            </tr>"""
        else:
            rows += f"""
            <tr class="clean">
              <td>{r['ip']}:{r['port']}</td>
              <td>{r['service']}</td>
              <td>{r['product']} {r['version']}</td>
              <td><span class="badge" style="background:#16A34A">CLEAN</span></td>
              <td>—</td>
              <td>—</td>
              <td>No known vulnerability found</td>
            </tr>"""

    nvd_note = (
        "This scan queried the live NVD (National Vulnerability Database) API for services not in the local database."
        if used_live_nvd else
        "This scan used the local vulnerability database only (offline demo mode)."
    )

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Vulnerability Scan Report — {target}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0F172A; color: #E2E8F0; margin: 0; padding: 40px; }}
  .container {{ max-width: 1050px; margin: 0 auto; }}
  h1 {{ font-size: 26px; margin-bottom: 4px; }}
  .subtitle {{ color: #94A3B8; margin-bottom: 8px; }}
  .nvdnote {{ color: #5EEAD4; font-size: 12.5px; margin-bottom: 24px; font-style: italic; }}
  .summary {{ display: flex; gap: 16px; margin-bottom: 28px; flex-wrap: wrap; }}
  .card {{ background: #1E293B; border-radius: 10px; padding: 18px 24px; flex: 1; min-width: 160px; }}
  .card .label {{ font-size: 12px; color: #94A3B8; text-transform: uppercase; letter-spacing: 1px; }}
  .card .value {{ font-size: 28px; font-weight: bold; margin-top: 6px; }}
  .risk-card {{ background: {rating_color}22; border: 1px solid {rating_color}; }}
  .risk-card .value {{ color: {rating_color}; }}
  table {{ width: 100%; border-collapse: collapse; background: #1E293B; border-radius: 10px; overflow: hidden; }}
  th {{ background: #0F172A; text-align: left; padding: 12px 14px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: #94A3B8; }}
  td {{ padding: 12px 14px; border-top: 1px solid #334155; font-size: 13.5px; }}
  tr.clean td {{ color: #64748B; }}
  .badge {{ color: white; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: bold; white-space: nowrap; }}
  .srcbadge {{ color: white; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: bold; white-space: nowrap; }}
  footer {{ margin-top: 24px; color: #64748B; font-size: 12px; }}
</style>
</head>
<body>
  <div class="container">
    <h1>Network Vulnerability Scan Report</h1>
    <div class="subtitle">Target: {target} &nbsp;|&nbsp; Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
    <div class="nvdnote">{nvd_note}</div>

    <div class="summary">
      <div class="card"><div class="label">Ports Scanned</div><div class="value">{len(report)}</div></div>
      <div class="card"><div class="label">Flagged Risky</div><div class="value">{len(risky)}</div></div>
      <div class="card risk-card"><div class="label">Overall Risk Rating</div><div class="value">{rating}</div></div>
    </div>

    <table>
      <tr>
        <th>Host:Port</th><th>Service</th><th>Product/Version</th>
        <th>Severity</th><th>CVE</th><th>Source</th><th>Description</th>
      </tr>
      {rows}
    </table>

    <footer>Generated by Automated Network Vulnerability Scanner — Praveen, RR Institute of Technology</footer>
  </div>
</body>
</html>"""
    REPORT_PATH.write_text(html)


def main():
    parser = argparse.ArgumentParser(description="Automated Network Vulnerability Scanner")
    parser.add_argument("target", nargs="?", default="scanme.nmap.org", help="Target IP / hostname")
    parser.add_argument("--demo", action="store_true", help="Fully offline demo mode (sample scan + local DB only)")
    parser.add_argument("--offline", action="store_true", help="Real scan, but skip live NVD lookups (local DB only)")
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open the HTML report")
    args = parser.parse_args()

    vuln_db = load_vuln_db()
    use_live_nvd = (not args.demo) and (not args.offline)

    if use_live_nvd and not HAVE_REQUESTS:
        print("[!] 'requests' library not installed — run: pip install requests --break-system-packages")
        print("[!] Falling back to local database only for this run.")
        use_live_nvd = False

    try:
        xml_data = load_demo_scan() if args.demo else run_nmap_scan(args.target)
    except FileNotFoundError:
        print("[!] nmap not found on this system — falling back to demo mode.")
        xml_data = load_demo_scan()
        use_live_nvd = False
    except Exception as e:
        print(f"[!] Live scan failed ({e}) — falling back to demo mode.")
        xml_data = load_demo_scan()
        use_live_nvd = False

    if use_live_nvd:
        print("[*] Live mode: will check local DB first, then the live NVD API for anything not found locally.")

    findings = parse_nmap_xml(xml_data)
    report = match_vulnerabilities(findings, vuln_db, use_live_nvd)
    print_report(report)
    generate_html_report(report, args.target, use_live_nvd)

    if not args.no_browser:
        try:
            webbrowser.open(f"file://{REPORT_PATH}")
        except Exception:
            pass


if __name__ == "__main__":
    main()
