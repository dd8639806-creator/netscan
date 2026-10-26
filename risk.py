"""risk.py - adds risk score, exploit check and fix advice to NetScan findings.

Each finding is a dict like:
  {"host": "192.168.56.101", "port": 21, "service": "ftp",
   "product": "vsftpd", "version": "2.3.4",
   "severity": "CRITICAL", "cve": "CVE-2011-2523"}
"""
import json
import shutil
import subprocess

# 1) Base points for each severity
SEVERITY_POINTS = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 40, "LOW": 15, "CLEAN": 0}

# 2) Fix advice (matched by product name, lowercase)
FIXES = {
    "vsftpd": "Upgrade vsftpd to 3.0.5 or later. Disable FTP if not needed, use SFTP.",
    "openssh": "Upgrade OpenSSH to the latest version. Disable password login, use keys.",
    "apache": "Upgrade Apache httpd to 2.4.58+. Hide version with ServerTokens Prod.",
    "mysql": "Update MySQL. Bind to 127.0.0.1 and block port 3306 in the firewall.",
    "nginx": "Upgrade nginx to the latest stable version.",
}
DEFAULT_FIX = "Update this service to the latest version and close the port if unused."


def has_exploit(product, version):
    """True if Kali's searchsploit finds a public exploit. False if tool missing."""
    if not shutil.which("searchsploit") or not product or not version:
        return False
    try:
        out = subprocess.run(
            ["searchsploit", "-j", f"{product} {version}"],
            capture_output=True, text=True, timeout=20,
        ).stdout
        return len(json.loads(out).get("RESULTS_EXPLOIT", [])) > 0
    except Exception:
        return False


def score(finding):
    """Risk score 0-100: severity points + 10 if a public exploit exists."""
    points = SEVERITY_POINTS.get(finding.get("severity", "").upper(), 0)
    if points and finding.get("exploit"):
        points += 10
    return min(points, 100)


def fix_for(finding):
    name = finding.get("product", "").lower()
    for key, advice in FIXES.items():
        if key in name:
            return advice
    return DEFAULT_FIX


def enrich(findings):
    """Adds exploit, score and fix to every finding. Returns the same list."""
    for f in findings:
        if f.get("severity", "").upper() == "CLEAN":
            f.update(exploit=False, score=0, fix="No action needed.")
            continue
        f["exploit"] = has_exploit(f.get("product"), f.get("version"))
        f["score"] = score(f)
        f["fix"] = fix_for(f)
    return findings


def fix_first(findings):
    """Findings sorted by score, highest first (the 'Fix first' list)."""
    return sorted(findings, key=lambda f: f["score"], reverse=True)


def overall(findings):
    """Overall rating from the highest score."""
    top = max((f["score"] for f in findings), default=0)
    if top >= 90:
        return "CRITICAL"
    if top >= 70:
        return "HIGH"
    if top >= 40:
        return "MEDIUM"
    return "LOW"


if __name__ == "__main__":  # quick test: python3 risk.py
    demo = [
        {"host": "192.168.56.101", "port": 21, "service": "ftp", "product": "vsftpd",
         "version": "2.3.4", "severity": "CRITICAL", "cve": "CVE-2011-2523"},
        {"host": "192.168.56.101", "port": 22, "service": "ssh", "product": "OpenSSH",
         "version": "7.2", "severity": "MEDIUM", "cve": "CVE-2016-6210"},
    ]
    for f in fix_first(enrich(demo)):
        print(f"[{f['score']:3}] {f['host']}:{f['port']} {f['product']} -> {f['fix']}")
    print("Overall:", overall(demo))
