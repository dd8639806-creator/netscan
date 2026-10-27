"""checks.py - configuration checks for NetScan (FTP, SSH, HTTP).

Finds real misconfigurations (not just old versions):
  - FTP: anonymous login allowed, or no encryption (clear-text passwords)
  - SSH: password login enabled (brute-force risk)
  - HTTP: missing security headers

Safety: these checks only run against private / local IPs (your own lab).
"""
import ftplib
import ipaddress
import ssl
import subprocess
import urllib.error
import urllib.request

TIMEOUT = 5
WANTED_HEADERS = ["X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy"]


def is_lab(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback
    except ValueError:
        return False


def finding(cid, severity, description, fix):
    return {"cve": cid, "severity": severity, "description": description,
            "fix": fix, "source": "config"}


def check_ftp(ip, port):
    # 1) anonymous login?
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=TIMEOUT)
    except Exception:
        return None
    try:
        ftp.login()  # user "anonymous"
        ftp.quit()
        return finding("CONFIG-FTP-ANON", "HIGH",
                       "Anonymous FTP login is allowed: anyone can connect without a password.",
                       "Set anonymous_enable=NO in /etc/vsftpd.conf, then: sudo systemctl restart vsftpd")
    except Exception:
        pass
    # 2) is encryption (TLS) supported?
    try:
        tls = ftplib.FTP_TLS()
        tls.connect(ip, port, timeout=TIMEOUT)
        tls.auth()
        tls.close()
        return None
    except Exception:
        return finding("CONFIG-FTP-PLAINTEXT", "MEDIUM",
                       "FTP has no encryption: usernames, passwords and files travel in clear text.",
                       "Disable FTP and use SFTP: sudo systemctl disable --now vsftpd")


def check_ssh(ip, port):
    try:
        out = subprocess.run(
            ["ssh", "-o", "PreferredAuthentications=none", "-o", "BatchMode=yes",
             "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=5", "-p", str(port), f"probe@{ip}", "true"],
            capture_output=True, text=True, timeout=15)
    except Exception:
        return None
    text = out.stderr.lower()
    if "permission denied" in text and ("password" in text or "keyboard-interactive" in text):
        return finding("CONFIG-SSH-PASSWORD", "MEDIUM",
                       "SSH allows password login: attackers can try to guess passwords (brute force).",
                       "Use SSH keys, set PasswordAuthentication no in /etc/ssh/sshd_config, "
                       "then: sudo systemctl restart ssh")
    return None


def check_http(ip, port, https=False):
    url = f"{'https' if https else 'http'}://{ip}:{port}/"
    ctx = ssl._create_unverified_context() if https else None
    try:
        resp = urllib.request.urlopen(url, timeout=TIMEOUT, context=ctx)
        headers = resp.headers
    except urllib.error.HTTPError as e:
        headers = e.headers
    except Exception:
        return None
    missing = [h for h in WANTED_HEADERS if h not in headers]
    if not missing:
        return None
    return finding("CONFIG-HTTP-HEADERS", "MEDIUM",
                   "Web server is missing security headers: " + ", ".join(missing) + ".",
                   "Run: sudo a2enmod headers, add the missing headers in your Apache config, "
                   "then: sudo systemctl restart apache2")


def check_port(ip, port, service):
    port = int(port)
    service = (service or "").lower()
    if service == "ftp":
        return check_ftp(ip, port)
    if service == "ssh":
        return check_ssh(ip, port)
    if port == 443 or service == "https":
        return check_http(ip, port, https=True)
    if service.startswith("http"):
        return check_http(ip, port)
    return None


def apply(report):
    """Add configuration findings to the NetScan report (lab IPs only)."""
    extra = []
    ran = False
    for r in report:
        if not is_lab(r["ip"]):
            continue
        if not ran:
            print("[*] Running configuration checks (lab target)...")
            ran = True
        f = check_port(r["ip"], r["port"], r["service"])
        if not f:
            continue
        if r["vulnerability"] is None:
            r["vulnerability"] = f
        else:  # port already has a CVE: show the config issue as its own row
            row = dict(r)
            row["vulnerability"] = f
            extra.append(row)
    return report + extra
