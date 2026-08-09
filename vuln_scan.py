"""
vuln_scan.py
Runs Nmap's vulnerability-detection NSE scripts against discovered
services, and cross-references service banners against the local
Exploit-DB mirror via `searchsploit` (ships with Kali).
"""

import subprocess
import shutil
import json
import re
from dataclasses import dataclass, field


@dataclass
class Finding:
    host: str
    port: int
    service: str
    finding_type: str      # 'nse' or 'exploit-db'
    title: str
    detail: str = ""
    severity: str = "info"  # info / low / medium / high / critical


def check_searchsploit_installed() -> bool:
    return shutil.which("searchsploit") is not None


def run_vuln_scripts(target: str, ports: str) -> str:
    """
    Runs nmap with the 'vuln' NSE script category against the given
    ports. Returns raw text output (greppable form for simplicity).
    """
    out_txt = "/tmp/vapt_vuln.txt"
    cmd = ["nmap", "-sV", "--script", "vuln", "-p", ports,
           "-oN", out_txt, target]
    print(f"[*] Running vuln scripts: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, timeout=900,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"[!] nmap vuln scan failed: {e.stderr.decode(errors='ignore')}")
        return ""
    except subprocess.TimeoutExpired:
        print("[!] vuln scan timed out")
        return ""

    with open(out_txt, "r", errors="ignore") as f:
        return f.read()


def parse_vuln_output(raw: str, host_ip: str) -> list:
    """
    Very lightweight parser: looks for lines flagged VULNERABLE
    or CVE references in nmap's NSE vuln output.
    """
    findings = []
    current_port = None
    for line in raw.splitlines():
        port_match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
        if port_match:
            current_port = int(port_match.group(1))
            current_service = port_match.group(3)
            continue

        if "VULNERABLE" in line or re.search(r"CVE-\d{4}-\d+", line):
            sev = "high" if "VULNERABLE" in line else "medium"
            findings.append(Finding(
                host=host_ip,
                port=current_port or 0,
                service=current_service if current_port else "unknown",
                finding_type="nse",
                title=line.strip(),
                severity=sev,
            ))
    return findings


def searchsploit_lookup(product: str, version: str = "") -> list:
    """
    Queries the local Exploit-DB database for known exploits matching
    a service banner. Returns a list of dicts (title, path, type).
    Does NOT return exploit source code, only catalog metadata.
    """
    if not check_searchsploit_installed():
        return []
    if not product:
        return []

    query = f"{product} {version}".strip()
    try:
        result = subprocess.run(
            ["searchsploit", "-j", query],
            check=True, timeout=30,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        data = json.loads(result.stdout.decode(errors="ignore"))
        results = data.get("RESULTS_EXPLOIT", [])
        return [
            {
                "title": r.get("Title", ""),
                "edb_id": r.get("EDB-ID", ""),
                "type": r.get("Type", ""),
                "platform": r.get("Platform", ""),
            }
            for r in results[:5]  # cap to top 5 matches
        ]
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            json.JSONDecodeError):
        return []


def enrich_with_exploitdb(hosts) -> list:
    """
    For every service on every host, look up matching Exploit-DB
    catalog entries. Returns Finding objects of type 'exploit-db'.
    """
    findings = []
    for h in hosts:
        for s in h.services:
            if not s.product:
                continue
            matches = searchsploit_lookup(s.product, s.version)
            for m in matches:
                findings.append(Finding(
                    host=h.ip,
                    port=s.port,
                    service=s.name,
                    finding_type="exploit-db",
                    title=m["title"],
                    detail=f"EDB-ID: {m['edb_id']} | Type: {m['type']} | Platform: {m['platform']}",
                    severity="medium",
                ))
    return findings
