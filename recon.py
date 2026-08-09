"""
recon.py
Handles host discovery, port scanning, and service/version detection
using Nmap. Requires nmap to be installed (default on Kali).
"""

import subprocess
import xml.etree.ElementTree as ET
import shutil
import sys
from dataclasses import dataclass, field


@dataclass
class Service:
    port: int
    protocol: str
    state: str
    name: str
    product: str = ""
    version: str = ""
    extrainfo: str = ""

    @property
    def banner(self) -> str:
        parts = [self.product, self.version, self.extrainfo]
        return " ".join(p for p in parts if p).strip()


@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    os_guess: str = ""
    services: list = field(default_factory=list)


def check_nmap_installed() -> bool:
    return shutil.which("nmap") is not None


def run_scan(target: str, ports: str = "1-1000", scan_type: str = "sV",
             extra_args: str = "", timeout: int = 600) -> str:
    """
    Runs an nmap scan against `target` and returns the path to the
    XML output file.

    scan_type: 'sV' (version detect), 'sС' not used, use flags directly
    extra_args: e.g. '-O' for OS detection (needs root), '-A' for aggressive
    """
    if not check_nmap_installed():
        print("[!] nmap not found. Install with: sudo apt install nmap")
        sys.exit(1)

    out_xml = "/tmp/vapt_scan.xml"
    cmd = ["nmap", f"-{scan_type}", "-p", ports, "-oX", out_xml]
    if extra_args:
        cmd += extra_args.split()
    cmd.append(target)

    print(f"[*] Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, timeout=timeout,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"[!] nmap failed: {e.stderr.decode(errors='ignore')}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[!] nmap scan timed out")
        sys.exit(1)

    return out_xml


def parse_scan(xml_path: str) -> list:
    """Parses nmap XML output into a list of HostResult objects."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts = []

    for host_el in root.findall("host"):
        state_el = host_el.find("status")
        if state_el is not None and state_el.get("state") != "up":
            continue

        addr_el = host_el.find("address")
        ip = addr_el.get("addr") if addr_el is not None else "unknown"

        hostname = ""
        hn_el = host_el.find("hostnames/hostname")
        if hn_el is not None:
            hostname = hn_el.get("name", "")

        os_guess = ""
        osmatch = host_el.find("os/osmatch")
        if osmatch is not None:
            os_guess = osmatch.get("name", "")

        result = HostResult(ip=ip, hostname=hostname, os_guess=os_guess)

        for port_el in host_el.findall("ports/port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue

            service_el = port_el.find("service")
            svc = Service(
                port=int(port_el.get("portid")),
                protocol=port_el.get("protocol"),
                state=state.get("state"),
                name=service_el.get("name", "unknown") if service_el is not None else "unknown",
                product=service_el.get("product", "") if service_el is not None else "",
                version=service_el.get("version", "") if service_el is not None else "",
                extrainfo=service_el.get("extrainfo", "") if service_el is not None else "",
            )
            result.services.append(svc)

        hosts.append(result)

    return hosts


def print_summary(hosts: list):
    for h in hosts:
        print(f"\n[+] Host: {h.ip} {f'({h.hostname})' if h.hostname else ''}")
        if h.os_guess:
            print(f"    OS guess: {h.os_guess}")
        if not h.services:
            print("    No open ports found in scanned range.")
        for s in h.services:
            banner = f" - {s.banner}" if s.banner else ""
            print(f"    {s.port}/{s.protocol:<4} {s.name:<15}{banner}")
